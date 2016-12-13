/*
 * Copyright (C) 2013-2016 Red Hat
 * Author: Rob Clark <robdclark@gmail.com>
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License version 2 as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <linux/fence.h>

#include "msm_drv.h"
#include "msm_fence.h"

struct msm_fence_context *
msm_fence_context_alloc(struct drm_device *dev, const char *name)
{
	struct msm_fence_context *fctx;

	fctx = kzalloc(sizeof(*fctx), GFP_KERNEL);
	if (!fctx)
		return ERR_PTR(-ENOMEM);

	fctx->dev = dev;
	fctx->name = name;
	fctx->context = fence_context_alloc(MSM_GPU_MAX_RINGS);
	init_waitqueue_head(&fctx->event);
	spin_lock_init(&fctx->spinlock);
	hash_init(fctx->hash);

	return fctx;
}

void msm_fence_context_free(struct msm_fence_context *fctx)
{
	kfree(fctx);
}

static inline bool fence_completed(struct msm_ringbuffer *ring, uint32_t fence)
{
	return (int32_t)(ring->completed_fence - fence) >= 0;
}

struct msm_fence {
	struct msm_fence_context *fctx;
	struct msm_ringbuffer *ring;
	struct fence base;
	struct hlist_node node;
	u32 fence_id;
};

static struct msm_fence *fence_from_id(struct msm_fence_context *fctx,
		uint32_t id)
{
	struct msm_fence *f;

	hash_for_each_possible_rcu(fctx->hash, f, node, id) {
		if (f->fence_id == id) {
			if (fence_get_rcu(&f->base))
				return f;
		}
	}

	return NULL;
}

/* legacy path for WAIT_FENCE ioctl: */
int msm_wait_fence(struct msm_fence_context *fctx, uint32_t fence,
		ktime_t *timeout, bool interruptible)
{
	struct msm_fence *f = fence_from_id(fctx, fence);
	int ret;

	/* If no active fence was found, there are two possibilities */
	if (!f) {
		/* The requested ID is newer than last issued - return error */
		if (fence > fctx->fence_id) {
			DRM_ERROR("%s: waiting on invalid fence: %u (of %u)\n",
				fctx->name, fence, fctx->fence_id);
			return -EINVAL;
		}

		/* If the id has been issued assume fence has been retired */
		return 0;
	}

	if (!timeout) {
		/* no-wait: */
		ret = fence_completed(f->ring, f->base.seqno) ? 0 : -EBUSY;
	} else {
		unsigned long remaining_jiffies = timeout_to_jiffies(timeout);

		if (interruptible)
			ret = wait_event_interruptible_timeout(fctx->event,
				fence_completed(f->ring, f->base.seqno),
				remaining_jiffies);
		else
			ret = wait_event_timeout(fctx->event,
				fence_completed(f->ring, f->base.seqno),
				remaining_jiffies);

		if (ret == 0) {
			DBG("timeout waiting for fence: %u (completed: %u)",
				f->base.seqno, f->ring->completed_fence);
			ret = -ETIMEDOUT;
		} else if (ret != -ERESTARTSYS) {
			ret = 0;
		}
	}

	fence_put(&f->base);

	return ret;
}

/* called from workqueue */
void msm_update_fence(struct msm_fence_context *fctx,
		struct msm_ringbuffer *ring, uint32_t fence)
{
	spin_lock(&fctx->spinlock);
	ring->completed_fence = max(fence, ring->completed_fence);

	spin_unlock(&fctx->spinlock);

	wake_up_all(&fctx->event);
}

static inline struct msm_fence *to_msm_fence(struct fence *fence)
{
	return container_of(fence, struct msm_fence, base);
}

static const char *msm_fence_get_driver_name(struct fence *fence)
{
	return "msm";
}

static const char *msm_fence_get_timeline_name(struct fence *fence)
{
	struct msm_fence *f = to_msm_fence(fence);
	return f->fctx->name;
}

static bool msm_fence_enable_signaling(struct fence *fence)
{
	return true;
}

static bool msm_fence_signaled(struct fence *fence)
{
	struct msm_fence *f = to_msm_fence(fence);
	return fence_completed(f->ring, f->base.seqno);
}

static void msm_fence_release(struct fence *fence)
{
	struct msm_fence *f = to_msm_fence(fence);

	spin_lock(&f->fctx->spinlock);
	hash_del_rcu(&f->node);
	spin_unlock(&f->fctx->spinlock);

	kfree_rcu(f, base.rcu);
}

static const struct fence_ops msm_fence_ops = {
	.get_driver_name = msm_fence_get_driver_name,
	.get_timeline_name = msm_fence_get_timeline_name,
	.enable_signaling = msm_fence_enable_signaling,
	.signaled = msm_fence_signaled,
	.wait = fence_default_wait,
	.release = msm_fence_release,
};

struct fence *
msm_fence_alloc(struct msm_fence_context *fctx, struct msm_ringbuffer *ring)
{
	struct msm_fence *f;

	f = kzalloc(sizeof(*f), GFP_KERNEL);
	if (!f)
		return ERR_PTR(-ENOMEM);

	f->fctx = fctx;
	f->ring = ring;

	/* Make a user fence ID to pass back for the legacy functions */
	f->fence_id = ++fctx->fence_id;

	spin_lock(&fctx->spinlock);
	hash_add(fctx->hash, &f->node, f->fence_id);
	spin_unlock(&fctx->spinlock);

	fence_init(&f->base, &msm_fence_ops, &fctx->spinlock,
			fctx->context + ring->id, ++ring->last_fence);

	return &f->base;
}
