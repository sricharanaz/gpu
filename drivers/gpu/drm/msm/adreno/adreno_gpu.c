/*
 * Copyright (C) 2013 Red Hat
 * Author: Rob Clark <robdclark@gmail.com>
 *
 * Copyright (c) 2014 The Linux Foundation. All rights reserved.
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

#include "adreno_gpu.h"
#include "msm_gem.h"
#include "msm_mmu.h"

#define RB_BLKSIZE 32

int adreno_get_param(struct msm_gpu *gpu, uint32_t param, uint64_t *value)
{
	struct adreno_gpu *adreno_gpu = to_adreno_gpu(gpu);

	switch (param) {
	case MSM_PARAM_GPU_ID:
		*value = adreno_gpu->info->revn;
		return 0;
	case MSM_PARAM_GMEM_SIZE:
		*value = adreno_gpu->gmem;
		return 0;
	case MSM_PARAM_GMEM_BASE:
		*value = 0x100000;
		return 0;
	case MSM_PARAM_CHIP_ID:
		*value = adreno_gpu->rev.patchid |
				(adreno_gpu->rev.minor << 8) |
				(adreno_gpu->rev.major << 16) |
				(adreno_gpu->rev.core << 24);
		return 0;
	case MSM_PARAM_MAX_FREQ:
		*value = adreno_gpu->base.fast_rate;
		return 0;
	case MSM_PARAM_TIMESTAMP:
		if (adreno_gpu->funcs->get_timestamp)
			return adreno_gpu->funcs->get_timestamp(gpu, value);
		return -EINVAL;
	default:
		DBG("%s: invalid param: %u", gpu->name, param);
		return -EINVAL;
	}
}

int adreno_hw_init(struct msm_gpu *gpu)
{
	struct adreno_gpu *adreno_gpu = to_adreno_gpu(gpu);
	int i;

	DBG("%s", gpu->name);

	for (i = 0; i < gpu->nr_rings; i++) {
		int ret = msm_gem_get_iova(gpu->rb[i]->bo, gpu->aspace,
			&gpu->rb[i]->iova);
		if (ret) {
			gpu->rb[i]->iova = 0;
			dev_err(gpu->dev->dev,
				"could not map ringbuffer %d: %d\n", i, ret);
			return ret;
		}
	}

	/* Setup REG_CP_RB_CNTL: */
	adreno_gpu_write(adreno_gpu, REG_ADRENO_CP_RB_CNTL,
		/* size is log2(quad-words): */
		AXXX_CP_RB_CNTL_BUFSZ(ilog2(MSM_GPU_RINGBUFFER_SZ / 8)) |
		AXXX_CP_RB_CNTL_BLKSZ(ilog2(RB_BLKSIZE / 8)) |
		(adreno_is_a430(adreno_gpu) ? AXXX_CP_RB_CNTL_NO_UPDATE : 0));

	/* Setup ringbuffer address - use ringbuffer[0] for GPU init */
	adreno_gpu_write64(adreno_gpu, REG_ADRENO_CP_RB_BASE,
		REG_ADRENO_CP_RB_BASE_HI, gpu->rb[0]->iova);

	if (!adreno_is_a430(adreno_gpu)) {
		adreno_gpu_write64(adreno_gpu, REG_ADRENO_CP_RB_RPTR_ADDR,
			REG_ADRENO_CP_RB_RPTR_ADDR_HI,
			rbmemptr(adreno_gpu, 0, rptr));
	}

	return 0;
}

static uint32_t get_wptr(struct msm_ringbuffer *ring)
{
	return ring->cur - ring->start;
}

/* Use this helper to read rptr, since a430 doesn't update rptr in memory */
static uint32_t get_rptr(struct adreno_gpu *adreno_gpu,
		struct msm_ringbuffer *ring)
{
	if (adreno_is_a430(adreno_gpu)) {
		/*
		 * If index is anything but 0 this will probably break horribly,
		 * but I think that we have enough infrastructure in place to
		 * ensure that it won't be. If not then this is why your
		 * a430 stopped working.
		 */
		return adreno_gpu->memptrs->rptr[ring->id] = adreno_gpu_read(
			adreno_gpu, REG_ADRENO_CP_RB_RPTR);
	} else
		return adreno_gpu->memptrs->rptr[ring->id];
}

struct msm_ringbuffer *adreno_active_ring(struct msm_gpu *gpu)
{
	return gpu->rb[0];
}

uint32_t adreno_last_fence(struct msm_gpu *gpu, struct msm_ringbuffer *ring)
{
	struct adreno_gpu *adreno_gpu = to_adreno_gpu(gpu);

	if (!ring)
		return 0;

	return adreno_gpu->memptrs->fence[ring->id];
}

void adreno_recover(struct msm_gpu *gpu)
{
	struct adreno_gpu *adreno_gpu = to_adreno_gpu(gpu);
	struct drm_device *dev = gpu->dev;
	struct msm_ringbuffer *ring;
	int ret, i;

	gpu->funcs->pm_suspend(gpu);

	/* reset ringbuffer(s): */

	FOR_EACH_RING(gpu, ring, i) {
		if (!ring)
			continue;

		ring->cur = ring->start;

		/* reset completed fence seqno, discard anything pending: */
		adreno_gpu->memptrs->fence[ring->id] = ring->completed_fence;
		adreno_gpu->memptrs->rptr[ring->id]  = 0;
	}

	gpu->funcs->pm_resume(gpu);

	disable_irq(gpu->irq);
	ret = gpu->funcs->hw_init(gpu);
	if (ret) {
		dev_err(dev->dev, "gpu hw init failed: %d\n", ret);
		/* hmm, oh well? */
	}
	enable_irq(gpu->irq);
}

void adreno_submit(struct msm_gpu *gpu, struct msm_gem_submit *submit,
		struct msm_file_private *ctx)
{
	struct adreno_gpu *adreno_gpu = to_adreno_gpu(gpu);
	struct msm_drm_private *priv = gpu->dev->dev_private;
	struct msm_ringbuffer *ring = submit->ring;
	unsigned i;

	for (i = 0; i < submit->nr_cmds; i++) {
		switch (submit->cmd[i].type) {
		case MSM_SUBMIT_CMD_IB_TARGET_BUF:
			/* ignore IB-targets */
			break;
		case MSM_SUBMIT_CMD_CTX_RESTORE_BUF:
			/* ignore if there has not been a ctx switch: */
			if (priv->lastctx == ctx)
				break;
		case MSM_SUBMIT_CMD_BUF:
			OUT_PKT3(ring, adreno_is_a430(adreno_gpu) ?
				CP_INDIRECT_BUFFER_PFE : CP_INDIRECT_BUFFER_PFD, 2);
			OUT_RING(ring, submit->cmd[i].iova);
			OUT_RING(ring, submit->cmd[i].size);
			OUT_PKT2(ring);
			break;
		}
	}

	OUT_PKT0(ring, REG_AXXX_CP_SCRATCH_REG2, 1);
	OUT_RING(ring, submit->fence->seqno);

	if (adreno_is_a3xx(adreno_gpu) || adreno_is_a4xx(adreno_gpu)) {
		/* Flush HLSQ lazy updates to make sure there is nothing
		 * pending for indirect loads after the timestamp has
		 * passed:
		 */
		OUT_PKT3(ring, CP_EVENT_WRITE, 1);
		OUT_RING(ring, HLSQ_FLUSH);

		OUT_PKT3(ring, CP_WAIT_FOR_IDLE, 1);
		OUT_RING(ring, 0x00000000);
	}

	OUT_PKT3(ring, CP_EVENT_WRITE, 3);
	OUT_RING(ring, CACHE_FLUSH_TS);
	OUT_RING(ring, rbmemptr(adreno_gpu, ring->id, fence));
	OUT_RING(ring, submit->fence->seqno);

	/* we could maybe be clever and only CP_COND_EXEC the interrupt: */
	OUT_PKT3(ring, CP_INTERRUPT, 1);
	OUT_RING(ring, 0x80000000);

	/* Workaround for missing irq issue on 8x16/a306.  Unsure if the
	 * root cause is a platform issue or some a306 quirk, but this
	 * keeps things humming along:
	 */
	if (adreno_is_a306(adreno_gpu)) {
		OUT_PKT3(ring, CP_WAIT_FOR_IDLE, 1);
		OUT_RING(ring, 0x00000000);
		OUT_PKT3(ring, CP_INTERRUPT, 1);
		OUT_RING(ring, 0x80000000);
	}

#if 0
	if (adreno_is_a3xx(adreno_gpu)) {
		/* Dummy set-constant to trigger context rollover */
		OUT_PKT3(ring, CP_SET_CONSTANT, 2);
		OUT_RING(ring, CP_REG(REG_A3XX_HLSQ_CL_KERNEL_GROUP_X_REG));
		OUT_RING(ring, 0x00000000);
	}
#endif

	gpu->funcs->flush(gpu, ring);
}

void adreno_flush(struct msm_gpu *gpu, struct msm_ringbuffer *ring)
{
	struct adreno_gpu *adreno_gpu = to_adreno_gpu(gpu);
	uint32_t wptr = get_wptr(ring);

	/* ensure writes to ringbuffer have hit system memory: */
	mb();

	adreno_gpu_write(adreno_gpu, REG_ADRENO_CP_RB_WPTR, wptr);
}

bool adreno_idle(struct msm_gpu *gpu, struct msm_ringbuffer *ring)
{
	struct adreno_gpu *adreno_gpu = to_adreno_gpu(gpu);
	uint32_t wptr = get_wptr(ring);

	/* wait for CP to drain ringbuffer: */
	if (!spin_until(get_rptr(adreno_gpu, ring) == wptr))
		return true;

	/* TODO maybe we need to reset GPU here to recover from hang? */
	DRM_ERROR("%s: timeout waiting to drain ringbuffer %d!\n", gpu->name,
		ring->id);
	return false;
}

#ifdef CONFIG_DEBUG_FS
void adreno_show(struct msm_gpu *gpu, struct seq_file *m)
{
	struct adreno_gpu *adreno_gpu = to_adreno_gpu(gpu);
	struct msm_ringbuffer *ring;
	int i;

	seq_printf(m, "revision: %d (%d.%d.%d.%d)\n",
			adreno_gpu->info->revn, adreno_gpu->rev.core,
			adreno_gpu->rev.major, adreno_gpu->rev.minor,
			adreno_gpu->rev.patchid);

	FOR_EACH_RING(gpu, ring, i) {
		if (!ring)
			continue;

		seq_printf(m, "rb %d: fence:    %d/%d\n", i,
			adreno_last_fence(gpu, ring),
			ring->completed_fence);

		seq_printf(m, "      rptr:     %d\n",
			get_rptr(adreno_gpu, ring));
		seq_printf(m, "rb wptr:  %d\n", get_wptr(ring));
	}

	gpu->funcs->pm_resume(gpu);

	/* dump these out in a form that can be parsed by demsm: */
	seq_printf(m, "IO:region %s 00000000 00020000\n", gpu->name);
	for (i = 0; adreno_gpu->registers[i] != ~0; i += 2) {
		uint32_t start = adreno_gpu->registers[i];
		uint32_t end   = adreno_gpu->registers[i+1];
		uint32_t addr;

		for (addr = start; addr <= end; addr++) {
			uint32_t val = gpu_read(gpu, addr);
			seq_printf(m, "IO:R %08x %08x\n", addr<<2, val);
		}
	}

	gpu->funcs->pm_suspend(gpu);
}
#endif

/* Dump common gpu status and scratch registers on any hang, to make
 * the hangcheck logs more useful.  The scratch registers seem always
 * safe to read when GPU has hung (unlike some other regs, depending
 * on how the GPU hung), and they are useful to match up to cmdstream
 * dumps when debugging hangs:
 */
void adreno_dump_info(struct msm_gpu *gpu)
{
	struct adreno_gpu *adreno_gpu = to_adreno_gpu(gpu);
	struct msm_ringbuffer *ring;
	int i;

	printk("revision: %d (%d.%d.%d.%d)\n",
			adreno_gpu->info->revn, adreno_gpu->rev.core,
			adreno_gpu->rev.major, adreno_gpu->rev.minor,
			adreno_gpu->rev.patchid);

	FOR_EACH_RING(gpu, ring, i) {
		if (!ring)
			continue;

		printk("rb %d: fence:    %d/%d\n", i,
			adreno_last_fence(gpu, ring),
			ring->completed_fence);

		printk("rptr:     %d\n", get_rptr(adreno_gpu, ring));
		printk("rb wptr:  %d\n", get_wptr(ring));
	}

	for (i = 0; i < 8; i++) {
		printk("CP_SCRATCH_REG%d: %u\n", i,
			gpu_read(gpu, REG_AXXX_CP_SCRATCH_REG0 + i));
	}
}

/* would be nice to not have to duplicate the _show() stuff with printk(): */
void adreno_dump(struct msm_gpu *gpu)
{
	struct adreno_gpu *adreno_gpu = to_adreno_gpu(gpu);
	int i;

	/* dump these out in a form that can be parsed by demsm: */
	printk("IO:region %s 00000000 00020000\n", gpu->name);
	for (i = 0; adreno_gpu->registers[i] != ~0; i += 2) {
		uint32_t start = adreno_gpu->registers[i];
		uint32_t end   = adreno_gpu->registers[i+1];
		uint32_t addr;

		for (addr = start; addr <= end; addr++) {
			uint32_t val = gpu_read(gpu, addr);
			printk("IO:R %08x %08x\n", addr<<2, val);
		}
	}
}

static uint32_t ring_freewords(struct msm_ringbuffer *ring)
{
	struct adreno_gpu *adreno_gpu = to_adreno_gpu(ring->gpu);
	uint32_t size = MSM_GPU_RINGBUFFER_SZ >> 2;
	uint32_t wptr = get_wptr(ring);
	uint32_t rptr = get_rptr(adreno_gpu, ring);
	return (rptr + (size - 1) - wptr) % size;
}

void adreno_wait_ring(struct msm_ringbuffer *ring, uint32_t ndwords)
{
	if (spin_until(ring_freewords(ring) >= ndwords))
		DRM_ERROR("%s: timeout waiting for space in ringubffer %d\n",
			ring->gpu->name, ring->id);
}

static const char *iommu_ports[] = {
		"gfx3d_user", "gfx3d_priv",
		"gfx3d1_user", "gfx3d1_priv",
};

int adreno_gpu_init(struct drm_device *drm, struct platform_device *pdev,
		struct adreno_gpu *adreno_gpu,
		const struct adreno_gpu_funcs *funcs, int nr_rings)
{
	struct adreno_platform_config *config = pdev->dev.platform_data;
	struct msm_gpu_config adreno_gpu_config  = { 0 };
	struct msm_gpu *gpu = &adreno_gpu->base;
	struct msm_mmu *mmu;
	int ret;

	adreno_gpu->funcs = funcs;
	adreno_gpu->info = adreno_info(config->rev);
	adreno_gpu->gmem = adreno_gpu->info->gmem;
	adreno_gpu->revn = adreno_gpu->info->revn;
	adreno_gpu->rev = config->rev;
	adreno_gpu->quirks = config->quirks;

	gpu->fast_rate = config->fast_rate;
	gpu->slow_rate = config->slow_rate;
	gpu->bus_freq  = config->bus_freq;
#ifdef DOWNSTREAM_CONFIG_MSM_BUS_SCALING
	gpu->bus_scale_table = config->bus_scale_table;
#endif

	DBG("fast_rate=%u, slow_rate=%u, bus_freq=%u",
			gpu->fast_rate, gpu->slow_rate, gpu->bus_freq);

	adreno_gpu_config.ioname = "kgsl_3d0_reg_memory";
	adreno_gpu_config.irqname = "kgsl_3d0_irq";

	adreno_gpu_config.va_start = SZ_16M;
	adreno_gpu_config.va_end = 0xffffffff;

	adreno_gpu_config.nr_rings = nr_rings;

	ret = msm_gpu_init(drm, pdev, &adreno_gpu->base, &funcs->base,
			adreno_gpu->info->name, &adreno_gpu_config);
	if (ret)
		return ret;

	ret = request_firmware(&adreno_gpu->pm4, adreno_gpu->info->pm4fw, drm->dev);
	if (ret) {
		dev_err(drm->dev, "failed to load %s PM4 firmware: %d\n",
				adreno_gpu->info->pm4fw, ret);
		return ret;
	}

	ret = request_firmware(&adreno_gpu->pfp, adreno_gpu->info->pfpfw, drm->dev);
	if (ret) {
		dev_err(drm->dev, "failed to load %s PFP firmware: %d\n",
				adreno_gpu->info->pfpfw, ret);
		return ret;
	}

	mmu = gpu->aspace->mmu;
	if (mmu) {
		ret = mmu->funcs->attach(mmu, iommu_ports,
				ARRAY_SIZE(iommu_ports));
		if (ret)
			return ret;
	}

	mutex_lock(&drm->struct_mutex);
	adreno_gpu->memptrs_bo = msm_gem_new(drm, sizeof(*adreno_gpu->memptrs),
			MSM_BO_UNCACHED);
	mutex_unlock(&drm->struct_mutex);
	if (IS_ERR(adreno_gpu->memptrs_bo)) {
		ret = PTR_ERR(adreno_gpu->memptrs_bo);
		adreno_gpu->memptrs_bo = NULL;
		dev_err(drm->dev, "could not allocate memptrs: %d\n", ret);
		return ret;
	}

	adreno_gpu->memptrs = msm_gem_get_vaddr(adreno_gpu->memptrs_bo);
	if (IS_ERR(adreno_gpu->memptrs)) {
		dev_err(drm->dev, "could not vmap memptrs\n");
		return -ENOMEM;
	}

	ret = msm_gem_get_iova(adreno_gpu->memptrs_bo, gpu->aspace,
			&adreno_gpu->memptrs_iova);
	if (ret) {
		dev_err(drm->dev, "could not map memptrs: %d\n", ret);
		return ret;
	}

	return 0;
}

void adreno_gpu_cleanup(struct adreno_gpu *gpu)
{
	if (gpu->memptrs_bo) {
		if (gpu->memptrs)
			msm_gem_put_vaddr(gpu->memptrs_bo);

		if (gpu->memptrs_iova)
			msm_gem_put_iova(gpu->memptrs_bo, gpu->base.aspace);

		drm_gem_object_unreference_unlocked(gpu->memptrs_bo);
	}
	release_firmware(gpu->pm4);
	release_firmware(gpu->pfp);
	msm_gpu_cleanup(&gpu->base);
}
