/*
 * Copyright (C) 2013 Red Hat
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

#include "msm_drv.h"
#include "msm_iommu.h"

static int msm_fault_handler(struct iommu_domain *iommu, struct device *dev,
		unsigned long iova, int flags, void *arg)
{
	pr_warn_ratelimited("*** fault: iova=%16lx, flags=%d\n", iova, flags);
	return 0;
}

static int msm_iommu_attach(struct msm_mmu *mmu, const char * const *names,
			    int cnt)
{
	struct msm_iommu *iommu = to_msm_iommu(mmu);
	int val = 1, ret;

	/* Hope springs eternal */
	iommu->allow_dynamic = true;

	/* Use TTBR1 if it exists */
	/* FIXME: This should only be for GPU and in theory only for A5XX */
	ret = iommu_domain_set_attr(iommu->domain,
		DOMAIN_ATTR_ENABLE_TTBR1, &val);
	if (ret)
		iommu->allow_dynamic = false;

	/* Attach the device to the domain */
	ret = iommu_attach_device(iommu->domain, mmu->dev);

	/*
	 * Get the context bank for the base domain; this will be shared with
	 * the children.
	 */

	if (!ret) {
		iommu->cb = -1;
		if (iommu_domain_get_attr(iommu->domain,
			DOMAIN_ATTR_CONTEXT_BANK, &iommu->cb))
			iommu->allow_dynamic = false;
	}

	return 0;
}

static int msm_iommu_attach_dynamic(struct msm_mmu *mmu,
		const char * const *names, int cnt)
{
	static unsigned int procid;
	struct msm_iommu *iommu = to_msm_iommu(mmu);
	int ret;
	unsigned int id;

	/* Assign a unique procid for the domain to cut down on TLB churn */
	id = ++procid;

	iommu_domain_set_attr(iommu->domain, DOMAIN_ATTR_PROCID, &id);

	ret = iommu_attach_device(iommu->domain, mmu->dev);
	if (ret)
		return ret;

	/*
	 * Get the TTBR0 and the CONTEXTIDR - these will be used by the GPU to
	 * switch the pagetable on its own.
	 */
	iommu_domain_get_attr(iommu->domain, DOMAIN_ATTR_TTBR0,
		&iommu->ttbr0);
	iommu_domain_get_attr(iommu->domain, DOMAIN_ATTR_CONTEXTIDR,
		&iommu->contextidr);

	return 0;
}

static void msm_iommu_detach(struct msm_mmu *mmu)
{
	struct msm_iommu *iommu = to_msm_iommu(mmu);
	iommu_detach_device(iommu->domain, mmu->dev);
}

static int msm_iommu_map(struct msm_mmu *mmu, uint64_t iova,
		struct sg_table *sgt, unsigned len, int prot)
{
	struct msm_iommu *iommu = to_msm_iommu(mmu);
	struct iommu_domain *domain = iommu->domain;
	struct scatterlist *sg;
	unsigned long da = iova;
	unsigned int i, j;
	int ret;

	if (!domain || !sgt)
		return -EINVAL;

	for_each_sg(sgt->sgl, sg, sgt->nents, i) {
		dma_addr_t pa = sg_phys(sg) - sg->offset;
		size_t bytes = sg->length + sg->offset;

		VERB("map[%d]: %16lx %16lx(%zx)", i, da, (unsigned long)pa, bytes);

		ret = iommu_map(domain, da, pa, bytes, prot);
		if (ret)
			goto fail;

		da += bytes;
	}

	return 0;

fail:
	da = iova;

	for_each_sg(sgt->sgl, sg, i, j) {
		size_t bytes = sg->length + sg->offset;
		iommu_unmap(domain, da, bytes);
		da += bytes;
	}
	return ret;
}

static int msm_iommu_unmap(struct msm_mmu *mmu, uint64_t iova,
		struct sg_table *sgt, unsigned len)
{
	struct msm_iommu *iommu = to_msm_iommu(mmu);
	struct iommu_domain *domain = iommu->domain;
	struct scatterlist *sg;
	unsigned long da = iova;
	int i;

	for_each_sg(sgt->sgl, sg, sgt->nents, i) {
		size_t bytes = sg->length + sg->offset;
		size_t unmapped;

		unmapped = iommu_unmap(domain, da, bytes);
		if (unmapped < bytes)
			return unmapped;

		VERB("unmap[%d]: %16lx(%zx)", i, da, bytes);

		BUG_ON(!PAGE_ALIGNED(bytes));

		da += bytes;
	}

	return 0;
}

static void msm_iommu_destroy(struct msm_mmu *mmu)
{
	struct msm_iommu *iommu = to_msm_iommu(mmu);
	iommu_domain_free(iommu->domain);
	kfree(iommu);
}

static const struct msm_mmu_funcs funcs = {
		.attach = msm_iommu_attach,
		.detach = msm_iommu_detach,
		.map = msm_iommu_map,
		.unmap = msm_iommu_unmap,
		.destroy = msm_iommu_destroy,
};

static const struct msm_mmu_funcs dynamic_funcs = {
		.attach = msm_iommu_attach_dynamic,
		.detach = msm_iommu_detach,
		.map = msm_iommu_map,
		.unmap = msm_iommu_unmap,
		.destroy = msm_iommu_destroy,
};

struct msm_mmu *_msm_iommu_new(struct device *dev, struct iommu_domain *domain,
		const struct msm_mmu_funcs *funcs)
{
	struct msm_iommu *iommu;

	iommu = kzalloc(sizeof(*iommu), GFP_KERNEL);
	if (!iommu)
		return ERR_PTR(-ENOMEM);

	iommu->domain = domain;
	msm_mmu_init(&iommu->base, dev, funcs);
	iommu_set_fault_handler(domain, msm_fault_handler, dev);

	return &iommu->base;
}
struct msm_mmu *msm_iommu_new(struct device *dev, struct iommu_domain *domain)
{
	return _msm_iommu_new(dev, domain, &funcs);
}

/*
 * Given a base domain that is attached to a IOMMU device try to create a
 * dynamic domain that is also attached to the same device but allocates a new
 * pagetable. This is used to allow multiple pagetables to be attached to the
 * same device.
 */
struct msm_mmu *msm_iommu_new_dynamic(struct msm_mmu *base)
{
	struct msm_iommu *base_iommu = to_msm_iommu(base);
	struct iommu_domain *domain;
	struct msm_mmu *mmu;
	int ret, val = 1;

	/* Don't continue if the base domain didn't have the support we need */
	if (!base || base_iommu->allow_dynamic == false)
		return ERR_PTR(-EOPNOTSUPP);

	domain = iommu_domain_alloc(&platform_bus_type);
	if (!domain)
		return ERR_PTR(-ENODEV);

	mmu = _msm_iommu_new(base->dev, domain, &dynamic_funcs);

	if (IS_ERR(mmu)) {
		if (domain)
			iommu_domain_free(domain);
		return mmu;
	}

	ret = iommu_domain_set_attr(domain, DOMAIN_ATTR_DYNAMIC, &val);
	if (ret) {
		msm_iommu_destroy(mmu);
		return ERR_PTR(ret);
	}

	/* Set the context bank to match the base domain */
	iommu_domain_set_attr(domain, DOMAIN_ATTR_CONTEXT_BANK,
		&base_iommu->cb);

	return mmu;
}
