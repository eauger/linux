/*
 * Reserved IOVA Management
 *
 * Copyright (c) 2015 Linaro Ltd.
 *              www.linaro.org
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 */

#include <linux/iommu.h>
#include <linux/dma-iommu.h>
#include <linux/msi-iommu.h>
#include <linux/spinlock.h>
#include <linux/iova.h>

struct doorbell_mapping {
	struct kref		kref;
	struct list_head	next;
	phys_addr_t		addr;
	dma_addr_t		iova;
	size_t			size;
};

struct doorbell_mapping_info {
	struct list_head list; /* list of doorbell mapping entries */
	spinlock_t lock;
};

int iommu_get_msi_cookie(struct iommu_domain *domain)
{
	struct doorbell_mapping_info *dmi;
	int ret;

	if (domain->msi_cookie || domain->iova_cookie)
		return -EINVAL;

	ret = iommu_get_dma_cookie(domain);
	if (ret)
		return ret;

	dmi = kzalloc(sizeof(*dmi), GFP_KERNEL);

	INIT_LIST_HEAD(&dmi->list);
	spin_lock_init(&dmi->lock);
	iova_cache_get();

	domain->msi_cookie = dmi;

	return dmi ? 0 : -ENOMEM;
}
EXPORT_SYMBOL(iommu_get_msi_cookie);

void iommu_put_msi_cookie(struct iommu_domain *domain)
{
	struct doorbell_mapping_info *dmi = domain->msi_cookie;

	if (!dmi)
		return;

	domain->msi_cookie = NULL;

	WARN_ON(!list_empty(&dmi->list));

	kfree(dmi);
	iommu_put_dma_cookie(domain);
	iova_cache_put();
}
EXPORT_SYMBOL(iommu_put_msi_cookie);

int iommu_msi_set_aperture(struct iommu_domain *domain,
			   dma_addr_t start, dma_addr_t end)
{
	struct doorbell_mapping_info *dmi = domain->msi_cookie;
	int ret;

	if (!dmi)
		return -ENODEV;

	if (iommu_domain_msi_aperture_valid(domain))
		return -EINVAL;

	ret = iommu_dma_init_domain(domain, start, end - start + 1);

	if (!ret) {
		domain->msi_geometry.aperture_start = start;
		domain->msi_geometry.aperture_end = end;
	}

	return ret;
}
EXPORT_SYMBOL_GPL(iommu_msi_set_aperture);

