/*
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
#ifndef __MSI_IOMMU_H
#define __MSI_IOMMU_H

#include <linux/types.h>
#include <linux/kernel.h>

struct iommu_domain;

#ifdef CONFIG_IOMMU_MSI

/**
 * iommu_get_msi_cookie - Acquire MSI mapping resources for a domain
 * @domain: IOMMU domain to prepare for MSI mapping
 *
 * IOMMU drivers which require MSI mapping should normally call this
 * from their domain_alloc callback when domain->type ==
 * IOMMU_DOMAIN_UNMANAGED.
 */
int iommu_get_msi_cookie(struct iommu_domain *domain);

/**
 * iommu_put_msi_cookie - Release a domain's MSI mapping resources
 * @domain: IOMMU domain previously prepared by iommu_get_msi_cookie()
 *
 * IOMMU drivers requesting MSI mapping should normally call this from
 * their domain_free callback.
 */
void iommu_put_msi_cookie(struct iommu_domain *domain);

/**
 * iommu_msi_set_aperture: allocate the msi iova domain
 * according to the specified start/end IOVAs
 *
 * @domain: iommu domain handle
 * @start: MSI iova start address
 * @end: MSI iova end address
 */
int iommu_msi_set_aperture(struct iommu_domain *domain,
			   dma_addr_t start, dma_addr_t end);

#else

static inline int
iommu_msi_set_aperture(struct iommu_domain *domain,
		       dma_addr_t start, dma_addr_t end)
{
	return -ENOENT;
}

#endif	/* CONFIG_IOMMU_MSI */
#endif	/* __MSI_IOMMU_H */
