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
struct msi_msg;

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

/**
 * iommu_msi_get_doorbell_iova: allocate a contiguous set of iova pages and
 * map them to the MSI doorbell's physical range defined by @addr and @size.
 *
 * @domain: iommu domain handle
 * @addr: physical address to bind
 * @size: size of the binding
 * @prot: mapping protection attribute
 * @iova: returned iova
 *
 * Mapped physical pfns are within [@addr >> order, (@addr + size -1) >> order]
 * where order corresponds to the iova domain order.
 * This mapping is tracked and reference counted with the minimal granularity
 * of @size.
 */
int iommu_msi_get_doorbell_iova(struct iommu_domain *domain,
				phys_addr_t addr, size_t size, int prot,
				dma_addr_t *iova);

/**
 * iommu_msi_put_doorbell_iova: decrement a ref count of the doorbell's mapping
 *
 * @domain: iommu domain handle
 * @addr: physical address whose binding ref count is decremented
 *
 * if the binding ref count is null, destroy the MSI doorbell's mapping
 */
void iommu_msi_put_doorbell_iova(struct iommu_domain *domain, phys_addr_t addr);

/**
 * iommu_msi_domain: in case the device is upstream to an IOMMU and this IOMMU
 * translates the MSI transaction, returns the iommu domain the MSI doorbell
 * address must be mapped in; else returns NULL.
 *
 * @dev: device handle
 */
struct iommu_domain *iommu_msi_domain(struct device *dev);

/**
 * iommu_msi_msg_pa_to_va: in case a device's MSI transaction is translated
 * by an IOMMU, the msg address must be an IOVA instead of a physical address.
 * This function overwrites the original MSI message containing the doorbell's
 * physical address with the doorbell's pre-allocated IOVA, if any.
 *
 * The doorbell physical address must be bound previously to an IOVA using
 * iommu_msi_get_doorbell_iova
 *
 * @dev: device emitting the MSI
 * @msg: original MSI message containing the PA to be overwritten with the IOVA
 *
 * return 0 if the MSI does not need to be mapped or when the PA/IOVA
 * were successfully swapped; return -EINVAL if the addresses need
 * to be swapped but not IOMMU binding is found
 */
int iommu_msi_msg_pa_to_va(struct device *dev, struct msi_msg *msg);


#else

static inline int
iommu_msi_set_aperture(struct iommu_domain *domain,
		       dma_addr_t start, dma_addr_t end)
{
	return -ENOENT;
}

static inline int iommu_msi_get_doorbell_iova(struct iommu_domain *domain,
					      phys_addr_t addr, size_t size,
					      int prot, dma_addr_t *iova)
{
	return -ENOENT;
}

static inline void iommu_msi_put_doorbell_iova(struct iommu_domain *domain,
					       phys_addr_t addr) {}

static inline struct iommu_domain *iommu_msi_domain(struct device *dev)
{
	return NULL;
}

static inline int iommu_msi_msg_pa_to_va(struct device *dev,
					 struct msi_msg *msg)
{
	return 0;
}

#endif	/* CONFIG_IOMMU_MSI */
#endif	/* __MSI_IOMMU_H */
