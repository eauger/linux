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
#include <linux/msi.h>

#ifdef CONFIG_PHYS_ADDR_T_64BIT
#define msg_to_phys_addr(msg) \
	(((phys_addr_t)((msg)->address_hi) << 32) | (msg)->address_lo)
#else
#define msg_to_phys_addr(msg)	((msg)->address_lo)
#endif

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

/* called with info->lock held */
static struct doorbell_mapping *
search_msi_doorbell_mapping(struct doorbell_mapping_info *info,
			    phys_addr_t addr, size_t size)
{
	struct doorbell_mapping *mapping;

	list_for_each_entry(mapping, &info->list, next) {
		if ((addr >= mapping->addr) &&
		    (addr + size <= mapping->addr + mapping->size))
			return mapping;
	}
	return NULL;
}

int iommu_msi_get_doorbell_iova(struct iommu_domain *domain,
				phys_addr_t addr, size_t size, int prot,
				dma_addr_t *iova)
{
	struct doorbell_mapping_info *dmi = domain->msi_cookie;
	struct iova_domain *iovad = domain->iova_cookie;
	struct doorbell_mapping *new_mapping, *mapping;
	phys_addr_t aligned_base, offset;
	size_t binding_size;
	struct iova *p_iova;
	dma_addr_t new_iova;
	int ret = -EINVAL;
	bool unmap = false;

	if (!dmi)
		return -ENODEV;

	if (!iommu_domain_msi_aperture_valid(domain))
		return -EINVAL;

	offset = iova_offset(iovad, addr);
	aligned_base = addr - offset;
	binding_size = iova_align(iovad, size + offset);

	spin_lock(&dmi->lock);

	mapping = search_msi_doorbell_mapping(dmi, aligned_base, binding_size);
	if (mapping) {
		*iova = mapping->iova + offset + aligned_base - mapping->addr;
		kref_get(&mapping->kref);
		ret = 0;
		goto unlock;
	}

	spin_unlock(&dmi->lock);

	new_mapping = kzalloc(sizeof(*new_mapping), GFP_KERNEL);
	if (!new_mapping)
		return -ENOMEM;

	p_iova = alloc_iova(iovad, binding_size >> iova_shift(iovad),
			    iovad->dma_32bit_pfn, true);
	if (!p_iova) {
		kfree(new_mapping);
		return -ENOMEM;
	}

	new_iova = iova_dma_addr(iovad, p_iova);
	*iova = new_iova;

	/* iommu_map is not supposed to be atomic */
	ret = iommu_map(domain, *iova, aligned_base, binding_size, prot);

	spin_lock(&dmi->lock);

	if (ret)
		goto free_iova;
	/*
	 * check again the doorbell mapping was not added while the lock
	 * was released
	 */
	mapping = search_msi_doorbell_mapping(dmi, aligned_base, binding_size);
	if (mapping) {
		*iova = mapping->iova + offset + aligned_base - mapping->addr;
		kref_get(&mapping->kref);
		ret = 0;
		unmap = true;
		goto free_iova;
	}

	kref_init(&new_mapping->kref);
	new_mapping->addr = aligned_base;
	new_mapping->iova = *iova;
	new_mapping->size = binding_size;

	list_add(&new_mapping->next, &dmi->list);

	*iova += offset;
	goto unlock;
free_iova:
	free_iova(iovad, p_iova->pfn_lo);
	kfree(new_mapping);
unlock:
	spin_unlock(&dmi->lock);
	if (unmap)
		iommu_unmap(domain, new_iova, binding_size);
	return ret;
}
EXPORT_SYMBOL_GPL(iommu_msi_get_doorbell_iova);

static void doorbell_mapping_release(struct kref *kref)
{
	struct doorbell_mapping *mapping =
		container_of(kref, struct doorbell_mapping, kref);

	list_del(&mapping->next);
	kfree(mapping);
}

void iommu_msi_put_doorbell_iova(struct iommu_domain *domain, phys_addr_t addr)
{
	struct doorbell_mapping_info *dmi = domain->msi_cookie;
	struct iova_domain *iovad = domain->iova_cookie;
	phys_addr_t aligned_addr, page_size, offset;
	struct doorbell_mapping *mapping;
	dma_addr_t iova;
	size_t size;
	int ret = 0;

	if (!dmi)
		return;

	page_size = (uint64_t)1 << iova_shift(iovad);
	offset = iova_offset(iovad, addr);
	aligned_addr = addr - offset;

	spin_lock(&dmi->lock);

	mapping = search_msi_doorbell_mapping(dmi, aligned_addr, page_size);
	if (!mapping)
		goto unlock;

	iova = mapping->iova;
	size = mapping->size;

	ret = kref_put(&mapping->kref, doorbell_mapping_release);

unlock:
	spin_unlock(&dmi->lock);
	if (ret) {
		iommu_unmap(domain, iova, size);
		free_iova(iovad, iova_pfn(iovad, iova));
	}
}
EXPORT_SYMBOL_GPL(iommu_msi_put_doorbell_iova);

struct iommu_domain *iommu_msi_domain(struct device *dev)
{
	struct iommu_domain *d = iommu_get_domain_for_dev(dev);
	struct iommu_domain_msi_geometry msi_geometry;

	if (!d || (d->type == IOMMU_DOMAIN_DMA))
		return NULL;

	iommu_domain_get_attr(d, DOMAIN_ATTR_MSI_GEOMETRY, &msi_geometry);
	if (!msi_geometry.iommu_msi_supported)
		return NULL;

	return d;
}
EXPORT_SYMBOL_GPL(iommu_msi_domain);

static dma_addr_t iommu_msi_find_iova(struct iommu_domain *domain,
				      phys_addr_t addr, size_t size)
{
	struct doorbell_mapping_info *dmi = domain->msi_cookie;
	struct iova_domain *iovad = domain->iova_cookie;
	struct doorbell_mapping *mapping;
	dma_addr_t iova = DMA_ERROR_CODE;
	phys_addr_t aligned_base, offset;
	size_t binding_size;

	if (!iovad || !dmi)
		return iova;

	offset = iova_offset(iovad, addr);
	aligned_base = addr - offset;
	binding_size = iova_align(iovad, size + offset);

	spin_lock(&dmi->lock);

	mapping = search_msi_doorbell_mapping(dmi, addr, size);
	if (mapping)
		iova = mapping->iova + offset + aligned_base - mapping->addr;

	spin_unlock(&dmi->lock);
	return iova;
}

int iommu_msi_msg_pa_to_va(struct device *dev, struct msi_msg *msg)
{
	struct iommu_domain *d = iommu_msi_domain(dev);
	dma_addr_t iova;

	if (!d)
		return 0;

	iova = iommu_msi_find_iova(d, msg_to_phys_addr(msg),
				   sizeof(phys_addr_t));

	if (iova == DMA_ERROR_CODE)
		return -EINVAL;

	msg->address_lo = lower_32_bits(iova);
	msg->address_hi = upper_32_bits(iova);
	return 0;
}
EXPORT_SYMBOL_GPL(iommu_msi_msg_pa_to_va);

