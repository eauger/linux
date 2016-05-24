/*
 * Copyright (C) 2016 Eric Auger
 *
 * Eric Auger <eric.auger@linaro.org>
 *
 * This file is licensed under the terms of the GNU General Public
 * License version 2.  This program is licensed "as is" without any
 * warranty of any kind, whether express or implied.
 */

#ifndef _LINUX_MSI_DOORBELL_H
#define _LINUX_MSI_DOORBELL_H

#include <linux/irq.h>

/* Describe all the MSI doorbell regions for an irqchip */
struct irq_chip_msi_doorbell_info {
	union {
		phys_addr_t __percpu *percpu_doorbells;
		phys_addr_t global_doorbell;
	};
	bool doorbell_is_percpu;
	bool irq_remapping;	/* is irq_remapping implemented? */
	size_t size;		/* size of a each doorbell */
	int prot;		/* iommu protection flag */
};

#ifdef CONFIG_MSI_DOORBELL

/**
 * msi_doorbell_register_global: allocate and register a global doorbell
 *
 * @chip_data: chip_data pointer
 * @addr: physical address of the global doorbell
 * @size: size of the global doorbell
 * @prot: protection/memory attributes
 * @irq_remapping: is irq_remapping implemented for this doorbell
 */
int msi_doorbell_register_global(void *chip_data, phys_addr_t addr,
				 size_t size, int prot, bool irq_remapping);

/**
 * msi_doorbell_unregister: remove a doorbell from the list of registered
 * doorbells
 * @chip_data: chip_data pointer
 */
void msi_doorbell_unregister(void *chip_data);

/**
 * msi_doorbell_lookup: return the doorbell info associated to @chip_data
 * doorbell info
 *
 * @chip_data: chip_data pointer
 * return NULL if no registered doorbell for that chip_data, or the actual
 * doorbell info pointer upon success
 */
struct irq_chip_msi_doorbell_info *
msi_doorbell_lookup(void *chip_data);

/**
 * msi_doorbell_pages: compute the number of iommu pages of size 1 << order
 * requested to map all the registered doorbells
 *
 * @order: iommu page order
 */
int msi_doorbell_pages(unsigned int order);

#else

static inline int
msi_doorbell_register_global(void *chip_data, phys_addr_t addr,
			     size_t size, int prot, bool irq_remapping)
{
	return -ENOENT;
}

static inline void msi_doorbell_unregister(void *chip_data);

static inline struct irq_chip_msi_doorbell_info *
msi_doorbell_lookup(void *chip_data)
{
	return NULL;
}

static inline int
msi_doorbell_pages(unsigned int order)
{
	return 0;
}

#endif /* CONFIG_MSI_DOORBELL */

#endif
