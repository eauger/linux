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

#ifdef CONFIG_MSI_DOORBELL

/**
 * msi_doorbell_register_global - allocate and register a global doorbell
 * @base: physical base address of the global doorbell
 * @size: size of the global doorbell
 * @prot: protection/memory attributes
 * @irq_remapping: is irq_remapping implemented for this doorbell
 *
 * Return: the newly allocated doorbell info handle or NULL if allocation
 * failed
 */
struct msi_doorbell_info *
msi_doorbell_register_global(phys_addr_t base, size_t size,
			     int prot, bool irq_remapping);

/**
 * msi_doorbell_unregister_global - unregister a global doorbell
 * @db: doorbell info to unregister
 *
 * remove the doorbell descriptor from the list of registered doorbells
 * and deallocates it
 */
void msi_doorbell_unregister_global(struct msi_doorbell_info *db);

/**
 * msi_doorbell_calc_pages - compute the number of pages
 * requested to map all the registered doorbells
 * @order: iommu page order
 *
 * Return: the number of requested pages
 */
int msi_doorbell_calc_pages(unsigned int order);

/**
 * msi_doorbell_safe - return whether all registered doorbells are safe
 *
 * Safe doorbells are those which implement irq remapping
 * Return: true if all doorbells are safe, false otherwise
 */
bool msi_doorbell_safe(void);

#else

static inline struct msi_doorbell_info *
msi_doorbell_register_global(phys_addr_t base, size_t size,
			     int prot, bool irq_remapping)
{
	return NULL;
}

static inline void
msi_doorbell_unregister_global(struct msi_doorbell_info *db) {}

static inline int msi_doorbell_calc_pages(unsigned int order)
{
	return 0;
}

static inline bool
msi_doorbell_safe(void)
{
	return true;
}
#endif /* CONFIG_MSI_DOORBELL */

#endif
