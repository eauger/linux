/*
 * API to register/query MSI doorbells likely to be IOMMU mapped
 *
 * Copyright (C) 2016 Red Hat, Inc.
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
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#ifndef _LINUX_MSI_DOORBELL_H
#define _LINUX_MSI_DOORBELL_H

struct msi_doorbell_info;

#ifdef CONFIG_MSI_DOORBELL

/**
 * msi_doorbell_register - allocate and register a global doorbell
 * @base: physical base address of the global doorbell
 * @size: size of the global doorbell
 * @prot: protection/memory attributes
 * @safe: true is irq_remapping implemented for this doorbell
 * @dbinfo: returned doorbell info
 *
 * Return: 0 on success, -ENOMEM on allocation failure
 */
int msi_doorbell_register_global(phys_addr_t base, size_t size,
				 bool safe,
				 struct msi_doorbell_info **dbinfo);

/**
 * msi_doorbell_unregister_global - unregister a global doorbell
 * @db: doorbell info to unregister
 *
 * remove the doorbell descriptor from the list of registered doorbells
 * and deallocates it
 */
void msi_doorbell_unregister_global(struct msi_doorbell_info *db);

/**
 * msi_doorbell_safe - return whether all registered doorbells are safe
 *
 * Safe doorbells are those which implement irq remapping
 * Return: true if all doorbells are safe, false otherwise
 */
bool msi_doorbell_safe(void);

/**
 * msi_doorbell_calc_pages - compute the number of pages
 * requested to map all the registered doorbells
 * @order: iommu page order
 *
 * Return: the number of requested pages
 */
int msi_doorbell_calc_pages(unsigned int order);

#else

static inline int
msi_doorbell_register_global(phys_addr_t base, size_t size,
			     int prot, bool safe,
			     struct msi_doorbell_info **dbinfo)
{
	*dbinfo = NULL;
	return 0;
}

static inline void
msi_doorbell_unregister_global(struct msi_doorbell_info *db) {}

static inline bool msi_doorbell_safe(void)
{
	return true;
}

static inline int msi_doorbell_calc_pages(unsigned int order)
{
	return 0;
}

#endif /* CONFIG_MSI_DOORBELL */

#endif
