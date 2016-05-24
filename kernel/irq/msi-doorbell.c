/*
 * linux/kernel/irq/msi-doorbell.c
 *
 * Copyright (C) 2016 Linaro
 * Author: Eric Auger <eric.auger@linaro.org>
 *
 * This file is licensed under GPLv2.
 *
 * This file contains common code to manage MSI doorbells likely
 * to be iommu mapped. Typically meaningful on ARM.
 */

#include <linux/slab.h>
#include <linux/irq.h>
#include <linux/msi-doorbell.h>

struct msi_doorbell {
	struct msi_doorbell_info	info;
	struct list_head		next;
};

/* list of registered MSI doorbells */
static LIST_HEAD(msi_doorbell_list);

/* counts the number of unsafe registered doorbells */
static uint nb_unsafe_doorbells;

/* protects the list and nb__unsafe_doorbells */
static DEFINE_MUTEX(msi_doorbell_mutex);

struct msi_doorbell_info *
msi_doorbell_register_global(phys_addr_t base, size_t size,
			     int prot, bool irq_remapping)
{
	struct msi_doorbell *db;

	db = kzalloc(sizeof(*db), GFP_KERNEL);
	if (!db)
		return NULL;

	db->info.global_doorbell = base;
	db->info.size = size;
	db->info.prot = prot;
	db->info.irq_remapping = irq_remapping;

	mutex_lock(&msi_doorbell_mutex);
	list_add(&db->next, &msi_doorbell_list);
	if (!db->info.irq_remapping)
		nb_unsafe_doorbells++;
	mutex_unlock(&msi_doorbell_mutex);
	return &db->info;
}
EXPORT_SYMBOL_GPL(msi_doorbell_register_global);

void msi_doorbell_unregister_global(struct msi_doorbell_info *dbinfo)
{
	struct msi_doorbell *db;

	db = container_of(dbinfo, struct msi_doorbell, info);

	mutex_lock(&msi_doorbell_mutex);
	list_del(&db->next);
	if (!db->info.irq_remapping)
		nb_unsafe_doorbells--;
	mutex_unlock(&msi_doorbell_mutex);
	kfree(db);
}
EXPORT_SYMBOL_GPL(msi_doorbell_unregister_global);
