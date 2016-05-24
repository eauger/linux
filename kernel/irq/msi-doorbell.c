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

struct irqchip_doorbell {
	struct irq_chip_msi_doorbell_info info;
	void *chip_data;
	struct list_head next;
};

static LIST_HEAD(irqchip_doorbell_list);
static DEFINE_MUTEX(irqchip_doorbell_mutex);

int msi_doorbell_register_global(void *chip_data, phys_addr_t addr,
				 size_t size, int prot, bool irq_remapping)
{
	struct irqchip_doorbell *db;

	db = kmalloc(sizeof(*db), GFP_KERNEL);
	if (!db)
		return -ENOMEM;

	db->chip_data = chip_data;
	db->info.doorbell_is_percpu = false;
	db->info.global_doorbell = addr;
	db->info.size = size;
	db->info.prot = prot;
	db->info.irq_remapping = irq_remapping;

	mutex_lock(&irqchip_doorbell_mutex);
	list_add(&db->next, &irqchip_doorbell_list);
	mutex_unlock(&irqchip_doorbell_mutex);
	return 0;
}
EXPORT_SYMBOL_GPL(msi_doorbell_register_global);

void msi_doorbell_unregister(void *chip_data)
{
	struct irqchip_doorbell *db, *tmp;

	mutex_lock(&irqchip_doorbell_mutex);
	list_for_each_entry_safe(db, tmp, &irqchip_doorbell_list, next) {
		if (db->chip_data == chip_data) {
			list_del(&db->next);
			kfree(db);
			break;
		}
	}
	mutex_unlock(&irqchip_doorbell_mutex);
}
EXPORT_SYMBOL_GPL(msi_doorbell_unregister);

struct irq_chip_msi_doorbell_info *
msi_doorbell_lookup(void *chip_data)
{
	struct irqchip_doorbell *db;
	struct irq_chip_msi_doorbell_info *dbinfo = NULL;

	mutex_lock(&irqchip_doorbell_mutex);
	list_for_each_entry(db, &irqchip_doorbell_list, next) {
		if (db->chip_data == chip_data) {
			dbinfo = &db->info;
			break;
		}
	}
	mutex_unlock(&irqchip_doorbell_mutex);
	return dbinfo;
}
EXPORT_SYMBOL_GPL(msi_doorbell_lookup);

static int compute_db_mapping_requirements(phys_addr_t addr, size_t size,
					   unsigned int order)
{
	phys_addr_t offset, granule;
	unsigned int nb_pages;

	granule = (uint64_t)(1 << order);
	offset = addr & (granule - 1);
	size = ALIGN(size + offset, granule);
	nb_pages = size >> order;

	return nb_pages;
}

static int
compute_dbinfo_mapping_requirements(struct irq_chip_msi_doorbell_info *dbinfo,
				    unsigned int order)
{
	int ret = 0;

	if (!dbinfo->doorbell_is_percpu) {
		ret = compute_db_mapping_requirements(dbinfo->global_doorbell,
						      dbinfo->size, order);
	} else {
		phys_addr_t __percpu *pbase;
		int cpu;

		for_each_possible_cpu(cpu) {
			pbase = per_cpu_ptr(dbinfo->percpu_doorbells, cpu);
			ret += compute_db_mapping_requirements(*pbase,
							       dbinfo->size,
							       order);
		}
	}
	return ret;
}

int msi_doorbell_pages(unsigned int order)
{
	struct irqchip_doorbell *db;
	int ret = 0;

	mutex_lock(&irqchip_doorbell_mutex);
	list_for_each_entry(db, &irqchip_doorbell_list, next) {
		ret += compute_dbinfo_mapping_requirements(&db->info, order);
	}
	mutex_unlock(&irqchip_doorbell_mutex);

	return ret;
}
EXPORT_SYMBOL_GPL(msi_doorbell_pages);

