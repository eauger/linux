/*
 * API to register/query MSI doorbells likely to be IOMMU mapped
 *
 * Copyright (C) 2016 Red Hat, Inc.
 * Author: Eric Auger <eric.auger@redhat.com>
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

#include <linux/slab.h>
#include <linux/irq.h>
#include <linux/msi-doorbell.h>

/**
 * struct msi_doorbell_info - MSI doorbell region descriptor
 * @percpu_doorbells: per cpu doorbell base address
 * @global_doorbell: base address of the doorbell
 * @doorbell_is_percpu: is the doorbell per cpu or global?
 * @safe: true if irq remapping is implemented
 * @size: size of the doorbell
 */
struct msi_doorbell_info {
	union {
		phys_addr_t __percpu    *percpu_doorbells;
		phys_addr_t             global_doorbell;
	};
	bool    doorbell_is_percpu;
	bool    safe;
	size_t  size;
};

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

int msi_doorbell_register_global(phys_addr_t base, size_t size, bool safe,
				 struct msi_doorbell_info **dbinfo)
{
	struct msi_doorbell *db;

	db = kzalloc(sizeof(*db), GFP_KERNEL);
	if (!db)
		return -ENOMEM;

	db->info.global_doorbell = base;
	db->info.size = size;
	db->info.safe = safe;

	mutex_lock(&msi_doorbell_mutex);
	list_add(&db->next, &msi_doorbell_list);
	if (!db->info.safe)
		nb_unsafe_doorbells++;
	mutex_unlock(&msi_doorbell_mutex);
	*dbinfo = &db->info;
	return 0;
}
EXPORT_SYMBOL_GPL(msi_doorbell_register_global);

void msi_doorbell_unregister_global(struct msi_doorbell_info *dbinfo)
{
	struct msi_doorbell *db;

	db = container_of(dbinfo, struct msi_doorbell, info);

	mutex_lock(&msi_doorbell_mutex);
	list_del(&db->next);
	if (!db->info.safe)
		nb_unsafe_doorbells--;
	mutex_unlock(&msi_doorbell_mutex);
	kfree(db);
}
EXPORT_SYMBOL_GPL(msi_doorbell_unregister_global);

bool msi_doorbell_safe(void)
{
	return !nb_unsafe_doorbells;
}
EXPORT_SYMBOL_GPL(msi_doorbell_safe);
