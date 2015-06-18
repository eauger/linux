/*
 * Copyright (C) 2015, 2016 ARM Ltd.
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

#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <trace/events/kvm.h>
#include <kvm/arm_vgic.h>
#include "vgic.h"

/**
 * vgic_irqfd_set_irq: inject the IRQ corresponding to the
 * irqchip routing entry
 *
 * This is the entry point for irqfd IRQ injection
 */
static int vgic_irqfd_set_irq(struct kvm_kernel_irq_routing_entry *e,
			struct kvm *kvm, int irq_source_id,
			int level, bool line_status)
{
	unsigned int spi_id = e->irqchip.pin + VGIC_NR_PRIVATE_IRQS;
	struct vgic_dist *dist = &kvm->arch.vgic;

	BUG_ON(!vgic_initialized(kvm));

	if (spi_id > min(dist->nr_spis, 1020))
		return -EINVAL;
	return kvm_vgic_inject_irq(kvm, 0, spi_id, level);
}

/**
 * kvm_set_routing_entry: populate a kvm routing entry
 * from a user routing entry
 *
 * @e: kvm kernel routing entry handle
 * @ue: user api routing entry handle
 * return 0 on success, -EINVAL on errors.
 */
int kvm_set_routing_entry(struct kvm_kernel_irq_routing_entry *e,
			  const struct kvm_irq_routing_entry *ue)
{
	int r = -EINVAL;

	switch (ue->type) {
	case KVM_IRQ_ROUTING_IRQCHIP:
		e->set = vgic_irqfd_set_irq;
		e->irqchip.irqchip = ue->u.irqchip.irqchip;
		e->irqchip.pin = ue->u.irqchip.pin;
		if ((e->irqchip.pin >= KVM_IRQCHIP_NUM_PINS) ||
		    (e->irqchip.irqchip >= KVM_NR_IRQCHIPS))
			goto out;
		break;
	case KVM_IRQ_ROUTING_MSI:
		e->set = kvm_set_msi;
		e->msi.address_lo = ue->u.msi.address_lo;
		e->msi.address_hi = ue->u.msi.address_hi;
		e->msi.data = ue->u.msi.data;
		e->flags = ue->flags;
		e->devid = ue->u.msi.devid;
		break;
	default:
		goto out;
	}
	r = 0;
out:
	return r;
}

/**
 * kvm_set_msi: inject the MSI corresponding to the
 * MSI routing entry
 *
 * This is the entry point for irqfd MSI injection
 * and userspace MSI injection.
 */
int kvm_set_msi(struct kvm_kernel_irq_routing_entry *e,
		struct kvm *kvm, int irq_source_id,
		int level, bool line_status)
{
	struct kvm_msi msi;

	msi.address_lo = e->msi.address_lo;
	msi.address_hi = e->msi.address_hi;
	msi.data = e->msi.data;
	msi.flags = e->flags;
	msi.devid = e->devid;

	if (!vgic_has_its(kvm))
		return vgic_v2m_inject_msi(kvm, &msi);

	return vgic_its_inject_msi(kvm, &msi);
}
