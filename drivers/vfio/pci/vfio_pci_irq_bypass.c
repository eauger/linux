/*
 * VFIO PCI device irqbypass callback implementation for DEOI
 *
 * Copyright (C) 2017 Red Hat, Inc.  All rights reserved.
 * Author: Eric Auger <eric.auger@redhat.com>
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */

#include <linux/err.h>
#include <linux/irqbypass.h>
#include "vfio_pci_private.h"

#ifdef CONFIG_VFIO_PCI_IRQ_BYPASS_DEOI

static inline void irq_bypass_deoi_start(struct irq_bypass_producer *prod)
{
	enable_irq(prod->irq);
}

static inline void irq_bypass_deoi_stop(struct irq_bypass_producer *prod)
{
	disable_irq(prod->irq);
}

/**
 * irq_bypass_deoi_add_consumer - turns direct EOI on
 *
 * The linux irq is disabled when the function is called.
 * The operation succeeds only if the irq is not active at irqchip level
 * and not automasked at VFIO level, meaning the IRQ is not under injection
 * into the guest.
 */
static int irq_bypass_deoi_add_consumer(struct irq_bypass_producer *prod,
					struct irq_bypass_consumer *cons)
{
	struct vfio_pci_device *vdev = (struct vfio_pci_device *)prod->private;
	struct vfio_pci_irq_ctx *irq_ctx =
		container_of(prod, struct vfio_pci_irq_ctx, producer);
	unsigned long flags;
	bool active;
	int ret;

	spin_lock_irqsave(&vdev->irqlock, flags);

	ret = irq_get_irqchip_state(prod->irq, IRQCHIP_STATE_ACTIVE,
				    &active);
	WARN_ON(ret);
	if (ret)
		goto out;

	if (active || irq_ctx->automasked) {
		ret = -EAGAIN;
		goto out;
	}

	ret = vfio_pci_set_deoi(vdev, irq_ctx, true);
out:
	spin_unlock_irqrestore(&vdev->irqlock, flags);
	return ret;
}

static void irq_bypass_deoi_del_consumer(struct irq_bypass_producer *prod,
					 struct irq_bypass_consumer *cons)
{
	struct vfio_pci_device *vdev = (struct vfio_pci_device *)prod->private;
	struct vfio_pci_irq_ctx *irq_ctx =
		container_of(prod, struct vfio_pci_irq_ctx, producer);
	unsigned long flags;

	spin_lock_irqsave(&vdev->irqlock, flags);
	vfio_pci_set_deoi(vdev, irq_ctx, false);
	spin_unlock_irqrestore(&vdev->irqlock, flags);
}

bool vfio_pci_has_deoi(void)
{
	return true;
}

void vfio_pci_register_deoi_producer(struct vfio_pci_device *vdev,
				     struct vfio_pci_irq_ctx *irq_ctx,
				     struct eventfd_ctx *trigger,
				     unsigned int irq)
{
	struct irq_bypass_producer *prod = &irq_ctx->producer;
	struct pci_dev *pdev = vdev->pdev;
	int ret;

	prod->token =		trigger;
	prod->irq =		irq;
	prod->private =		vdev;
	prod->add_consumer =	irq_bypass_deoi_add_consumer;
	prod->del_consumer =	irq_bypass_deoi_del_consumer;
	prod->stop =		irq_bypass_deoi_stop;
	prod->start =		irq_bypass_deoi_start;

	ret = irq_bypass_register_producer(prod);
	if (unlikely(ret))
		dev_info(&pdev->dev,
		"irq bypass producer (token %p) registration fails for irq %s: %d\n",
		prod->token, irq_ctx->name, ret);
}

#endif /* DEOI */

void vfio_pci_register_default_producer(struct vfio_pci_device *vdev,
					struct vfio_pci_irq_ctx *irq_ctx,
					struct eventfd_ctx *trigger,
					unsigned int irq)
{
	struct irq_bypass_producer *prod = &irq_ctx->producer;
	struct pci_dev *pdev = vdev->pdev;
	int ret;

	prod->token =	trigger;
	prod->irq =	irq;
	prod->private = vdev;

	ret = irq_bypass_register_producer(prod);
	if (unlikely(ret))
		dev_info(&pdev->dev,
		"irq bypass producer (token %p) registration fails for irq %s: %d\n",
		prod->token, irq_ctx->name, ret);
}


