// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 ARM Ltd.
 */

#ifndef __ASM_ARM_KVM_SPE_H
#define __ASM_ARM_KVM_SPE_H

#include <uapi/linux/kvm.h>
#include <linux/kvm_host.h>

struct kvm_spe {
	int irq_num;
	bool ready; /* indicates that SPE KVM instance is ready for use */
	bool created; /* SPE KVM instance is created, may not be ready yet */
	bool irq_level;
};

#endif /* __ASM_ARM_KVM_SPE_H */
