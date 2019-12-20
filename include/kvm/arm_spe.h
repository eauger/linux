// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 ARM Ltd.
 */

#ifndef __ASM_ARM_KVM_SPE_H
#define __ASM_ARM_KVM_SPE_H

#include <uapi/linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/cpufeature.h>

struct kvm_spe {
	int irq_num;
	bool ready; /* indicates that SPE KVM instance is ready for use */
	bool created; /* SPE KVM instance is created, may not be ready yet */
	bool irq_level;
};

struct arm_spe_kvm_info {
	int physical_irq;
};

struct arm_spe_kvm_info *arm_spe_get_kvm_info(void);

#ifdef CONFIG_KVM_ARM_SPE
#define kvm_arm_spe_v1_ready(v)		((v)->arch.spe.ready)
#define kvm_arm_spe_irq_initialized(v)		\
	((v)->arch.spe.irq_num >= VGIC_NR_SGIS &&	\
	(v)->arch.spe.irq_num <= VGIC_MAX_PRIVATE)

static inline bool kvm_arm_support_spe_v1(void)
{
	u64 dfr0 = read_sanitised_ftr_reg(SYS_ID_AA64DFR0_EL1);

	return !!cpuid_feature_extract_unsigned_field(dfr0,
						      ID_AA64DFR0_PMSVER_SHIFT);
}

int kvm_arm_spe_v1_set_attr(struct kvm_vcpu *vcpu,
			    struct kvm_device_attr *attr);
int kvm_arm_spe_v1_get_attr(struct kvm_vcpu *vcpu,
			    struct kvm_device_attr *attr);
int kvm_arm_spe_v1_has_attr(struct kvm_vcpu *vcpu,
			    struct kvm_device_attr *attr);
int kvm_arm_spe_v1_enable(struct kvm_vcpu *vcpu);
#else
#define kvm_arm_spe_v1_ready(v)		(false)
#define kvm_arm_support_spe_v1()	(false)
#define kvm_arm_spe_irq_initialized(v)	(false)

static inline int kvm_arm_spe_v1_set_attr(struct kvm_vcpu *vcpu,
					  struct kvm_device_attr *attr)
{
	return -ENXIO;
}

static inline int kvm_arm_spe_v1_get_attr(struct kvm_vcpu *vcpu,
					  struct kvm_device_attr *attr)
{
	return -ENXIO;
}

static inline int kvm_arm_spe_v1_has_attr(struct kvm_vcpu *vcpu,
					  struct kvm_device_attr *attr)
{
	return -ENXIO;
}

static inline int kvm_arm_spe_v1_enable(struct kvm_vcpu *vcpu)
{
	return 0;
}
#endif /* CONFIG_KVM_ARM_SPE */

#endif /* __ASM_ARM_KVM_SPE_H */
