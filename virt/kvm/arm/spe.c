// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 ARM Ltd.
 */

#include <linux/cpu.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/uaccess.h>
#include <asm/kvm_emulate.h>
#include <kvm/arm_spe.h>
#include <kvm/arm_vgic.h>

int kvm_arm_spe_v1_enable(struct kvm_vcpu *vcpu)
{
	if (!vcpu->arch.spe.created)
		return 0;

	/*
	 * A valid interrupt configuration for the SPE is either to have a
	 * properly configured interrupt number and using an in-kernel irqchip.
	 */
	if (irqchip_in_kernel(vcpu->kvm)) {
		int irq = vcpu->arch.spe.irq_num;

		if (!kvm_arm_spe_irq_initialized(vcpu))
			return -EINVAL;

		if (!irq_is_ppi(irq))
			return -EINVAL;
	}

	vcpu->arch.spe.ready = true;

	return 0;
}

static inline void set_spe_irq_phys_active(struct arm_spe_kvm_info *info,
					   bool active)
{
	int r;
	r = irq_set_irqchip_state(info->physical_irq, IRQCHIP_STATE_ACTIVE,
				  active);
	WARN_ON(r);
}

void kvm_spe_flush_hwstate(struct kvm_vcpu *vcpu)
{
	struct kvm_spe *spe = &vcpu->arch.spe;
	bool phys_active = false;
	struct arm_spe_kvm_info *info = arm_spe_get_kvm_info();

	if (!kvm_arm_spe_v1_ready(vcpu))
		return;

	if (irqchip_in_kernel(vcpu->kvm))
		phys_active = kvm_vgic_map_is_active(vcpu, spe->irq_num);

	phys_active |= spe->irq_level;

	set_spe_irq_phys_active(info, phys_active);
}

void kvm_spe_sync_hwstate(struct kvm_vcpu *vcpu)
{
	struct kvm_spe *spe = &vcpu->arch.spe;
	u64 pmbsr;
	int r;
	bool service;
	struct kvm_cpu_context *ctxt = &vcpu->arch.ctxt;
	struct arm_spe_kvm_info *info = arm_spe_get_kvm_info();

	if (!kvm_arm_spe_v1_ready(vcpu))
		return;

	set_spe_irq_phys_active(info, false);

	pmbsr = ctxt->sys_regs[PMBSR_EL1];
	service = !!(pmbsr & BIT(SYS_PMBSR_EL1_S_SHIFT));
	if (spe->irq_level == service)
		return;

	spe->irq_level = service;

	if (likely(irqchip_in_kernel(vcpu->kvm))) {
		r = kvm_vgic_inject_irq(vcpu->kvm, vcpu->vcpu_id,
					spe->irq_num, service, spe);
		WARN_ON(r);
	}
}

static inline bool kvm_arch_arm_spe_v1_get_input_level(int vintid)
{
	struct kvm_vcpu *vcpu = kvm_arm_get_running_vcpu();
	struct kvm_spe *spe = &vcpu->arch.spe;

	return spe->irq_level;
}

static int kvm_arm_spe_v1_init(struct kvm_vcpu *vcpu)
{
	if (!kvm_arm_support_spe_v1())
		return -ENODEV;

	if (!test_bit(KVM_ARM_VCPU_SPE_V1, vcpu->arch.features))
		return -ENXIO;

	if (vcpu->arch.spe.created)
		return -EBUSY;

	if (irqchip_in_kernel(vcpu->kvm)) {
		int ret;
		struct arm_spe_kvm_info *info;

		/*
		 * If using the SPE with an in-kernel virtual GIC
		 * implementation, we require the GIC to be already
		 * initialized when initializing the SPE.
		 */
		if (!vgic_initialized(vcpu->kvm))
			return -ENODEV;

		info = arm_spe_get_kvm_info();
		if (!info->physical_irq)
			return -ENODEV;

		ret = kvm_vgic_set_owner(vcpu, vcpu->arch.spe.irq_num,
					 &vcpu->arch.spe);
		if (ret)
			return ret;

		ret = kvm_vgic_map_phys_irq(vcpu, info->physical_irq,
					    vcpu->arch.spe.irq_num,
					    kvm_arch_arm_spe_v1_get_input_level);
	}

	vcpu->arch.spe.created = true;
	return 0;
}

/*
 * For one VM the interrupt type must be same for each vcpu.
 * As a PPI, the interrupt number is the same for all vcpus,
 * while as an SPI it must be a separate number per vcpu.
 */
static bool spe_irq_is_valid(struct kvm *kvm, int irq)
{
	int i;
	struct kvm_vcpu *vcpu;

	kvm_for_each_vcpu(i, vcpu, kvm) {
		if (!kvm_arm_spe_irq_initialized(vcpu))
			continue;

		if (vcpu->arch.spe.irq_num != irq)
			return false;
	}

	return true;
}

int kvm_arm_spe_v1_set_attr(struct kvm_vcpu *vcpu, struct kvm_device_attr *attr)
{
	switch (attr->attr) {
	case KVM_ARM_VCPU_SPE_V1_IRQ: {
		int __user *uaddr = (int __user *)(long)attr->addr;
		int irq;

		if (!irqchip_in_kernel(vcpu->kvm))
			return -EINVAL;

		if (!test_bit(KVM_ARM_VCPU_SPE_V1, vcpu->arch.features))
			return -ENODEV;

		if (get_user(irq, uaddr))
			return -EFAULT;

		/* The SPE overflow interrupt can be a PPI only */
		if (!(irq_is_ppi(irq)))
			return -EINVAL;

		if (!spe_irq_is_valid(vcpu->kvm, irq))
			return -EINVAL;

		if (kvm_arm_spe_irq_initialized(vcpu))
			return -EBUSY;

		kvm_debug("Set kvm ARM SPE irq: %d\n", irq);
		vcpu->arch.spe.irq_num = irq;
		return 0;
	}
	case KVM_ARM_VCPU_SPE_V1_INIT:
		return kvm_arm_spe_v1_init(vcpu);
	}

	return -ENXIO;
}

int kvm_arm_spe_v1_get_attr(struct kvm_vcpu *vcpu, struct kvm_device_attr *attr)
{
	switch (attr->attr) {
	case KVM_ARM_VCPU_SPE_V1_IRQ: {
		int __user *uaddr = (int __user *)(long)attr->addr;
		int irq;

		if (!irqchip_in_kernel(vcpu->kvm))
			return -EINVAL;

		if (!test_bit(KVM_ARM_VCPU_SPE_V1, vcpu->arch.features))
			return -ENODEV;

		if (!kvm_arm_spe_irq_initialized(vcpu))
			return -ENXIO;

		irq = vcpu->arch.spe.irq_num;
		return put_user(irq, uaddr);
	}
	}

	return -ENXIO;
}

int kvm_arm_spe_v1_has_attr(struct kvm_vcpu *vcpu, struct kvm_device_attr *attr)
{
	switch (attr->attr) {
	case KVM_ARM_VCPU_SPE_V1_IRQ:
	case KVM_ARM_VCPU_SPE_V1_INIT:
		if (kvm_arm_support_spe_v1() &&
		    test_bit(KVM_ARM_VCPU_SPE_V1, vcpu->arch.features))
			return 0;
	}

	return -ENXIO;
}
