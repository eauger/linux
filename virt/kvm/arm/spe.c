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

		/*
		 * If using the SPE with an in-kernel virtual GIC
		 * implementation, we require the GIC to be already
		 * initialized when initializing the SPE.
		 */
		if (!vgic_initialized(vcpu->kvm))
			return -ENODEV;

		ret = kvm_vgic_set_owner(vcpu, vcpu->arch.spe.irq_num,
					 &vcpu->arch.spe);
		if (ret)
			return ret;
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
