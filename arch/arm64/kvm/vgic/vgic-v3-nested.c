// SPDX-License-Identifier: GPL-2.0-only

#include <linux/cpu.h>
#include <linux/kvm.h>
#include <linux/kvm_host.h>
#include <linux/interrupt.h>
#include <linux/io.h>
#include <linux/uaccess.h>

#include <linux/irqchip/arm-gic-v3.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_arm.h>
#include <kvm/arm_vgic.h>

#include "vgic.h"

#define CREATE_TRACE_POINTS
#include "vgic-nested-trace.h"

/*
 * The shadow registers loaded to the hardware when running a L2 guest
 * with the virtual IMO/FMO bits set.
 */
static DEFINE_PER_CPU(struct vgic_v3_cpu_if, shadow_cpuif);

static inline struct vgic_v3_cpu_if *vcpu_shadow_if(struct kvm_vcpu *vcpu)
{
	return this_cpu_ptr(&shadow_cpuif);
}

static inline bool lr_triggers_eoi(u64 lr)
{
	return !(lr & (ICH_LR_STATE | ICH_LR_HW)) && (lr & ICH_LR_EOI);
}

u16 vgic_v3_get_eisr(struct kvm_vcpu *vcpu)
{
	u16 reg = 0;
	int i;

	if (vgic_state_is_nested(vcpu))
		return read_sysreg_s(SYS_ICH_EISR_EL2);

	for (i = 0; i < kvm_vgic_global_state.nr_lr; i++) {
		if (lr_triggers_eoi(__vcpu_sys_reg(vcpu, ICH_LRN(i))))
			reg |= BIT(i);
	}

	return reg;
}

u16 vgic_v3_get_elrsr(struct kvm_vcpu *vcpu)
{
	u16 reg = 0;
	int i;

	if (vgic_state_is_nested(vcpu))
		return read_sysreg_s(SYS_ICH_ELRSR_EL2);

	for (i = 0; i < kvm_vgic_global_state.nr_lr; i++) {
		if (!(__vcpu_sys_reg(vcpu, ICH_LRN(i)) & ICH_LR_STATE))
			reg |= BIT(i);
	}

	return reg;
}

u64 vgic_v3_get_misr(struct kvm_vcpu *vcpu)
{
	int nr_lr = kvm_vgic_global_state.nr_lr;
	u64 reg = 0;

	if (vgic_state_is_nested(vcpu))
		return read_sysreg_s(SYS_ICH_MISR_EL2);

	if (vgic_v3_get_eisr(vcpu))
		reg |= ICH_MISR_EOI;

	if (__vcpu_sys_reg(vcpu, ICH_HCR_EL2) & ICH_HCR_UIE) {
		int used_lrs;

		used_lrs = nr_lr - hweight16(vgic_v3_get_elrsr(vcpu));
		if (used_lrs <= 1)
			reg |= ICH_MISR_U;
	}

	/* TODO: Support remaining bits in this register */
	return reg;
}

/*
 * For LRs which have HW bit set such as timer interrupts, we modify them to
 * have the host hardware interrupt number instead of the virtual one programmed
 * by the guest hypervisor.
 */
static void vgic_v3_create_shadow_lr(struct kvm_vcpu *vcpu)
{
	struct vgic_v3_cpu_if *s_cpu_if = vcpu_shadow_if(vcpu);
	struct vgic_irq *irq;
	int i, used_lrs = 0;

	for (i = 0; i < kvm_vgic_global_state.nr_lr; i++) {
		u64 lr = __vcpu_sys_reg(vcpu, ICH_LRN(i));
		int l1_irq;

		if (!(lr & ICH_LR_STATE))
			lr = 0;

		if (!(lr & ICH_LR_HW))
			goto next;

		/* We have the HW bit set */
		l1_irq = (lr & ICH_LR_PHYS_ID_MASK) >> ICH_LR_PHYS_ID_SHIFT;
		irq = vgic_get_irq(vcpu->kvm, vcpu, l1_irq);

		if (!irq || !irq->hw) {
			/* There was no real mapping, so nuke the HW bit */
			lr &= ~ICH_LR_HW;
			if (irq)
				vgic_put_irq(vcpu->kvm, irq);
			goto next;
		}

		/* Translate the virtual mapping to the real one */
		lr &= ~ICH_LR_EOI; /* Why? */
		lr &= ~ICH_LR_PHYS_ID_MASK;
		lr |= (u64)irq->hwintid << ICH_LR_PHYS_ID_SHIFT;
		vgic_put_irq(vcpu->kvm, irq);

next:
		s_cpu_if->vgic_lr[i] = lr;
		used_lrs = i + 1;
	}

	trace_vgic_create_shadow_lrs(vcpu, kvm_vgic_global_state.nr_lr,
				     s_cpu_if->vgic_lr,
				     __ctxt_sys_reg(&vcpu->arch.ctxt, ICH_LR0_EL2));

	s_cpu_if->used_lrs = used_lrs;
}

void vgic_v3_sync_nested(struct kvm_vcpu *vcpu)
{
	struct vgic_v3_cpu_if *s_cpu_if = vcpu_shadow_if(vcpu);
	struct vgic_irq *irq;
	int i;

	for (i = 0; i < s_cpu_if->used_lrs; i++) {
		u64 lr = __vcpu_sys_reg(vcpu, ICH_LRN(i));
		int l1_irq;

		if (!(lr & ICH_LR_HW) || !(lr & ICH_LR_STATE))
			continue;

		/*
		 * If we had a HW lr programmed by the guest hypervisor, we
		 * need to emulate the HW effect between the guest hypervisor
		 * and the nested guest.
		 */
		l1_irq = (lr & ICH_LR_PHYS_ID_MASK) >> ICH_LR_PHYS_ID_SHIFT;
		irq = vgic_get_irq(vcpu->kvm, vcpu, l1_irq);
		if (!irq)
			continue; /* oh well, the guest hyp is broken */

		lr = __gic_v3_get_lr(i);
		if (!(lr & ICH_LR_STATE)) {
			trace_vgic_nested_hw_emulate(i, lr, l1_irq);
			irq->active = false;
		}

		vgic_put_irq(vcpu->kvm, irq);
	}
}

void vgic_v3_create_shadow_state(struct kvm_vcpu *vcpu)
{
	struct vgic_v3_cpu_if *s_cpu_if = vcpu_shadow_if(vcpu);
	struct vgic_v3_cpu_if *host_if = &vcpu->arch.vgic_cpu.vgic_v3;
	u64 val = 0;
	int i;

	/*
	 * If we're on a system with a broken vgic that requires
	 * trapping, propagate the trapping requirements.
	 *
	 * Ah, the smell of rotten fruits...
	 */
	if (static_branch_unlikely(&vgic_v3_cpuif_trap))
		val = host_if->vgic_hcr & (ICH_HCR_TALL0 | ICH_HCR_TALL1 |
					   ICH_HCR_TC | ICH_HCR_TDIR);
	s_cpu_if->vgic_hcr = __vcpu_sys_reg(vcpu, ICH_HCR_EL2) | val;
	s_cpu_if->vgic_vmcr = __vcpu_sys_reg(vcpu, ICH_VMCR_EL2);
	s_cpu_if->vgic_sre = host_if->vgic_sre;

	for (i = 0; i < 4; i++) {
		s_cpu_if->vgic_ap0r[i] = __vcpu_sys_reg(vcpu, ICH_AP0RN(i));
		s_cpu_if->vgic_ap1r[i] = __vcpu_sys_reg(vcpu, ICH_AP1RN(i));
	}

	vgic_v3_create_shadow_lr(vcpu);

	vcpu->arch.vgic_cpu.current_cpu_if = s_cpu_if;
}

void vgic_v3_load_nested(struct kvm_vcpu *vcpu)
{
	struct vgic_irq *irq;
	unsigned long flags;

	__vgic_v3_restore_state(vcpu_shadow_if(vcpu));

	irq = vgic_get_irq(vcpu->kvm, vcpu, vcpu->kvm->arch.vgic.maint_irq);
	raw_spin_lock_irqsave(&irq->irq_lock, flags);
	if (irq->line_level || irq->active)
		irq_set_irqchip_state(kvm_vgic_global_state.maint_irq,
				      IRQCHIP_STATE_ACTIVE, true);
	raw_spin_unlock_irqrestore(&irq->irq_lock, flags);
	vgic_put_irq(vcpu->kvm, irq);
}

void vgic_v3_put_nested(struct kvm_vcpu *vcpu)
{
	struct vgic_v3_cpu_if *s_cpu_if = vcpu_shadow_if(vcpu);
	u64 val;
	int i;

	__vgic_v3_save_state(s_cpu_if);

	trace_vgic_put_nested(vcpu, kvm_vgic_global_state.nr_lr, s_cpu_if->vgic_lr);

	/*
	 * Translate the shadow state HW fields back to the virtual ones
	 * before copying the shadow struct back to the nested one.
	 */
	val = __vcpu_sys_reg(vcpu, ICH_HCR_EL2);
	val &= ~ICH_HCR_EOIcount_MASK;
	val |= (s_cpu_if->vgic_hcr & ICH_HCR_EOIcount_MASK);
	__vcpu_sys_reg(vcpu, ICH_HCR_EL2) = val;
	__vcpu_sys_reg(vcpu, ICH_VMCR_EL2) = s_cpu_if->vgic_vmcr;

	for (i = 0; i < 4; i++) {
		__vcpu_sys_reg(vcpu, ICH_AP0RN(i)) = s_cpu_if->vgic_ap0r[i];
		__vcpu_sys_reg(vcpu, ICH_AP1RN(i)) = s_cpu_if->vgic_ap1r[i];
	}

	for (i = 0; i < s_cpu_if->used_lrs; i++) {
		val = __vcpu_sys_reg(vcpu, ICH_LRN(i));

		val &= ~ICH_LR_STATE;
		val |= s_cpu_if->vgic_lr[i] & ICH_LR_STATE;

		__vcpu_sys_reg(vcpu, ICH_LRN(i)) = val;
		s_cpu_if->vgic_lr[i] = 0;
	}

	irq_set_irqchip_state(kvm_vgic_global_state.maint_irq,
			      IRQCHIP_STATE_ACTIVE, false);
}

void vgic_v3_handle_nested_maint_irq(struct kvm_vcpu *vcpu)
{
	/*
	 * If we exit a nested VM with a pending maintenance interrupt from the
	 * GIC, then we need to forward this to the guest hypervisor so that it
	 * can re-sync the appropriate LRs and sample level triggered interrupts
	 * again.
	 */
	if (vgic_state_is_nested(vcpu)) {
		bool state;

		state  = __vcpu_sys_reg(vcpu, ICH_HCR_EL2) & ICH_HCR_EN;
		state &= vgic_v3_get_misr(vcpu);

		kvm_vgic_inject_irq(vcpu->kvm, vcpu,
				    vcpu->kvm->arch.vgic.maint_irq, state, vcpu);
	}

	if (unlikely(kvm_vgic_global_state.no_hw_deactivation))
		sysreg_clear_set_s(SYS_ICH_HCR_EL2, ICH_HCR_EN, 0);
}
