// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#include <hyp/switch.h>

#include <linux/arm-smccc.h>
#include <linux/kvm_host.h>
#include <linux/types.h>
#include <linux/jump_label.h>
#include <linux/percpu.h>
#include <uapi/linux/psci.h>

#include <kvm/arm_psci.h>

#include <asm/barrier.h>
#include <asm/cpufeature.h>
#include <asm/kprobes.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>
#include <asm/fpsimd.h>
#include <asm/debug-monitors.h>
#include <asm/processor.h>
#include <asm/thread_info.h>
#include <asm/vectors.h>

/* VHE specific context */
DEFINE_PER_CPU(struct kvm_host_data, kvm_host_data);
DEFINE_PER_CPU(struct kvm_cpu_context, kvm_hyp_ctxt);
DEFINE_PER_CPU(unsigned long, kvm_hyp_vector);

static void __activate_traps(struct kvm_vcpu *vcpu)
{
	u64 hcr = vcpu->arch.hcr_el2;
	u64 val;

	if (is_hyp_ctxt(vcpu)) {
		hcr |= HCR_NV;

		if (!vcpu_el2_e2h_is_set(vcpu)) {
			/*
			 * For a guest hypervisor on v8.0, trap and emulate
			 * the EL1 virtual memory control register accesses
			 * as well as the AT S1 operations.
			 */
			hcr |= HCR_TVM | HCR_TRVM | HCR_AT | HCR_TTLB | HCR_NV1;
		} else {
			/*
			 * For a guest hypervisor on v8.1 (VHE), allow to
			 * access the EL1 virtual memory control registers
			 * natively. These accesses are to access EL2 register
			 * states.
			 * Note that we still need to respect the virtual
			 * HCR_EL2 state.
			 */
			u64 vhcr_el2 = __vcpu_sys_reg(vcpu, HCR_EL2);

			vhcr_el2 &= ~HCR_GUEST_NV_FILTER_FLAGS;

			/*
			 * We already set TVM to handle set/way cache maint
			 * ops traps, this somewhat collides with the nested
			 * virt trapping for nVHE. So turn this off for now
			 * here, in the hope that VHE guests won't ever do this.
			 * TODO: find out whether it's worth to support both
			 * cases at the same time.
			 */
			hcr &= ~HCR_TVM;

			hcr |= vhcr_el2 & (HCR_TVM | HCR_TRVM);

			/*
			 * If we're using the EL1 translation regime
			 * (TGE clear), then ensure that AT S1 and
			 * TLBI E1 ops are trapped too.
			 */
			if (!vcpu_el2_tge_is_set(vcpu))
				hcr |= HCR_AT | HCR_TTLB;
		}
	} else if (vcpu_has_nv(vcpu)) {
		u64 vhcr_el2 = __vcpu_sys_reg(vcpu, HCR_EL2);

		vhcr_el2 &= ~HCR_GUEST_NV_FILTER_FLAGS;
		hcr |= vhcr_el2;
	}

	___activate_traps(vcpu, hcr);

	val = read_sysreg(cpacr_el1);
	val |= CPACR_ELx_TTA;
	val &= ~(CPACR_EL1_ZEN_EL0EN | CPACR_EL1_ZEN_EL1EN |
		 CPACR_EL1_SMEN_EL0EN | CPACR_EL1_SMEN_EL1EN);

	/*
	 * With VHE (HCR.E2H == 1), accesses to CPACR_EL1 are routed to
	 * CPTR_EL2. In general, CPACR_EL1 has the same layout as CPTR_EL2,
	 * except for some missing controls, such as TAM.
	 * In this case, CPTR_EL2.TAM has the same position with or without
	 * VHE (HCR.E2H == 1) which allows us to use here the CPTR_EL2.TAM
	 * shift value for trapping the AMU accesses.
	 */

	val |= CPTR_EL2_TAM;

	if (guest_owns_fp_regs(vcpu)) {
		if (vcpu_has_sve(vcpu))
			val |= CPACR_EL1_ZEN_EL0EN | CPACR_EL1_ZEN_EL1EN;
	} else {
		val &= ~(CPACR_EL1_FPEN_EL0EN | CPACR_EL1_FPEN_EL1EN);
		__activate_traps_fpsimd32(vcpu);
	}

	if (vcpu_is_el2(vcpu) && !vcpu_el2_e2h_is_set(vcpu))
		val |= CPTR_EL2_TCPAC;
	
	write_sysreg(val, cpacr_el1);

	write_sysreg(__this_cpu_read(kvm_hyp_vector), vbar_el1);
}
NOKPROBE_SYMBOL(__activate_traps);

static void __deactivate_traps(struct kvm_vcpu *vcpu)
{
	const char *host_vectors = vectors;

	___deactivate_traps(vcpu);

	write_sysreg(HCR_HOST_VHE_FLAGS, hcr_el2);

	/*
	 * ARM errata 1165522 and 1530923 require the actual execution of the
	 * above before we can switch to the EL2/EL0 translation regime used by
	 * the host.
	 */
	asm(ALTERNATIVE("nop", "isb", ARM64_WORKAROUND_SPECULATIVE_AT));

	write_sysreg(CPACR_EL1_DEFAULT, cpacr_el1);

	if (!arm64_kernel_unmapped_at_el0())
		host_vectors = __this_cpu_read(this_cpu_vector);
	write_sysreg(host_vectors, vbar_el1);
}
NOKPROBE_SYMBOL(__deactivate_traps);

void activate_traps_vhe_load(struct kvm_vcpu *vcpu)
{
	__activate_traps_common(vcpu);
}

void deactivate_traps_vhe_put(struct kvm_vcpu *vcpu)
{
	__deactivate_traps_common(vcpu);
}

static const exit_handler_fn hyp_exit_handlers[] = {
	[0 ... ESR_ELx_EC_MAX]		= NULL,
	[ESR_ELx_EC_CP15_32]		= kvm_hyp_handle_cp15_32,
	[ESR_ELx_EC_SYS64]		= kvm_hyp_handle_sysreg,
	[ESR_ELx_EC_SVE]		= kvm_hyp_handle_fpsimd,
	[ESR_ELx_EC_FP_ASIMD]		= kvm_hyp_handle_fpsimd,
	[ESR_ELx_EC_IABT_LOW]		= kvm_hyp_handle_iabt_low,
	[ESR_ELx_EC_DABT_LOW]		= kvm_hyp_handle_dabt_low,
	[ESR_ELx_EC_PAC]		= kvm_hyp_handle_ptrauth,
};

static const exit_handler_fn *kvm_get_exit_handler_array(struct kvm_vcpu *vcpu)
{
	return hyp_exit_handlers;
}

static void early_exit_filter(struct kvm_vcpu *vcpu, u64 *exit_code)
{
	/*
	 * If we were in HYP context on entry, adjust the PSTATE view
	 * so that the usual helpers work correctly.
	 */
	if (unlikely(vcpu_get_flag(vcpu, VCPU_HYP_CONTEXT))) {
		u64 mode = *vcpu_cpsr(vcpu) & (PSR_MODE_MASK | PSR_MODE32_BIT);

		switch (mode) {
		case PSR_MODE_EL1t:
			mode = PSR_MODE_EL2t;
			break;
		case PSR_MODE_EL1h:
			mode = PSR_MODE_EL2h;
			break;
		}

		*vcpu_cpsr(vcpu) &= ~(PSR_MODE_MASK | PSR_MODE32_BIT);
		*vcpu_cpsr(vcpu) |= mode;
	}
}

/* Switch to the guest for VHE systems running in EL2 */
static int __kvm_vcpu_run_vhe(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *host_ctxt;
	struct kvm_cpu_context *guest_ctxt;
	u64 exit_code;

	host_ctxt = &this_cpu_ptr(&kvm_host_data)->host_ctxt;
	host_ctxt->__hyp_running_vcpu = vcpu;
	guest_ctxt = &vcpu->arch.ctxt;

	sysreg_save_host_state_vhe(host_ctxt);

	/*
	 * ARM erratum 1165522 requires us to configure both stage 1 and
	 * stage 2 translation for the guest context before we clear
	 * HCR_EL2.TGE.
	 *
	 * We have already configured the guest's stage 1 translation in
	 * kvm_vcpu_load_sysregs_vhe above.  We must now call
	 * __load_stage2 before __activate_traps, because
	 * __load_stage2 configures stage 2 translation, and
	 * __activate_traps clear HCR_EL2.TGE (among other things).
	 */
	__load_stage2(vcpu->arch.hw_mmu, vcpu->arch.hw_mmu->arch);
	__activate_traps(vcpu);

	__kvm_adjust_pc(vcpu);

	sysreg_restore_guest_state_vhe(guest_ctxt);
	__debug_switch_to_guest(vcpu);

	if (is_hyp_ctxt(vcpu))
		vcpu_set_flag(vcpu, VCPU_HYP_CONTEXT);
	else
		vcpu_clear_flag(vcpu, VCPU_HYP_CONTEXT);

	do {
		/* Jump in the fire! */
		exit_code = __guest_enter(vcpu);

		/* And we're baaack! */
	} while (fixup_guest_exit(vcpu, &exit_code));

	sysreg_save_guest_state_vhe(guest_ctxt);

	__deactivate_traps(vcpu);

	sysreg_restore_host_state_vhe(host_ctxt);

	if (vcpu->arch.fp_state == FP_STATE_GUEST_OWNED)
		__fpsimd_save_fpexc32(vcpu);

	__debug_switch_to_host(vcpu);

	return exit_code;
}
NOKPROBE_SYMBOL(__kvm_vcpu_run_vhe);

int __kvm_vcpu_run(struct kvm_vcpu *vcpu)
{
	int ret;

	local_daif_mask();

	/*
	 * Having IRQs masked via PMR when entering the guest means the GIC
	 * will not signal the CPU of interrupts of lower priority, and the
	 * only way to get out will be via guest exceptions.
	 * Naturally, we want to avoid this.
	 *
	 * local_daif_mask() already sets GIC_PRIO_PSR_I_SET, we just need a
	 * dsb to ensure the redistributor is forwards EL2 IRQs to the CPU.
	 */
	pmr_sync();

	ret = __kvm_vcpu_run_vhe(vcpu);

	/*
	 * local_daif_restore() takes care to properly restore PSTATE.DAIF
	 * and the GIC PMR if the host is using IRQ priorities.
	 */
	local_daif_restore(DAIF_PROCCTX_NOIRQ);

	/*
	 * When we exit from the guest we change a number of CPU configuration
	 * parameters, such as traps.  We rely on the isb() in kvm_call_hyp*()
	 * to make sure these changes take effect before running the host or
	 * additional guests.
	 */
	return ret;
}

static void __hyp_call_panic(u64 spsr, u64 elr, u64 par)
{
	struct kvm_cpu_context *host_ctxt;
	struct kvm_vcpu *vcpu;

	host_ctxt = &this_cpu_ptr(&kvm_host_data)->host_ctxt;
	vcpu = host_ctxt->__hyp_running_vcpu;

	__deactivate_traps(vcpu);
	sysreg_restore_host_state_vhe(host_ctxt);

	panic("HYP panic:\nPS:%08llx PC:%016llx ESR:%08llx\nFAR:%016llx HPFAR:%016llx PAR:%016llx\nVCPU:%p\n",
	      spsr, elr,
	      read_sysreg_el2(SYS_ESR), read_sysreg_el2(SYS_FAR),
	      read_sysreg(hpfar_el2), par, vcpu);
}
NOKPROBE_SYMBOL(__hyp_call_panic);

void __noreturn hyp_panic(void)
{
	u64 spsr = read_sysreg_el2(SYS_SPSR);
	u64 elr = read_sysreg_el2(SYS_ELR);
	u64 par = read_sysreg_par();

	__hyp_call_panic(spsr, elr, par);
	unreachable();
}

asmlinkage void kvm_unexpected_el2_exception(void)
{
	__kvm_unexpected_el2_exception();
}
