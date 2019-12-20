// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2015 - ARM Ltd
 * Author: Marc Zyngier <marc.zyngier@arm.com>
 */

#include <linux/compiler.h>
#include <linux/kvm_host.h>

#include <asm/debug-monitors.h>
#include <asm/kvm_asm.h>
#include <asm/kvm_hyp.h>
#include <asm/kvm_mmu.h>

#define read_debug(r,n)		read_sysreg(r##n##_el1)
#define write_debug(v,r,n)	write_sysreg(v, r##n##_el1)

#define save_debug(ptr,reg,nr)						\
	switch (nr) {							\
	case 15:	ptr[15] = read_debug(reg, 15);			\
			/* Fall through */				\
	case 14:	ptr[14] = read_debug(reg, 14);			\
			/* Fall through */				\
	case 13:	ptr[13] = read_debug(reg, 13);			\
			/* Fall through */				\
	case 12:	ptr[12] = read_debug(reg, 12);			\
			/* Fall through */				\
	case 11:	ptr[11] = read_debug(reg, 11);			\
			/* Fall through */				\
	case 10:	ptr[10] = read_debug(reg, 10);			\
			/* Fall through */				\
	case 9:		ptr[9] = read_debug(reg, 9);			\
			/* Fall through */				\
	case 8:		ptr[8] = read_debug(reg, 8);			\
			/* Fall through */				\
	case 7:		ptr[7] = read_debug(reg, 7);			\
			/* Fall through */				\
	case 6:		ptr[6] = read_debug(reg, 6);			\
			/* Fall through */				\
	case 5:		ptr[5] = read_debug(reg, 5);			\
			/* Fall through */				\
	case 4:		ptr[4] = read_debug(reg, 4);			\
			/* Fall through */				\
	case 3:		ptr[3] = read_debug(reg, 3);			\
			/* Fall through */				\
	case 2:		ptr[2] = read_debug(reg, 2);			\
			/* Fall through */				\
	case 1:		ptr[1] = read_debug(reg, 1);			\
			/* Fall through */				\
	default:	ptr[0] = read_debug(reg, 0);			\
	}

#define restore_debug(ptr,reg,nr)					\
	switch (nr) {							\
	case 15:	write_debug(ptr[15], reg, 15);			\
			/* Fall through */				\
	case 14:	write_debug(ptr[14], reg, 14);			\
			/* Fall through */				\
	case 13:	write_debug(ptr[13], reg, 13);			\
			/* Fall through */				\
	case 12:	write_debug(ptr[12], reg, 12);			\
			/* Fall through */				\
	case 11:	write_debug(ptr[11], reg, 11);			\
			/* Fall through */				\
	case 10:	write_debug(ptr[10], reg, 10);			\
			/* Fall through */				\
	case 9:		write_debug(ptr[9], reg, 9);			\
			/* Fall through */				\
	case 8:		write_debug(ptr[8], reg, 8);			\
			/* Fall through */				\
	case 7:		write_debug(ptr[7], reg, 7);			\
			/* Fall through */				\
	case 6:		write_debug(ptr[6], reg, 6);			\
			/* Fall through */				\
	case 5:		write_debug(ptr[5], reg, 5);			\
			/* Fall through */				\
	case 4:		write_debug(ptr[4], reg, 4);			\
			/* Fall through */				\
	case 3:		write_debug(ptr[3], reg, 3);			\
			/* Fall through */				\
	case 2:		write_debug(ptr[2], reg, 2);			\
			/* Fall through */				\
	case 1:		write_debug(ptr[1], reg, 1);			\
			/* Fall through */				\
	default:	write_debug(ptr[0], reg, 0);			\
	}

static void __hyp_text
__debug_save_spe_nvhe(struct kvm_cpu_context *ctxt, bool full_ctxt)
{
	u64 reg;

	/* Clear pmscr in case of early return */
	ctxt->sys_regs[PMSCR_EL1] = 0;

	/* SPE present on this CPU? */
	if (!cpuid_feature_extract_unsigned_field(read_sysreg(id_aa64dfr0_el1),
						  ID_AA64DFR0_PMSVER_SHIFT))
		return;

	/* Yes; is it owned by higher EL? */
	reg = read_sysreg_s(SYS_PMBIDR_EL1);
	if (reg & BIT(SYS_PMBIDR_EL1_P_SHIFT))
		return;

	/* Save the control register and disable data generation */
	ctxt->sys_regs[PMSCR_EL1] = read_sysreg_el1(SYS_PMSCR);

	if (!ctxt->sys_regs[PMSCR_EL1])
		return;

	/* Yes; save the control register and disable data generation */
	write_sysreg_el1(0, SYS_PMSCR);
	isb();

	/* Now drain all buffered data to memory */
	psb_csync();
	dsb(nsh);

	if (!full_ctxt)
		return;

	ctxt->sys_regs[PMBLIMITR_EL1] = read_sysreg_s(SYS_PMBLIMITR_EL1);
	write_sysreg_s(0, SYS_PMBLIMITR_EL1);

	/*
	 * As PMBSR is conditionally restored when returning to the host we
	 * must ensure the service bit is unset here to prevent a spurious
	 * host SPE interrupt from being raised.
	 */
	ctxt->sys_regs[PMBSR_EL1] = read_sysreg_s(SYS_PMBSR_EL1);
	write_sysreg_s(0, SYS_PMBSR_EL1);

	isb();

	ctxt->sys_regs[PMSICR_EL1] = read_sysreg_s(SYS_PMSICR_EL1);
	ctxt->sys_regs[PMSIRR_EL1] = read_sysreg_s(SYS_PMSIRR_EL1);
	ctxt->sys_regs[PMSFCR_EL1] = read_sysreg_s(SYS_PMSFCR_EL1);
	ctxt->sys_regs[PMSEVFR_EL1] = read_sysreg_s(SYS_PMSEVFR_EL1);
	ctxt->sys_regs[PMSLATFR_EL1] = read_sysreg_s(SYS_PMSLATFR_EL1);
	ctxt->sys_regs[PMBPTR_EL1] = read_sysreg_s(SYS_PMBPTR_EL1);
}

static void __hyp_text
__debug_restore_spe_nvhe(struct kvm_cpu_context *ctxt, bool full_ctxt)
{
	if (!ctxt->sys_regs[PMSCR_EL1])
		return;

	/* The host page table is installed, but not yet synchronised */
	isb();

	/* Re-enable data generation */
	if (full_ctxt) {
		write_sysreg_s(ctxt->sys_regs[PMBPTR_EL1], SYS_PMBPTR_EL1);
		write_sysreg_s(ctxt->sys_regs[PMBLIMITR_EL1], SYS_PMBLIMITR_EL1);
		write_sysreg_s(ctxt->sys_regs[PMSFCR_EL1], SYS_PMSFCR_EL1);
		write_sysreg_s(ctxt->sys_regs[PMSEVFR_EL1], SYS_PMSEVFR_EL1);
		write_sysreg_s(ctxt->sys_regs[PMSLATFR_EL1], SYS_PMSLATFR_EL1);
		write_sysreg_s(ctxt->sys_regs[PMSIRR_EL1], SYS_PMSIRR_EL1);
		write_sysreg_s(ctxt->sys_regs[PMSICR_EL1], SYS_PMSICR_EL1);
		write_sysreg_s(ctxt->sys_regs[PMBSR_EL1], SYS_PMBSR_EL1);
	}
	write_sysreg_el1(ctxt->sys_regs[PMSCR_EL1], SYS_PMSCR);
}

static void __hyp_text __debug_save_state(struct kvm_vcpu *vcpu,
					  struct kvm_guest_debug_arch *dbg,
					  struct kvm_cpu_context *ctxt)
{
	u64 aa64dfr0;
	int brps, wrps;

	aa64dfr0 = read_sysreg(id_aa64dfr0_el1);
	brps = (aa64dfr0 >> 12) & 0xf;
	wrps = (aa64dfr0 >> 20) & 0xf;

	save_debug(dbg->dbg_bcr, dbgbcr, brps);
	save_debug(dbg->dbg_bvr, dbgbvr, brps);
	save_debug(dbg->dbg_wcr, dbgwcr, wrps);
	save_debug(dbg->dbg_wvr, dbgwvr, wrps);

	ctxt->sys_regs[MDCCINT_EL1] = read_sysreg(mdccint_el1);
}

static void __hyp_text __debug_restore_state(struct kvm_vcpu *vcpu,
					     struct kvm_guest_debug_arch *dbg,
					     struct kvm_cpu_context *ctxt)
{
	u64 aa64dfr0;
	int brps, wrps;

	aa64dfr0 = read_sysreg(id_aa64dfr0_el1);

	brps = (aa64dfr0 >> 12) & 0xf;
	wrps = (aa64dfr0 >> 20) & 0xf;

	restore_debug(dbg->dbg_bcr, dbgbcr, brps);
	restore_debug(dbg->dbg_bvr, dbgbvr, brps);
	restore_debug(dbg->dbg_wcr, dbgwcr, wrps);
	restore_debug(dbg->dbg_wvr, dbgwvr, wrps);

	write_sysreg(ctxt->sys_regs[MDCCINT_EL1], mdccint_el1);
}

void __hyp_text __debug_restore_guest_context(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *host_ctxt;
	struct kvm_cpu_context *guest_ctxt;
	struct kvm_guest_debug_arch *host_dbg;
	struct kvm_guest_debug_arch *guest_dbg;

	if (!(vcpu->arch.flags & KVM_ARM64_DEBUG_DIRTY))
		return;

	host_ctxt = kern_hyp_va(vcpu->arch.host_cpu_context);
	guest_ctxt = &vcpu->arch.ctxt;
	host_dbg = &vcpu->arch.host_debug_state.regs;
	guest_dbg = kern_hyp_va(vcpu->arch.debug_ptr);

	__debug_save_state(vcpu, host_dbg, host_ctxt);
	__debug_restore_state(vcpu, guest_dbg, guest_ctxt);
}

void __hyp_text __debug_restore_host_context(struct kvm_vcpu *vcpu)
{
	struct kvm_cpu_context *host_ctxt;
	struct kvm_cpu_context *guest_ctxt;
	struct kvm_guest_debug_arch *host_dbg;
	struct kvm_guest_debug_arch *guest_dbg;

	host_ctxt = kern_hyp_va(vcpu->arch.host_cpu_context);
	guest_ctxt = &vcpu->arch.ctxt;

	if (!has_vhe())
		__debug_restore_spe_nvhe(host_ctxt, false);

	if (!(vcpu->arch.flags & KVM_ARM64_DEBUG_DIRTY))
		return;

	host_dbg = &vcpu->arch.host_debug_state.regs;
	guest_dbg = kern_hyp_va(vcpu->arch.debug_ptr);

	__debug_save_state(vcpu, guest_dbg, guest_ctxt);
	__debug_restore_state(vcpu, host_dbg, host_ctxt);

	vcpu->arch.flags &= ~KVM_ARM64_DEBUG_DIRTY;
}

void __hyp_text __debug_save_host_context(struct kvm_vcpu *vcpu)
{
	/*
	 * Non-VHE: Disable and flush SPE data generation
	 * VHE: The vcpu can run, but it can't hide.
	 */
	struct kvm_cpu_context *host_ctxt;

	host_ctxt = kern_hyp_va(vcpu->arch.host_cpu_context);
	if (!has_vhe())
		__debug_save_spe_nvhe(host_ctxt, false);
}

void __hyp_text __debug_save_guest_context(struct kvm_vcpu *vcpu)
{
}

u32 __hyp_text __kvm_get_mdcr_el2(void)
{
	return read_sysreg(mdcr_el2);
}
