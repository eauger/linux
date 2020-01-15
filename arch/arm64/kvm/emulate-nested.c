// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2016 - Linaro and Columbia University
 * Author: Jintack Lim <jintack.lim@linaro.org>
 */

#include <linux/kvm.h>
#include <linux/kvm_host.h>

#include <asm/kvm_emulate.h>
#include <asm/kvm_nested.h>

#include "hyp/include/hyp/adjust_pc.h"

#include "trace.h"

enum trap_behaviour {
	BEHAVE_HANDLE_LOCALLY	= 0,
	BEHAVE_FORWARD_READ	= BIT(0),
	BEHAVE_FORWARD_WRITE	= BIT(1),
	BEHAVE_FORWARD_ANY	= BEHAVE_FORWARD_READ | BEHAVE_FORWARD_WRITE,
};

struct trap_bits {
	const enum vcpu_sysreg		index;
	const enum trap_behaviour	behaviour;
	const u64			value;
	const u64			mask;
};

enum coarse_grain_trap_id {
	/* Indicates no coarse trap control */
	__RESERVED__,

	/*
	 * The first batch of IDs denote coarse trapping that are used
	 * on their own instead of being part of a combination of
	 * trap controls.
	 */
	CGT_HCR_TID1,
	CGT_HCR_TID2,
	CGT_HCR_TID3,
	CGT_HCR_IMO,
	CGT_HCR_FMO,
	CGT_HCR_TIDCP,
	CGT_HCR_TACR,
	CGT_HCR_TSW,
	CGT_HCR_TPC,
	CGT_HCR_TPU,
	CGT_HCR_TTLB,
	CGT_HCR_TVM,
	CGT_HCR_TDZ,
	CGT_HCR_TRVM,
	CGT_HCR_TLOR,
	CGT_HCR_TERR,
	CGT_HCR_APK,
	CGT_HCR_NV,
	CGT_HCR_NV1,
	CGT_HCR_AT,
	CGT_HCR_FIEN,
	CGT_HCR_TID4,
	CGT_HCR_TICAB,
	CGT_HCR_TOCU,
	CGT_HCR_ENSCXT,
	CGT_HCR_TTLBIS,
	CGT_HCR_TTLBOS,

	CGT_MDCR_TPMCR,
	CGT_MDCR_TPM,
	CGT_MDCR_TDE,
	CGT_MDCR_TDA,
	CGT_MDCR_TDOSA,
	CGT_MDCR_TDRA,
	CGT_MDCR_E2PB,
	CGT_MDCR_TPMS,
	CGT_MDCR_TTRF,
	CGT_MDCR_E2TB,
	CGT_MDCR_TDCC,

	/*
	 * Anything after this point is a combination of trap controls,
	 * which all must be evaluated to decide what to do.
	 */
	__MULTIPLE_CONTROL_BITS__,
	CGT_HCR_IMO_FMO = __MULTIPLE_CONTROL_BITS__,
	CGT_HCR_TID2_TID4,
	CGT_HCR_TTLB_TTLBIS,
	CGT_HCR_TTLB_TTLBOS,
	CGT_HCR_TVM_TRVM,
	CGT_HCR_TPU_TICAB,
	CGT_HCR_TPU_TOCU,
	CGT_HCR_NV1_ENSCXT,
	CGT_MDCR_TPM_TPMCR,
	CGT_MDCR_TDE_TDA,
	CGT_MDCR_TDE_TDOSA,
	CGT_MDCR_TDE_TDRA,
	CGT_MDCR_TDCC_TDE_TDA,

	/*
	 * Anything after this point requires a callback evaluating a
	 * complex trap condition. Ugly stuff.
	 */
	__COMPLEX_CONDITIONS__,
	CGT_CNTHCTL_EL1PCTEN = __COMPLEX_CONDITIONS__,
	CGT_CNTHCTL_EL1PTEN,
};

static const struct trap_bits coarse_trap_bits[] = {
	[CGT_HCR_TID1] = {
		.index		= HCR_EL2,
		.value 		= HCR_TID1,
		.mask		= HCR_TID1,
		.behaviour	= BEHAVE_FORWARD_READ,
	},
	[CGT_HCR_TID2] = {
		.index		= HCR_EL2,
		.value 		= HCR_TID2,
		.mask		= HCR_TID2,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_HCR_TID3] = {
		.index		= HCR_EL2,
		.value 		= HCR_TID3,
		.mask		= HCR_TID3,
		.behaviour	= BEHAVE_FORWARD_READ,
	},
	[CGT_HCR_IMO] = {
		.index		= HCR_EL2,
		.value 		= HCR_IMO,
		.mask		= HCR_IMO,
		.behaviour	= BEHAVE_FORWARD_WRITE,
	},
	[CGT_HCR_FMO] = {
		.index		= HCR_EL2,
		.value 		= HCR_FMO,
		.mask		= HCR_FMO,
		.behaviour	= BEHAVE_FORWARD_WRITE,
	},
	[CGT_HCR_TIDCP] = {
		.index		= HCR_EL2,
		.value		= HCR_TIDCP,
		.mask		= HCR_TIDCP,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_HCR_TACR] = {
		.index		= HCR_EL2,
		.value		= HCR_TACR,
		.mask		= HCR_TACR,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_HCR_TSW] = {
		.index		= HCR_EL2,
		.value		= HCR_TSW,
		.mask		= HCR_TSW,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_HCR_TPC] = {
		.index		= HCR_EL2,
		.value		= HCR_TPC,
		.mask		= HCR_TPC,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_HCR_TPU] = {
		.index		= HCR_EL2,
		.value		= HCR_TPU,
		.mask		= HCR_TPU,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_HCR_TTLB] = {
		.index		= HCR_EL2,
		.value		= HCR_TTLB,
		.mask		= HCR_TTLB,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_HCR_TVM] = {
		.index		= HCR_EL2,
		.value		= HCR_TVM,
		.mask		= HCR_TVM,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_HCR_TDZ] = {
		.index		= HCR_EL2,
		.value		= HCR_TDZ,
		.mask		= HCR_TDZ,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_HCR_TRVM] = {
		.index		= HCR_EL2,
		.value		= HCR_TRVM,
		.mask		= HCR_TRVM,
		.behaviour	= BEHAVE_FORWARD_READ,
	},
	[CGT_HCR_TLOR] = {
		.index		= HCR_EL2,
		.value		= HCR_TLOR,
		.mask		= HCR_TLOR,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_HCR_TERR] = {
		.index		= HCR_EL2,
		.value		= HCR_TERR,
		.mask		= HCR_TERR,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_HCR_APK] = {
		.index		= HCR_EL2,
		.value		= 0,
		.mask		= HCR_APK,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_HCR_NV] = {
		.index		= HCR_EL2,
		.value		= HCR_NV,
		.mask		= HCR_NV | HCR_NV2,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_HCR_NV1] = {
		.index		= HCR_EL2,
		.value		= HCR_NV | HCR_NV1,
		.mask		= HCR_NV | HCR_NV1 | HCR_NV2,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_HCR_AT] = {
		.index		= HCR_EL2,
		.value		= HCR_AT,
		.mask		= HCR_AT,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_HCR_FIEN] = {
		.index		= HCR_EL2,
		.value		= HCR_FIEN,
		.mask		= HCR_FIEN,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_HCR_TID4] = {
		.index		= HCR_EL2,
		.value 		= HCR_TID4,
		.mask		= HCR_TID4,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_HCR_TICAB] = {
		.index		= HCR_EL2,
		.value 		= HCR_TICAB,
		.mask		= HCR_TICAB,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_HCR_TOCU] = {
		.index		= HCR_EL2,
		.value 		= HCR_TOCU,
		.mask		= HCR_TOCU,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_HCR_ENSCXT] = {
		.index		= HCR_EL2,
		.value 		= 0,
		.mask		= HCR_ENSCXT,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_HCR_TTLBIS] = {
		.index		= HCR_EL2,
		.value		= HCR_TTLBIS,
		.mask		= HCR_TTLBIS,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_HCR_TTLBOS] = {
		.index		= HCR_EL2,
		.value		= HCR_TTLBOS,
		.mask		= HCR_TTLBOS,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_MDCR_TPMCR] = {
		.index		= MDCR_EL2,
		.value		= MDCR_EL2_TPMCR,
		.mask		= MDCR_EL2_TPMCR,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_MDCR_TPM] = {
		.index		= MDCR_EL2,
		.value		= MDCR_EL2_TPM,
		.mask		= MDCR_EL2_TPM,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_MDCR_TDE] = {
		.index		= MDCR_EL2,
		.value		= MDCR_EL2_TDE,
		.mask		= MDCR_EL2_TDE,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_MDCR_TDA] = {
		.index		= MDCR_EL2,
		.value		= MDCR_EL2_TDA,
		.mask		= MDCR_EL2_TDA,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_MDCR_TDOSA] = {
		.index		= MDCR_EL2,
		.value		= MDCR_EL2_TDOSA,
		.mask		= MDCR_EL2_TDOSA,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_MDCR_TDRA] = {
		.index		= MDCR_EL2,
		.value		= MDCR_EL2_TDRA,
		.mask		= MDCR_EL2_TDRA,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_MDCR_E2PB] = {
		.index		= MDCR_EL2,
		.value		= 0,
		.mask		= BIT(MDCR_EL2_E2PB_SHIFT),
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_MDCR_TPMS] = {
		.index		= MDCR_EL2,
		.value		= MDCR_EL2_TPMS,
		.mask		= MDCR_EL2_TPMS,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_MDCR_TTRF] = {
		.index		= MDCR_EL2,
		.value		= MDCR_EL2_TTRF,
		.mask		= MDCR_EL2_TTRF,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_MDCR_E2TB] = {
		.index		= MDCR_EL2,
		.value		= 0,
		.mask		= BIT(MDCR_EL2_E2TB_SHIFT),
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
	[CGT_MDCR_TDCC] = {
		.index		= MDCR_EL2,
		.value		= MDCR_EL2_TDCC,
		.mask		= MDCR_EL2_TDCC,
		.behaviour	= BEHAVE_FORWARD_ANY,
	},
};

#define MCB(id, ...)					\
	[id - __MULTIPLE_CONTROL_BITS__]	=	\
		(const enum coarse_grain_trap_id []){	\
			__VA_ARGS__ , __RESERVED__	\
		}

static const enum coarse_grain_trap_id *coarse_control_combo[] = {
	MCB(CGT_HCR_IMO_FMO,		CGT_HCR_IMO, CGT_HCR_FMO),
	MCB(CGT_HCR_TID2_TID4,		CGT_HCR_TID2, CGT_HCR_TID4),
	MCB(CGT_HCR_TTLB_TTLBIS,	CGT_HCR_TTLB, CGT_HCR_TTLBIS),
	MCB(CGT_HCR_TTLB_TTLBOS,	CGT_HCR_TTLB, CGT_HCR_TTLBOS),
	MCB(CGT_HCR_TVM_TRVM,		CGT_HCR_TVM, CGT_HCR_TRVM),
	MCB(CGT_HCR_TPU_TICAB,		CGT_HCR_TPU, CGT_HCR_TICAB),
	MCB(CGT_HCR_TPU_TOCU,		CGT_HCR_TPU, CGT_HCR_TOCU),
	MCB(CGT_HCR_NV1_ENSCXT,		CGT_HCR_NV1, CGT_HCR_ENSCXT),
	MCB(CGT_MDCR_TPM_TPMCR,		CGT_MDCR_TPM, CGT_MDCR_TPMCR),
	MCB(CGT_MDCR_TDE_TDA,		CGT_MDCR_TDE, CGT_MDCR_TDA),
	MCB(CGT_MDCR_TDE_TDOSA,		CGT_MDCR_TDE, CGT_MDCR_TDOSA),
	MCB(CGT_MDCR_TDE_TDRA,		CGT_MDCR_TDE, CGT_MDCR_TDRA),
	MCB(CGT_MDCR_TDCC_TDE_TDA,	CGT_MDCR_TDCC, CGT_MDCR_TDE_TDA),
};

typedef enum trap_behaviour (*complex_condition_check)(struct kvm_vcpu *);

static u64 get_sanitized_cnthctl(struct kvm_vcpu *vcpu)
{
	u64 val = __vcpu_sys_reg(vcpu, CNTHCTL_EL2);

	if (!vcpu_el2_e2h_is_set(vcpu))
		val = (val & (CNTHCTL_EL1PCEN | CNTHCTL_EL1PCTEN)) << 10;

	return val;
}

static enum trap_behaviour check_cnthctl_el1pcten(struct kvm_vcpu *vcpu)
{
	if (get_sanitized_cnthctl(vcpu) & (CNTHCTL_EL1PCTEN << 10))
		return BEHAVE_HANDLE_LOCALLY;

	return BEHAVE_FORWARD_ANY;
}

static enum trap_behaviour check_cnthctl_el1pten(struct kvm_vcpu *vcpu)
{
	if (get_sanitized_cnthctl(vcpu) & (CNTHCTL_EL1PCEN << 10))
		return BEHAVE_HANDLE_LOCALLY;

	return BEHAVE_FORWARD_ANY;
}

#define CCC(id, fn)	[id - __COMPLEX_CONDITIONS__] = fn

static const complex_condition_check ccc[] = {
	CCC(CGT_CNTHCTL_EL1PCTEN, check_cnthctl_el1pcten),
	CCC(CGT_CNTHCTL_EL1PTEN, check_cnthctl_el1pten),
};

struct encoding_to_trap_configs {
	const u32			encoding;
	const u32			end;
	const enum coarse_grain_trap_id	id;
};

#define SR_RANGE_TRAP(sr_start, sr_end, trap_id)			\
	{								\
		.encoding	= sr_start,				\
		.end		= sr_end,				\
		.id		= trap_id,				\
	}

#define SR_TRAP(sr, trap_id)		SR_RANGE_TRAP(sr, sr, trap_id)

/*
 * Map encoding to trap bits for exception reported with EC=0x18.
 * These must only be evaluated when running a nested hypervisor, but
 * that the current context is not a hypervisor context. When the
 * trapped access matches one of the trap controls, the exception is
 * re-injected in the nested hypervisor.
 */
static const struct encoding_to_trap_configs encoding_to_traps[] __initdata = {
	SR_TRAP(SYS_REVIDR_EL1,		CGT_HCR_TID1),
	SR_TRAP(SYS_AIDR_EL1,		CGT_HCR_TID1),
	SR_TRAP(SYS_SMIDR_EL1,		CGT_HCR_TID1),
	SR_TRAP(SYS_CTR_EL0,		CGT_HCR_TID2),
	SR_TRAP(SYS_CCSIDR_EL1,		CGT_HCR_TID2_TID4),
	SR_TRAP(SYS_CCSIDR2_EL1,	CGT_HCR_TID2_TID4),
	SR_TRAP(SYS_CLIDR_EL1,		CGT_HCR_TID2_TID4),
	SR_TRAP(SYS_CSSELR_EL1,		CGT_HCR_TID2_TID4),
	SR_RANGE_TRAP(SYS_ID_PFR0_EL1,
		      sys_reg(3, 0, 0, 7, 7), CGT_HCR_TID3),
	SR_TRAP(SYS_ICC_SGI0R_EL1,	CGT_HCR_IMO_FMO),
	SR_TRAP(SYS_ICC_ASGI1R_EL1,	CGT_HCR_IMO_FMO),
	SR_TRAP(SYS_ICC_SGI1R_EL1,	CGT_HCR_IMO_FMO),
	SR_RANGE_TRAP(sys_reg(3, 0, 11, 0, 0),
		      sys_reg(3, 0, 11, 15, 7), CGT_HCR_TIDCP),
	SR_RANGE_TRAP(sys_reg(3, 1, 11, 0, 0),
		      sys_reg(3, 1, 11, 15, 7), CGT_HCR_TIDCP),
	SR_RANGE_TRAP(sys_reg(3, 2, 11, 0, 0),
		      sys_reg(3, 2, 11, 15, 7), CGT_HCR_TIDCP),
	SR_RANGE_TRAP(sys_reg(3, 3, 11, 0, 0),
		      sys_reg(3, 3, 11, 15, 7), CGT_HCR_TIDCP),
	SR_RANGE_TRAP(sys_reg(3, 4, 11, 0, 0),
		      sys_reg(3, 4, 11, 15, 7), CGT_HCR_TIDCP),
	SR_RANGE_TRAP(sys_reg(3, 5, 11, 0, 0),
		      sys_reg(3, 5, 11, 15, 7), CGT_HCR_TIDCP),
	SR_RANGE_TRAP(sys_reg(3, 6, 11, 0, 0),
		      sys_reg(3, 6, 11, 15, 7), CGT_HCR_TIDCP),
	SR_RANGE_TRAP(sys_reg(3, 7, 11, 0, 0),
		      sys_reg(3, 7, 11, 15, 7), CGT_HCR_TIDCP),
	SR_RANGE_TRAP(sys_reg(3, 0, 15, 0, 0),
		      sys_reg(3, 0, 15, 15, 7), CGT_HCR_TIDCP),
	SR_RANGE_TRAP(sys_reg(3, 1, 15, 0, 0),
		      sys_reg(3, 1, 15, 15, 7), CGT_HCR_TIDCP),
	SR_RANGE_TRAP(sys_reg(3, 2, 15, 0, 0),
		      sys_reg(3, 2, 15, 15, 7), CGT_HCR_TIDCP),
	SR_RANGE_TRAP(sys_reg(3, 3, 15, 0, 0),
		      sys_reg(3, 3, 15, 15, 7), CGT_HCR_TIDCP),
	SR_RANGE_TRAP(sys_reg(3, 4, 15, 0, 0),
		      sys_reg(3, 4, 15, 15, 7), CGT_HCR_TIDCP),
	SR_RANGE_TRAP(sys_reg(3, 5, 15, 0, 0),
		      sys_reg(3, 5, 15, 15, 7), CGT_HCR_TIDCP),
	SR_RANGE_TRAP(sys_reg(3, 6, 15, 0, 0),
		      sys_reg(3, 6, 15, 15, 7), CGT_HCR_TIDCP),
	SR_RANGE_TRAP(sys_reg(3, 7, 15, 0, 0),
		      sys_reg(3, 7, 15, 15, 7), CGT_HCR_TIDCP),
	SR_TRAP(SYS_ACTLR_EL1,		CGT_HCR_TACR),
	SR_TRAP(SYS_DC_ISW,		CGT_HCR_TSW),
	SR_TRAP(SYS_DC_CSW,		CGT_HCR_TSW),
	SR_TRAP(SYS_DC_CISW,		CGT_HCR_TSW),
	SR_TRAP(SYS_DC_IGSW,		CGT_HCR_TSW),
	SR_TRAP(SYS_DC_IGDSW,		CGT_HCR_TSW),
	SR_TRAP(SYS_DC_CGSW,		CGT_HCR_TSW),
	SR_TRAP(SYS_DC_CGDSW,		CGT_HCR_TSW),
	SR_TRAP(SYS_DC_CIGSW,		CGT_HCR_TSW),
	SR_TRAP(SYS_DC_CIGDSW,		CGT_HCR_TSW),
	SR_TRAP(SYS_DC_CIVAC,		CGT_HCR_TPC),
	SR_TRAP(SYS_DC_CVAC,		CGT_HCR_TPC),
	SR_TRAP(SYS_DC_CVAP,		CGT_HCR_TPC),
	SR_TRAP(SYS_DC_IVAC,		CGT_HCR_TPC),
	SR_TRAP(SYS_DC_CIGVAC,		CGT_HCR_TPC),
	SR_TRAP(SYS_DC_CIGDVAC,		CGT_HCR_TPC),
	SR_TRAP(SYS_DC_IGVAC,		CGT_HCR_TPC),
	SR_TRAP(SYS_DC_IGDVAC,		CGT_HCR_TPC),
	SR_TRAP(SYS_DC_CGVAC,		CGT_HCR_TPC),
	SR_TRAP(SYS_DC_CGDVAC,		CGT_HCR_TPC),
	SR_TRAP(SYS_DC_CGVAP,		CGT_HCR_TPC),
	SR_TRAP(SYS_DC_CGDVAP,		CGT_HCR_TPC),
	SR_TRAP(SYS_DC_CGVADP,		CGT_HCR_TPC),
	SR_TRAP(SYS_DC_CGDVADP,		CGT_HCR_TPC),
	SR_TRAP(SYS_IC_IVAU,		CGT_HCR_TPU_TOCU),
	SR_TRAP(SYS_IC_IALLU,		CGT_HCR_TPU_TOCU),
	SR_TRAP(SYS_IC_IALLUIS,		CGT_HCR_TPU_TICAB),
	SR_TRAP(SYS_DC_CVAU,		CGT_HCR_TPU_TOCU),
	SR_TRAP(OP_TLBI_RVAE1,		CGT_HCR_TTLB),
	SR_TRAP(OP_TLBI_RVAAE1,		CGT_HCR_TTLB),
	SR_TRAP(OP_TLBI_RVALE1,		CGT_HCR_TTLB),
	SR_TRAP(OP_TLBI_RVAALE1,	CGT_HCR_TTLB),
	SR_TRAP(OP_TLBI_VMALLE1,	CGT_HCR_TTLB),
	SR_TRAP(OP_TLBI_VAE1,		CGT_HCR_TTLB),
	SR_TRAP(OP_TLBI_ASIDE1,		CGT_HCR_TTLB),
	SR_TRAP(OP_TLBI_VAAE1,		CGT_HCR_TTLB),
	SR_TRAP(OP_TLBI_VALE1,		CGT_HCR_TTLB),
	SR_TRAP(OP_TLBI_VAALE1,		CGT_HCR_TTLB),
	SR_TRAP(OP_TLBI_RVAE1NXS,	CGT_HCR_TTLB),
	SR_TRAP(OP_TLBI_RVAAE1NXS,	CGT_HCR_TTLB),
	SR_TRAP(OP_TLBI_RVALE1NXS,	CGT_HCR_TTLB),
	SR_TRAP(OP_TLBI_RVAALE1NXS,	CGT_HCR_TTLB),
	SR_TRAP(OP_TLBI_VMALLE1NXS,	CGT_HCR_TTLB),
	SR_TRAP(OP_TLBI_VAE1NXS,	CGT_HCR_TTLB),
	SR_TRAP(OP_TLBI_ASIDE1NXS,	CGT_HCR_TTLB),
	SR_TRAP(OP_TLBI_VAAE1NXS,	CGT_HCR_TTLB),
	SR_TRAP(OP_TLBI_VALE1NXS,	CGT_HCR_TTLB),
	SR_TRAP(OP_TLBI_VAALE1NXS,	CGT_HCR_TTLB),
	SR_TRAP(OP_TLBI_RVAE1IS,	CGT_HCR_TTLB_TTLBIS),
	SR_TRAP(OP_TLBI_RVAAE1IS,	CGT_HCR_TTLB_TTLBIS),
	SR_TRAP(OP_TLBI_RVALE1IS,	CGT_HCR_TTLB_TTLBIS),
	SR_TRAP(OP_TLBI_RVAALE1IS,	CGT_HCR_TTLB_TTLBIS),
	SR_TRAP(OP_TLBI_VMALLE1IS,	CGT_HCR_TTLB_TTLBIS),
	SR_TRAP(OP_TLBI_VAE1IS,		CGT_HCR_TTLB_TTLBIS),
	SR_TRAP(OP_TLBI_ASIDE1IS,	CGT_HCR_TTLB_TTLBIS),
	SR_TRAP(OP_TLBI_VAAE1IS,	CGT_HCR_TTLB_TTLBIS),
	SR_TRAP(OP_TLBI_VALE1IS,	CGT_HCR_TTLB_TTLBIS),
	SR_TRAP(OP_TLBI_VAALE1IS,	CGT_HCR_TTLB_TTLBIS),
	SR_TRAP(OP_TLBI_RVAE1ISNXS,	CGT_HCR_TTLB_TTLBIS),
	SR_TRAP(OP_TLBI_RVAAE1ISNXS,	CGT_HCR_TTLB_TTLBIS),
	SR_TRAP(OP_TLBI_RVALE1ISNXS,	CGT_HCR_TTLB_TTLBIS),
	SR_TRAP(OP_TLBI_RVAALE1ISNXS,	CGT_HCR_TTLB_TTLBIS),
	SR_TRAP(OP_TLBI_VMALLE1ISNXS,	CGT_HCR_TTLB_TTLBIS),
	SR_TRAP(OP_TLBI_VAE1ISNXS,	CGT_HCR_TTLB_TTLBIS),
	SR_TRAP(OP_TLBI_ASIDE1ISNXS,	CGT_HCR_TTLB_TTLBIS),
	SR_TRAP(OP_TLBI_VAAE1ISNXS,	CGT_HCR_TTLB_TTLBIS),
	SR_TRAP(OP_TLBI_VALE1ISNXS,	CGT_HCR_TTLB_TTLBIS),
	SR_TRAP(OP_TLBI_VAALE1ISNXS,	CGT_HCR_TTLB_TTLBIS),
	SR_TRAP(OP_TLBI_VMALLE1OS,	CGT_HCR_TTLB_TTLBOS),
	SR_TRAP(OP_TLBI_VAE1OS,		CGT_HCR_TTLB_TTLBOS),
	SR_TRAP(OP_TLBI_ASIDE1OS,	CGT_HCR_TTLB_TTLBOS),
	SR_TRAP(OP_TLBI_VAAE1OS,	CGT_HCR_TTLB_TTLBOS),
	SR_TRAP(OP_TLBI_VALE1OS,	CGT_HCR_TTLB_TTLBOS),
	SR_TRAP(OP_TLBI_VAALE1OS,	CGT_HCR_TTLB_TTLBOS),
	SR_TRAP(OP_TLBI_RVAE1OS,	CGT_HCR_TTLB_TTLBOS),
	SR_TRAP(OP_TLBI_RVAAE1OS,	CGT_HCR_TTLB_TTLBOS),
	SR_TRAP(OP_TLBI_RVALE1OS,	CGT_HCR_TTLB_TTLBOS),
	SR_TRAP(OP_TLBI_RVAALE1OS,	CGT_HCR_TTLB_TTLBOS),
	SR_TRAP(OP_TLBI_VMALLE1OSNXS,	CGT_HCR_TTLB_TTLBOS),
	SR_TRAP(OP_TLBI_VAE1OSNXS,	CGT_HCR_TTLB_TTLBOS),
	SR_TRAP(OP_TLBI_ASIDE1OSNXS,	CGT_HCR_TTLB_TTLBOS),
	SR_TRAP(OP_TLBI_VAAE1OSNXS,	CGT_HCR_TTLB_TTLBOS),
	SR_TRAP(OP_TLBI_VALE1OSNXS,	CGT_HCR_TTLB_TTLBOS),
	SR_TRAP(OP_TLBI_VAALE1OSNXS,	CGT_HCR_TTLB_TTLBOS),
	SR_TRAP(OP_TLBI_RVAE1OSNXS,	CGT_HCR_TTLB_TTLBOS),
	SR_TRAP(OP_TLBI_RVAAE1OSNXS,	CGT_HCR_TTLB_TTLBOS),
	SR_TRAP(OP_TLBI_RVALE1OSNXS,	CGT_HCR_TTLB_TTLBOS),
	SR_TRAP(OP_TLBI_RVAALE1OSNXS,	CGT_HCR_TTLB_TTLBOS),
	SR_TRAP(SYS_SCTLR_EL1,		CGT_HCR_TVM_TRVM),
	SR_TRAP(SYS_TTBR0_EL1,		CGT_HCR_TVM_TRVM),
	SR_TRAP(SYS_TTBR1_EL1,		CGT_HCR_TVM_TRVM),
	SR_TRAP(SYS_TCR_EL1,		CGT_HCR_TVM_TRVM),
	SR_TRAP(SYS_ESR_EL1,		CGT_HCR_TVM_TRVM),
	SR_TRAP(SYS_FAR_EL1,		CGT_HCR_TVM_TRVM),
	SR_TRAP(SYS_AFSR0_EL1,		CGT_HCR_TVM_TRVM),
	SR_TRAP(SYS_AFSR1_EL1,		CGT_HCR_TVM_TRVM),
	SR_TRAP(SYS_MAIR_EL1,		CGT_HCR_TVM_TRVM),
	SR_TRAP(SYS_AMAIR_EL1,		CGT_HCR_TVM_TRVM),
	SR_TRAP(SYS_CONTEXTIDR_EL1,	CGT_HCR_TVM_TRVM),
	SR_TRAP(SYS_DC_ZVA,		CGT_HCR_TDZ),
	SR_TRAP(SYS_DC_GVA,		CGT_HCR_TDZ),
	SR_TRAP(SYS_DC_GZVA,		CGT_HCR_TDZ),
	SR_RANGE_TRAP(SYS_LORSA_EL1,
		      SYS_LORC_EL1,	CGT_HCR_TLOR),
	SR_TRAP(SYS_LORID_EL1,		CGT_HCR_TLOR),
	SR_TRAP(SYS_ERRIDR_EL1,		CGT_HCR_TERR),
	SR_TRAP(SYS_ERRSELR_EL1,	CGT_HCR_TERR),
	SR_TRAP(SYS_ERXADDR_EL1,	CGT_HCR_TERR),
	SR_TRAP(SYS_ERXCTLR_EL1,	CGT_HCR_TERR),
	SR_TRAP(SYS_ERXFR_EL1,		CGT_HCR_TERR),
	SR_TRAP(SYS_ERXMISC0_EL1,	CGT_HCR_TERR),
	SR_TRAP(SYS_ERXMISC1_EL1,	CGT_HCR_TERR),
	SR_TRAP(SYS_ERXMISC2_EL1,	CGT_HCR_TERR),
	SR_TRAP(SYS_ERXMISC3_EL1,	CGT_HCR_TERR),
	SR_TRAP(SYS_ERXSTATUS_EL1,	CGT_HCR_TERR),
	SR_TRAP(SYS_APIAKEYLO_EL1,	CGT_HCR_APK),
	SR_TRAP(SYS_APIAKEYHI_EL1,	CGT_HCR_APK),
	SR_TRAP(SYS_APIBKEYLO_EL1,	CGT_HCR_APK),
	SR_TRAP(SYS_APIBKEYHI_EL1,	CGT_HCR_APK),
	SR_TRAP(SYS_APDAKEYLO_EL1,	CGT_HCR_APK),
	SR_TRAP(SYS_APDAKEYHI_EL1,	CGT_HCR_APK),
	SR_TRAP(SYS_APDBKEYLO_EL1,	CGT_HCR_APK),
	SR_TRAP(SYS_APDBKEYHI_EL1,	CGT_HCR_APK),
	SR_TRAP(SYS_APGAKEYLO_EL1,	CGT_HCR_APK),
	SR_TRAP(SYS_APGAKEYHI_EL1,	CGT_HCR_APK),
	/* All _EL2 registers */
	SR_RANGE_TRAP(sys_reg(3, 4, 0, 0, 0),
		      sys_reg(3, 4, 10, 15, 7), CGT_HCR_NV),
	SR_RANGE_TRAP(sys_reg(3, 4, 12, 0, 0),
		      sys_reg(3, 4, 14, 15, 7), CGT_HCR_NV),
	/* All _EL02, _EL12 registers */
	SR_RANGE_TRAP(sys_reg(3, 5, 0, 0, 0),
		      sys_reg(3, 5, 10, 15, 7), CGT_HCR_NV),
	SR_RANGE_TRAP(sys_reg(3, 5, 12, 0, 0),
		      sys_reg(3, 5, 14, 15, 7), CGT_HCR_NV),
	SR_TRAP(SYS_SP_EL1,		CGT_HCR_NV),
	SR_TRAP(OP_AT_S1E2R,		CGT_HCR_NV),
	SR_TRAP(OP_AT_S1E2W,		CGT_HCR_NV),
	SR_TRAP(OP_AT_S12E1R,		CGT_HCR_NV),
	SR_TRAP(OP_AT_S12E1W,		CGT_HCR_NV),
	SR_TRAP(OP_AT_S12E0R,		CGT_HCR_NV),
	SR_TRAP(OP_AT_S12E0W,		CGT_HCR_NV),
	SR_TRAP(OP_TLBI_IPAS2E1,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RIPAS2E1,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_IPAS2LE1,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RIPAS2LE1,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RVAE2,		CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RVALE2,		CGT_HCR_NV),
	SR_TRAP(OP_TLBI_ALLE2,		CGT_HCR_NV),
	SR_TRAP(OP_TLBI_VAE2,		CGT_HCR_NV),
	SR_TRAP(OP_TLBI_ALLE1,		CGT_HCR_NV),
	SR_TRAP(OP_TLBI_VALE2,		CGT_HCR_NV),
	SR_TRAP(OP_TLBI_VMALLS12E1,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_IPAS2E1NXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RIPAS2E1NXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_IPAS2LE1NXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RIPAS2LE1NXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RVAE2NXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RVALE2NXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_ALLE2NXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_VAE2NXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_ALLE1NXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_VALE2NXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_VMALLS12E1NXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_IPAS2E1IS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RIPAS2E1IS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_IPAS2LE1IS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RIPAS2LE1IS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RVAE2IS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RVALE2IS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_ALLE2IS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_VAE2IS,		CGT_HCR_NV),
	SR_TRAP(OP_TLBI_ALLE1IS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_VALE2IS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_VMALLS12E1IS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_IPAS2E1ISNXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RIPAS2E1ISNXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_IPAS2LE1ISNXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RIPAS2LE1ISNXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RVAE2ISNXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RVALE2ISNXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_ALLE2ISNXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_VAE2ISNXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_ALLE1ISNXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_VALE2ISNXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_VMALLS12E1ISNXS,CGT_HCR_NV),
	SR_TRAP(OP_TLBI_ALLE2OS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_VAE2OS,		CGT_HCR_NV),
	SR_TRAP(OP_TLBI_ALLE1OS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_VALE2OS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_VMALLS12E1OS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_IPAS2E1OS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RIPAS2E1OS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_IPAS2LE1OS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RIPAS2LE1OS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RVAE2OS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RVALE2OS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_ALLE2OSNXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_VAE2OSNXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_ALLE1OSNXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_VALE2OSNXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_VMALLS12E1OSNXS,CGT_HCR_NV),
	SR_TRAP(OP_TLBI_IPAS2E1OSNXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RIPAS2E1OSNXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_IPAS2LE1OSNXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RIPAS2LE1OSNXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RVAE2OSNXS,	CGT_HCR_NV),
	SR_TRAP(OP_TLBI_RVALE2OSNXS,	CGT_HCR_NV),
	SR_TRAP(SYS_VBAR_EL1,		CGT_HCR_NV1),
	SR_TRAP(SYS_ELR_EL1,		CGT_HCR_NV1),
	SR_TRAP(SYS_SPSR_EL1,		CGT_HCR_NV1),
	SR_TRAP(SYS_SCXTNUM_EL1,	CGT_HCR_NV1_ENSCXT),
	SR_TRAP(OP_AT_S1E1R, 		CGT_HCR_AT),
	SR_TRAP(OP_AT_S1E1W, 		CGT_HCR_AT),
	SR_TRAP(OP_AT_S1E0R, 		CGT_HCR_AT),
	SR_TRAP(OP_AT_S1E0W, 		CGT_HCR_AT),
	SR_TRAP(OP_AT_S1E1RP, 		CGT_HCR_AT),
	SR_TRAP(OP_AT_S1E1WP, 		CGT_HCR_AT),
	/* ERXPFGCDN_EL1, ERXPFGCTL_EL1, and ERXPFGF_EL1 */
	SR_RANGE_TRAP(sys_reg(3, 0, 5, 4, 4),
		      sys_reg(3, 0, 5, 4, 6), CGT_HCR_FIEN),
	SR_TRAP(SYS_SCXTNUM_EL0,	CGT_HCR_ENSCXT),
	SR_TRAP(SYS_PMCR_EL0,		CGT_MDCR_TPM_TPMCR),
	SR_TRAP(SYS_PMCNTENSET_EL0,	CGT_MDCR_TPM),
	SR_TRAP(SYS_PMCNTENCLR_EL0,	CGT_MDCR_TPM),
	SR_TRAP(SYS_PMOVSSET_EL0,	CGT_MDCR_TPM),
	SR_TRAP(SYS_PMOVSCLR_EL0,	CGT_MDCR_TPM),
	SR_TRAP(SYS_PMCEID0_EL0,	CGT_MDCR_TPM),
	SR_TRAP(SYS_PMCEID1_EL0,	CGT_MDCR_TPM),
	SR_TRAP(SYS_PMXEVTYPER_EL0,	CGT_MDCR_TPM),
	SR_TRAP(SYS_PMSWINC_EL0,	CGT_MDCR_TPM),
	SR_TRAP(SYS_PMSELR_EL0,		CGT_MDCR_TPM),
	SR_TRAP(SYS_PMXEVCNTR_EL0,	CGT_MDCR_TPM),
	SR_TRAP(SYS_PMCCNTR_EL0,	CGT_MDCR_TPM),
	SR_TRAP(SYS_PMUSERENR_EL0,	CGT_MDCR_TPM),
	SR_TRAP(SYS_PMINTENSET_EL1,	CGT_MDCR_TPM),
	SR_TRAP(SYS_PMINTENCLR_EL1,	CGT_MDCR_TPM),
	SR_TRAP(SYS_PMMIR_EL1,		CGT_MDCR_TPM),
	SR_RANGE_TRAP(SYS_PMEVCNTRn_EL0(0),
		      SYS_PMEVCNTRn_EL0(30), CGT_MDCR_TPM),
	SR_RANGE_TRAP(SYS_PMEVTYPERn_EL0(0),
		      SYS_PMEVTYPERn_EL0(30), CGT_MDCR_TPM),
	SR_TRAP(SYS_PMCCFILTR_EL0,	CGT_MDCR_TPM),
	SR_TRAP(SYS_MDCCSR_EL0,		CGT_MDCR_TDCC_TDE_TDA),
	SR_TRAP(SYS_MDCCINT_EL1,	CGT_MDCR_TDCC_TDE_TDA),
	SR_TRAP(SYS_OSDTRRX_EL1,	CGT_MDCR_TDCC_TDE_TDA),
	SR_TRAP(SYS_OSDTRTX_EL1,	CGT_MDCR_TDCC_TDE_TDA),
	SR_TRAP(SYS_MDSCR_EL1,		CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_OSECCR_EL1,		CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBVRn_EL1(0),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBVRn_EL1(1),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBVRn_EL1(2),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBVRn_EL1(3),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBVRn_EL1(4),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBVRn_EL1(5),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBVRn_EL1(6),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBVRn_EL1(7),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBVRn_EL1(8),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBVRn_EL1(9),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBVRn_EL1(10),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBVRn_EL1(11),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBVRn_EL1(12),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBVRn_EL1(13),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBVRn_EL1(14),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBVRn_EL1(15),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBCRn_EL1(0),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBCRn_EL1(1),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBCRn_EL1(2),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBCRn_EL1(3),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBCRn_EL1(4),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBCRn_EL1(5),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBCRn_EL1(6),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBCRn_EL1(7),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBCRn_EL1(8),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBCRn_EL1(9),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBCRn_EL1(10),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBCRn_EL1(11),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBCRn_EL1(12),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBCRn_EL1(13),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBCRn_EL1(14),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGBCRn_EL1(15),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWVRn_EL1(0),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWVRn_EL1(1),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWVRn_EL1(2),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWVRn_EL1(3),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWVRn_EL1(4),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWVRn_EL1(5),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWVRn_EL1(6),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWVRn_EL1(7),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWVRn_EL1(8),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWVRn_EL1(9),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWVRn_EL1(10),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWVRn_EL1(11),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWVRn_EL1(12),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWVRn_EL1(13),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWVRn_EL1(14),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWVRn_EL1(15),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWCRn_EL1(0),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWCRn_EL1(1),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWCRn_EL1(2),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWCRn_EL1(3),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWCRn_EL1(4),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWCRn_EL1(5),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWCRn_EL1(6),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWCRn_EL1(7),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWCRn_EL1(8),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWCRn_EL1(9),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWCRn_EL1(10),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWCRn_EL1(11),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWCRn_EL1(12),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWCRn_EL1(13),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGWCRn_EL1(14),	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGCLAIMSET_EL1,	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGCLAIMCLR_EL1,	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_DBGAUTHSTATUS_EL1,	CGT_MDCR_TDE_TDA),
	SR_TRAP(SYS_OSLAR_EL1,		CGT_MDCR_TDE_TDOSA),
	SR_TRAP(SYS_OSLSR_EL1,		CGT_MDCR_TDE_TDOSA),
	SR_TRAP(SYS_OSDLR_EL1,		CGT_MDCR_TDE_TDOSA),
	SR_TRAP(SYS_DBGPRCR_EL1,	CGT_MDCR_TDE_TDOSA),
	SR_TRAP(SYS_MDRAR_EL1,		CGT_MDCR_TDE_TDRA),
	SR_TRAP(SYS_PMBLIMITR_EL1,	CGT_MDCR_E2PB),
	SR_TRAP(SYS_PMBPTR_EL1,		CGT_MDCR_E2PB),
	SR_TRAP(SYS_PMBSR_EL1,		CGT_MDCR_E2PB),
	SR_TRAP(SYS_PMSCR_EL1,		CGT_MDCR_TPMS),
	SR_TRAP(SYS_PMSEVFR_EL1,	CGT_MDCR_TPMS),
	SR_TRAP(SYS_PMSFCR_EL1,		CGT_MDCR_TPMS),
	SR_TRAP(SYS_PMSICR_EL1,		CGT_MDCR_TPMS),
	SR_TRAP(SYS_PMSIDR_EL1,		CGT_MDCR_TPMS),
	SR_TRAP(SYS_PMSIRR_EL1,		CGT_MDCR_TPMS),
	SR_TRAP(SYS_PMSLATFR_EL1,	CGT_MDCR_TPMS),
	SR_TRAP(SYS_PMSNEVFR_EL1,	CGT_MDCR_TPMS),
	SR_TRAP(SYS_TRFCR_EL1,		CGT_MDCR_TTRF),
	SR_TRAP(SYS_TRBBASER_EL1,	CGT_MDCR_E2TB),
	SR_TRAP(SYS_TRBLIMITR_EL1,	CGT_MDCR_E2TB),
	SR_TRAP(SYS_TRBMAR_EL1, 	CGT_MDCR_E2TB),
	SR_TRAP(SYS_TRBPTR_EL1, 	CGT_MDCR_E2TB),
	SR_TRAP(SYS_TRBSR_EL1, 		CGT_MDCR_E2TB),
	SR_TRAP(SYS_TRBTRG_EL1,		CGT_MDCR_E2TB),
	SR_TRAP(SYS_CNTP_TVAL_EL0,	CGT_CNTHCTL_EL1PTEN),
	SR_TRAP(SYS_CNTP_CVAL_EL0,	CGT_CNTHCTL_EL1PTEN),
	SR_TRAP(SYS_CNTP_CTL_EL0,	CGT_CNTHCTL_EL1PTEN),
	SR_TRAP(SYS_CNTPCT_EL0,		CGT_CNTHCTL_EL1PCTEN),
	SR_TRAP(SYS_CNTPCTSS_EL0,	CGT_CNTHCTL_EL1PCTEN),
};

static DEFINE_XARRAY(sr_forward_xa);

void __init populate_nv_trap_config(void)
{
	for (int i = 0; i < ARRAY_SIZE(encoding_to_traps); i++) {
		const struct encoding_to_trap_configs *ett = &encoding_to_traps[i];
		void *prev;

		prev = xa_store_range(&sr_forward_xa, ett->encoding, ett->end,
				      xa_mk_value(ett->id), GFP_KERNEL);
		WARN_ON(prev);
	}

	kvm_info("nv: %ld trap handlers\n", ARRAY_SIZE(encoding_to_traps));
}

static const enum coarse_grain_trap_id get_trap_config(u32 sysreg)
{
	return xa_to_value(xa_load(&sr_forward_xa, sysreg));
}

static enum trap_behaviour get_behaviour(struct kvm_vcpu *vcpu,
					 const struct trap_bits *tb)
{
	enum trap_behaviour b = BEHAVE_HANDLE_LOCALLY;
	u64 val;

	val = __vcpu_sys_reg(vcpu, tb->index);
	if ((val & tb->mask) == tb->value)
		b |= tb->behaviour;

	return b;
}

static enum trap_behaviour __do_compute_behaviour(struct kvm_vcpu *vcpu,
						  const enum coarse_grain_trap_id id,
						  enum trap_behaviour b)
{
	switch (id) {
		const enum coarse_grain_trap_id *cgids;

	case __RESERVED__ ... __MULTIPLE_CONTROL_BITS__ - 1:
		if (likely(id != __RESERVED__))
			b |= get_behaviour(vcpu, &coarse_trap_bits[id]);
		break;
	case __MULTIPLE_CONTROL_BITS__ ... __COMPLEX_CONDITIONS__ - 1:
		/* Yes, this is recursive. Don't do anything stupid. */
		cgids = coarse_control_combo[id - __MULTIPLE_CONTROL_BITS__];
		for (int i = 0; cgids[i] != __RESERVED__; i++)
			b |= __do_compute_behaviour(vcpu, cgids[i], b);
		break;
	default:
		if (ARRAY_SIZE(ccc))
			b |= ccc[id -  __COMPLEX_CONDITIONS__](vcpu);
		break;
	}

	return b;
}

static enum trap_behaviour compute_behaviour(struct kvm_vcpu *vcpu, u32 sysreg)
{
	const enum coarse_grain_trap_id id = get_trap_config(sysreg);
	enum trap_behaviour b = BEHAVE_HANDLE_LOCALLY;

	return __do_compute_behaviour(vcpu, id, b);
}

bool __check_nv_sr_forward(struct kvm_vcpu *vcpu)
{
	enum trap_behaviour b;
	bool is_read;
	u32 sysreg;
	u64 esr;

	if (!vcpu_has_nv(vcpu) || is_hyp_ctxt(vcpu))
		return false;

	esr = kvm_vcpu_get_esr(vcpu);
	sysreg = esr_sys64_to_sysreg(esr);
	is_read = (esr & ESR_ELx_SYS64_ISS_DIR_MASK) == ESR_ELx_SYS64_ISS_DIR_READ;

	b = compute_behaviour(vcpu, sysreg);

	if (!((b & BEHAVE_FORWARD_READ) && is_read) &&
	    !((b & BEHAVE_FORWARD_WRITE) && !is_read))
		return false;

	trace_kvm_forward_sysreg_trap(vcpu, sysreg, is_read);

	kvm_inject_nested_sync(vcpu, kvm_vcpu_get_esr(vcpu));
	return true;
}

static bool forward_traps(struct kvm_vcpu *vcpu, u64 control_bit)
{
	bool control_bit_set;

	if (!vcpu_has_nv(vcpu))
		return false;

	control_bit_set = __vcpu_sys_reg(vcpu, HCR_EL2) & control_bit;
	if (!vcpu_is_el2(vcpu) && control_bit_set) {
		kvm_inject_nested_sync(vcpu, kvm_vcpu_get_esr(vcpu));
		return true;
	}
	return false;
}

bool forward_smc_trap(struct kvm_vcpu *vcpu)
{
	return forward_traps(vcpu, HCR_TSC);
}

static u64 kvm_check_illegal_exception_return(struct kvm_vcpu *vcpu, u64 spsr)
{
	u64 mode = spsr & PSR_MODE_MASK;

	/*
	 * Possible causes for an Illegal Exception Return from EL2:
	 * - trying to return to EL3
	 * - trying to return to an illegal M value
	 * - trying to return to a 32bit EL
	 * - trying to return to EL1 with HCR_EL2.TGE set
	 */
	if (mode == PSR_MODE_EL3t   || mode == PSR_MODE_EL3h ||
	    mode == 0b00001         || (mode & BIT(1))       ||
	    (spsr & PSR_MODE32_BIT) ||
	    (vcpu_el2_tge_is_set(vcpu) && (mode == PSR_MODE_EL1t ||
					   mode == PSR_MODE_EL1h))) {
		/*
		 * The guest is playing with our nerves. Preserve EL, SP,
		 * masks, flags from the existing PSTATE, and set IL.
		 * The HW will then generate an Illegal State Exception
		 * immediately after ERET.
		 */
		spsr = *vcpu_cpsr(vcpu);

		spsr &= (PSR_D_BIT | PSR_A_BIT | PSR_I_BIT | PSR_F_BIT |
			 PSR_N_BIT | PSR_Z_BIT | PSR_C_BIT | PSR_V_BIT |
			 PSR_MODE_MASK | PSR_MODE32_BIT);
		spsr |= PSR_IL_BIT;
	}

	return spsr;
}

void kvm_emulate_nested_eret(struct kvm_vcpu *vcpu)
{
	u64 spsr, elr;

	/*
	 * Forward this trap to the virtual EL2 if the virtual
	 * HCR_EL2.NV bit is set and this is coming from !EL2.
	 */
	if (forward_traps(vcpu, HCR_NV))
		return;

	preempt_disable();
	kvm_arch_vcpu_put(vcpu);

	spsr = __vcpu_sys_reg(vcpu, SPSR_EL2);
	spsr = kvm_check_illegal_exception_return(vcpu, spsr);
	elr = __vcpu_sys_reg(vcpu, ELR_EL2);

	trace_kvm_nested_eret(vcpu, elr, spsr);

	/*
	 * Note that the current exception level is always the virtual EL2,
	 * since we set HCR_EL2.NV bit only when entering the virtual EL2.
	 */
	*vcpu_pc(vcpu) = elr;
	*vcpu_cpsr(vcpu) = spsr;

	kvm_arch_vcpu_load(vcpu, smp_processor_id());
	preempt_enable();
}

static void kvm_inject_el2_exception(struct kvm_vcpu *vcpu, u64 esr_el2,
				     enum exception_type type)
{
	trace_kvm_inject_nested_exception(vcpu, esr_el2, type);

	switch (type) {
	case except_type_sync:
		kvm_pend_exception(vcpu, EXCEPT_AA64_EL2_SYNC);
		vcpu_write_sys_reg(vcpu, esr_el2, ESR_EL2);
		break;
	case except_type_irq:
		kvm_pend_exception(vcpu, EXCEPT_AA64_EL2_IRQ);
		break;
	default:
		WARN_ONCE(1, "Unsupported EL2 exception injection %d\n", type);
	}
}

/*
 * Emulate taking an exception to EL2.
 * See ARM ARM J8.1.2 AArch64.TakeException()
 */
static int kvm_inject_nested(struct kvm_vcpu *vcpu, u64 esr_el2,
			     enum exception_type type)
{
	u64 pstate, mode;
	bool direct_inject;

	if (!vcpu_has_nv(vcpu)) {
		kvm_err("Unexpected call to %s for the non-nesting configuration\n",
				__func__);
		return -EINVAL;
	}

	/*
	 * As for ERET, we can avoid doing too much on the injection path by
	 * checking that we either took the exception from a VHE host
	 * userspace or from vEL2. In these cases, there is no change in
	 * translation regime (or anything else), so let's do as little as
	 * possible.
	 */
	pstate = *vcpu_cpsr(vcpu);
	mode = pstate & (PSR_MODE_MASK | PSR_MODE32_BIT);

	direct_inject  = (mode == PSR_MODE_EL0t &&
			  vcpu_el2_e2h_is_set(vcpu) &&
			  vcpu_el2_tge_is_set(vcpu));
	direct_inject |= (mode == PSR_MODE_EL2h || mode == PSR_MODE_EL2t);

	if (direct_inject) {
		kvm_inject_el2_exception(vcpu, esr_el2, type);
		return 1;
	}

	preempt_disable();

	/*
	 * We may have an exception or PC update in the EL0/EL1 context.
	 * Commit it before entering EL2.
	 */
	__kvm_adjust_pc(vcpu);

	kvm_arch_vcpu_put(vcpu);

	kvm_inject_el2_exception(vcpu, esr_el2, type);

	/*
	 * A hard requirement is that a switch between EL1 and EL2
	 * contexts has to happen between a put/load, so that we can
	 * pick the correct timer and interrupt configuration, among
	 * other things.
	 *
	 * Make sure the exception actually took place before we load
	 * the new context.
	 */
	__kvm_adjust_pc(vcpu);

	kvm_arch_vcpu_load(vcpu, smp_processor_id());
	preempt_enable();

	return 1;
}

int kvm_inject_nested_sync(struct kvm_vcpu *vcpu, u64 esr_el2)
{
	return kvm_inject_nested(vcpu, esr_el2, except_type_sync);
}

int kvm_inject_nested_irq(struct kvm_vcpu *vcpu)
{
	/*
	 * Do not inject an irq if the:
	 *  - Current exception level is EL2, and
	 *  - virtual HCR_EL2.TGE == 0
	 *  - virtual HCR_EL2.IMO == 0
	 *
	 * See Table D1-17 "Physical interrupt target and masking when EL3 is
	 * not implemented and EL2 is implemented" in ARM DDI 0487C.a.
	 */

	if (vcpu_is_el2(vcpu) && !vcpu_el2_tge_is_set(vcpu) &&
	    !(__vcpu_sys_reg(vcpu, HCR_EL2) & HCR_IMO))
		return 1;

	/* esr_el2 value doesn't matter for exits due to irqs. */
	return kvm_inject_nested(vcpu, 0, except_type_irq);
}
