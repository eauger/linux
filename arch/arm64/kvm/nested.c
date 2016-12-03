// SPDX-License-Identifier: GPL-2.0-only
/*
 * Copyright (C) 2017 - Columbia University and Linaro Ltd.
 * Author: Jintack Lim <jintack.lim@linaro.org>
 */

#include <linux/kvm.h>
#include <linux/kvm_host.h>

#include <asm/kvm_arm.h>
#include <asm/kvm_emulate.h>
#include <asm/kvm_mmu.h>
#include <asm/kvm_nested.h>
#include <asm/sysreg.h>

#include "sys_regs.h"

/* Protection against the sysreg repainting madness... */
#define NV_FTR(r, f)		ID_AA64##r##_EL1_##f

void kvm_init_nested(struct kvm *kvm)
{
	kvm->arch.nested_mmus = NULL;
	kvm->arch.nested_mmus_size = 0;
}

int kvm_vcpu_init_nested(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_s2_mmu *tmp;
	int num_mmus;
	int ret = -ENOMEM;

	if (!test_bit(KVM_ARM_VCPU_HAS_EL2, vcpu->arch.features))
		return 0;

	if (!cpus_have_final_cap(ARM64_HAS_NESTED_VIRT))
		return -EINVAL;

	mutex_lock(&kvm->arch.config_lock);

	/*
	 * Let's treat memory allocation failures as benign: If we fail to
	 * allocate anything, return an error and keep the allocated array
	 * alive. Userspace may try to recover by intializing the vcpu
	 * again, and there is no reason to affect the whole VM for this.
	 */
	num_mmus = atomic_read(&kvm->online_vcpus) * 2;
	tmp = krealloc(kvm->arch.nested_mmus,
		       num_mmus * sizeof(*kvm->arch.nested_mmus),
		       GFP_KERNEL_ACCOUNT | __GFP_ZERO);
	if (tmp) {
		/*
		 * If we went through a realocation, adjust the MMU
		 * back-pointers in the previously initialised
		 * pg_table structures.
		 */
		if (kvm->arch.nested_mmus != tmp) {
			int i;

			for (i = 0; i < num_mmus - 2; i++)
				tmp[i].pgt->mmu = &tmp[i];
		}

		if (kvm_init_stage2_mmu(kvm, &tmp[num_mmus - 1], 0) ||
		    kvm_init_stage2_mmu(kvm, &tmp[num_mmus - 2], 0)) {
			kvm_free_stage2_pgd(&tmp[num_mmus - 1]);
			kvm_free_stage2_pgd(&tmp[num_mmus - 2]);
		} else {
			kvm->arch.nested_mmus_size = num_mmus;
			ret = 0;
		}

		kvm->arch.nested_mmus = tmp;
	}

	mutex_unlock(&kvm->arch.config_lock);
	return ret;
}

struct s2_walk_info {
	int	     (*read_desc)(phys_addr_t pa, u64 *desc, void *data);
	void	     *data;
	u64	     baddr;
	unsigned int max_pa_bits;
	unsigned int max_ipa_bits;
	unsigned int pgshift;
	unsigned int pgsize;
	unsigned int ps;
	unsigned int sl;
	unsigned int t0sz;
	bool	     be;
};

static unsigned int ps_to_output_size(unsigned int ps)
{
	switch (ps) {
	case 0: return 32;
	case 1: return 36;
	case 2: return 40;
	case 3: return 42;
	case 4: return 44;
	case 5:
	default:
		return 48;
	}
}

static u32 compute_fsc(int level, u32 fsc)
{
	return fsc | (level & 0x3);
}

static int esr_s2_fault(struct kvm_vcpu *vcpu, int level, u32 fsc)
{
	u32 esr;

	esr = kvm_vcpu_get_esr(vcpu) & ~ESR_ELx_FSC;
	esr |= compute_fsc(level, fsc);
	return esr;
}

static int check_base_s2_limits(struct s2_walk_info *wi,
				int level, int input_size, int stride)
{
	int start_size;

	/* Check translation limits */
	switch (wi->pgsize) {
	case SZ_64K:
		if (level == 0 || (level == 1 && wi->max_ipa_bits <= 42))
			return -EFAULT;
		break;
	case SZ_16K:
		if (level == 0 || (level == 1 && wi->max_ipa_bits <= 40))
			return -EFAULT;
		break;
	case SZ_4K:
		if (level < 0 || (level == 0 && wi->max_ipa_bits <= 42))
			return -EFAULT;
		break;
	}

	/* Check input size limits */
	if (input_size > wi->max_ipa_bits)
		return -EFAULT;

	/* Check number of entries in starting level table */
	start_size = input_size - ((3 - level) * stride + wi->pgshift);
	if (start_size < 1 || start_size > stride + 4)
		return -EFAULT;

	return 0;
}

/* Check if output is within boundaries */
static int check_output_size(struct s2_walk_info *wi, phys_addr_t output)
{
	unsigned int output_size = ps_to_output_size(wi->ps);

	if (output_size > wi->max_pa_bits)
		output_size = wi->max_pa_bits;

	if (output_size != 48 && (output & GENMASK_ULL(47, output_size)))
		return -1;

	return 0;
}

/*
 * This is essentially a C-version of the pseudo code from the ARM ARM
 * AArch64.TranslationTableWalk  function.  I strongly recommend looking at
 * that pseudocode in trying to understand this.
 *
 * Must be called with the kvm->srcu read lock held
 */
static int walk_nested_s2_pgd(phys_addr_t ipa,
			      struct s2_walk_info *wi, struct kvm_s2_trans *out)
{
	int first_block_level, level, stride, input_size, base_lower_bound;
	phys_addr_t base_addr;
	unsigned int addr_top, addr_bottom;
	u64 desc;  /* page table entry */
	int ret;
	phys_addr_t paddr;

	switch (wi->pgsize) {
	case SZ_64K:
	case SZ_16K:
		level = 3 - wi->sl;
		first_block_level = 2;
		break;
	case SZ_4K:
		level = 2 - wi->sl;
		first_block_level = 1;
		break;
	default:
		/* GCC is braindead */
		unreachable();
	}

	stride = wi->pgshift - 3;
	input_size = 64 - wi->t0sz;
	if (input_size > 48 || input_size < 25)
		return -EFAULT;

	ret = check_base_s2_limits(wi, level, input_size, stride);
	if (WARN_ON(ret))
		return ret;

	base_lower_bound = 3 + input_size - ((3 - level) * stride +
			   wi->pgshift);
	base_addr = wi->baddr & GENMASK_ULL(47, base_lower_bound);

	if (check_output_size(wi, base_addr)) {
		out->esr = compute_fsc(level, ESR_ELx_FSC_ADDRSZ);
		return 1;
	}

	addr_top = input_size - 1;

	while (1) {
		phys_addr_t index;

		addr_bottom = (3 - level) * stride + wi->pgshift;
		index = (ipa & GENMASK_ULL(addr_top, addr_bottom))
			>> (addr_bottom - 3);

		paddr = base_addr | index;
		ret = wi->read_desc(paddr, &desc, wi->data);
		if (ret < 0)
			return ret;

		/*
		 * Handle reversedescriptors if endianness differs between the
		 * host and the guest hypervisor.
		 */
		if (wi->be)
			desc = be64_to_cpu(desc);
		else
			desc = le64_to_cpu(desc);

		/* Check for valid descriptor at this point */
		if (!(desc & 1) || ((desc & 3) == 1 && level == 3)) {
			out->esr = compute_fsc(level, ESR_ELx_FSC_FAULT);
			out->upper_attr = desc;
			return 1;
		}

		/* We're at the final level or block translation level */
		if ((desc & 3) == 1 || level == 3)
			break;

		if (check_output_size(wi, desc)) {
			out->esr = compute_fsc(level, ESR_ELx_FSC_ADDRSZ);
			out->upper_attr = desc;
			return 1;
		}

		base_addr = desc & GENMASK_ULL(47, wi->pgshift);

		level += 1;
		addr_top = addr_bottom - 1;
	}

	if (level < first_block_level) {
		out->esr = compute_fsc(level, ESR_ELx_FSC_FAULT);
		out->upper_attr = desc;
		return 1;
	}

	/*
	 * We don't use the contiguous bit in the stage-2 ptes, so skip check
	 * for misprogramming of the contiguous bit.
	 */

	if (check_output_size(wi, desc)) {
		out->esr = compute_fsc(level, ESR_ELx_FSC_ADDRSZ);
		out->upper_attr = desc;
		return 1;
	}

	if (!(desc & BIT(10))) {
		out->esr = compute_fsc(level, ESR_ELx_FSC_ACCESS);
		out->upper_attr = desc;
		return 1;
	}

	/* Calculate and return the result */
	paddr = (desc & GENMASK_ULL(47, addr_bottom)) |
		(ipa & GENMASK_ULL(addr_bottom - 1, 0));
	out->output = paddr;
	out->block_size = 1UL << ((3 - level) * stride + wi->pgshift);
	out->readable = desc & (0b01 << 6);
	out->writable = desc & (0b10 << 6);
	out->level = level;
	out->upper_attr = desc & GENMASK_ULL(63, 52);
	return 0;
}

static int read_guest_s2_desc(phys_addr_t pa, u64 *desc, void *data)
{
	struct kvm_vcpu *vcpu = data;

	return kvm_read_guest(vcpu->kvm, pa, desc, sizeof(*desc));
}

static void vtcr_to_walk_info(u64 vtcr, struct s2_walk_info *wi)
{
	wi->t0sz = vtcr & TCR_EL2_T0SZ_MASK;

	switch (vtcr & VTCR_EL2_TG0_MASK) {
	case VTCR_EL2_TG0_4K:
		wi->pgshift = 12;	 break;
	case VTCR_EL2_TG0_16K:
		wi->pgshift = 14;	 break;
	case VTCR_EL2_TG0_64K:
	default:
		wi->pgshift = 16;	 break;
	}

	wi->pgsize = BIT(wi->pgshift);
	wi->ps = FIELD_GET(VTCR_EL2_PS_MASK, vtcr);
	wi->sl = FIELD_GET(VTCR_EL2_SL0_MASK, vtcr);
	wi->max_ipa_bits = VTCR_EL2_IPA(vtcr);
	/* Global limit for now, should eventually be per-VM */
	wi->max_pa_bits = get_kvm_ipa_limit();
}

int kvm_walk_nested_s2(struct kvm_vcpu *vcpu, phys_addr_t gipa,
		       struct kvm_s2_trans *result)
{
	u64 vtcr = vcpu_read_sys_reg(vcpu, VTCR_EL2);
	struct s2_walk_info wi;
	int ret;

	result->esr = 0;

	if (!vcpu_has_nv(vcpu))
		return 0;

	wi.read_desc = read_guest_s2_desc;
	wi.data = vcpu;
	wi.baddr = vcpu_read_sys_reg(vcpu, VTTBR_EL2);

	vtcr_to_walk_info(vtcr, &wi);

	wi.be = vcpu_read_sys_reg(vcpu, SCTLR_EL2) & SCTLR_EE;

	ret = walk_nested_s2_pgd(gipa, &wi, result);
	if (ret)
		result->esr |= (kvm_vcpu_get_esr(vcpu) & ~ESR_ELx_FSC);

	return ret;
}

/*
 * We can have multiple *different* MMU contexts with the same VMID:
 *
 * - S2 being enabled or not, hence differing by the HCR_EL2.VM bit
 *
 * - Multiple vcpus using private S2s (huh huh...), hence differing by the
 *   VBBTR_EL2.BADDR address
 *
 * - A combination of the above...
 *
 * We can always identify which MMU context to pick at run-time.  However,
 * TLB invalidation involving a VMID must take action on all the TLBs using
 * this particular VMID. This translates into applying the same invalidation
 * operation to all the contexts that are using this VMID. Moar phun!
 */
void kvm_s2_mmu_iterate_by_vmid(struct kvm *kvm, u16 vmid,
				const union tlbi_info *info,
				void (*tlbi_callback)(struct kvm_s2_mmu *,
						      const union tlbi_info *))
{
	write_lock(&kvm->mmu_lock);

	for (int i = 0; i < kvm->arch.nested_mmus_size; i++) {
		struct kvm_s2_mmu *mmu = &kvm->arch.nested_mmus[i];

		if (!kvm_s2_mmu_valid(mmu))
			continue;

		if (vmid == get_vmid(mmu->tlb_vttbr))
			tlbi_callback(mmu, info);
	}

	write_unlock(&kvm->mmu_lock);
}

/* Must be called with kvm->mmu_lock held */
struct kvm_s2_mmu *lookup_s2_mmu(struct kvm_vcpu *vcpu)
{
	bool nested_stage2_enabled;
	u64 vttbr, vtcr, hcr;
	struct kvm *kvm;
	int i;

	kvm = vcpu->kvm;

	vttbr = vcpu_read_sys_reg(vcpu, VTTBR_EL2);
	vtcr = vcpu_read_sys_reg(vcpu, VTCR_EL2);
	hcr = vcpu_read_sys_reg(vcpu, HCR_EL2);

	nested_stage2_enabled = hcr & HCR_VM;

	/* Don't consider the CnP bit for the vttbr match */
	vttbr = vttbr & ~VTTBR_CNP_BIT;

	/*
	 * Two possibilities when looking up a S2 MMU context:
	 *
	 * - either S2 is enabled in the guest, and we need a context that is
         *   S2-enabled and matches the full VTTBR (VMID+BADDR) and VTCR,
         *   which makes it safe from a TLB conflict perspective (a broken
         *   guest won't be able to generate them),
	 *
	 * - or S2 is disabled, and we need a context that is S2-disabled
         *   and matches the VMID only, as all TLBs are tagged by VMID even
         *   if S2 translation is disabled.
	 */
	for (i = 0; i < kvm->arch.nested_mmus_size; i++) {
		struct kvm_s2_mmu *mmu = &kvm->arch.nested_mmus[i];

		if (!kvm_s2_mmu_valid(mmu))
			continue;

		if (nested_stage2_enabled &&
		    mmu->nested_stage2_enabled &&
		    vttbr == mmu->tlb_vttbr &&
		    vtcr == mmu->tlb_vtcr)
			return mmu;

		if (!nested_stage2_enabled &&
		    !mmu->nested_stage2_enabled &&
		    get_vmid(vttbr) == get_vmid(mmu->tlb_vttbr))
			return mmu;
	}
	return NULL;
}

/* Must be called with kvm->mmu_lock held */
static struct kvm_s2_mmu *get_s2_mmu_nested(struct kvm_vcpu *vcpu)
{
	struct kvm *kvm = vcpu->kvm;
	struct kvm_s2_mmu *s2_mmu;
	int i;

	s2_mmu = lookup_s2_mmu(vcpu);
	if (s2_mmu)
		goto out;

	/*
	 * Make sure we don't always search from the same point, or we
	 * will always reuse a potentially active context, leaving
	 * free contexts unused.
	 */
	for (i = kvm->arch.nested_mmus_next;
	     i < (kvm->arch.nested_mmus_size + kvm->arch.nested_mmus_next);
	     i++) {
		s2_mmu = &kvm->arch.nested_mmus[i % kvm->arch.nested_mmus_size];

		if (atomic_read(&s2_mmu->refcnt) == 0)
			break;
	}
	BUG_ON(atomic_read(&s2_mmu->refcnt)); /* We have struct MMUs to spare */

	/* Set the scene for the next search */
	kvm->arch.nested_mmus_next = (i + 1) % kvm->arch.nested_mmus_size;

	if (kvm_s2_mmu_valid(s2_mmu)) {
		/* Clear the old state */
		kvm_unmap_stage2_range(s2_mmu, 0, kvm_phys_size(s2_mmu));
		if (atomic64_read(&s2_mmu->vmid.id))
			kvm_call_hyp(__kvm_tlb_flush_vmid, s2_mmu);
	}

	/*
	 * The virtual VMID (modulo CnP) will be used as a key when matching
	 * an existing kvm_s2_mmu.
	 *
	 * We cache VTCR at allocation time, once and for all. It'd be great
	 * if the guest didn't screw that one up, as this is not very
	 * forgiving...
	 */
	s2_mmu->tlb_vttbr = vcpu_read_sys_reg(vcpu, VTTBR_EL2) & ~VTTBR_CNP_BIT;
	s2_mmu->tlb_vtcr = vcpu_read_sys_reg(vcpu, VTCR_EL2);
	s2_mmu->nested_stage2_enabled = vcpu_read_sys_reg(vcpu, HCR_EL2) & HCR_VM;

out:
	atomic_inc(&s2_mmu->refcnt);
	return s2_mmu;
}

void kvm_init_nested_s2_mmu(struct kvm_s2_mmu *mmu)
{
	mmu->tlb_vttbr = 1;
	mmu->nested_stage2_enabled = false;
	atomic_set(&mmu->refcnt, 0);
}

void kvm_vcpu_load_hw_mmu(struct kvm_vcpu *vcpu)
{
	if (is_hyp_ctxt(vcpu)) {
		vcpu->arch.hw_mmu = &vcpu->kvm->arch.mmu;
	} else {
		write_lock(&vcpu->kvm->mmu_lock);
		vcpu->arch.hw_mmu = get_s2_mmu_nested(vcpu);
		write_unlock(&vcpu->kvm->mmu_lock);
	}
}

void kvm_vcpu_put_hw_mmu(struct kvm_vcpu *vcpu)
{
	if (vcpu->arch.hw_mmu != &vcpu->kvm->arch.mmu) {
		atomic_dec(&vcpu->arch.hw_mmu->refcnt);
		vcpu->arch.hw_mmu = NULL;
	}
}

/*
 * Returns non-zero if permission fault is handled by injecting it to the next
 * level hypervisor.
 */
int kvm_s2_handle_perm_fault(struct kvm_vcpu *vcpu, struct kvm_s2_trans *trans)
{
	unsigned long fault_status = kvm_vcpu_trap_get_fault_type(vcpu);
	bool forward_fault = false;

	trans->esr = 0;

	if (fault_status != ESR_ELx_FSC_PERM)
		return 0;

	if (kvm_vcpu_trap_is_iabt(vcpu)) {
		forward_fault = !kvm_s2_trans_executable(trans);
	} else {
		bool write_fault = kvm_is_write_fault(vcpu);

		forward_fault = ((write_fault && !trans->writable) ||
				 (!write_fault && !trans->readable));
	}

	if (forward_fault) {
		trans->esr = esr_s2_fault(vcpu, trans->level, ESR_ELx_FSC_PERM);
		return 1;
	}

	return 0;
}

int kvm_inject_s2_fault(struct kvm_vcpu *vcpu, u64 esr_el2)
{
	vcpu_write_sys_reg(vcpu, vcpu->arch.fault.far_el2, FAR_EL2);
	vcpu_write_sys_reg(vcpu, vcpu->arch.fault.hpfar_el2, HPFAR_EL2);

	return kvm_inject_nested_sync(vcpu, esr_el2);
}

/* expects kvm->mmu_lock to be held */
void kvm_nested_s2_wp(struct kvm *kvm)
{
	int i;

	for (i = 0; i < kvm->arch.nested_mmus_size; i++) {
		struct kvm_s2_mmu *mmu = &kvm->arch.nested_mmus[i];

		if (kvm_s2_mmu_valid(mmu))
			kvm_stage2_wp_range(mmu, 0, kvm_phys_size(mmu));
	}
}

/* expects kvm->mmu_lock to be held */
void kvm_nested_s2_unmap(struct kvm *kvm)
{
	int i;

	for (i = 0; i < kvm->arch.nested_mmus_size; i++) {
		struct kvm_s2_mmu *mmu = &kvm->arch.nested_mmus[i];

		if (kvm_s2_mmu_valid(mmu))
			kvm_unmap_stage2_range(mmu, 0, kvm_phys_size(mmu));
	}
}

/* expects kvm->mmu_lock to be held */
void kvm_nested_s2_flush(struct kvm *kvm)
{
	int i;

	for (i = 0; i < kvm->arch.nested_mmus_size; i++) {
		struct kvm_s2_mmu *mmu = &kvm->arch.nested_mmus[i];

		if (kvm_s2_mmu_valid(mmu))
			kvm_stage2_flush_range(mmu, 0, kvm_phys_size(mmu));
	}
}

void kvm_arch_flush_shadow_all(struct kvm *kvm)
{
	int i;

	for (i = 0; i < kvm->arch.nested_mmus_size; i++) {
		struct kvm_s2_mmu *mmu = &kvm->arch.nested_mmus[i];

		WARN_ON(atomic_read(&mmu->refcnt));

		if (!atomic_read(&mmu->refcnt))
			kvm_free_stage2_pgd(mmu);
	}
	kfree(kvm->arch.nested_mmus);
	kvm->arch.nested_mmus = NULL;
	kvm->arch.nested_mmus_size = 0;
	kvm_free_stage2_pgd(&kvm->arch.mmu);
}

bool vgic_state_is_nested(struct kvm_vcpu *vcpu)
{
	bool imo = __vcpu_sys_reg(vcpu, HCR_EL2) & HCR_IMO;
	bool fmo = __vcpu_sys_reg(vcpu, HCR_EL2) & HCR_FMO;

	WARN_ONCE(imo != fmo, "Separate virtual IRQ/FIQ settings not supported\n");

	return vcpu_has_nv(vcpu) && imo && fmo && !is_hyp_ctxt(vcpu);
}

void check_nested_vcpu_requests(struct kvm_vcpu *vcpu)
{
	if (kvm_check_request(KVM_REQ_GUEST_HYP_IRQ_PENDING, vcpu))
		kvm_inject_nested_irq(vcpu);
}

/*
 * Our emulated CPU doesn't support all the possible features. For the
 * sake of simplicity (and probably mental sanity), wipe out a number
 * of feature bits we don't intend to support for the time being.
 * This list should get updated as new features get added to the NV
 * support, and new extension to the architecture.
 */
void access_nested_id_reg(struct kvm_vcpu *v, struct sys_reg_params *p,
			  const struct sys_reg_desc *r)
{
	u32 id = reg_to_encoding(r);
	u64 val, tmp;

	val = p->regval;

	switch (id) {
	case SYS_ID_AA64ISAR0_EL1:
		/* Support everything but TME, O.S. and Range TLBIs */
		val &= ~(NV_FTR(ISAR0, TLB)		|
			 NV_FTR(ISAR0, TME));
		break;

	case SYS_ID_AA64ISAR1_EL1:
		/* Support everything but PtrAuth and Spec Invalidation */
		val &= ~(GENMASK_ULL(63, 56)	|
			 NV_FTR(ISAR1, SPECRES)	|
			 NV_FTR(ISAR1, GPI)	|
			 NV_FTR(ISAR1, GPA)	|
			 NV_FTR(ISAR1, API)	|
			 NV_FTR(ISAR1, APA));
		break;

	case SYS_ID_AA64PFR0_EL1:
		/* No AMU, MPAM, S-EL2, RAS or SVE */
		val &= ~(GENMASK_ULL(55, 52)	|
			 NV_FTR(PFR0, AMU)	|
			 NV_FTR(PFR0, MPAM)	|
			 NV_FTR(PFR0, SEL2)	|
			 NV_FTR(PFR0, RAS)	|
			 NV_FTR(PFR0, SVE)	|
			 NV_FTR(PFR0, EL3)	|
			 NV_FTR(PFR0, EL2)	|
			 NV_FTR(PFR0, EL1));
		/* 64bit EL1/EL2/EL3 only */
		val |= FIELD_PREP(NV_FTR(PFR0, EL1), 0b0001);
		val |= FIELD_PREP(NV_FTR(PFR0, EL2), 0b0001);
		val |= FIELD_PREP(NV_FTR(PFR0, EL3), 0b0001);
		break;

	case SYS_ID_AA64PFR1_EL1:
		/* Only support SSBS */
		val &= NV_FTR(PFR1, SSBS);
		break;

	case SYS_ID_AA64MMFR0_EL1:
		/* Hide ECV, FGT, ExS, Secure Memory */
		val &= ~(GENMASK_ULL(63, 43)		|
			 NV_FTR(MMFR0, TGRAN4_2)	|
			 NV_FTR(MMFR0, TGRAN16_2)	|
			 NV_FTR(MMFR0, TGRAN64_2)	|
			 NV_FTR(MMFR0, SNSMEM));

		/* Disallow unsupported S2 page sizes */
		switch (PAGE_SIZE) {
		case SZ_64K:
			val |= FIELD_PREP(NV_FTR(MMFR0, TGRAN16_2), 0b0001);
			fallthrough;
		case SZ_16K:
			val |= FIELD_PREP(NV_FTR(MMFR0, TGRAN4_2), 0b0001);
			fallthrough;
		case SZ_4K:
			/* Support everything */
			break;
		}
		/*
		 * Since we can't support a guest S2 page size smaller than
		 * the host's own page size (due to KVM only populating its
		 * own S2 using the kernel's page size), advertise the
		 * limitation using FEAT_GTG.
		 */
		switch (PAGE_SIZE) {
		case SZ_4K:
			val |= FIELD_PREP(NV_FTR(MMFR0, TGRAN4_2), 0b0010);
			fallthrough;
		case SZ_16K:
			val |= FIELD_PREP(NV_FTR(MMFR0, TGRAN16_2), 0b0010);
			fallthrough;
		case SZ_64K:
			val |= FIELD_PREP(NV_FTR(MMFR0, TGRAN64_2), 0b0010);
			break;
		}
		/* Cap PARange to 48bits */
		tmp = FIELD_GET(NV_FTR(MMFR0, PARANGE), val);
		if (tmp > 0b0101) {
			val &= ~NV_FTR(MMFR0, PARANGE);
			val |= FIELD_PREP(NV_FTR(MMFR0, PARANGE), 0b0101);
		}
		break;

	case SYS_ID_AA64MMFR1_EL1:
		val &= (NV_FTR(MMFR1, PAN)	|
			NV_FTR(MMFR1, LO)	|
			NV_FTR(MMFR1, HPDS)	|
			NV_FTR(MMFR1, VH)	|
			NV_FTR(MMFR1, VMIDBits));
		break;

	case SYS_ID_AA64MMFR2_EL1:
		val &= ~(NV_FTR(MMFR2, BBM)	|
			 NV_FTR(MMFR2, TTL)	|
			 GENMASK_ULL(47, 44)	|
			 NV_FTR(MMFR2, ST)	|
			 NV_FTR(MMFR2, CCIDX)	|
			 NV_FTR(MMFR2, VARange));

		/* Force TTL support */
		val |= FIELD_PREP(NV_FTR(MMFR2, TTL), 0b0001);
		break;

	case SYS_ID_AA64DFR0_EL1:
		/* Only limited support for PMU, Debug, BPs and WPs */
		val &= (NV_FTR(DFR0, PMUVer)	|
			NV_FTR(DFR0, WRPs)	|
			NV_FTR(DFR0, BRPs)	|
			NV_FTR(DFR0, DebugVer));

		/* Cap Debug to ARMv8.1 */
		tmp = FIELD_GET(NV_FTR(DFR0, DebugVer), val);
		if (tmp > 0b0111) {
			val &= ~NV_FTR(DFR0, DebugVer);
			val |= FIELD_PREP(NV_FTR(DFR0, DebugVer), 0b0111);
		}
		break;

	default:
		/* Unknown register, just wipe it clean */
		val = 0;
		break;
	}

	p->regval = val;
}
