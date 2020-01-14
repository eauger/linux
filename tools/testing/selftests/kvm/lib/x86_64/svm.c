// SPDX-License-Identifier: GPL-2.0-only
/*
 * tools/testing/selftests/kvm/lib/x86_64/svm.c
 * Helpers used for nested SVM testing
 * Largely inspired from KVM unit test svm.c
 *
 * Copyright (C) 2020, Red Hat, Inc.
 */

#include "test_util.h"
#include "kvm_util.h"
#include "../kvm_util_internal.h"
#include "processor.h"
#include "svm.h"

struct regs regs;

/* Allocate memory regions for nested SVM tests.
 *
 * Input Args:
 *   vm - The VM to allocate guest-virtual addresses in.
 *
 * Output Args:
 *   p_svm_gva - The guest virtual address for the struct svm_test_data.
 *
 * Return:
 *   Pointer to structure with the addresses of the SVM areas.
 */
struct svm_test_data *
vcpu_alloc_svm(struct kvm_vm *vm, vm_vaddr_t *p_svm_gva)
{
	vm_vaddr_t svm_gva = vm_vaddr_alloc(vm, getpagesize(),
					    0x10000, 0, 0);
	struct svm_test_data *svm = addr_gva2hva(vm, svm_gva);

	svm->vmcb = (void *)vm_vaddr_alloc(vm, getpagesize(),
					   0x10000, 0, 0);
	svm->vmcb_hva = addr_gva2hva(vm, (uintptr_t)svm->vmcb);
	svm->vmcb_gpa = addr_gva2gpa(vm, (uintptr_t)svm->vmcb);

	svm->save_area = (void *)vm_vaddr_alloc(vm, getpagesize(),
						0x10000, 0, 0);
	svm->save_area_hva = addr_gva2hva(vm, (uintptr_t)svm->save_area);
	svm->save_area_gpa = addr_gva2gpa(vm, (uintptr_t)svm->save_area);

	*p_svm_gva = svm_gva;
	return svm;
}

struct descriptor_table_ptr {
	u16 limit;
	ulong base;
} __attribute__((packed));

static inline void sgdt(struct descriptor_table_ptr *ptr)
{
	asm volatile ("sgdt %0" : "=m"(*ptr));
}

static inline void sidt(struct descriptor_table_ptr *ptr)
{
	asm volatile ("sidt %0" : "=m"(*ptr));
}

static void vmcb_set_seg(struct vmcb_seg *seg, u16 selector,
			 u64 base, u32 limit, u32 attr)
{
	seg->selector = selector;
	seg->attrib = attr;
	seg->limit = limit;
	seg->base = base;
}

static inline u16 read_cs(void)
{
	u16 val;

	asm volatile ("mov %%cs, %0" : "=mr"(val));
	return val;
}

static inline u16 read_ds(void)
{
	u16 val;

	asm volatile ("mov %%ds, %0" : "=mr"(val));
	return val;
}

static inline u16 read_es(void)
{
	u16 val;

	asm volatile ("mov %%es, %0" : "=mr"(val));
	return val;
}

static inline u16 read_ss(void)
{
	unsigned int val;

	asm volatile ("mov %%ss, %0" : "=mr"(val));
	return val;
}

void generic_svm_setup(struct svm_test_data *svm, void *guest_rip, void *guest_rsp)
{
	struct vmcb *vmcb = svm->vmcb;
	uint64_t vmcb_gpa = svm->vmcb_gpa;
	struct vmcb_save_area *save = &vmcb->save;
	struct vmcb_control_area *ctrl = &vmcb->control;
	u32 data_seg_attr = 3 | SVM_SELECTOR_S_MASK | SVM_SELECTOR_P_MASK
	      | SVM_SELECTOR_DB_MASK | SVM_SELECTOR_G_MASK;
	u32 code_seg_attr = 9 | SVM_SELECTOR_S_MASK | SVM_SELECTOR_P_MASK
		| SVM_SELECTOR_L_MASK | SVM_SELECTOR_G_MASK;
	struct descriptor_table_ptr desc_table_ptr;
	uint64_t efer;

	efer = rdmsr(MSR_EFER);
	wrmsr(MSR_EFER, efer | EFER_SVME);
	wrmsr(MSR_VM_HSAVE_PA, svm->save_area_gpa);

	memset(vmcb, 0, sizeof(*vmcb));
	asm volatile ("vmsave %0" : : "a" (vmcb_gpa) : "memory");
	vmcb_set_seg(&save->es, read_es(), 0, -1U, data_seg_attr);
	vmcb_set_seg(&save->cs, read_cs(), 0, -1U, code_seg_attr);
	vmcb_set_seg(&save->ss, read_ss(), 0, -1U, data_seg_attr);
	vmcb_set_seg(&save->ds, read_ds(), 0, -1U, data_seg_attr);
	sgdt(&desc_table_ptr);
	vmcb_set_seg(&save->gdtr, 0,
		     desc_table_ptr.base, desc_table_ptr.limit, 0);
	sidt(&desc_table_ptr);
	vmcb_set_seg(&save->idtr, 0,
		     desc_table_ptr.base, desc_table_ptr.limit, 0);

	ctrl->asid = 1;
	save->cpl = 0;
	save->efer = rdmsr(MSR_EFER);
	asm volatile ("mov %%cr4, %0" : "=r"(save->cr4) : : "memory");
	asm volatile ("mov %%cr3, %0" : "=r"(save->cr3) : : "memory");
	asm volatile ("mov %%cr0, %0" : "=r"(save->cr0) : : "memory");
	asm volatile ("mov %%dr7, %0" : "=r"(save->dr7));
	asm volatile ("mov %%dr6, %0" : "=r"(save->dr6));
	asm volatile ("mov %%cr2, %0" : "=r"(save->cr2) : : "memory");
	save->g_pat = rdmsr(MSR_IA32_CR_PAT);
	save->dbgctl = rdmsr(MSR_IA32_DEBUGCTLMSR);
	ctrl->intercept = (1ULL << INTERCEPT_VMRUN) |
				(1ULL << INTERCEPT_VMMCALL);

	vmcb->save.rip = (ulong)guest_rip;
	vmcb->save.rsp = (ulong)guest_rsp;
	regs.rdi = (ulong)svm;
}

#define SAVE_GPR_C                              \
	"xchg %%rbx, regs+0x8\n\t"              \
	"xchg %%rcx, regs+0x10\n\t"             \
	"xchg %%rdx, regs+0x18\n\t"             \
	"xchg %%rbp, regs+0x28\n\t"             \
	"xchg %%rsi, regs+0x30\n\t"             \
	"xchg %%rdi, regs+0x38\n\t"             \
	"xchg %%r8, regs+0x40\n\t"              \
	"xchg %%r9, regs+0x48\n\t"              \
	"xchg %%r10, regs+0x50\n\t"             \
	"xchg %%r11, regs+0x58\n\t"             \
	"xchg %%r12, regs+0x60\n\t"             \
	"xchg %%r13, regs+0x68\n\t"             \
	"xchg %%r14, regs+0x70\n\t"             \
	"xchg %%r15, regs+0x78\n\t"

#define LOAD_GPR_C      SAVE_GPR_C

/*
 * selftests do not use interrupts so we dropped clgi/sti/cli/stgi
 * for now
 */
void run_guest(struct vmcb *vmcb, uint64_t vmcb_gpa)
{
	asm volatile (
		"vmload\n\t"
		"vmload %[vmcb_gpa]\n\t"
		"mov regs+0x80, %%r15\n\t"  // rflags
		"mov %%r15, 0x170(%[vmcb])\n\t"
		"mov regs, %%r15\n\t"       // rax
		"mov %%r15, 0x1f8(%[vmcb])\n\t"
		LOAD_GPR_C
		"vmrun %[vmcb_gpa]\n\t"
		SAVE_GPR_C
		"mov 0x170(%[vmcb]), %%r15\n\t"  // rflags
		"mov %%r15, regs+0x80\n\t"
		"mov 0x1f8(%[vmcb]), %%r15\n\t"  // rax
		"mov %%r15, regs\n\t"
		"vmsave %[vmcb_gpa]\n\t"
		: : [vmcb] "r" (vmcb), [vmcb_gpa] "a" (vmcb_gpa)
		: "rbx", "rcx", "rdx", "rsi",
		  "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
		  "memory");

}

void nested_svm_check_supported(void)
{
	struct kvm_cpuid_entry2 *entry =
		kvm_get_supported_cpuid_entry(0x80000001);

	if (!(entry->ecx & CPUID_SVM)) {
		fprintf(stderr, "nested SVM not enabled, skipping test\n");
		exit(KSFT_SKIP);
	}
}

