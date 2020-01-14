// SPDX-License-Identifier: GPL-2.0-only
/*
 * svm_test
 *
 * Copyright (C) 2020, Red Hat, Inc.
 *
 * Nested SVM testing
 *
 * The main executes several nested SVM tests
 */

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"
#include "svm.h"

#include <string.h>
#include <sys/ioctl.h>

#include "kselftest.h"
#include <linux/kernel.h>

#define VCPU_ID		5

/* The virtual machine object. */
static struct kvm_vm *vm;

static void l2_vmcall(struct svm_test_data *svm)
{
	__asm__ __volatile__("vmcall");
}

static void l2_vmrun(struct svm_test_data *svm)
{
	__asm__ __volatile__("vmrun");
}

static void l2_cr3_read(struct svm_test_data *svm)
{
	asm volatile ("mov %%cr3, %0" : "=r"(svm->test->scratch) : : "memory");
}
static void prepare_cr3_intercept(struct svm_test_data *svm)
{
	svm->vmcb->control.intercept_cr_read |= 1 << 3;
}

static struct test tests[] = {
	/* name, supported, custom setup, l2 code, exit code, custom check, finished */
	{"vmmcall", NULL, NULL, l2_vmcall, SVM_EXIT_VMMCALL},
	{"vmrun", NULL, NULL, l2_vmrun, SVM_EXIT_VMRUN},
	{"CR3 read intercept", NULL, prepare_cr3_intercept, l2_cr3_read, SVM_EXIT_READ_CR3},
};

static void l1_guest_code(struct svm_test_data *svm)
{
	#define L2_GUEST_STACK_SIZE 64
	unsigned long l2_guest_stack[L2_GUEST_STACK_SIZE];
	struct vmcb *vmcb = svm->vmcb;

	/* Prepare for L2 execution. */
	generic_svm_setup(svm, svm->test->l2_guest_code,
			  &l2_guest_stack[L2_GUEST_STACK_SIZE]);
	if (svm->test->l1_custom_setup)
		svm->test->l1_custom_setup(svm);

	run_guest(vmcb, svm->vmcb_gpa);
	do {
		run_guest(vmcb, svm->vmcb_gpa);
		if (!svm->test->finished)
			break;
	} while (!svm->test->finished(svm));

	GUEST_ASSERT(vmcb->control.exit_code ==
			svm->test->expected_exit_code);
	GUEST_DONE();
}

int main(int argc, char *argv[])
{
	vm_vaddr_t svm_gva;
	int i;

	nested_svm_check_supported();


	for (i = 0; i < ARRAY_SIZE(tests); i++) {
		struct svm_test_data *svm;

		vm = vm_create_default(VCPU_ID, 0, (void *) l1_guest_code);
		vcpu_set_cpuid(vm, VCPU_ID, kvm_get_supported_cpuid());

		/* Allocate VMX pages and shared descriptors (svm_pages). */
		svm = vcpu_alloc_svm(vm, &svm_gva);
		svm->test = &tests[i];
		vcpu_args_set(vm, VCPU_ID, 1, svm_gva);

		printf("Execute test %s\n", svm->test->name);

		for (;;) {
			volatile struct kvm_run *run = vcpu_state(vm, VCPU_ID);
			struct ucall uc;

			vcpu_run(vm, VCPU_ID);
			TEST_ASSERT(run->exit_reason == KVM_EXIT_IO,
				    "Got exit_reason other than KVM_EXIT_IO: %u (%s)\n",
				    run->exit_reason,
				    exit_reason_str(run->exit_reason));

			switch (get_ucall(vm, VCPU_ID, &uc)) {
			case UCALL_ABORT:
				TEST_ASSERT(false, "%s",
					    (const char *)uc.args[0]);
				/* NOT REACHED */
			case UCALL_SYNC:
				break;
			case UCALL_DONE:
				goto done;
			default:
				TEST_ASSERT(false,
					    "Unknown ucall 0x%x.", uc.cmd);
			}
		}
done:
		kvm_vm_free(vm);
	}
	return 0;
}
