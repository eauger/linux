// SPDX-License-Identifier: GPL-2.0
/*
 * vgic init sequence tests
 *
 * Copyright (C) 2020, Red Hat, Inc.
 */
#define _GNU_SOURCE
#include <linux/kernel.h>
#include <sys/syscall.h>
#include <asm/kvm.h>
#include <asm/kvm_para.h>

#include "test_util.h"
#include "kvm_util.h"
#include "processor.h"

#define NR_VCPUS		4

#define REDIST_REGION_ATTR_ADDR(count, base, flags, index) (((uint64_t)(count) << 52) | \
	((uint64_t)((base) >> 16) << 16) | ((uint64_t)(flags) << 12) | index)
#define REG_OFFSET(vcpu, offset) (((uint64_t)vcpu << 32) | offset)

#define GICR_TYPER 0x8

static int access_redist_reg(int gicv3_fd, int vcpu, int offset,
			     uint32_t *val, bool write)
{
	uint64_t attr = REG_OFFSET(vcpu, offset);

	return kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_REDIST_REGS,
				 attr, val, write);
}

static void guest_code(int cpu)
{
	GUEST_SYNC(0);
	GUEST_SYNC(1);
	GUEST_SYNC(2);
	GUEST_DONE();
}

static int run_vcpu(struct kvm_vm *vm, uint32_t vcpuid)
{
	static int run;
	struct ucall uc;
	int ret;

	vcpu_args_set(vm, vcpuid, 1, vcpuid);
	ret = _vcpu_ioctl(vm, vcpuid, KVM_RUN, NULL);
	get_ucall(vm, vcpuid, &uc);
	run++;

	if (ret)
		return -errno;
	return 0;
}

int dist_rdist_tests(struct kvm_vm *vm)
{
	int ret, gicv3_fd, max_ipa_bits;
	uint64_t addr;

	max_ipa_bits = kvm_check_cap(KVM_CAP_ARM_VM_IPA_SIZE);

	ret = kvm_create_device(vm, KVM_DEV_TYPE_ARM_VGIC_V3, true);
	if (ret) {
		print_skip("GICv3 not supported");
		exit(KSFT_SKIP);
	}

	ret = kvm_create_device(vm, 0, true);
	TEST_ASSERT(ret == -ENODEV, "unsupported device");

	/* Create the device */

	gicv3_fd = kvm_create_device(vm, KVM_DEV_TYPE_ARM_VGIC_V3, false);
	TEST_ASSERT(gicv3_fd > 0, "GICv3 device created");

	/* Check attributes */

	ret = kvm_device_check_attr(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				    KVM_VGIC_V3_ADDR_TYPE_DIST);
	TEST_ASSERT(!ret, "KVM_DEV_ARM_VGIC_GRP_ADDR/KVM_VGIC_V3_ADDR_TYPE_DIST supported");

	ret = kvm_device_check_attr(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				    KVM_VGIC_V3_ADDR_TYPE_REDIST);
	TEST_ASSERT(!ret, "KVM_DEV_ARM_VGIC_GRP_ADDR/KVM_VGIC_V3_ADDR_TYPE_REDIST supported");

	ret = kvm_device_check_attr(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR, 0);
	TEST_ASSERT(ret == -ENXIO, "attribute not supported");

	/* misaligned DIST and REDIST addresses */

	addr = 0x1000;
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_DIST, &addr, true);
	TEST_ASSERT(ret == -EINVAL, "GICv3 dist base not 64kB aligned");

	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST, &addr, true);
	TEST_ASSERT(ret == -EINVAL, "GICv3 redist base not 64kB aligned");

	/* out of range address */
	if (max_ipa_bits) {
		addr = 1ULL << max_ipa_bits;
		ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
					KVM_VGIC_V3_ADDR_TYPE_DIST, &addr, true);
		TEST_ASSERT(ret == -E2BIG, "dist address beyond IPA limit");

		ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
					KVM_VGIC_V3_ADDR_TYPE_REDIST, &addr, true);
		TEST_ASSERT(ret == -E2BIG, "redist address beyond IPA limit");
	}

	/* set REDIST base address */
	addr = 0x00000;
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST, &addr, true);
	TEST_ASSERT(!ret, "GICv3 redist base set");

	addr = 0xE0000;
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST, &addr, true);
	TEST_ASSERT(ret == -EEXIST, "GICv3 redist base set again");

	addr = REDIST_REGION_ATTR_ADDR(NR_VCPUS, 0x100000, 0, 0);
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &addr, true);
	TEST_ASSERT(ret == -EINVAL, "attempt to mix GICv3 REDIST and REDIST_REGION");

	/*
	 * Set overlapping DIST / REDIST, cannot be detected here. Will be detected
	 * on first vcpu run instead.
	 */
	addr = 3 * 2 * 0x10000;
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR, KVM_VGIC_V3_ADDR_TYPE_DIST,
				&addr, true);
	TEST_ASSERT(!ret, "dist overlapping rdist");

	ret = kvm_create_device(vm, KVM_DEV_TYPE_ARM_VGIC_V3, false);
	TEST_ASSERT(ret == -EEXIST, "create GICv3 device twice");

	ret = kvm_create_device(vm, KVM_DEV_TYPE_ARM_VGIC_V3, true);
	TEST_ASSERT(!ret, "create GICv3 in test mode while the same already is created");

	if (!kvm_create_device(vm, KVM_DEV_TYPE_ARM_VGIC_V2, true)) {
		ret = kvm_create_device(vm, KVM_DEV_TYPE_ARM_VGIC_V2, true);
		TEST_ASSERT(ret == -EINVAL, "create GICv2 while v3 exists");
	}

	return gicv3_fd;
}

static int redist_region_tests(struct kvm_vm *vm, int gicv3_fd)
{
	int ret, max_ipa_bits;
	uint64_t addr, expected_addr;

	max_ipa_bits = kvm_check_cap(KVM_CAP_ARM_VM_IPA_SIZE);

	ret = kvm_create_device(vm, KVM_DEV_TYPE_ARM_VGIC_V3, true);
	if (ret) {
		print_skip("GICv3 not supported");
		exit(KSFT_SKIP);
	}

	if (gicv3_fd < 0) {
		gicv3_fd = kvm_create_device(vm, KVM_DEV_TYPE_ARM_VGIC_V3, false);
		TEST_ASSERT(gicv3_fd >= 0, "VGIC_V3 device created");
	}

	ret = kvm_device_check_attr(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				    KVM_VGIC_V3_ADDR_TYPE_REDIST);
	TEST_ASSERT(!ret, "Multiple redist regions advertised");

	addr = REDIST_REGION_ATTR_ADDR(NR_VCPUS, 0x100000, 2, 0);
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &addr, true);
	TEST_ASSERT(ret == -EINVAL, "redist region attr value with flags != 0");

	addr = REDIST_REGION_ATTR_ADDR(0, 0x100000, 0, 0);
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &addr, true);
	TEST_ASSERT(ret == -EINVAL, "redist region attr value with count== 0");

	addr = REDIST_REGION_ATTR_ADDR(2, 0x200000, 0, 1);
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &addr, true);
	TEST_ASSERT(ret == -EINVAL, "attempt to register the first rdist region with index != 0");

	addr = REDIST_REGION_ATTR_ADDR(2, 0x201000, 0, 1);
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &addr, true);
	TEST_ASSERT(ret == -EINVAL, "rdist region with misaligned address");

	addr = REDIST_REGION_ATTR_ADDR(2, 0x200000, 0, 0);
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &addr, true);
	TEST_ASSERT(!ret, "First valid redist region with 2 rdist @ 0x200000, index 0");

	addr = REDIST_REGION_ATTR_ADDR(2, 0x200000, 0, 1);
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &addr, true);
	TEST_ASSERT(ret == -EINVAL, "register an rdist region with already used index");

	addr = REDIST_REGION_ATTR_ADDR(1, 0x210000, 0, 2);
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &addr, true);
	TEST_ASSERT(ret == -EINVAL, "register an rdist region overlapping with another one");

	addr = REDIST_REGION_ATTR_ADDR(1, 0x240000, 0, 2);
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &addr, true);
	TEST_ASSERT(ret == -EINVAL, "register redist region with index not +1");

	addr = REDIST_REGION_ATTR_ADDR(1, 0x240000, 0, 1);
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &addr, true);
	TEST_ASSERT(!ret, "register valid redist region with 1 rdist @ 0x220000, index 1");

	addr = REDIST_REGION_ATTR_ADDR(1, 1ULL << max_ipa_bits, 0, 2);
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &addr, true);
	TEST_ASSERT(ret == -E2BIG, "register redist region with base address beyond IPA range");

	addr = 0x260000;
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST, &addr, true);
	TEST_ASSERT(ret == -EINVAL, "Mix KVM_VGIC_V3_ADDR_TYPE_REDIST and REDIST_REGION");

	/*
	 * Now there are 2 redist regions:
	 * region 0 @ 0x200000 2 redists
	 * region 1 @ 0x240000 1 redist
	 * now attempt to read their characteristics
	 */

	addr = REDIST_REGION_ATTR_ADDR(0, 0, 0, 0);
	expected_addr = REDIST_REGION_ATTR_ADDR(2, 0x200000, 0, 0);
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &addr, false);
	TEST_ASSERT(!ret && addr == expected_addr, "read characteristics of region #0");

	addr = REDIST_REGION_ATTR_ADDR(0, 0, 0, 1);
	expected_addr = REDIST_REGION_ATTR_ADDR(1, 0x240000, 0, 1);
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &addr, false);
	TEST_ASSERT(!ret && addr == expected_addr, "read characteristics of region #1");

	addr = REDIST_REGION_ATTR_ADDR(0, 0, 0, 2);
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &addr, false);
	TEST_ASSERT(ret == -ENOENT, "read characteristics of non existing region");

	addr = 0x260000;
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_DIST, &addr, true);
	TEST_ASSERT(!ret, "set dist region");

	addr = REDIST_REGION_ATTR_ADDR(1, 0x260000, 0, 2);
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &addr, true);
	TEST_ASSERT(ret == -EINVAL, "register redist region colliding with dist");

	return gicv3_fd;
}

static void vgic_first(void)
{
	int ret, i, gicv3_fd;
	struct kvm_vm *vm;

	vm = vm_create_default(0, 0, guest_code);

	gicv3_fd = dist_rdist_tests(vm);

	/* Add the rest of the VCPUs */
	for (i = 1; i < NR_VCPUS; ++i)
		vm_vcpu_add_default(vm, i, guest_code);

	ret = run_vcpu(vm, 3);
	TEST_ASSERT(ret == -EINVAL, "dist/rdist overlap detected on 1st vcpu run");

	close(gicv3_fd);
	kvm_vm_free(vm);
}


static void vcpu_first(void)
{
	int ret, i, gicv3_fd;
	struct kvm_vm *vm;

	vm = vm_create_default(0, 0, guest_code);

	/* Add the rest of the VCPUs */
	for (i = 1; i < NR_VCPUS; ++i)
		vm_vcpu_add_default(vm, i, guest_code);

	gicv3_fd = dist_rdist_tests(vm);

	ret = run_vcpu(vm, 3);
	TEST_ASSERT(ret == -EINVAL, "dist/rdist overlap detected on 1st vcpu run");

	close(gicv3_fd);
	kvm_vm_free(vm);
}

static void redist_regions(void)
{
	int ret, i, gicv3_fd = -1;
	struct kvm_vm *vm;
	uint64_t addr;
	void *dummy = NULL;

	vm = vm_create_default(0, 0, guest_code);
	ucall_init(vm, NULL);

	/* Add the rest of the VCPUs */
	for (i = 1; i < NR_VCPUS; ++i)
		vm_vcpu_add_default(vm, i, guest_code);

	gicv3_fd = redist_region_tests(vm, gicv3_fd);

	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_CTRL,
				KVM_DEV_ARM_VGIC_CTRL_INIT, NULL, true);
	TEST_ASSERT(!ret, "init the vgic");

	ret = run_vcpu(vm, 3);
	TEST_ASSERT(ret == -ENXIO, "running without sufficient number of rdists");

	/*
	 * At this time the kvm_vgic_map_resources destroyed the vgic
	 * Redo everything
	 */
	gicv3_fd = redist_region_tests(vm, gicv3_fd);

	addr = REDIST_REGION_ATTR_ADDR(1, 0x280000, 0, 2);
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &addr, true);
	TEST_ASSERT(!ret, "register a third region allowing to cover the 4 vcpus");

	ret = run_vcpu(vm, 3);
	TEST_ASSERT(ret == -EBUSY, "running without vgic explicit init");

	/* again need to redo init and this time do the explicit init*/
	gicv3_fd = redist_region_tests(vm, gicv3_fd);

	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, dummy, true);
	TEST_ASSERT(ret == -EFAULT, "register a third region allowing to cover the 4 vcpus");

	addr = REDIST_REGION_ATTR_ADDR(1, 0x280000, 0, 2);
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &addr, true);
	TEST_ASSERT(!ret, "register a third region allowing to cover the 4 vcpus");

	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_CTRL,
				KVM_DEV_ARM_VGIC_CTRL_INIT, NULL, true);
	TEST_ASSERT(!ret, "init the vgic");

	ret = run_vcpu(vm, 3);
	TEST_ASSERT(!ret, "vcpu run");

	close(gicv3_fd);
	kvm_vm_free(vm);
}

static void typer_accesses(void)
{
	int ret, i, gicv3_fd = -1;
	uint64_t addr;
	struct kvm_vm *vm;
	uint32_t val;

	vm = vm_create_default(0, 0, guest_code);
	ucall_init(vm, NULL);

	gicv3_fd = kvm_create_device(vm, KVM_DEV_TYPE_ARM_VGIC_V3, false);
	TEST_ASSERT(gicv3_fd >= 0, "VGIC_V3 device created");

	vm_vcpu_add_default(vm, 3, guest_code);

	ret = access_redist_reg(gicv3_fd, 1, GICR_TYPER, &val, false);
	TEST_ASSERT(ret == -EINVAL, "attempting to read GICR_TYPER of non created vcpu");

	vm_vcpu_add_default(vm, 1, guest_code);

	ret = access_redist_reg(gicv3_fd, 1, GICR_TYPER, &val, false);
	TEST_ASSERT(ret == -EBUSY, "read GICR_TYPER before GIC initialized");

	vm_vcpu_add_default(vm, 2, guest_code);

	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_CTRL,
				KVM_DEV_ARM_VGIC_CTRL_INIT, NULL, true);
	TEST_ASSERT(!ret, "init the vgic after the vcpu creations");

	for (i = 0; i < NR_VCPUS ; i++) {
		ret = access_redist_reg(gicv3_fd, 0, GICR_TYPER, &val, false);
		TEST_ASSERT(!ret && !val, "read GICR_TYPER before rdist region setting");
	}

	addr = REDIST_REGION_ATTR_ADDR(2, 0x200000, 0, 0);
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &addr, true);
	TEST_ASSERT(!ret, "first rdist region with a capacity of 2 rdists");

	/* The 2 first rdists should be put there (vcpu 0 and 3) */
	ret = access_redist_reg(gicv3_fd, 0, GICR_TYPER, &val, false);
	TEST_ASSERT(!ret && !val, "read typer of rdist #0");

	ret = access_redist_reg(gicv3_fd, 3, GICR_TYPER, &val, false);
	TEST_ASSERT(!ret && val == 0x310, "read typer of rdist #1");

	addr = REDIST_REGION_ATTR_ADDR(10, 0x100000, 0, 1);
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &addr, true);
	TEST_ASSERT(ret == -EINVAL, "collision with previous rdist region");

	ret = access_redist_reg(gicv3_fd, 1, GICR_TYPER, &val, false);
	TEST_ASSERT(!ret && val == 0x100,
		    "no redist region attached to vcpu #1 yet, last cannot be returned");

	ret = access_redist_reg(gicv3_fd, 2, GICR_TYPER, &val, false);
	TEST_ASSERT(!ret && val == 0x200,
		    "no redist region attached to vcpu #2, last cannot be returned");

	addr = REDIST_REGION_ATTR_ADDR(10, 0x20000, 0, 1);
	ret = kvm_device_access(gicv3_fd, KVM_DEV_ARM_VGIC_GRP_ADDR,
				KVM_VGIC_V3_ADDR_TYPE_REDIST_REGION, &addr, true);
	TEST_ASSERT(!ret, "second rdist region");

	ret = access_redist_reg(gicv3_fd, 1, GICR_TYPER, &val, false);
	TEST_ASSERT(!ret && val == 0x100, "read typer of rdist #1");

	ret = access_redist_reg(gicv3_fd, 2, GICR_TYPER, &val, false);
	TEST_ASSERT(!ret && val == 0x210,
		    "read typer of rdist #1, last properly returned");

	close(gicv3_fd);
	kvm_vm_free(vm);
}

int main(int ac, char **av)
{
	vcpu_first();
	vgic_first();
	redist_regions();
	typer_accesses();

	return 0;
}

