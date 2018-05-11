/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * IOMMU user API definitions
 *
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 */

#ifndef _UAPI_IOMMU_H
#define _UAPI_IOMMU_H

#include <linux/types.h>

/**
 * PASID table data used to bind guest PASID table to the host IOMMU. This will
 * enable guest managed first level page tables.
 * @version: for future extensions and identification of the data format
 * @bytes: size of this structure
 * @base_ptr:	PASID table pointer
 * @pasid_bits:	number of bits supported in the guest PASID table, must be less
 *		or equal than the host supported PASID size.
 */
struct iommu_pasid_table_config {
	__u32 version;
#define PASID_TABLE_CFG_VERSION_1 1
	__u32 bytes;
	__u64 base_ptr;
	__u8 pasid_bits;
};

/**
 * Stream Table Entry stage info
 * @flags: indicate the stage 1 state
 * @cdptr_dma: GPA of the Context Descriptor
 * @asid_bits: number of asid bits supported in the guest, must be less or
 *             equal than the host asid size
 */
struct iommu_smmu_s1_config {
#define IOMMU_SMMU_S1_DISABLED	(1 << 0)
#define IOMMU_SMMU_S1_BYPASSED	(1 << 1)
#define IOMMU_SMMU_S1_ABORTED	(1 << 2)
	__u32 flags;
	__u64 cdptr_dma;
	__u8 asid_bits;
};

struct iommu_guest_stage_config {
#define PASID_TABLE	(1 << 0)
#define SMMUV3_S1_CFG	(1 << 1)
	__u32 flags;
	union {
		struct iommu_pasid_table_config pasidt;
		struct iommu_smmu_s1_config smmu_s1;
	};
};

#endif /* _UAPI_IOMMU_H */
