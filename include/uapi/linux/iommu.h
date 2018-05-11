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
 * SMMUv3 Stream Table Entry stage 1 related information
 * @abort: shall the STE lead to abort
 * @s1fmt: STE s1fmt field as set by the guest
 * @s1dss: STE s1dss as set by the guest
 * All field names match the smmu 3.0/3.1 spec (ARM IHI 0070A)
 */
struct iommu_pasid_smmuv3 {
	__u8 abort;
	__u8 s1fmt;
	__u8 s1dss;
};

/**
 * PASID table data used to bind guest PASID table to the host IOMMU
 * Note PASID table corresponds to the Context Table on ARM SMMUv3.
 *
 * @version: API version to prepare for future extensions
 * @format: format of the PASID table
 *
 */
struct iommu_pasid_table_config {
#define PASID_TABLE_CFG_VERSION_1 1
	__u32	version;
#define IOMMU_PASID_FORMAT_SMMUV3	(1 << 0)
	__u32	format;
	__u64	base_ptr;
	__u8	pasid_bits;
	__u8	bypass;
	union {
		struct iommu_pasid_smmuv3 smmuv3;
	};
};

#endif /* _UAPI_IOMMU_H */
