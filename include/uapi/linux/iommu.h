/* SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note */
/*
 * IOMMU user API definitions
 */

#ifndef _UAPI_IOMMU_H
#define _UAPI_IOMMU_H

#include <linux/types.h>

/*  Generic fault types, can be expanded IRQ remapping fault */
enum iommu_fault_type {
	IOMMU_FAULT_DMA_UNRECOV = 1,	/* unrecoverable fault */
	IOMMU_FAULT_PAGE_REQ,		/* page request fault */
};

enum iommu_fault_reason {
	IOMMU_FAULT_REASON_UNKNOWN = 0,

	/* Could not access the PASID table (fetch caused external abort) */
	IOMMU_FAULT_REASON_PASID_FETCH,

	/* pasid entry is invalid or has configuration errors */
	IOMMU_FAULT_REASON_BAD_PASID_ENTRY,

	/*
	 * PASID is out of range (e.g. exceeds the maximum PASID
	 * supported by the IOMMU) or disabled.
	 */
	IOMMU_FAULT_REASON_PASID_INVALID,

	/*
	 * An external abort occurred fetching (or updating) a translation
	 * table descriptor
	 */
	IOMMU_FAULT_REASON_WALK_EABT,

	/*
	 * Could not access the page table entry (Bad address),
	 * actual translation fault
	 */
	IOMMU_FAULT_REASON_PTE_FETCH,

	/* Protection flag check failed */
	IOMMU_FAULT_REASON_PERMISSION,

	/* access flag check failed */
	IOMMU_FAULT_REASON_ACCESS,

	/* Output address of a translation stage caused Address Size fault */
	IOMMU_FAULT_REASON_OOR_ADDRESS,
};

/**
 * Unrecoverable fault data
 * @reason: reason of the fault
 * @addr: offending page address
 * @fetch_addr: address that caused a fetch abort, if any
 * @pasid: contains process address space ID, used in shared virtual memory
 * @perm: Requested permission access using by the incoming transaction
 *	IOMMU_FAULT_READ, IOMMU_FAULT_WRITE
 */
struct iommu_fault_unrecoverable {
	__u32	reason; /* enum iommu_fault_reason */
#define IOMMU_FAULT_UNRECOV_PASID_VALID		(1 << 0)
#define IOMMU_FAULT_UNRECOV_PERM_VALID		(1 << 1)
#define IOMMU_FAULT_UNRECOV_ADDR_VALID		(1 << 2)
#define IOMMU_FAULT_UNRECOV_FETCH_ADDR_VALID	(1 << 3)
	__u32	flags;
	__u32	pasid;
#define IOMMU_FAULT_PERM_WRITE	(1 << 0) /* write */
#define IOMMU_FAULT_PERM_EXEC	(1 << 1) /* exec */
#define IOMMU_FAULT_PERM_PRIV	(1 << 2) /* priviledged */
#define IOMMU_FAULT_PERM_INST	(1 << 3) /* instruction */
	__u32	perm;
	__u64	addr;
	__u64	fetch_addr;
};

/*
 * Page Request data (aka. recoverable fault data)
 * @flags : encodes whether the pasid is valid and whether this
 * is the last page in group
 * @pasid: pasid
 * @grpid: page request group index
 * @perm: requested page permissions
 * @addr: page address
 */
struct iommu_fault_page_request {
#define IOMMU_FAULT_PAGE_REQUEST_PASID_PRESENT	(1 << 0)
#define IOMMU_FAULT_PAGE_REQUEST_LAST_PAGE	(1 << 1)
#define IOMMU_FAULT_PAGE_REQUEST_PRIV_DATA	(1 << 2)
	__u32   flags;
	__u32	pasid;
	__u32	grpid;
	__u32	perm;
	__u64	addr;
	__u64	private_data[2];
};

/**
 * struct iommu_fault - Generic fault data
 *
 * @type contains fault type
 */

struct iommu_fault {
	__u32	type;   /* enum iommu_fault_type */
	__u32	reserved;
	union {
		struct iommu_fault_unrecoverable event;
		struct iommu_fault_page_request prm;
	};
};
#endif /* _UAPI_IOMMU_H */
