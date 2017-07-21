/*
 * Virtio-iommu definition v0.4
 *
 * Copyright (C) 2017 ARM Ltd.
 *
 * This header is BSD licensed so anyone can use the definitions
 * to implement compatible drivers/servers:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of ARM Ltd. nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * ``AS IS'' AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
 * FOR A PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL IBM OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF
 * USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT
 * OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */
#ifndef _UAPI_LINUX_VIRTIO_IOMMU_H
#define _UAPI_LINUX_VIRTIO_IOMMU_H

/* Feature bits */
#define VIRTIO_IOMMU_F_INPUT_RANGE		0
#define VIRTIO_IOMMU_F_IOASID_BITS		1
#define VIRTIO_IOMMU_F_MAP_UNMAP		2
#define VIRTIO_IOMMU_F_BYPASS			3

struct virtio_iommu_config {
	/* Supported page sizes */
	__u64					page_size_mask;
	struct virtio_iommu_range {
		__u64				start;
		__u64				end;
	} input_range;
	__u8 					ioasid_bits;
} __packed;

/* Request types */
#define VIRTIO_IOMMU_T_ATTACH			0x01
#define VIRTIO_IOMMU_T_DETACH			0x02
#define VIRTIO_IOMMU_T_MAP			0x03
#define VIRTIO_IOMMU_T_UNMAP			0x04

/* Status types */
#define VIRTIO_IOMMU_S_OK			0x00
#define VIRTIO_IOMMU_S_IOERR			0x01
#define VIRTIO_IOMMU_S_UNSUPP			0x02
#define VIRTIO_IOMMU_S_DEVERR			0x03
#define VIRTIO_IOMMU_S_INVAL			0x04
#define VIRTIO_IOMMU_S_RANGE			0x05
#define VIRTIO_IOMMU_S_NOENT			0x06
#define VIRTIO_IOMMU_S_FAULT			0x07

struct virtio_iommu_req_head {
	__u8					type;
	__u8					reserved[3];
} __packed;

struct virtio_iommu_req_tail {
	__u8					status;
	__u8					reserved[3];
} __packed;

struct virtio_iommu_req_attach {
	struct virtio_iommu_req_head		head;

	__le32					address_space;
	__le32					device;
	__le32					reserved;

	struct virtio_iommu_req_tail		tail;
} __packed;

struct virtio_iommu_req_detach {
	struct virtio_iommu_req_head		head;

	__le32					device;
	__le32					reserved;

	struct virtio_iommu_req_tail		tail;
} __packed;

#define VIRTIO_IOMMU_MAP_F_READ			(1 << 0)
#define VIRTIO_IOMMU_MAP_F_WRITE		(1 << 1)
#define VIRTIO_IOMMU_MAP_F_EXEC			(1 << 2)

#define VIRTIO_IOMMU_MAP_F_MASK			(VIRTIO_IOMMU_MAP_F_READ |	\
						 VIRTIO_IOMMU_MAP_F_WRITE |	\
						 VIRTIO_IOMMU_MAP_F_EXEC)

struct virtio_iommu_req_map {
	struct virtio_iommu_req_head		head;

	__le32					address_space;
	__le64					virt_addr;
	__le64					phys_addr;
	__le64					size;
	__le32					flags;

	struct virtio_iommu_req_tail		tail;
} __packed;

__packed
struct virtio_iommu_req_unmap {
	struct virtio_iommu_req_head		head;

	__le32					address_space;
	__le64					virt_addr;
	__le64					size;
	__le32					reserved;

	struct virtio_iommu_req_tail		tail;
} __packed;

union virtio_iommu_req {
	struct virtio_iommu_req_head		head;

	struct virtio_iommu_req_attach		attach;
	struct virtio_iommu_req_detach		detach;
	struct virtio_iommu_req_map		map;
	struct virtio_iommu_req_unmap		unmap;
};

#endif
