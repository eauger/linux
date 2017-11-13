/*
 * Virtio driver for the paravirtualized IOMMU
 *
 * Copyright (C) 2017 ARM Limited
 * Author: Jean-Philippe Brucker <jean-philippe.brucker@arm.com>
 *
 * SPDX-License-Identifier: GPL-2.0
 */

#define pr_fmt(fmt) KBUILD_MODNAME ": " fmt

#include <linux/amba/bus.h>
#include <linux/delay.h>
#include <linux/dma-iommu.h>
#include <linux/freezer.h>
#include <linux/interval_tree.h>
#include <linux/iommu.h>
#include <linux/module.h>
#include <linux/of_iommu.h>
#include <linux/of_platform.h>
#include <linux/pci.h>
#include <linux/platform_device.h>
#include <linux/virtio.h>
#include <linux/virtio_config.h>
#include <linux/virtio_ids.h>
#include <linux/wait.h>

#include <uapi/linux/virtio_iommu.h>

#define MSI_IOVA_BASE			0x8000000
#define MSI_IOVA_LENGTH			0x100000

enum viommu_vq_idx {
	VIOMMU_REQUEST_VQ	= 0,
	VIOMMU_EVENT_VQ		= 1,
	VIOMMU_NUM_VQS		= 2,
};

struct viommu_dev {
	struct iommu_device		iommu;
	struct device			*dev;
	struct virtio_device		*vdev;

	struct ida			domain_ids;

	struct virtqueue		*vqs[VIOMMU_NUM_VQS];
	/* Serialize anything touching the request queue */
	spinlock_t			request_lock;

	/* Device configuration */
	struct iommu_domain_geometry	geometry;
	u64				pgsize_bitmap;
	u8				domain_bits;
	u32				probe_size;
};

struct viommu_mapping {
	phys_addr_t			paddr;
	struct interval_tree_node	iova;
	union {
		struct virtio_iommu_req_map map;
		struct virtio_iommu_req_unmap unmap;
	} req;
};

struct viommu_domain {
	struct iommu_domain		domain;
	struct viommu_dev		*viommu;
	struct mutex			mutex;
	unsigned int			id;

	spinlock_t			mappings_lock;
	struct rb_root_cached		mappings;

	/* Number of endpoints attached to this domain */
	refcount_t			endpoints;
};

struct viommu_endpoint {
	struct viommu_dev		*viommu;
	struct viommu_domain		*vdomain;
	struct list_head		resv_regions;
};

struct viommu_request {
	struct scatterlist		top;
	struct scatterlist		bottom;

	int				written;
	struct list_head		list;
};

#define VIOMMU_FAULT_RESV_MASK		0xffffff00

struct viommu_event {
	union {
		u32			head;
		struct virtio_iommu_fault fault;
	};
};

#define to_viommu_domain(domain) container_of(domain, struct viommu_domain, domain)

/* Virtio transport */

static int viommu_status_to_errno(u8 status)
{
	switch (status) {
	case VIRTIO_IOMMU_S_OK:
		return 0;
	case VIRTIO_IOMMU_S_UNSUPP:
		return -ENOSYS;
	case VIRTIO_IOMMU_S_INVAL:
		return -EINVAL;
	case VIRTIO_IOMMU_S_RANGE:
		return -ERANGE;
	case VIRTIO_IOMMU_S_NOENT:
		return -ENOENT;
	case VIRTIO_IOMMU_S_FAULT:
		return -EFAULT;
	case VIRTIO_IOMMU_S_IOERR:
	case VIRTIO_IOMMU_S_DEVERR:
	default:
		return -EIO;
	}
}

/*
 * viommu_get_req_size - compute request size
 *
 * A virtio-iommu request is split into one device-read-only part (top) and one
 * device-write-only part (bottom). Given a request, return the sizes of the two
 * parts in @top and @bottom.
 *
 * Return 0 on success, or an error when the request seems invalid.
 */
static int viommu_get_req_size(struct viommu_dev *viommu,
			       struct virtio_iommu_req_head *req, size_t *top,
			       size_t *bottom)
{
	size_t size;
	union virtio_iommu_req *r = (void *)req;

	*bottom = sizeof(struct virtio_iommu_req_tail);

	switch (req->type) {
	case VIRTIO_IOMMU_T_ATTACH:
		size = sizeof(r->attach);
		break;
	case VIRTIO_IOMMU_T_DETACH:
		size = sizeof(r->detach);
		break;
	case VIRTIO_IOMMU_T_MAP:
		size = sizeof(r->map);
		break;
	case VIRTIO_IOMMU_T_UNMAP:
		size = sizeof(r->unmap);
		break;
	case VIRTIO_IOMMU_T_PROBE:
		*bottom += viommu->probe_size;
		size = sizeof(r->probe) + *bottom;
		break;
	default:
		return -EINVAL;
	}

	*top = size - *bottom;
	return 0;
}

static int viommu_receive_resp(struct viommu_dev *viommu, int nr_sent,
			       struct list_head *sent)
{

	unsigned int len;
	int nr_received = 0;
	struct viommu_request *req, *pending;
	struct virtqueue *vq = viommu->vqs[VIOMMU_REQUEST_VQ];

	pending = list_first_entry_or_null(sent, struct viommu_request, list);
	if (WARN_ON(!pending))
		return 0;

	while ((req = virtqueue_get_buf(vq, &len)) != NULL) {
		if (req != pending) {
			dev_warn(viommu->dev, "discarding stale request\n");
			continue;
		}

		pending->written = len;

		if (++nr_received == nr_sent) {
			WARN_ON(!list_is_last(&pending->list, sent));
			break;
		} else if (WARN_ON(list_is_last(&pending->list, sent))) {
			break;
		}

		pending = list_next_entry(pending, list);
	}

	return nr_received;
}

/* Must be called with request_lock held */
static int _viommu_send_reqs_sync(struct viommu_dev *viommu,
				  struct viommu_request *req, int nr,
				  int *nr_sent)
{
	int i, ret;
	ktime_t timeout;
	LIST_HEAD(pending);
	int nr_received = 0;
	struct scatterlist *sg[2];
	/*
	 * Yes, 1s timeout. As a guest, we don't necessarily have a precise
	 * notion of time and this just prevents locking up a CPU if the device
	 * dies.
	 */
	unsigned long timeout_ms = 1000;
	struct virtqueue *vq = viommu->vqs[VIOMMU_REQUEST_VQ];

	*nr_sent = 0;

	for (i = 0; i < nr; i++, req++) {
		req->written = 0;

		sg[0] = &req->top;
		sg[1] = &req->bottom;

		ret = virtqueue_add_sgs(vq, sg, 1, 1, req, GFP_ATOMIC);
		if (ret)
			break;

		list_add_tail(&req->list, &pending);
	}

	if (i && !virtqueue_kick(vq))
		return -EPIPE;

	timeout = ktime_add_ms(ktime_get(), timeout_ms * i);
	while (nr_received < i && ktime_before(ktime_get(), timeout)) {
		nr_received += viommu_receive_resp(viommu, i - nr_received,
						   &pending);
		if (nr_received < i) {
			/*
			 * FIXME: what's a good way to yield to host? A second
			 * virtqueue_kick won't have any effect since we haven't
			 * added any descriptor.
			 */
			udelay(10);
		}
	}

	if (nr_received != i)
		ret = -ETIMEDOUT;

	if (ret == -ENOSPC && nr_received)
		/*
		 * We've freed some space since virtio told us that the ring is
		 * full, tell the caller to come back for more.
		 */
		ret = -EAGAIN;

	*nr_sent = nr_received;

	return ret;
}

/*
 * viommu_send_reqs_sync - add a batch of requests, kick the host and wait for
 *                         them to return
 *
 * @req: array of requests
 * @nr: array length
 * @nr_sent: on return, contains the number of requests actually sent
 *
 * Return 0 on success, or an error if we failed to send some of the requests.
 */
static int viommu_send_reqs_sync(struct viommu_dev *viommu,
				 struct viommu_request *req, int nr,
				 int *nr_sent)
{
	int ret;
	int sent = 0;
	unsigned long flags;

	*nr_sent = 0;
	do {
		spin_lock_irqsave(&viommu->request_lock, flags);
		ret = _viommu_send_reqs_sync(viommu, req, nr, &sent);
		spin_unlock_irqrestore(&viommu->request_lock, flags);

		*nr_sent += sent;
		req += sent;
		nr -= sent;
	} while (ret == -EAGAIN);

	return ret;
}

/*
 * viommu_send_req_sync - send one request and wait for reply
 *
 * @top: pointer to a virtio_iommu_req_* structure
 *
 * Returns 0 if the request was successful, or an error number otherwise. No
 * distinction is done between transport and request errors.
 */
static int viommu_send_req_sync(struct viommu_dev *viommu, void *top)
{
	int ret;
	int nr_sent;
	void *bottom;
	struct viommu_request req = {0};
	size_t top_size, bottom_size;
	struct virtio_iommu_req_tail *tail;
	struct virtio_iommu_req_head *head = top;

	ret = viommu_get_req_size(viommu, head, &top_size, &bottom_size);
	if (ret)
		return ret;

	bottom = top + top_size;
	tail = bottom + bottom_size - sizeof(*tail);

	sg_init_one(&req.top, top, top_size);
	sg_init_one(&req.bottom, bottom, bottom_size);

	ret = viommu_send_reqs_sync(viommu, &req, 1, &nr_sent);
	if (ret || !req.written || nr_sent != 1) {
		dev_err(viommu->dev, "failed to send request\n");
		return -EIO;
	}

	return viommu_status_to_errno(tail->status);
}

/*
 * viommu_add_mapping - add a mapping to the internal tree
 *
 * On success, return the new mapping. Otherwise return NULL.
 */
static struct viommu_mapping *
viommu_add_mapping(struct viommu_domain *vdomain, unsigned long iova,
		   phys_addr_t paddr, size_t size)
{
	unsigned long flags;
	struct viommu_mapping *mapping;

	mapping = kzalloc(sizeof(*mapping), GFP_ATOMIC);
	if (!mapping)
		return NULL;

	mapping->paddr		= paddr;
	mapping->iova.start	= iova;
	mapping->iova.last	= iova + size - 1;

	spin_lock_irqsave(&vdomain->mappings_lock, flags);
	interval_tree_insert(&mapping->iova, &vdomain->mappings);
	spin_unlock_irqrestore(&vdomain->mappings_lock, flags);

	return mapping;
}

/*
 * viommu_del_mappings - remove mappings from the internal tree
 *
 * @vdomain: the domain
 * @iova: start of the range
 * @size: size of the range. A size of 0 corresponds to the entire address
 *	space.
 * @out_mapping: if not NULL, the first removed mapping is returned in there.
 *	This allows the caller to reuse the buffer for the unmap request. Caller
 *	must always free the returned mapping, whether the function succeeds or
 *	not.
 *
 * On success, returns the number of unmapped bytes (>= size)
 */
static size_t viommu_del_mappings(struct viommu_domain *vdomain,
				 unsigned long iova, size_t size,
				 struct viommu_mapping **out_mapping)
{
	size_t unmapped = 0;
	unsigned long flags;
	unsigned long last = iova + size - 1;
	struct viommu_mapping *mapping = NULL;
	struct interval_tree_node *node, *next;

	spin_lock_irqsave(&vdomain->mappings_lock, flags);
	next = interval_tree_iter_first(&vdomain->mappings, iova, last);

	if (next) {
		mapping = container_of(next, struct viommu_mapping, iova);
		/* Trying to split a mapping? */
		if (WARN_ON(mapping->iova.start < iova))
			next = NULL;
	}

	while (next) {
		node = next;
		mapping = container_of(node, struct viommu_mapping, iova);

		next = interval_tree_iter_next(node, iova, last);

		/*
		 * Note that for a partial range, this will return the full
		 * mapping so we avoid sending split requests to the device.
		 */
		unmapped += mapping->iova.last - mapping->iova.start + 1;

		interval_tree_remove(node, &vdomain->mappings);

		if (out_mapping && !(*out_mapping))
			*out_mapping = mapping;
		else
			kfree(mapping);
	}
	spin_unlock_irqrestore(&vdomain->mappings_lock, flags);

	return unmapped;
}

/*
 * viommu_replay_mappings - re-send MAP requests
 *
 * When reattaching a domain that was previously detached from all devices,
 * mappings were deleted from the device. Re-create the mappings available in
 * the internal tree.
 *
 * Caller should hold the mapping lock if necessary.
 */
static int viommu_replay_mappings(struct viommu_domain *vdomain)
{
	int i = 1, ret, nr_sent;
	struct viommu_request *reqs;
	struct viommu_mapping *mapping;
	struct interval_tree_node *node;
	size_t top_size, bottom_size;

	node = interval_tree_iter_first(&vdomain->mappings, 0, -1UL);
	if (!node)
		return 0;

	while ((node = interval_tree_iter_next(node, 0, -1UL)) != NULL)
		i++;

	reqs = kcalloc(i, sizeof(*reqs), GFP_KERNEL);
	if (!reqs)
		return -ENOMEM;

	bottom_size = sizeof(struct virtio_iommu_req_tail);
	top_size = sizeof(struct virtio_iommu_req_map) - bottom_size;

	i = 0;
	node = interval_tree_iter_first(&vdomain->mappings, 0, -1UL);
	while (node) {
		mapping = container_of(node, struct viommu_mapping, iova);
		sg_init_one(&reqs[i].top, &mapping->req.map, top_size);
		sg_init_one(&reqs[i].bottom, &mapping->req.map.tail,
			    bottom_size);

		node = interval_tree_iter_next(node, 0, -1UL);
		i++;
	}

	ret = viommu_send_reqs_sync(vdomain->viommu, reqs, i, &nr_sent);
	kfree(reqs);

	return ret;
}

static int viommu_add_resv_mem(struct viommu_endpoint *vdev,
			       struct virtio_iommu_probe_resv_mem *mem,
			       size_t len)
{
	struct iommu_resv_region *region = NULL;
	unsigned long prot = IOMMU_WRITE | IOMMU_NOEXEC | IOMMU_MMIO;

	u64 addr = le64_to_cpu(mem->addr);
	u64 size = le64_to_cpu(mem->size);

	if (len < sizeof(*mem))
		return -EINVAL;

	switch (mem->subtype) {
	case VIRTIO_IOMMU_RESV_MEM_T_MSI:
		region = iommu_alloc_resv_region(addr, size, prot,
						 IOMMU_RESV_MSI);
		break;
	case VIRTIO_IOMMU_RESV_MEM_T_RESERVED:
	default:
		region = iommu_alloc_resv_region(addr, size, 0,
						 IOMMU_RESV_RESERVED);
		break;
	}

	list_add(&vdev->resv_regions, &region->list);

	if (mem->subtype != VIRTIO_IOMMU_RESV_MEM_T_RESERVED &&
	    mem->subtype != VIRTIO_IOMMU_RESV_MEM_T_MSI) {
		/* Please update your driver. */
		pr_warn("unknown resv mem subtype 0x%x\n", mem->subtype);
		return -EINVAL;
	}

	return 0;
}

static int viommu_probe_endpoint(struct viommu_dev *viommu, struct device *dev)
{
	int ret;
	u16 type, len;
	size_t cur = 0;
	struct virtio_iommu_req_probe *probe;
	struct virtio_iommu_probe_property *prop;
	struct iommu_fwspec *fwspec = dev->iommu_fwspec;
	struct viommu_endpoint *vdev = fwspec->iommu_priv;

	if (!fwspec->num_ids)
		/* Trouble ahead. */
		return -EINVAL;

	probe = kzalloc(sizeof(*probe) + viommu->probe_size +
			sizeof(struct virtio_iommu_req_tail), GFP_KERNEL);
	if (!probe)
		return -ENOMEM;

	probe->head.type = VIRTIO_IOMMU_T_PROBE;
	/*
	 * For now, assume that properties of an endpoint that outputs multiple
	 * IDs are consistent. Only probe the first one.
	 */
	probe->endpoint = cpu_to_le32(fwspec->ids[0]);

	ret = viommu_send_req_sync(viommu, probe);
	if (ret) {
		kfree(probe);
		return ret;
	}

	prop = (void *)probe->properties;
	type = le16_to_cpu(prop->type) & VIRTIO_IOMMU_PROBE_T_MASK;

	while (type != VIRTIO_IOMMU_PROBE_T_NONE &&
	       cur < viommu->probe_size) {
		len = le16_to_cpu(prop->length);

		switch (type) {
		case VIRTIO_IOMMU_PROBE_T_RESV_MEM:
			ret = viommu_add_resv_mem(vdev, (void *)prop->value, len);
			break;
		default:
			dev_dbg(dev, "unknown viommu prop 0x%x\n", type);
		}

		if (ret)
			dev_err(dev, "failed to parse viommu prop 0x%x\n", type);

		cur += sizeof(*prop) + len;
		if (cur >= viommu->probe_size)
			break;

		prop = (void *)probe->properties + cur;
		type = le16_to_cpu(prop->type) & VIRTIO_IOMMU_PROBE_T_MASK;
	}

	kfree(probe);

	return 0;
}

static int viommu_fault_handler(struct viommu_dev *viommu,
				struct virtio_iommu_fault *fault)
{
	char *reason_str;

	u8 reason	= fault->reason;
	u32 flags	= le32_to_cpu(fault->flags);
	u32 endpoint	= le32_to_cpu(fault->endpoint);
	u64 address	= le64_to_cpu(fault->address);

	switch (reason) {
	case VIRTIO_IOMMU_FAULT_R_DOMAIN:
		reason_str = "domain";
		break;
	case VIRTIO_IOMMU_FAULT_R_MAPPING:
		reason_str = "page";
		break;
	case VIRTIO_IOMMU_FAULT_R_UNKNOWN:
	default:
		reason_str = "unknown";
		break;
	}

	/* TODO: find EP by ID and report_iommu_fault */
	if (flags & VIRTIO_IOMMU_FAULT_F_ADDRESS)
		dev_err_ratelimited(viommu->dev, "%s fault from EP %u at %#llx [%s%s%s]\n",
				    reason_str, endpoint, address,
				    flags & VIRTIO_IOMMU_FAULT_F_READ ? "R" : "",
				    flags & VIRTIO_IOMMU_FAULT_F_WRITE ? "W" : "",
				    flags & VIRTIO_IOMMU_FAULT_F_EXEC ? "X" : "");
	else
		dev_err_ratelimited(viommu->dev, "%s fault from EP %u\n",
				    reason_str, endpoint);

	return 0;
}

static void viommu_event_handler(struct virtqueue *vq)
{
	int ret;
	unsigned int len;
	struct scatterlist sg[1];
	struct viommu_event *evt;
	struct viommu_dev *viommu = vq->vdev->priv;

	while ((evt = virtqueue_get_buf(vq, &len)) != NULL) {
		if (len > sizeof(*evt)) {
			dev_err(viommu->dev,
				"invalid event buffer (len %u != %zu)\n",
				len, sizeof(*evt));
		} else if (!(evt->head & VIOMMU_FAULT_RESV_MASK)) {
			viommu_fault_handler(viommu, &evt->fault);
		}

		sg_init_one(sg, evt, sizeof(*evt));
		ret = virtqueue_add_inbuf(vq, sg, 1, evt, GFP_ATOMIC);
		if (ret)
			dev_err(viommu->dev, "could not add event buffer\n");
	}

	if (!virtqueue_kick(vq))
		dev_err(viommu->dev, "kick failed\n");
}

/* IOMMU API */

static bool viommu_capable(enum iommu_cap cap)
{
	return false; /* :( */
}

static struct iommu_domain *viommu_domain_alloc(unsigned type)
{
	struct viommu_domain *vdomain;

	if (type != IOMMU_DOMAIN_UNMANAGED && type != IOMMU_DOMAIN_DMA)
		return NULL;

	vdomain = kzalloc(sizeof(*vdomain), GFP_KERNEL);
	if (!vdomain)
		return NULL;

	mutex_init(&vdomain->mutex);
	spin_lock_init(&vdomain->mappings_lock);
	vdomain->mappings = RB_ROOT_CACHED;
	refcount_set(&vdomain->endpoints, 0);

	if (type == IOMMU_DOMAIN_DMA &&
	    iommu_get_dma_cookie(&vdomain->domain)) {
		kfree(vdomain);
		return NULL;
	}

	return &vdomain->domain;
}

static int viommu_domain_finalise(struct viommu_dev *viommu,
				  struct iommu_domain *domain)
{
	int ret;
	struct viommu_domain *vdomain = to_viommu_domain(domain);
	/* ida limits size to 31 bits. A value of 0 means "max" */
	unsigned int max_domain = viommu->domain_bits >= 31 ? 0 :
				  1U << viommu->domain_bits;

	vdomain->viommu		= viommu;

	domain->pgsize_bitmap	= viommu->pgsize_bitmap;
	domain->geometry	= viommu->geometry;

	ret = ida_simple_get(&viommu->domain_ids, 0, max_domain, GFP_KERNEL);
	if (ret >= 0)
		vdomain->id = (unsigned int)ret;

	return ret > 0 ? 0 : ret;
}

static void viommu_domain_free(struct iommu_domain *domain)
{
	struct viommu_domain *vdomain = to_viommu_domain(domain);

	iommu_put_dma_cookie(domain);

	/* Free all remaining mappings (size 2^64) */
	viommu_del_mappings(vdomain, 0, 0, NULL);

	if (vdomain->viommu)
		ida_simple_remove(&vdomain->viommu->domain_ids, vdomain->id);

	kfree(vdomain);
}

static int viommu_attach_dev(struct iommu_domain *domain, struct device *dev)
{
	int i;
	int ret = 0;
	struct virtio_iommu_req_attach *req;
	struct iommu_fwspec *fwspec = dev->iommu_fwspec;
	struct viommu_endpoint *vdev = fwspec->iommu_priv;
	struct viommu_domain *vdomain = to_viommu_domain(domain);

	mutex_lock(&vdomain->mutex);
	if (!vdomain->viommu) {
		/*
		 * Initialize the domain proper now that we know which viommu
		 * owns it.
		 */
		ret = viommu_domain_finalise(vdev->viommu, domain);
	} else if (vdomain->viommu != vdev->viommu) {
		dev_err(dev, "cannot attach to foreign vIOMMU\n");
		ret = -EXDEV;
	}
	mutex_unlock(&vdomain->mutex);

	if (ret)
		return ret;

	/*
	 * When attaching the device to a new domain, it will be detached from
	 * the old one and, if as as a result the old domain isn't attached to
	 * any device, all mappings are removed from the old domain and it is
	 * freed. (Note that we can't use get_domain_for_dev here, it returns
	 * the default domain during initial attach.)
	 *
	 * Take note of the device disappearing, so we can ignore unmap request
	 * on stale domains (that is, between this detach and the upcoming
	 * free.)
	 *
	 * vdev->vdomain is protected by group->mutex
	 */
	if (vdev->vdomain)
		refcount_dec(&vdev->vdomain->endpoints);

	/* DMA to the stack is forbidden, store request on the heap */
	req = kzalloc(sizeof(*req), GFP_KERNEL);
	if (!req)
		return -ENOMEM;

	*req = (struct virtio_iommu_req_attach) {
		.head.type	= VIRTIO_IOMMU_T_ATTACH,
		.domain		= cpu_to_le32(vdomain->id),
	};

	for (i = 0; i < fwspec->num_ids; i++) {
		req->endpoint = cpu_to_le32(fwspec->ids[i]);

		ret = viommu_send_req_sync(vdomain->viommu, req);
		if (ret)
			break;
	}

	kfree(req);

	if (ret)
		return ret;

	if (!refcount_read(&vdomain->endpoints)) {
		/*
		 * This endpoint is the first to be attached to the domain.
		 * Replay existing mappings if any.
		 */
		ret = viommu_replay_mappings(vdomain);
		if (ret)
			return ret;
	}

	refcount_inc(&vdomain->endpoints);
	vdev->vdomain = vdomain;

	return 0;
}

static int viommu_map(struct iommu_domain *domain, unsigned long iova,
		      phys_addr_t paddr, size_t size, int prot)
{
	int ret;
	int flags;
	struct viommu_mapping *mapping;
	struct viommu_domain *vdomain = to_viommu_domain(domain);

	mapping = viommu_add_mapping(vdomain, iova, paddr, size);
	if (!mapping)
		return -ENOMEM;

	flags = (prot & IOMMU_READ ? VIRTIO_IOMMU_MAP_F_READ : 0) |
		(prot & IOMMU_WRITE ? VIRTIO_IOMMU_MAP_F_WRITE : 0);

	mapping->req.map = (struct virtio_iommu_req_map) {
		.head.type	= VIRTIO_IOMMU_T_MAP,
		.domain		= cpu_to_le32(vdomain->id),
		.virt_addr	= cpu_to_le64(iova),
		.phys_addr	= cpu_to_le64(paddr),
		.size		= cpu_to_le64(size),
		.flags		= cpu_to_le32(flags),
	};

	if (!refcount_read(&vdomain->endpoints))
		return 0;

	ret = viommu_send_req_sync(vdomain->viommu, &mapping->req);
	if (ret)
		viommu_del_mappings(vdomain, iova, size, NULL);

	return ret;
}

static size_t viommu_unmap(struct iommu_domain *domain, unsigned long iova,
			   size_t size)
{
	int ret = 0;
	size_t unmapped;
	struct viommu_mapping *mapping = NULL;
	struct viommu_domain *vdomain = to_viommu_domain(domain);

	unmapped = viommu_del_mappings(vdomain, iova, size, &mapping);
	if (unmapped < size) {
		ret = -EINVAL;
		goto out_free;
	}

	/* Device already removed all mappings after detach. */
	if (!refcount_read(&vdomain->endpoints))
		goto out_free;

	if (WARN_ON(!mapping))
		return 0;

	mapping->req.unmap = (struct virtio_iommu_req_unmap) {
		.head.type	= VIRTIO_IOMMU_T_UNMAP,
		.domain		= cpu_to_le32(vdomain->id),
		.virt_addr	= cpu_to_le64(iova),
		.size		= cpu_to_le64(unmapped),
	};

	ret = viommu_send_req_sync(vdomain->viommu, &mapping->req);

out_free:
	if (mapping)
		kfree(mapping);

	return ret ? 0 : unmapped;
}

static phys_addr_t viommu_iova_to_phys(struct iommu_domain *domain,
				       dma_addr_t iova)
{
	u64 paddr = 0;
	unsigned long flags;
	struct viommu_mapping *mapping;
	struct interval_tree_node *node;
	struct viommu_domain *vdomain = to_viommu_domain(domain);

	spin_lock_irqsave(&vdomain->mappings_lock, flags);
	node = interval_tree_iter_first(&vdomain->mappings, iova, iova);
	if (node) {
		mapping = container_of(node, struct viommu_mapping, iova);
		paddr = mapping->paddr + (iova - mapping->iova.start);
	}
	spin_unlock_irqrestore(&vdomain->mappings_lock, flags);

	return paddr;
}

static struct iommu_ops viommu_ops;
static struct virtio_driver virtio_iommu_drv;

static int viommu_match_node(struct device *dev, void *data)
{
	return dev->parent->fwnode == data;
}

static struct viommu_dev *viommu_get_by_fwnode(struct fwnode_handle *fwnode)
{
	struct device *dev = driver_find_device(&virtio_iommu_drv.driver, NULL,
						fwnode, viommu_match_node);
	put_device(dev);

	return dev ? dev_to_virtio(dev)->priv : NULL;
}

static int viommu_add_device(struct device *dev)
{
	int ret;
	struct iommu_group *group;
	struct viommu_endpoint *vdev;
	struct viommu_dev *viommu = NULL;
	struct iommu_fwspec *fwspec = dev->iommu_fwspec;

	if (!fwspec || fwspec->ops != &viommu_ops)
		return -ENODEV;

	viommu = viommu_get_by_fwnode(fwspec->iommu_fwnode);
	if (!viommu)
		return -ENODEV;

	vdev = kzalloc(sizeof(*vdev), GFP_KERNEL);
	if (!vdev)
		return -ENOMEM;

	vdev->viommu = viommu;
	INIT_LIST_HEAD(&vdev->resv_regions);
	fwspec->iommu_priv = vdev;

	if (viommu->probe_size) {
		/* Get additional information for this endpoint */
		ret = viommu_probe_endpoint(viommu, dev);
		if (ret)
			return ret;
	}

	/*
	 * Last step creates a default domain and attaches to it. Everything
	 * must be ready.
	 */
	group = iommu_group_get_for_dev(dev);
	if (!IS_ERR(group))
		iommu_group_put(group);

	return PTR_ERR_OR_ZERO(group);
}

static void viommu_remove_device(struct device *dev)
{
	struct viommu_endpoint *vdev;
	struct iommu_resv_region *entry, *next;
	struct iommu_fwspec *fwspec = dev->iommu_fwspec;

	if (!fwspec || fwspec->ops != &viommu_ops)
		return;

	vdev = fwspec->iommu_priv;

	list_for_each_entry_safe(entry, next, &vdev->resv_regions, list)
		kfree(entry);

	kfree(vdev);
}

static struct iommu_group *viommu_device_group(struct device *dev)
{
	if (dev_is_pci(dev))
		return pci_device_group(dev);
	else
		return generic_device_group(dev);
}

static int viommu_of_xlate(struct device *dev, struct of_phandle_args *args)
{
	return iommu_fwspec_add_ids(dev, args->args, 1);
}

static void viommu_get_resv_regions(struct device *dev, struct list_head *head)
{
	struct iommu_resv_region *entry, *new_entry, *msi = NULL;
	struct viommu_endpoint *vdev = dev->iommu_fwspec->iommu_priv;
	int prot = IOMMU_WRITE | IOMMU_NOEXEC | IOMMU_MMIO;

	list_for_each_entry(entry, &vdev->resv_regions, list) {
		/*
		 * If the device registered a bypass MSI windows, use it.
		 * Otherwise add a software-mapped region
		 */
		if (entry->type == IOMMU_RESV_MSI)
			msi = entry;

		new_entry = kmemdup(entry, sizeof(*entry), GFP_KERNEL);
		if (!new_entry)
			return;
		list_add_tail(&new_entry->list, head);
	}

	if (!msi) {
		msi = iommu_alloc_resv_region(MSI_IOVA_BASE, MSI_IOVA_LENGTH,
					      prot, IOMMU_RESV_SW_MSI);
		if (!msi)
			return;

		list_add_tail(&msi->list, head);
	}

	iommu_dma_get_resv_regions(dev, head);
}

static void viommu_put_resv_regions(struct device *dev, struct list_head *head)
{
	struct iommu_resv_region *entry, *next;

	list_for_each_entry_safe(entry, next, head, list)
		kfree(entry);
}

static struct iommu_ops viommu_ops = {
	.capable		= viommu_capable,
	.domain_alloc		= viommu_domain_alloc,
	.domain_free		= viommu_domain_free,
	.attach_dev		= viommu_attach_dev,
	.map			= viommu_map,
	.unmap			= viommu_unmap,
	.map_sg			= default_iommu_map_sg,
	.iova_to_phys		= viommu_iova_to_phys,
	.add_device		= viommu_add_device,
	.remove_device		= viommu_remove_device,
	.device_group		= viommu_device_group,
	.of_xlate		= viommu_of_xlate,
	.get_resv_regions	= viommu_get_resv_regions,
	.put_resv_regions	= viommu_put_resv_regions,
};

static int viommu_init_vqs(struct viommu_dev *viommu)
{
	struct virtio_device *vdev = dev_to_virtio(viommu->dev);
	const char *names[] = { "request", "event" };
	vq_callback_t *callbacks[] = {
		NULL, /* No async requests */
		viommu_event_handler,
	};

	return virtio_find_vqs(vdev, VIOMMU_NUM_VQS, viommu->vqs, callbacks,
			       names, NULL);
}

static int viommu_fill_evtq(struct viommu_dev *viommu)
{
	int i, ret;
	struct scatterlist sg[1];
	struct viommu_event *evts;
	struct virtqueue *vq = viommu->vqs[VIOMMU_EVENT_VQ];
	size_t nr_evts = min_t(size_t, PAGE_SIZE / sizeof(struct viommu_event),
			       viommu->vqs[VIOMMU_EVENT_VQ]->num_free);

	evts = devm_kmalloc_array(viommu->dev, nr_evts, sizeof(*evts),
				  GFP_KERNEL);
	if (!evts)
		return -ENOMEM;

	for (i = 0; i < nr_evts; i++) {
		sg_init_one(sg, &evts[i], sizeof(*evts));
		ret = virtqueue_add_inbuf(vq, sg, 1, &evts[i], GFP_KERNEL);
		if (ret)
			return ret;
	}

	if (!virtqueue_kick(vq))
		return -EPIPE;

	dev_info(viommu->dev, "%zu event buffers\n", nr_evts);

	return 0;
}

static int viommu_probe(struct virtio_device *vdev)
{
	struct device *parent_dev = vdev->dev.parent;
	struct viommu_dev *viommu = NULL;
	struct device *dev = &vdev->dev;
	u64 input_start = 0;
	u64 input_end = -1UL;
	int ret;

	viommu = kzalloc(sizeof(*viommu), GFP_KERNEL);
	if (!viommu)
		return -ENOMEM;

	spin_lock_init(&viommu->request_lock);
	ida_init(&viommu->domain_ids);
	viommu->dev = dev;
	viommu->vdev = vdev;

	ret = viommu_init_vqs(viommu);
	if (ret)
		goto err_free_viommu;

	virtio_cread(vdev, struct virtio_iommu_config, page_size_mask,
		     &viommu->pgsize_bitmap);

	if (!viommu->pgsize_bitmap) {
		ret = -EINVAL;
		goto err_free_viommu;
	}

	viommu->domain_bits = 32;

	/* Optional features */
	virtio_cread_feature(vdev, VIRTIO_IOMMU_F_INPUT_RANGE,
			     struct virtio_iommu_config, input_range.start,
			     &input_start);

	virtio_cread_feature(vdev, VIRTIO_IOMMU_F_INPUT_RANGE,
			     struct virtio_iommu_config, input_range.end,
			     &input_end);

	virtio_cread_feature(vdev, VIRTIO_IOMMU_F_DOMAIN_BITS,
			     struct virtio_iommu_config, domain_bits,
			     &viommu->domain_bits);

	virtio_cread_feature(vdev, VIRTIO_IOMMU_F_PROBE,
			     struct virtio_iommu_config, probe_size,
			     &viommu->probe_size);

	viommu->geometry = (struct iommu_domain_geometry) {
		.aperture_start	= input_start,
		.aperture_end	= input_end,
		.force_aperture	= true,
	};

	viommu_ops.pgsize_bitmap = viommu->pgsize_bitmap;

	virtio_device_ready(vdev);

	/* Populate the event queue with buffers */
	ret = viommu_fill_evtq(viommu);
	if (ret)
		goto err_free_viommu;

	ret = iommu_device_sysfs_add(&viommu->iommu, dev, NULL, "%s",
				     virtio_bus_name(vdev));
	if (ret)
		goto err_free_viommu;

	iommu_device_set_ops(&viommu->iommu, &viommu_ops);
	iommu_device_set_fwnode(&viommu->iommu, parent_dev->fwnode);

	iommu_device_register(&viommu->iommu);

#ifdef CONFIG_PCI
	if (pci_bus_type.iommu_ops != &viommu_ops) {
		pci_request_acs();
		ret = bus_set_iommu(&pci_bus_type, &viommu_ops);
		if (ret)
			goto err_unregister;
	}
#endif
#ifdef CONFIG_ARM_AMBA
	if (amba_bustype.iommu_ops != &viommu_ops) {
		ret = bus_set_iommu(&amba_bustype, &viommu_ops);
		if (ret)
			goto err_unregister;
	}
#endif
	if (platform_bus_type.iommu_ops != &viommu_ops) {
		ret = bus_set_iommu(&platform_bus_type, &viommu_ops);
		if (ret)
			goto err_unregister;
	}

	vdev->priv = viommu;

	dev_info(dev, "input address: %u bits\n",
		 order_base_2(viommu->geometry.aperture_end));
	dev_info(dev, "page mask: %#llx\n", viommu->pgsize_bitmap);

	return 0;

err_unregister:
	iommu_device_unregister(&viommu->iommu);

err_free_viommu:
	kfree(viommu);

	return ret;
}

static void viommu_remove(struct virtio_device *vdev)
{
	struct viommu_dev *viommu = vdev->priv;

	iommu_device_unregister(&viommu->iommu);
	kfree(viommu);

	dev_info(&vdev->dev, "device removed\n");
}

static void viommu_config_changed(struct virtio_device *vdev)
{
	dev_warn(&vdev->dev, "config changed\n");
}

static unsigned int features[] = {
	VIRTIO_IOMMU_F_MAP_UNMAP,
	VIRTIO_IOMMU_F_DOMAIN_BITS,
	VIRTIO_IOMMU_F_INPUT_RANGE,
	VIRTIO_IOMMU_F_PROBE,
};

static struct virtio_device_id id_table[] = {
	{ VIRTIO_ID_IOMMU, VIRTIO_DEV_ANY_ID },
	{ 0 },
};

static struct virtio_driver virtio_iommu_drv = {
	.driver.name		= KBUILD_MODNAME,
	.driver.owner		= THIS_MODULE,
	.id_table		= id_table,
	.feature_table		= features,
	.feature_table_size	= ARRAY_SIZE(features),
	.probe			= viommu_probe,
	.remove			= viommu_remove,
	.config_changed		= viommu_config_changed,
};

module_virtio_driver(virtio_iommu_drv);

IOMMU_OF_DECLARE(viommu, "virtio,mmio", NULL);

MODULE_DESCRIPTION("Virtio IOMMU driver");
MODULE_AUTHOR("Jean-Philippe Brucker <jean-philippe.brucker@arm.com>");
MODULE_LICENSE("GPL v2");
