/*
 * Virtio driver for the paravirtualized IOMMU
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
 *
 * Copyright (C) 2017 ARM Limited
 *
 * Author: Jean-Philippe Brucker <jean-philippe.brucker@arm.com>
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

struct viommu_dev {
	struct iommu_device		iommu;
	struct device			*dev;
	struct virtio_device		*vdev;

	struct virtqueue		*vq;
	struct list_head		pending_requests;
	/* Serialize anything touching the vq and the request list */
	spinlock_t			vq_lock;

	struct list_head		list;

	/* Device configuration */
	u64				pgsize_bitmap;
	u64				aperture_start;
	u64				aperture_end;
	u32				probe_size;
	u8				ioasid_bits;
};

struct viommu_mapping {
	phys_addr_t			paddr;
	struct interval_tree_node	iova;
};

struct viommu_domain {
	struct iommu_domain		domain;
	struct viommu_dev		*viommu;
	struct mutex			mutex;
	u64				id;

	spinlock_t			mappings_lock;
	struct rb_root			mappings;

	/* Number of devices attached to this domain */
	unsigned long			attached;
};

struct viommu_endpoint {
	struct viommu_dev		*viommu;
	struct viommu_domain		*vdomain;
};

struct viommu_request {
	struct scatterlist		top;
	struct scatterlist		bottom;

	int				written;
	struct list_head		list;
};

/* TODO: use an IDA */
static atomic64_t viommu_domain_ids_gen;

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

static int viommu_receive_resp(struct viommu_dev *viommu, int nr_expected)
{

	unsigned int len;
	int nr_received = 0;
	struct viommu_request *req, *pending, *next;

	pending = list_first_entry_or_null(&viommu->pending_requests,
					   struct viommu_request, list);
	if (WARN_ON(!pending))
		return 0;

	while ((req = virtqueue_get_buf(viommu->vq, &len)) != NULL) {
		if (req != pending) {
			dev_warn(viommu->dev, "discarding stale request\n");
			continue;
		}

		pending->written = len;

		if (++nr_received == nr_expected) {
			list_del(&pending->list);
			/*
			 * In an ideal world, we'd wake up the waiter for this
			 * group of requests here. But everything is painfully
			 * synchronous, so waiter is the caller.
			 */
			break;
		}

		next = list_next_entry(pending, list);
		list_del(&pending->list);

		if (WARN_ON(list_empty(&viommu->pending_requests)))
			return 0;

		pending = next;
	}

	return nr_received;
}

/* Must be called with vq_lock held */
static int _viommu_send_reqs_sync(struct viommu_dev *viommu,
				  struct viommu_request *req, int nr,
				  int *nr_sent)
{
	int i, ret;
	ktime_t timeout;
	int nr_received = 0;
	struct scatterlist *sg[2];
	/*
	 * FIXME: as it stands, 1s timeout per request. This is a voluntary
	 * exaggeration because I have no idea how real our ktime is. Are we
	 * using a RTC? Are we aware of steal time? I don't know much about
	 * this, need to do some digging.
	 */
	unsigned long timeout_ms = 1000;

	*nr_sent = 0;

	for (i = 0; i < nr; i++, req++) {
		/*
		 * The backend will allocate one indirect descriptor for each
		 * request, which allows to double the ring consumption, but
		 * might be slower.
		 */
		req->written = 0;

		sg[0] = &req->top;
		sg[1] = &req->bottom;

		ret = virtqueue_add_sgs(viommu->vq, sg, 1, 1, req,
					GFP_ATOMIC);
		if (ret)
			break;

		list_add_tail(&req->list, &viommu->pending_requests);
	}

	if (i && !virtqueue_kick(viommu->vq))
		return -EPIPE;

	/*
	 * Absolutely no wiggle room here. We're not allowed to sleep as callers
	 * might be holding spinlocks, so we have to poll like savages until
	 * something appears. Hopefully the host already handled the request
	 * during the above kick and returned it to us.
	 *
	 * A nice improvement would be for the caller to tell us if we can sleep
	 * whilst mapping, but this has to go through the IOMMU/DMA API.
	 */
	timeout = ktime_add_ms(ktime_get(), timeout_ms * i);
	while (nr_received < i && ktime_before(ktime_get(), timeout)) {
		nr_received += viommu_receive_resp(viommu, i - nr_received);
		if (nr_received < i) {
			/*
			 * FIXME: what's a good way to yield to host? A second
			 * virtqueue_kick won't have any effect since we haven't
			 * added any descriptor.
			 */
			udelay(10);
		}
	}
	dev_dbg(viommu->dev, "request took %lld us\n",
		ktime_us_delta(ktime_get(), ktime_sub_ms(timeout, timeout_ms * i)));

	if (nr_received != i)
		ret = -ETIMEDOUT;

	if (ret == -ENOSPC && nr_received)
		/*
		 * We've freed some space since virtio told us that the ring is
		 * full, tell the caller to come back later (after releasing the
		 * lock first, to be fair to other threads)
		 */
		ret = -EAGAIN;

	*nr_sent = nr_received;

	return ret;
}

/**
 * viommu_send_reqs_sync - add a batch of requests, kick the host and wait for
 *                         them to return
 *
 * @req: array of requests
 * @nr: size of the array
 * @nr_sent: contains the number of requests actually sent after this function
 *           returns
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
		spin_lock_irqsave(&viommu->vq_lock, flags);
		ret = _viommu_send_reqs_sync(viommu, req, nr, &sent);
		spin_unlock_irqrestore(&viommu->vq_lock, flags);

		*nr_sent += sent;
		req += sent;
		nr -= sent;
	} while (ret == -EAGAIN);

	return ret;
}

/**
 * viommu_send_req_sync - send one request and wait for reply
 *
 * @head_ptr: pointer to a virtio_iommu_req_* structure
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

	dev_dbg(viommu->dev, "Sending request 0x%x, %zu + %zu bytes\n", head->type,
		top_size, bottom_size);

	bottom = top + top_size;
	tail = bottom + bottom_size - sizeof(*tail);

	sg_init_one(&req.top, top, top_size);
	sg_init_one(&req.bottom, bottom, bottom_size);

	ret = viommu_send_reqs_sync(viommu, &req, 1, &nr_sent);
	if (ret || !req.written || nr_sent != 1) {
		dev_err(viommu->dev, "failed to send request\n");
		return -EIO;
	}

	ret = viommu_status_to_errno(tail->status);
	if (ret)
		dev_dbg(viommu->dev, " completed with %d\n", ret);

	return ret;
}

static int viommu_tlb_map(struct viommu_domain *vdomain, unsigned long iova,
			  phys_addr_t paddr, size_t size)
{
	unsigned long flags;
	struct viommu_mapping *mapping;

	mapping = kzalloc(sizeof(*mapping), GFP_ATOMIC);
	if (!mapping)
		return -ENOMEM;

	mapping->paddr = paddr;
	mapping->iova.start = iova;
	mapping->iova.last = iova + size - 1;

	spin_lock_irqsave(&vdomain->mappings_lock, flags);
	interval_tree_insert(&mapping->iova, &vdomain->mappings);
	spin_unlock_irqrestore(&vdomain->mappings_lock, flags);

	return 0;
}

static size_t viommu_tlb_unmap(struct viommu_domain *vdomain,
			       unsigned long iova, size_t size)
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
		kfree(mapping);
	}
	spin_unlock_irqrestore(&vdomain->mappings_lock, flags);

	return unmapped;
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

	vdomain = kzalloc(sizeof(struct viommu_domain), GFP_KERNEL);
	if (!vdomain)
		return NULL;

	vdomain->id = atomic64_inc_return_relaxed(&viommu_domain_ids_gen);
	mutex_init(&vdomain->mutex);
	spin_lock_init(&vdomain->mappings_lock);
	vdomain->mappings = RB_ROOT;

	pr_debug("alloc domain of type %d -> %llu\n", type, vdomain->id);

	if (type == IOMMU_DOMAIN_DMA &&
	    iommu_get_dma_cookie(&vdomain->domain)) {
		kfree(vdomain);
		return NULL;
	}

	return &vdomain->domain;
}

static void viommu_domain_free(struct iommu_domain *domain)
{
	struct viommu_domain *vdomain = to_viommu_domain(domain);

	pr_debug("free domain %llu\n", vdomain->id);

	iommu_put_dma_cookie(domain);

	/* Free all remaining mappings (size 2^64) */
	viommu_tlb_unmap(vdomain, 0, 0);

	kfree(vdomain);
}

static int viommu_attach_dev(struct iommu_domain *domain, struct device *dev)
{
	int i;
	int ret = 0;
	struct iommu_fwspec *fwspec = dev->iommu_fwspec;
	struct viommu_endpoint *vdev = fwspec->iommu_priv;
	struct viommu_domain *vdomain = to_viommu_domain(domain);
	struct virtio_iommu_req_attach req = {
		.head.type	= VIRTIO_IOMMU_T_ATTACH,
		.address_space	= cpu_to_le32(vdomain->id),
	};

	mutex_lock(&vdomain->mutex);
	if (!vdomain->viommu) {
		/*
		 * Initialize the domain proper now that we know which viommu
		 * owns it.
		 */
		struct viommu_dev *viommu = vdev->viommu;

		vdomain->viommu = viommu;

		domain->pgsize_bitmap		= viommu->pgsize_bitmap;
		domain->geometry.aperture_start	= viommu->aperture_start;
		domain->geometry.aperture_end	= viommu->aperture_end;
		domain->geometry.force_aperture	= true;

		if (vdomain->id >= (1ULL << viommu->ioasid_bits)) {
			/* TODO: recycle ASIDs */
			dev_err(dev, "Out of ASIDs!\n");
			ret = -ENOSPC;
		}

	} else if (vdomain->viommu != vdev->viommu) {
		dev_err(dev, "cannot attach to foreign VIOMMU\n");
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
	if (vdev->vdomain) {
		dev_dbg(dev, "detach from domain %llu\n", vdev->vdomain->id);
		vdev->vdomain->attached--;
	}

	dev_dbg(dev, "attach to domain %llu\n", vdomain->id);

	for (i = 0; i < fwspec->num_ids; i++) {
		req.device = cpu_to_le32(fwspec->ids[i]);

		ret = viommu_send_req_sync(vdomain->viommu, &req);
		if (ret)
			break;
	}

	vdomain->attached++;
	vdev->vdomain = vdomain;

	return ret;
}

static int viommu_map(struct iommu_domain *domain, unsigned long iova,
		      phys_addr_t paddr, size_t size, int prot)
{
	int ret;
	struct viommu_domain *vdomain = to_viommu_domain(domain);
	struct virtio_iommu_req_map req = {
		.head.type	= VIRTIO_IOMMU_T_MAP,
		.address_space	= cpu_to_le32(vdomain->id),
		.virt_addr	= cpu_to_le64(iova),
		.phys_addr	= cpu_to_le64(paddr),
		.size		= cpu_to_le64(size),
	};

	pr_debug("map %llu 0x%lx -> 0x%llx (%zu)\n", vdomain->id, iova,
		 paddr, size);

	if (!vdomain->attached)
		return -ENODEV;

	if (prot & IOMMU_READ)
		req.flags |= cpu_to_le32(VIRTIO_IOMMU_MAP_F_READ);

	if (prot & IOMMU_WRITE)
		req.flags |= cpu_to_le32(VIRTIO_IOMMU_MAP_F_WRITE);

	ret = viommu_tlb_map(vdomain, iova, paddr, size);
	if (ret)
		return ret;

	ret = viommu_send_req_sync(vdomain->viommu, &req);
	if (ret)
		viommu_tlb_unmap(vdomain, iova, size);

	return ret;
}

static size_t viommu_unmap(struct iommu_domain *domain, unsigned long iova,
			   size_t size)
{
	int ret;
	size_t unmapped;
	struct viommu_domain *vdomain = to_viommu_domain(domain);
	struct virtio_iommu_req_unmap req = {
		.head.type	= VIRTIO_IOMMU_T_UNMAP,
		.address_space	= cpu_to_le32(vdomain->id),
		.virt_addr	= cpu_to_le64(iova),
	};

	pr_debug("unmap %llu 0x%lx (%zu)\n", vdomain->id, iova, size);

	/* Callers may unmap after detach, but device already took care of it. */
	if (!vdomain->attached)
		return size;

	unmapped = viommu_tlb_unmap(vdomain, iova, size);
	if (unmapped < size)
		return 0;

	req.size = cpu_to_le64(unmapped);

	ret = viommu_send_req_sync(vdomain->viommu, &req);
	if (ret)
		return 0;

	return unmapped;
}

static size_t viommu_map_sg(struct iommu_domain *domain, unsigned long iova,
			    struct scatterlist *sg, unsigned int nents, int prot)
{
	int i, ret;
	int nr_sent;
	size_t mapped;
	size_t min_pagesz;
	size_t total_size;
	struct scatterlist *s;
	unsigned int flags = 0;
	unsigned long cur_iova;
	unsigned long mapped_iova;
	size_t top_size, bottom_size;
	struct viommu_request reqs[nents];
	struct virtio_iommu_req_map map_reqs[nents];
	struct viommu_domain *vdomain = to_viommu_domain(domain);

	if (!vdomain->attached)
		return 0;

	pr_debug("map_sg %llu %u 0x%lx\n", vdomain->id, nents, iova);

	if (prot & IOMMU_READ)
		flags |= VIRTIO_IOMMU_MAP_F_READ;

	if (prot & IOMMU_WRITE)
		flags |= VIRTIO_IOMMU_MAP_F_WRITE;

	min_pagesz = 1 << __ffs(domain->pgsize_bitmap);
	bottom_size = sizeof(struct virtio_iommu_req_tail);
	top_size = sizeof(*map_reqs) - bottom_size;

	cur_iova = iova;

	for_each_sg(sg, s, nents, i) {
		size_t size = s->length;
		phys_addr_t paddr = sg_phys(s);

		if (!IS_ALIGNED(paddr | size, min_pagesz)) {
			ret = -EFAULT;
			break;
		}

		/* TODO: merge physically-contiguous mappings if any */
		map_reqs[i] = (struct virtio_iommu_req_map) {
			.head.type	= VIRTIO_IOMMU_T_MAP,
			.address_space	= cpu_to_le32(vdomain->id),
			.flags		= cpu_to_le32(flags),
			.virt_addr	= cpu_to_le64(cur_iova),
			.phys_addr	= cpu_to_le64(paddr),
			.size		= cpu_to_le64(size),
		};

		ret = viommu_tlb_map(vdomain, cur_iova, paddr, size);
		if (ret)
			break;

		sg_init_one(&reqs[i].top, &map_reqs[i], top_size);
		sg_init_one(&reqs[i].bottom, &map_reqs[i].tail, bottom_size);

		cur_iova += size;
	}

	total_size = cur_iova - iova;

	if (ret) {
		viommu_tlb_unmap(vdomain, iova, total_size);
		return 0;
	}

	ret = viommu_send_reqs_sync(vdomain->viommu, reqs, i, &nr_sent);

	if (nr_sent != nents)
		goto err_rollback;

	for (i = 0; i < nents; i++) {
		if (!reqs[i].written || map_reqs[i].tail.status)
			goto err_rollback;
	}

	return total_size;

err_rollback:
	/*
	 * Any request in the range might have failed. Unmap what was
	 * successful.
	 */
	cur_iova = iova;
	mapped_iova = iova;
	mapped = 0;
	for_each_sg(sg, s, nents, i) {
		size_t size = s->length;

		cur_iova += size;

		if (!reqs[i].written || map_reqs[i].tail.status) {
			if (mapped)
				viommu_unmap(domain, mapped_iova, mapped);

			mapped_iova = cur_iova;
			mapped = 0;
		} else {
			mapped += size;
		}
	}

	viommu_tlb_unmap(vdomain, iova, total_size);

	return 0;
}

static phys_addr_t viommu_iova_to_phys(struct iommu_domain *domain,
				       dma_addr_t iova)
{
	u64 paddr = 0;
	unsigned long flags;
	struct viommu_mapping *mapping;
	struct interval_tree_node *node;
	struct viommu_domain *vdomain = to_viommu_domain(domain);

	if (!vdomain->attached)
		return 0;

	spin_lock_irqsave(&vdomain->mappings_lock, flags);
	node = interval_tree_iter_first(&vdomain->mappings, iova, iova);
	if (node) {
		mapping = container_of(node, struct viommu_mapping, iova);
		paddr = mapping->paddr + (iova - mapping->iova.start);
	}
	spin_unlock_irqrestore(&vdomain->mappings_lock, flags);

	pr_debug("iova_to_phys %llu 0x%llx->0x%llx\n", vdomain->id, iova,
		 paddr);

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

static int viommu_probe_device(struct viommu_dev *viommu,
			       struct device *dev)
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
		return 0;

	probe = kzalloc(sizeof(*probe) + viommu->probe_size +
			sizeof(struct virtio_iommu_req_tail), GFP_KERNEL);
	if (!probe)
		return -ENOMEM;

	probe->head.type = VIRTIO_IOMMU_T_PROBE;
	/*
	 * For now, assume that properties of a device that spouts multiple IDs
	 * are consistent. Only probe the first one.
	 */
	probe->device = cpu_to_le32(fwspec->ids[0]);

	ret = viommu_send_req_sync(viommu, probe);
	if (ret)
		return ret;

	prop = (void *)probe->properties;
	type = le16_to_cpu(prop->type) & VIRTIO_IOMMU_PROBE_T_MASK;

	while (type != VIRTIO_IOMMU_PROBE_T_NONE &&
	       cur < viommu->probe_size) {
		len = le16_to_cpu(prop->length);

		switch (type) {
		default:
			dev_dbg(dev, "unknown viommu prop 0x%x\n", type);
		}

		cur += sizeof(*prop) + len;
		if (cur >= viommu->probe_size)
			break;

		prop = (void *)probe->properties + cur;
		type = le16_to_cpu(prop->type) & VIRTIO_IOMMU_PROBE_T_MASK;
	}

	return 0;
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
	fwspec->iommu_priv = vdev;

	if (viommu->probe_size) {
		/* Get additional information for this device */
		ret = viommu_probe_device(viommu, dev);
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
	kfree(dev->iommu_fwspec->iommu_priv);
}

static struct iommu_group *
viommu_device_group(struct device *dev)
{
	if (dev_is_pci(dev))
		return pci_device_group(dev);
	else
		return generic_device_group(dev);
}

static int viommu_of_xlate(struct device *dev, struct of_phandle_args *args)
{
	u32 *id = args->args;

	dev_dbg(dev, "of_xlate 0x%x\n", *id);
	return iommu_fwspec_add_ids(dev, args->args, 1);
}

/*
 * (Maybe) temporary hack for device pass-through into guest userspace. On ARM
 * with an ITS, VFIO will look for a region where to map the doorbell, even
 * though the virtual doorbell is never written to by the device, and instead
 * the host injects interrupts directly. TODO: sort this out in VFIO.
 */
#define MSI_IOVA_BASE			0x8000000
#define MSI_IOVA_LENGTH			0x100000

static void viommu_get_resv_regions(struct device *dev, struct list_head *head)
{
	struct iommu_resv_region *region;
	int prot = IOMMU_WRITE | IOMMU_NOEXEC | IOMMU_MMIO;

	region = iommu_alloc_resv_region(MSI_IOVA_BASE, MSI_IOVA_LENGTH, prot,
					 IOMMU_RESV_SW_MSI);
	if (!region)
		return;

	list_add_tail(&region->list, head);
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
	.map_sg			= viommu_map_sg,
	.iova_to_phys		= viommu_iova_to_phys,
	.add_device		= viommu_add_device,
	.remove_device		= viommu_remove_device,
	.device_group		= viommu_device_group,
	.of_xlate		= viommu_of_xlate,
	.get_resv_regions	= viommu_get_resv_regions,
	.put_resv_regions	= viommu_put_resv_regions,
};

static int viommu_init_vq(struct viommu_dev *viommu)
{
	struct virtio_device *vdev = dev_to_virtio(viommu->dev);
	const char *name = "request";
	void *ret;

	ret = virtio_find_single_vq(vdev, NULL, name);
	if (IS_ERR(ret)) {
		dev_err(viommu->dev, "cannot find VQ\n");
		return PTR_ERR(ret);
	}

	viommu->vq = ret;

	return 0;
}

static int viommu_probe(struct virtio_device *vdev)
{
	struct device *parent_dev = vdev->dev.parent;
	struct viommu_dev *viommu = NULL;
	struct device *dev = &vdev->dev;
	int ret;

	viommu = kzalloc(sizeof(*viommu), GFP_KERNEL);
	if (!viommu)
		return -ENOMEM;

	spin_lock_init(&viommu->vq_lock);
	INIT_LIST_HEAD(&viommu->pending_requests);
	viommu->dev = dev;
	viommu->vdev = vdev;

	ret = viommu_init_vq(viommu);
	if (ret)
		goto err_free_viommu;

	virtio_cread(vdev, struct virtio_iommu_config, page_size_mask,
		     &viommu->pgsize_bitmap);

	if (!viommu->pgsize_bitmap) {
		ret = -EINVAL;
		goto err_free_viommu;
	}

	viommu->ioasid_bits = 32;
	viommu->aperture_end = -1UL;

	virtio_cread_feature(vdev, VIRTIO_IOMMU_F_INPUT_RANGE,
			     struct virtio_iommu_config, input_range.start,
			     &viommu->aperture_start);

	virtio_cread_feature(vdev, VIRTIO_IOMMU_F_INPUT_RANGE,
			     struct virtio_iommu_config, input_range.end,
			     &viommu->aperture_end);

	virtio_cread_feature(vdev, VIRTIO_IOMMU_F_IOASID_BITS,
			     struct virtio_iommu_config, ioasid_bits,
			     &viommu->ioasid_bits);

	virtio_cread_feature(vdev, VIRTIO_IOMMU_F_PROBE,
			     struct virtio_iommu_config, probe_size,
			     &viommu->probe_size);

	viommu_ops.pgsize_bitmap = viommu->pgsize_bitmap;

	/*
	 * Not strictly necessary, virtio would enable it later. This allows to
	 * start using the request queue early.
	 */
	virtio_device_ready(vdev);

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

	dev_info(dev, "aperture: %#llx-%#llx\n", viommu->aperture_start,
		 viommu->aperture_end);
	dev_info(dev, "page mask: %#llx\n", viommu->pgsize_bitmap);
	dev_info(viommu->dev, "probe successful\n");

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
	VIRTIO_IOMMU_F_IOASID_BITS,
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

MODULE_DESCRIPTION("virtio-iommu driver");
MODULE_AUTHOR("Jean-Philippe Brucker <jean-philippe.brucker@arm.com>");
MODULE_LICENSE("GPL v2");
