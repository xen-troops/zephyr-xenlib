// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright (c) 2023 EPAM Systems
 *
 */

#include <stdio.h>
#include <string.h>
#include <xss.h>

#include <zephyr/sys/util.h>

#include <zephyr/xen/events.h>
#include <zephyr/xen/gnttab.h>

#include "vch.h"

#define RD_PROD(h) ((h)->read->prod)
#define RD_CONS(h) ((h)->read->cons)
#define WR_PROD(h) ((h)->write->prod)
#define WR_CONS(h) ((h)->write->cons)
#define ORD10_RING_SHIFT 10
#define ORD11_RING_SHIFT 11
#define ORD10_RING_SZ (1 << ORD10_RING_SHIFT)
#define ORD11_RING_SZ (1 << ORD11_RING_SHIFT)
#define RD_RING_SZ(h) (1 << (h)->read_ord)
#define WR_RING_SZ(h) (1 << (h)->write_ord)

#define MAX_XS_KEY_LEN 64
#define MAX_XS_VAL_LEN 8

#define SERVER_CONNECTED 1
#define CLIENT_CONNECTED (SERVER_CONNECTED)
#define CLIENT_NOT_CONNECTED 2

static void _vch_wait(struct vch_handle *h)
{
	__ASSERT(h, "Invalid handle");
	k_sem_take(&h->sem, K_FOREVER);
}

static void _vch_notify_cb(void *data)
{
	struct vch_handle *h = data;

	__ASSERT(h, "Invalid handle");
	k_sem_give(&h->sem);
}

static int _vch_notify(struct vch_handle *h, int rw)
{
	uint8_t *target, val;

	if (!h || !h->ring) {
		return -EINVAL;
	}

	dmb();
	if (h->is_server) {
		target = &h->ring->srv_notify;
	} else {
		target = &h->ring->cli_notify;
	}

	val = __atomic_fetch_and(target, ~rw, __ATOMIC_SEQ_CST);
	if (val & rw) {
		return notify_evtchn(h->evtch);
	}
	return 0;
}

static int _vch_is_live(struct vch_handle *h)
{
	return h->is_server ? h->ring->cli_live : h->ring->srv_live;
}

static void _vch_unmask_notify(struct vch_handle *h, int bit)
{
	uint8_t *target;

	__ASSERT(h && h->ring, "Invalid handler");

	if (h->is_server) {
		target = &h->ring->cli_notify;
	} else {
		target = &h->ring->srv_notify;
	}

	__atomic_fetch_or(target, bit, __ATOMIC_SEQ_CST);
	dmb();
}

static inline size_t _vch_get_rd_avail(struct vch_handle *h, size_t req)
{

	size_t avail = RD_PROD(h) - RD_CONS(h);

	dmb();

	return avail;
}

static inline size_t _vch_get_wr_avail(struct vch_handle *h, size_t req)
{

	size_t avail = WR_RING_SZ(h) - (WR_PROD(h) - WR_CONS(h));

	dmb();

	return avail;
}

int vch_open(domid_t domain, const char *path, size_t min_rs, size_t min_ws,
	     struct vch_handle *h)
{
	int rc;
	grant_ref_t ring_gref;
	uintptr_t ring_pfn;
	char xs_key_scratch[MAX_XS_KEY_LEN] = { 0 },
	     xs_val_scratch[MAX_XS_VAL_LEN] = { 0 };

	if (!h || !path) {
		return -EINVAL;
	}

	if (strlen(path) >= sizeof(h->path)) {
		return -ENAMETOOLONG;
	}

	memset(h, 0, sizeof(*h));
	h->is_server = true;
	strncpy(h->path, path, MIN(sizeof(h->path) - 1, strlen(path)));

	if (min_rs <= ORD10_RING_SZ && min_ws <= ORD11_RING_SZ) {
		h->read_ord = ORD10_RING_SHIFT;
		h->write_ord = ORD11_RING_SHIFT;
	} else if (min_rs <= ORD11_RING_SZ && min_ws <= ORD10_RING_SZ) {
		h->read_ord = ORD11_RING_SHIFT;
		h->write_ord = ORD10_RING_SHIFT;
	} else {
		/*TODO: arbitrary sized ring not supported yet */
		return -EINVAL;
	}

	rc = k_sem_init(&h->sem, 1, 1);
	if (rc) {
		return rc;
	}

	h->ring = k_aligned_alloc(XEN_PAGE_SIZE, XEN_PAGE_SIZE);
	if (!h->ring) {
		return -ENOMEM;
	}

	memset(h->ring, 0, XEN_PAGE_SIZE);

	rc = alloc_unbound_event_channel(domain);
	if (rc < 0) {
		return rc;
	}

	h->evtch = rc;
	rc = bind_event_channel(h->evtch, _vch_notify_cb, h);
	if (rc) {
		goto free_evtch;
	}

	ring_pfn = xen_virt_to_gfn(h->ring);
	rc = gnttab_grant_access(domain, ring_pfn, false);
	if (rc < 0) {
		goto free_evtch;
	}

	ring_gref = rc;

	h->ring->left_order = h->read_ord;
	h->ring->right_order = h->write_ord;
	h->ring->srv_live = SERVER_CONNECTED;
	h->ring->cli_live = CLIENT_NOT_CONNECTED;
	h->ring->cli_notify = VCHAN_NOTIFY_WRITE;
	h->read_cbuf = ((uint8_t *)h->ring) + (1 << h->read_ord);
	h->write_cbuf = ((uint8_t *)h->ring) + (1 << h->write_ord);
	h->read = &h->ring->left;
	h->write = &h->ring->right;
	h->gref = ring_gref;

	snprintf(xs_key_scratch, sizeof(xs_key_scratch),
		 "%s/ring-ref", h->path);
	snprintf(xs_val_scratch, sizeof(xs_val_scratch), "%u", h->gref);

	/*TODO: writing to both entries and permission settings must be
	 * wrapped in single XS transaction, when transactions are supported
	 * by xenstore-srv implementation -- to prevent hard-to-debug problems
	 * with synchronization. The other side expects both ring-ref and
	 * event-channel entries to be in consistent state when connecting.
	 * With current code it is possible that it will see only ring-ref
	 * because event-channel is not yet ready.
	 */
	rc = xss_write(xs_key_scratch, xs_val_scratch);
	if (rc) {
		goto free_gnt;
	}

	rc = xss_set_perm(xs_key_scratch, domain, XS_PERM_READ);
	if (rc) {
		goto free_gnt;
	}

	snprintf(xs_key_scratch, sizeof(xs_key_scratch),
		 "%s/event-channel", h->path);
	snprintf(xs_val_scratch, sizeof(xs_val_scratch), "%u", h->evtch);
	rc = xss_write(xs_key_scratch, xs_val_scratch);
	if (rc) {
		goto free_gnt;
	}

	rc = xss_set_perm(xs_key_scratch, domain, XS_PERM_READ);
	if (rc) {
		goto free_gnt;
	}

	rc = unmask_event_channel(h->evtch);
	if (rc) {
		goto free_gnt;
	}

	return 0;
free_gnt:
	gnttab_end_access(ring_gref);
free_evtch:
	if (h->evtch) {
		unbind_event_channel(h->evtch);
		evtchn_close(h->evtch);
	}
	if (h->ring) {
		k_free(h->ring);
	}
	return rc;
}

int vch_connect(domid_t domain, const char *path, struct vch_handle *h)
{
	int rc;
	grant_ref_t ring_gref;
	evtchn_port_t remote_port;
	char xs_key_scratch[MAX_XS_KEY_LEN] = { 0 };
	struct gnttab_map_grant_ref map;

	if (!h || !path) {
		return -EINVAL;
	}

	if (strlen(path) >= sizeof(h->path)) {
		return -ENAMETOOLONG;
	}

	memset(h, 0, sizeof(*h));
	h->is_server = false;
	strncpy(h->path, path, MIN(sizeof(h->path) - 1, strlen(path)));
	rc = k_sem_init(&h->sem, 1, 1);
	if (rc) {
		return rc;
	}

	snprintf(xs_key_scratch, sizeof(xs_key_scratch),
		 "%s/ring-ref", h->path);
	rc = xss_read_integer(xs_key_scratch, &ring_gref);
	if (rc) {
		return rc;
	}

	if (!ring_gref) {
		return -EFAULT;
	}

	snprintf(xs_key_scratch, sizeof(xs_key_scratch),
		 "%s/event-channel", h->path);
	rc = xss_read_integer(xs_key_scratch, &remote_port);
	if (rc) {
		return rc;
	}

	if (!remote_port) {
		return -ENODEV;
	}

	rc = bind_interdomain_event_channel(domain, remote_port,
					    _vch_notify_cb, h);
	if (rc < 0) {
		return rc;
	}

	h->evtch = rc;

	h->ring = (struct vchan_interface *)gnttab_get_page();
	if (!h->ring) {
		rc = -ENOMEM;
		goto free_evtch;
	}

	map.host_addr = xen_to_phys(h->ring);
	map.flags = GNTMAP_host_map;
	map.ref = ring_gref;
	map.dom = domain;
	rc = gnttab_map_refs(&map, 1);
	if (rc) {
		goto free_gnt;
	}

	h->read_ord = h->ring->right_order;
	h->write_ord = h->ring->left_order;

	/*TODO: validate shared ring */

	h->read_cbuf = ((uint8_t *)h->ring) + (1 << h->read_ord);
	h->write_cbuf = ((uint8_t *)h->ring) + (1 << h->write_ord);
	h->read = &h->ring->right;
	h->write = &h->ring->left;
	h->gref = ring_gref;
	h->ring->cli_live = CLIENT_CONNECTED;
	h->ring->srv_notify = VCHAN_NOTIFY_WRITE;
	rc = unmask_event_channel(h->evtch);
	if (rc) {
		goto free_gnt;
	}

	rc = notify_evtchn(h->evtch);
	if (rc) {
		goto free_gnt;
	}

	return 0;

free_gnt:
	gnttab_unmap_refs(&map, 1);
	gnttab_put_page(h->ring);
free_evtch:
	unbind_event_channel(h->evtch);
	return rc;
}

void vch_close(struct vch_handle *h)
{
	struct gnttab_map_grant_ref map;

	if (!h) {
		return;
	}

	notify_evtchn(h->evtch);
	unbind_event_channel(h->evtch);
	evtchn_close(h->evtch);
	k_sem_give(&h->sem);

	if (h->is_server) {
		xss_rm(h->path);
		gnttab_end_access(h->gref);
		k_free(h->ring);
	} else {
		map.host_addr = xen_to_phys(h->ring);
		map.ref = h->gref;
		map.flags = GNTMAP_host_map;
		gnttab_unmap_refs(&map, 1);
		gnttab_put_page(h->ring);
	}
}

int vch_read(struct vch_handle *h, void *buf, size_t size)
{
	if (!h) {
		return -EINVAL;
	}

	while (_vch_is_live(h)) {
		size_t avail = _vch_get_rd_avail(h, size);

		if (avail) {
			int idx = RD_CONS(h) & (RD_RING_SZ(h) - 1);
			size_t chunk = RD_RING_SZ(h) - idx;

			if (!buf) {
				return -ENOBUFS;
			}

			/* ensure indexes are read before data access */
			dmb();
			size = MIN(size, avail);
			chunk = MIN(chunk, size);
			memcpy((uint8_t *)buf, h->read_cbuf + idx, chunk);
			memcpy((uint8_t *)buf + chunk, h->read_cbuf,
			       size - chunk);
			dmb();
			RD_CONS(h) += size;
			if (_vch_notify(h, VCHAN_NOTIFY_READ)) {
				return -EFAULT;
			}
			return size;
		} else {
			/* ask the sender to signal us when more data written */
			_vch_unmask_notify(h, VCHAN_NOTIFY_WRITE);
		}

		if (h->blocking) {
			_vch_wait(h);
		} else {
			return 0;
		}
	}

	return -ENOTCONN;
}

int vch_write(struct vch_handle *h, const void *buf, size_t size)
{
	if (!h) {
		return -EINVAL;
	}

	while (_vch_is_live(h)) {
		size_t avail = _vch_get_wr_avail(h, size);

		if (avail) {
			int idx = WR_PROD(h) & (WR_RING_SZ(h) - 1);
			size_t chunk = WR_RING_SZ(h) - idx;

			if (!buf) {
				return -ENOBUFS;
			}

			/* ensure indexes are read before buffer fill */
			dmb();
			size = MIN(size, avail);
			chunk = MIN(chunk, size);
			memcpy(h->write_cbuf + idx, buf, chunk);
			memcpy(h->write_cbuf, (uint8_t *)buf + chunk,
			       size - chunk);
			dmb();
			WR_PROD(h) += size;
			if (_vch_notify(h, VCHAN_NOTIFY_WRITE)) {
				return -EFAULT;
			}
			return size;
		} else {
			/* ask receiver to signal us when some space is freed */
			_vch_unmask_notify(h, VCHAN_NOTIFY_READ);
		}

		if (h->blocking) {
			_vch_wait(h);
		} else {
			return 0;
		}
	}

	return -ENOTCONN;
}
