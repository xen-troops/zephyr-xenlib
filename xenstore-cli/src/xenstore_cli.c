/*
 * Copyright (c) 2025 TOKITA Hiroshi
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include <xen/public/io/xs_wire.h>
#include <xen/public/memory.h>
#include <xen/public/xen.h>
#include <xenstore_common.h>
#include <xenstore_cli.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/spinlock.h>
#include <zephyr/sys/device_mmio.h>
#include <zephyr/sys/slist.h>
#include <zephyr/sys/util.h>
#include <zephyr/sys/barrier.h>
#include <zephyr/sys/atomic.h>

#include <zephyr/xen/events.h>
#include <zephyr/xen/generic.h>
#include <zephyr/xen/hvm.h>

LOG_MODULE_REGISTER(xenstore_cli);

#define SZ_SOCKMSG  sizeof(struct xsd_sockmsg)
#define SZ_FRAME(h) (SZ_SOCKMSG + h->len)

/* Per-call waiter: caller owns the semaphore, worker side just signals it. */
struct xenstore_response {
	sys_snode_t node;
	uint8_t *buf;
	size_t len;
	size_t pos;
	struct k_sem sem;
	uint32_t req_id;
	int err;
};

/*
 * Central client state shared by all APIs. Ring access and frame parsing are
 * funneled through the dedicated work queue thread, so most members only need
 * to be touched from a single context and can stay lock-free.
 */
struct xenstore_client {
	struct xenstore_domain_interface *domint;
	evtchn_port_t local_evtchn;

	k_timeout_t default_timeout;
	atomic_t next_req_id;
	size_t to_discard;

	struct k_spinlock lock;
	struct k_mutex req_mutex;

	/** Headers of the currently processed payload */
	uint8_t hdr_buf[SZ_SOCKMSG];
	size_t hdr_pos;

	uint8_t work_buf[XENSTORE_PAYLOAD_MAX + 1];
	struct xenstore_response work_resp;

	/* resp_list: pending synchronous requests waiting on the worker to signal. */
	sys_slist_t resp_list;
	/* notify_list: registered watchers fired from the same frame pipeline. */
	sys_slist_t notify_list;

	K_KERNEL_STACK_MEMBER(workq_stack, CONFIG_XEN_STORE_CLI_WORKQ_STACK_SIZE);
	struct k_work event_work;
	struct k_work_q workq;
	int workq_priority;
	bool workq_started;
};

static struct xenstore_client xs_cli;

/* Frame helpers keep the normal/exceptional paths from duplicating resets. */
static void xs_frame_reset(struct xenstore_client *xs)
{
	xs->hdr_pos = 0;
	xs->to_discard = 0;
	xs->work_resp.pos = 0;
	xs->work_resp.err = 0;
	xs->work_resp.len = 0;
}

/* Lazily size the scratch buffer so the owning waiter receives the right span. */
static void xs_frame_prepare_buffer(struct xenstore_client *xs, size_t capacity, uint32_t req_id)
{
	xs->work_resp.len = capacity;
	xs->work_resp.pos = 0;
	xs->work_resp.req_id = req_id;

	xs->work_resp.node.next = NULL;
	xs->work_resp.buf = xs->work_buf;
	xs->work_resp.err = 0;

	if (capacity > 0) {
		memset(xs->work_resp.buf, 0, capacity);
	}
}

static void xs_frame_mark_discard(struct xenstore_client *xs, size_t hdr_len)
{
	xs->hdr_pos = 0;
	/* Remember the unread tail so the worker drains it before parsing again. */
	xs->to_discard = hdr_len;
	xs->work_resp.pos = 0;
	xs->work_resp.err = 0;
	xs->work_resp.len = 0;
}

static inline bool xs_is_initialized(const struct xenstore_client *xs)
{
	return xs && (xs->domint != NULL);
}

static inline uint32_t alloc_req_id(void)
{
	uint32_t id = (atomic_inc(&xs_cli.next_req_id) & UINT32_MAX);

	/* id=0 is reserved for watch notification */
	if (id == 0) {
		id = (atomic_inc(&xs_cli.next_req_id) & UINT32_MAX);
	}

	return id;
}

static inline size_t ring_avail_for_read(struct xenstore_client *xs)
{
	struct xenstore_domain_interface *intf = xs->domint;

	z_barrier_dmem_fence_full();

	XENSTORE_RING_IDX cons = intf->rsp_cons;
	XENSTORE_RING_IDX prod = intf->rsp_prod;

	z_barrier_dmem_fence_full();
	if (xenstore_check_indexes(cons, prod)) {
		return 0;
	}

	return prod - cons;
}

static inline size_t ring_avail_for_write(struct xenstore_client *xs)
{
	struct xenstore_domain_interface *intf = xs->domint;

	z_barrier_dmem_fence_full();

	XENSTORE_RING_IDX cons = intf->req_cons;
	XENSTORE_RING_IDX prod = intf->req_prod;

	z_barrier_dmem_fence_full();

	if (xenstore_check_indexes(cons, prod)) {
		return 0;
	}

	return XENSTORE_RING_SIZE - (prod - cons);
}

static int ring_write_all(struct xenstore_client *xs, const void *buf, size_t len)
{
	const uint8_t *p = buf;
	size_t written = 0;

	while (written < len) {
		int rc = xenstore_ring_write(xs->domint, p + written, len - written, true);

		if (rc < 0) {
			return rc;
		}

		if (rc == 0) {
			k_yield();
			continue;
		}

		written += rc;
	}

	return written;
}

static int ring_read(struct xenstore_client *xenstore, void *data, size_t len)
{
	int ret;

	if (len == 0) {
		return 0;
	}

	ret = xenstore_ring_read(xenstore->domint, data, len, true);

	if (ret > 0) {
		notify_evtchn(xenstore->local_evtchn);
	}

	return ret;
}

static struct xenstore_response *lock_response(struct xenstore_client *xs, uint32_t req_id,
					       k_spinlock_key_t *key)
{
	sys_snode_t *n;

	*key = k_spin_lock(&xs->lock);

	SYS_SLIST_FOR_EACH_NODE(&xs->resp_list, n) {
		struct xenstore_response *resp = CONTAINER_OF(n, struct xenstore_response, node);

		if (resp->req_id == req_id) {
			return resp;
		}
	}

	k_spin_unlock(&xs->lock, *key);

	return NULL;
}

static void unlock_response(struct xenstore_client *xs, k_spinlock_key_t key)
{
	k_spin_unlock(&xs->lock, key);
}

/*
 * Read enough of the response header to determine which response context to use,
 * returning -EAGAIN when the header is still incomplete.
 */
static int prepare_response(struct xenstore_client *xs, size_t *avail)
{
	struct xsd_sockmsg *hdr = (struct xsd_sockmsg *)(xs->hdr_buf);
	int ret;

	LOG_DBG("avail=%zu hdr_pos=%zu", *avail, xs->hdr_pos);

	if (xs->hdr_pos < SZ_SOCKMSG) {
		const size_t hdr_to_read = MIN(SZ_SOCKMSG - xs->hdr_pos, *avail);

		ret = ring_read(xs, xs->hdr_buf + xs->hdr_pos, hdr_to_read);
		if (ret < 0) {
			LOG_ERR("ring_read failed: %d", ret);
			return ret;
		}

		xs->hdr_pos += ret;
		*avail -= ret;

		if (xs->hdr_pos < SZ_SOCKMSG) {
			LOG_DBG("header not ready");
			return -EAGAIN;
		}
	}

	if (hdr->type != XS_WATCH_EVENT) {
		struct xenstore_response *pending;
		k_spinlock_key_t key;

		pending = lock_response(xs, hdr->req_id, &key);
		if (!pending) {
			LOG_WRN("Discarding stale response type=%u req_id=%u len=%u", hdr->type,
				hdr->req_id, hdr->len);
			xs_frame_mark_discard(xs, hdr->len);
			return -ENOMSG;
		}

		if (xs->work_resp.pos == 0) {
			size_t capacity = MIN(pending->len, sizeof(xs->work_buf));

			xs_frame_prepare_buffer(xs, capacity, hdr->req_id);
		}

		unlock_response(xs, key);
	} else {
		if (xs->work_resp.pos == 0) {
			size_t capacity = MIN(hdr->len, sizeof(xs->work_buf));

			xs_frame_prepare_buffer(xs, capacity, hdr->req_id);
		}
	}

	return 0;
}

static int read_payload(struct xenstore_client *xs, size_t avail)
{
	struct xsd_sockmsg *hdr = (struct xsd_sockmsg *)(xs->hdr_buf);
	int ret;

	if (hdr->len > XENSTORE_PAYLOAD_MAX) {
		LOG_ERR("payload too large: %u > " STRINGIFY(XENSTORE_PAYLOAD_MAX), hdr->len);
		ret = -EMSGSIZE;
	} else if ((hdr->type != XS_WATCH_EVENT) && (hdr->req_id == 0)) {
		LOG_ERR("Invalid response header: req_id must be non-zero");
		ret = -EPROTO;
	} else if ((hdr->type == XS_WATCH_EVENT) && (hdr->req_id != 0)) {
		LOG_ERR("Invalid watch header: req_id=%u (expected 0)", hdr->req_id);
		ret = -EPROTO;
	} else if (hdr->len > xs->work_resp.len) {
		LOG_ERR("Response buffer too small: need %u bytes", hdr->len);
		ret = -EMSGSIZE;
	} else {
		ret = 0;
	}

	if (ret == 0) {
		const size_t remaining = hdr->len - xs->work_resp.pos;
		const size_t room = (xs->work_resp.len > xs->work_resp.pos)
					    ? xs->work_resp.len - xs->work_resp.pos
					    : 0;
		const size_t to_read = MIN(MIN(remaining, avail), room);

		ret = ring_read(xs, xs->work_resp.buf + xs->work_resp.pos, to_read);
		if (ret < 0) {
			LOG_ERR("ring_read failed while fetching type=%u req_id=%u: %d", hdr->type,
				hdr->req_id, ret);
		} else {
			xs->work_resp.pos += ret;

			if (ret < to_read) {
				return -EAGAIN; /* Wait for more data */
			}
		}
	}

	if (ret < 0) {
		if (hdr->type != XS_WATCH_EVENT) {
			k_spinlock_key_t key;
			struct xenstore_response *pending = lock_response(xs, hdr->req_id, &key);

			if (pending) {
				pending->err = ret;
				pending->pos = 0;
				k_sem_give(&pending->sem);
				unlock_response(xs, key);
			}
		}

		xs_frame_mark_discard(xs, hdr->len - MIN(xs->work_resp.pos, hdr->len));

		return ret;
	}

	if (xs->work_resp.pos < hdr->len) {
		return -EAGAIN; /* Wait for more data */
	}

	return 0;
}

static void dispatch_watcher_callback(struct xenstore_client *xs)
{
	const size_t payload_len = xs->work_resp.pos;
	const char *path = "";
	const char *token = "";
	k_spinlock_key_t key;
	sys_snode_t *node;

	/* Watches ride the same frame path; here we only parse the dual-string payload. */
	if (xs->work_resp.pos > 0) {
		const char *payload = xs->work_resp.buf;
		const char *sep = memchr(payload, '\0', payload_len);

		if (sep) {
			size_t token_len = xs->work_resp.pos - (size_t)(sep - payload) - 1;

			path = payload;
			token = (token_len > 0) ? sep + 1 : "";
		} else {
			/* Malformed payload – hand the raw buffer back as the path. */
			path = payload;
		}
	}

	/* Release the lock while invoking callbacks to avoid deadlocks. */
	key = k_spin_lock(&xs->lock);
	node = sys_slist_peek_head(&xs->notify_list);

	while (node) {
		struct xs_watcher *w = CONTAINER_OF(node, struct xs_watcher, node);
		sys_snode_t *next = sys_slist_peek_next(node);

		k_spin_unlock(&xs->lock, key);
		if (w->cb) {
			w->cb(path, token, w->param);
		}
		key = k_spin_lock(&xs->lock);

		node = next;
	}

	k_spin_unlock(&xs->lock, key);

	xs_frame_reset(xs);
}

/* Response path for synchronous callers: find the waiter, copy payload, signal its semaphore. */
static void response_to_request(struct xenstore_client *xs)
{
	struct xsd_sockmsg *hdr = (struct xsd_sockmsg *)(xs->hdr_buf);
	struct xenstore_response *pending;
	k_spinlock_key_t key;
	int err = 0;

	if (hdr->type == XS_ERROR) {
		err = xenstore_get_error(xs->work_resp.buf,
					 MIN(xs->work_resp.pos, sizeof(xs->work_buf)));
		if (err == 0) {
			err = -EINVAL;
		} else {
			err = -err;
		}
	}

	pending = lock_response(xs, xs->work_resp.req_id, &key);
	if (pending) {
		__ASSERT_NO_MSG(xs->work_resp.pos <= pending->len);

		memset(pending->buf, 0, pending->len);
		memcpy(pending->buf, xs->work_resp.buf, xs->work_resp.pos);

		pending->pos = xs->work_resp.pos;
		pending->err = err;

		k_sem_give(&pending->sem);
		unlock_response(xs, key);
	}

	xs_frame_reset(xs);
}

/*
 * Drop any unread bytes left in the ring after a failed transfer.
 * Ensures protocol violations do not poison the next frame parse.
 */
static int drain_ring(struct xenstore_client *xs)
{
	int ret = 0;

	if (xs->to_discard) {
		LOG_DBG("Draining %zu pending bytes", xs->to_discard);

		ret = ring_read(xs, NULL, xs->to_discard);
		if (ret < 0) {
			LOG_ERR("Failed to drain %zu pending bytes: %d", xs->to_discard, ret);
			return ret;
		}

		xs->to_discard -= (ret < xs->to_discard) ? ret : xs->to_discard;
	}

	return ret;
}

/*
 * Process a single XenStore frame. The worker repeats:
 *   1. prepare_response(): resolve the waiting requester / staging buffer
 *   2. read_payload():     pull body bytes, catching protocol violations
 *   3. dispatch:           synchronous waiter vs. watch notification
 * Requests and watches therefore share the same pipeline, differing only
 * at the final dispatch step.
 *
 * Returns 0 on success, -EAGAIN/-ENOMSG when the caller should retry, or any
 * other negative error to break out of the work loop.
 */
static int process_one_frame(struct xenstore_client *xs, size_t avail)
{
	struct xsd_sockmsg *hdr = (struct xsd_sockmsg *)(xs->hdr_buf);
	int ret;

	ret = prepare_response(xs, &avail);
	if (ret < 0) {
		return ret;
	}

	ret = read_payload(xs, avail);
	if (ret < 0) {
		return ret;
	}

	if (hdr->type != XS_WATCH_EVENT) {
		response_to_request(xs);
	} else {
		dispatch_watcher_callback(xs);
	}

	return 0;
}

static void event_work_handler(struct k_work *work)
{
	struct xenstore_client *xs = CONTAINER_OF(work, struct xenstore_client, event_work);
	size_t avail;
	int ret;

	/* Single-threaded pump: consume new bytes, parse at most one frame per iteration. */
	while ((avail = ring_avail_for_read(xs))) {
		ret = drain_ring(xs);
		if (ret < 0) {
			break;
		}

		avail -= ret;
		if (avail == 0) {
			continue;
		}

		ret = process_one_frame(xs, avail);
		if ((ret == -EAGAIN) || (ret == -ENOMSG)) {
			continue;
		} else if (ret < 0) {
			break;
		}

		ret = drain_ring(xs);
		if (ret < 0) {
			break;
		}
	}
}

static void event_callback(void *ptr)
{
	struct xenstore_client *xs = ptr;

	k_work_submit_to_queue(&xs->workq, &xs->event_work);
}

static size_t calc_param_write_size(const char *const *params, const size_t *param_lens,
				    size_t param_num, size_t index)
{
	if (!params || (index >= param_num)) {
		return 0;
	}

	if (param_lens) {
		return param_lens[index];
	}

	return strlen(params[index]) + 1;
}

static int prepare_request(struct xsd_sockmsg *hdr, enum xsd_sockmsg_type type,
			   const char *const *params, const size_t *param_lens, size_t param_num,
			   uint32_t req_id, uint32_t tx_id)
{
	size_t payload_len = 0;

	/* Header construction is pure: fail fast if the aggregate payload is too large. */
	for (size_t i = 0; i < param_num; i++) {
		payload_len += calc_param_write_size(params, param_lens, param_num, i);
	}

	if (payload_len > XENSTORE_PAYLOAD_MAX) {
		LOG_ERR("payload too large: %zu > " STRINGIFY(XENSTORE_PAYLOAD_MAX), payload_len);
		return -ENAMETOOLONG;
	}

	hdr->type = type;
	hdr->req_id = req_id;
	hdr->tx_id = tx_id;
	hdr->len = payload_len;

	return 0;
}

static int write_request(struct xenstore_client *xs, const struct xsd_sockmsg *hdr,
			 const char *const *params, const size_t *param_lens, size_t param_num)
{
	int err;

	err = ring_write_all(xs, hdr, sizeof(*hdr));
	if (err < 0) {
		LOG_ERR("ring_write_all(hdr) failed: %d", err);
		return err;
	}

	for (size_t i = 0; i < param_num; i++) {
		const size_t param_len = calc_param_write_size(params, param_lens, param_num, i);

		err = ring_write_all(xs, params[i], param_len);
		if (err < 0) {
			LOG_ERR("ring_write_all(param) failed: %d", err);
			return err;
		}
	}

	return 0;
}

static int submit_request(struct xenstore_client *xs, enum xsd_sockmsg_type type,
			  const char *const *params, const size_t *param_lens, size_t param_num,
			  uint32_t req_id, uint32_t tx_id)
{
	struct xsd_sockmsg hdr = {0};
	size_t avail;
	int err;
	int mutex_err;

	err = prepare_request(&hdr, type, params, param_lens, param_num, req_id, tx_id);
	if (err < 0) {
		return err;
	}

	mutex_err = k_mutex_lock(&xs->req_mutex, K_FOREVER);
	if (mutex_err != 0) {
		LOG_ERR("Failed to lock request mutex: %d", mutex_err);
		return mutex_err;
	}

	avail = ring_avail_for_write(xs);

	if (avail < (SZ_SOCKMSG + hdr.len)) {
		k_yield();
		avail = ring_avail_for_write(xs);
		if (avail < (SZ_SOCKMSG + hdr.len)) {
			LOG_ERR("ring_write: nospace: %zu < %zu", avail, SZ_SOCKMSG + hdr.len);
			err = -EAGAIN;
			goto end;
		}
	}

	err = write_request(xs, &hdr, params, param_lens, param_num);

end:
	k_mutex_unlock(&xs->req_mutex);

	return err;
}

static ssize_t execute_request(struct xenstore_client *xs, enum xsd_sockmsg_type type,
			       const char *const *params, const size_t *param_lens,
			       size_t params_num, char *buf, size_t len, uint32_t tx_id,
			       k_timeout_t timeout)
{
	/* Stack-allocated waiter: appended to resp_list, woken when matching response finalizes. */
	struct xenstore_response resp_local = {
		.node = {0},
		.buf = (uint8_t *)buf,
		.len = len,
		.pos = 0,
		.req_id = 0,
		.err = 0,
	};
	k_spinlock_key_t key;
	ssize_t result = 0;
	int err;

	if (!xs_is_initialized(xs)) {
		LOG_ERR("XenStore client not initialized");
		return -ENODEV;
	}

	resp_local.node.next = NULL;
	k_sem_init(&resp_local.sem, 0, 1);
	resp_local.req_id = alloc_req_id();

	/* Publish our waiter to the worker thread – it owns unblocking us. */
	key = k_spin_lock(&xs->lock);
	sys_slist_append(&xs->resp_list, &resp_local.node);
	k_spin_unlock(&xs->lock, key);

	err = submit_request(xs, type, params, param_lens, params_num, resp_local.req_id, tx_id);
	if (err < 0) {
		LOG_ERR("Failed to submit request: %d", err);

		key = k_spin_lock(&xs->lock);
		sys_slist_find_and_remove(&xs->resp_list, &resp_local.node);
		k_spin_unlock(&xs->lock, key);

		return err;
	}

	notify_evtchn(xs->local_evtchn);

	err = k_sem_take(&resp_local.sem, timeout);
	if (err != 0) {
		LOG_ERR("k_sem_take error: %d", err);

		key = k_spin_lock(&xs->lock);
		(void)sys_slist_find_and_remove(&xs->resp_list, &resp_local.node);
		k_spin_unlock(&xs->lock, key);

		return err;
	}

	key = k_spin_lock(&xs->lock);
	(void)sys_slist_find_and_remove(&xs->resp_list, &resp_local.node);
	k_spin_unlock(&xs->lock, key);

	if (resp_local.err < 0) {
		LOG_ERR("Error response: %d", resp_local.err);
		return resp_local.err;
	}

	if (resp_local.pos > 0) {
		result = MIN(len, resp_local.pos);
	}

	return result;
}

int xs_init(void)
{
	const struct k_work_queue_config qcfg = {.name = "xenstore-wq"};
	uint64_t paddr = 0;
	uint64_t value = 0;
	mm_reg_t vaddr = 0;
	int err;

	if (xs_cli.domint) {
		return 0;
	}

	atomic_set(&xs_cli.next_req_id, 1);
	xs_cli.workq_priority = CONFIG_XEN_STORE_CLI_WORKQ_PRIORITY;

	k_work_init(&xs_cli.event_work, event_work_handler);
	k_mutex_init(&xs_cli.req_mutex);

	if (!xs_cli.workq_started) {
		k_work_queue_init(&xs_cli.workq);
		k_work_queue_start(&xs_cli.workq, xs_cli.workq_stack,
				   K_THREAD_STACK_SIZEOF(xs_cli.workq_stack), xs_cli.workq_priority,
				   &qcfg);
		xs_cli.workq_started = true;
	}

	sys_slist_init(&xs_cli.notify_list);
	sys_slist_init(&xs_cli.resp_list);

	err = hvm_get_parameter(HVM_PARAM_STORE_EVTCHN, DOMID_SELF, &value);
	if (err) {
		LOG_ERR("hvm_get_parameter(STORE_EVTCHN) failed: %d", err);
		return -ENODEV;
	}
	xs_cli.local_evtchn = value;

	err = hvm_get_parameter(HVM_PARAM_STORE_PFN, DOMID_SELF, &paddr);
	if (err) {
		LOG_ERR("hvm_get_param(STORE_PFN) failed: err=%d", err);
		return -EIO;
	}

	device_map(&vaddr, XEN_PFN_PHYS(paddr), XEN_PAGE_SIZE, K_MEM_CACHE_WB | K_MEM_PERM_RW);
	if (vaddr == 0) {
		LOG_ERR("device_map failed.");
		return -EIO;
	}

	xs_cli.domint = (struct xenstore_domain_interface *)vaddr;

	while (ring_avail_for_read(&xs_cli)) {
		(void)ring_read(&xs_cli, NULL, ring_avail_for_read(&xs_cli));
	}

	err = bind_event_channel(xs_cli.local_evtchn, event_callback, &xs_cli);
	if (err) {
		LOG_ERR("bind_event_channel failed: %d", err);
		xs_cli.domint = NULL;
		return (err < 0) ? err : -EIO;
	}

	unmask_event_channel(xs_cli.local_evtchn);

	xs_cli.default_timeout = K_FOREVER;

	return 0;
}

void xs_set_default_timeout(k_timeout_t tout)
{
	xs_cli.default_timeout = tout;
}

void xs_watcher_init(struct xs_watcher *w, xs_watch_cb cb, void *param)
{
	if (!w) {
		return;
	}

	w->node.next = NULL;
	w->cb = cb;
	w->param = param;
}

int xs_watcher_register(struct xs_watcher *w)
{
	k_spinlock_key_t key;

	if (!w || !w->cb) {
		return -EINVAL;
	}

	if (!xs_is_initialized(&xs_cli)) {
		return -ENODEV;
	}

	key = k_spin_lock(&xs_cli.lock);
	sys_slist_append(&xs_cli.notify_list, &w->node);
	k_spin_unlock(&xs_cli.lock, key);

	return 0;
}

ssize_t xs_cmd_no_param_timeout(enum xsd_sockmsg_type type, const char *path, char *buf, size_t len,
				uint32_t tx_id, k_timeout_t tout)
{
	const char *const params[] = {path};

	if (!path || !buf || len == 0) {
		return -EINVAL;
	}

	return execute_request(&xs_cli, type, params, NULL, ARRAY_SIZE(params), buf, len, tx_id,
			       tout);
}

ssize_t xs_cmd_str_param_timeout(enum xsd_sockmsg_type type, const char *path, const char *str,
				 char *buf, size_t len, uint32_t tx_id, k_timeout_t tout)
{
	const char *const params[] = {path, str};

	if (!path || !str || !buf || len == 0) {
		return -EINVAL;
	}

	return execute_request(&xs_cli, type, params, NULL, ARRAY_SIZE(params), buf, len, tx_id,
			       tout);
}

ssize_t xs_read_timeout(const char *path, char *buf, size_t len, uint32_t tx_id, k_timeout_t tout)
{
	return xs_cmd_no_param_timeout(XS_READ, path, buf, len, tx_id, tout);
}

ssize_t xs_read(const char *path, char *buf, size_t len, uint32_t tx_id)
{
	return xs_cmd_no_param_timeout(XS_READ, path, buf, len, tx_id, xs_cli.default_timeout);
}

ssize_t xs_rm_timeout(const char *path, char *buf, size_t len, uint32_t tx_id, k_timeout_t tout)
{
	return xs_cmd_no_param_timeout(XS_RM, path, buf, len, tx_id, tout);
}

ssize_t xs_rm(const char *path, char *buf, size_t len, uint32_t tx_id)
{
	return xs_cmd_no_param_timeout(XS_RM, path, buf, len, tx_id, xs_cli.default_timeout);
}

ssize_t xs_directory_timeout(const char *path, char *buf, size_t len, uint32_t tx_id,
			     k_timeout_t tout)
{
	return xs_cmd_no_param_timeout(XS_DIRECTORY, path, buf, len, tx_id, tout);
}

ssize_t xs_directory(const char *path, char *buf, size_t len, uint32_t tx_id)
{
	return xs_cmd_no_param_timeout(XS_DIRECTORY, path, buf, len, tx_id, xs_cli.default_timeout);
}

ssize_t xs_get_permissions_timeout(const char *path, char *buf, size_t len, uint32_t tx_id,
				   k_timeout_t tout)
{
	return xs_cmd_no_param_timeout(XS_GET_PERMS, path, buf, len, tx_id, tout);
}

ssize_t xs_get_permissions(const char *path, char *buf, size_t len, uint32_t tx_id)
{
	return xs_cmd_no_param_timeout(XS_GET_PERMS, path, buf, len, tx_id, xs_cli.default_timeout);
}

ssize_t xs_watch_timeout(const char *path, const char *token, char *buf, size_t len, uint32_t tx_id,
			 k_timeout_t tout)
{
	return xs_cmd_str_param_timeout(XS_WATCH, path, token, buf, len, tx_id, tout);
}

ssize_t xs_watch(const char *path, const char *token, char *buf, size_t len, uint32_t tx_id)
{
	return xs_cmd_str_param_timeout(XS_WATCH, path, token, buf, len, tx_id,
					xs_cli.default_timeout);
}

ssize_t xs_unwatch_timeout(const char *path, const char *token, char *buf, size_t len,
			   uint32_t tx_id, k_timeout_t tout)
{
	return xs_cmd_str_param_timeout(XS_UNWATCH, path, token, buf, len, tx_id, tout);
}

ssize_t xs_unwatch(const char *path, const char *token, char *buf, size_t len, uint32_t tx_id)
{
	return xs_cmd_str_param_timeout(XS_UNWATCH, path, token, buf, len, tx_id,
					xs_cli.default_timeout);
}

ssize_t xs_write_timeout(const char *path, const char *value, size_t value_len, char *buf,
			 size_t len, uint32_t tx_id, k_timeout_t tout)
{
	const char *const params[] = {path, value};
	const size_t param_lens[] = {
		strlen(path) + 1,
		value_len,
	};

	if (!path || !value || !buf || len == 0) {
		return -EINVAL;
	}

	return execute_request(&xs_cli, XS_WRITE, params, param_lens, ARRAY_SIZE(params), buf, len,
			       tx_id, tout);
}

ssize_t xs_write(const char *path, const char *value, size_t value_len, char *buf, size_t len,
		 uint32_t tx_id)
{
	return xs_write_timeout(path, value, value_len, buf, len, tx_id, xs_cli.default_timeout);
}

ssize_t xs_set_permissions_timeout(const char *path, const char **perms, size_t perms_num,
				   char *buf, size_t len, uint32_t tx_id, k_timeout_t tout)
{
	const char *params[perms_num + 1];

	params[0] = path;

	for (size_t i = 1; i < (perms_num + 1); i++) {
		params[i] = perms[i - 1];
	}

	if (!path || !buf || len == 0) {
		return -EINVAL;
	}

	return execute_request(&xs_cli, XS_SET_PERMS, (const char *const *)params, NULL,
			       perms_num + 1, buf, len, tx_id, tout);
}

ssize_t xs_set_permissions(const char *path, const char **perms, size_t perms_num, char *buf,
			   size_t len, uint32_t tx_id)
{
	return xs_set_permissions_timeout(path, perms, perms_num, buf, len, tx_id,
					  xs_cli.default_timeout);
}
