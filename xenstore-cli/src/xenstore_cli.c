/*
 * Copyright (c) 2025 TOKITA Hiroshi
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <ctype.h>
#include <errno.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#include <xen/public/io/xs_wire.h>
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

/* XenStore frames always start with struct xsd_sockmsg followed by payload bytes. */
#define SZ_SOCKMSG               sizeof(struct xsd_sockmsg)
#define SZ_FRAME(h)              (SZ_SOCKMSG + h->len)
/* Keep the fixed stack buffers for typed set-perms serialization bounded. */
#define XS_SET_PERMS_MAX_ENTRIES 32
/* Longest supported wire permission string: one access char plus 10 digit domid plus NUL. */
#define XS_PERM_WIRE_ENTRY_MAX   12
/* Longest XenStore error name, including its trailing NUL. */
#define XS_ERROR_WIRE_MAX        sizeof("ENOTEMPTY")
/* Soft retry used to catch replies when no extra event interrupt arrives. */
#define XS_RING_RETRY_DELAY      K_MSEC(10)
/* Bounded set of already-submitted request ids whose caller timed out locally. */
#define XS_TIMED_OUT_REQ_IDS_MAX 64
/* Bound one workqueue turn so equal-priority callers can observe their timeouts. */
#define XS_EVENT_WORK_MAX_LOOPS  32

/*
 * Per-call waiter for one synchronous request. Caller threads allocate this on
 * their own stack, publish it in xenstore_client.pending_responses, then block on sem.
 * The workqueue owns matching replies by req_id and only signals completion.
 */
struct pending_response {
	/* Node in xenstore_client.pending_responses while the caller waits for a reply. */
	sys_snode_t node;
	/* Caller-owned response buffer where the workqueue copies reply payload. */
	uint8_t *buf;
	/* Capacity of buf in bytes. */
	size_t len;
	/* Number of reply payload bytes copied into buf. */
	size_t pos;
	/* Posted by the workqueue when this request completes or fails. */
	struct k_sem sem;
	/* Non-zero XenStore request id used to match the backend reply. */
	uint32_t req_id;
	/* Response type expected for this request; XS_ERROR is also accepted. */
	enum xsd_sockmsg_type expected_type;
	/* Completion status; zero on success, negative errno on failure. */
	int err;
};

/*
 * Workqueue-owned frame being assembled from the response ring. It describes
 * the bytes currently staged in xenstore_client.work_buf; it is not a waiter
 * and is never linked into xenstore_client.pending_responses.
 */
struct response_frame {
	/* Staging buffer where the workqueue assembles one payload. */
	uint8_t *buf;
	/* Capacity of buf in bytes. */
	size_t len;
	/* Number of payload bytes already copied into buf. */
	size_t pos;
	/* Request id from the frame header, or zero for watch events. */
	uint32_t req_id;
	/* Expected frame type for the current staged response. */
	enum xsd_sockmsg_type expected_type;
};

/*
 * Central client state shared by all APIs. Ring access and frame parsing are
 * funneled through the dedicated work queue thread, so most members only need
 * to be touched from a single context and can stay lock-free.
 */
struct xenstore_client {
	/* Mapped XenStore shared ring page; request-side use is under req_mutex. */
	struct xenstore_domain_interface *domint;
	/* Local event-channel port used to notify the XenStore backend. */
	evtchn_port_t local_evtchn;
	/* Readiness flag published after xs_init() completes; protected by lock. */
	bool initialized;

	/* Timeout used by API wrappers that do not take an explicit timeout. */
	k_timeout_t default_timeout;
	/* Monotonic source of non-zero request ids. */
	atomic_t next_req_id;
	/* Remaining payload bytes to discard after a failed frame read. */
	size_t to_discard;

	/* Protects readiness, response waiters, watcher callbacks, and watcher state flags. */
	struct k_spinlock lock;
	/* Serializes request-ring writes and domint teardown against active submitters. */
	struct k_mutex req_mutex;

	/* Partially received XenStore response header. */
	uint8_t hdr_buf[SZ_SOCKMSG] __aligned(4);
	/* Bytes currently present in hdr_buf. */
	size_t hdr_pos;

	/* Workqueue-owned staging buffer for one reply or watch-event payload. */
	uint8_t work_buf[XENSTORE_PAYLOAD_MAX + 1];
	/* Metadata for the payload currently staged in work_buf. */
	struct response_frame frame;

	/* Pending synchronous requests waiting for matching replies. */
	sys_slist_t pending_responses;
	/* Request ids whose callers timed out after the request reached XenStore. */
	uint32_t timed_out_req_ids[XS_TIMED_OUT_REQ_IDS_MAX];
	/* Local callbacks receiving all watch events delivered to this client. */
	sys_slist_t notify_list;
	/*
	 * Current watch-event dispatch generation; protected by lock.
	 *
	 * A watcher with the same dispatch_gen has already been selected for the
	 * event currently staged in work_buf. This avoids keeping list cursors
	 * across callback calls, because callbacks run with xs->lock released and
	 * may unregister watchers.
	 */
	uint32_t watch_dispatch_gen;

	/* Work item submitted by the event-channel callback and request submit path. */
	struct k_work event_work;
	/* Sleep-based retry used when callers wait but the response ring is empty. */
	struct k_work_delayable retry_work;
	/* Dedicated workqueue that drains the response ring. */
	struct k_work_q workq;
	/* Configured priority for the response workqueue thread. */
	int workq_priority;
	/* True after xs_init() starts workq; used only to avoid a second start. */
	bool workq_started;
	/* True after local_evtchn has been bound and must be unbound on teardown. */
	bool evtchn_bound;
};

static struct xenstore_client xs_cli;
/*
 * Keep the workqueue stack as a real kernel stack object. Embedding it inside
 * struct xenstore_client can place it outside the architecture-specific stack
 * sections that Zephyr expects on ARM64 exception entry.
 */
static K_KERNEL_STACK_DEFINE(xs_workq_stack, CONFIG_XEN_STORE_CLI_WORKQ_STACK_SIZE);
static K_MUTEX_DEFINE(xs_init_lock);

/*
 * Helper sections:
 *
 * - Common helpers used by several client paths.
 * - Pending synchronous request waiters matched by backend req_id.
 * - Client lifecycle, readiness, and transport teardown.
 * - Response-ring draining, frame assembly, and watch dispatch.
 * - Request-frame construction, submission, and synchronous wait.
 */

/*
 * Common helpers cover small conversions and state resets shared by
 * more than one pipeline stage. Keeping them first avoids local forward
 * declarations for client/request/response blocks below.
 */

/* Convert the public permission enum to XenStore's one-character wire form. */
static int perm_to_wire(enum xs_permission perm, char *wire)
{
	switch (perm) {
	case XS_PERMISSION_NONE:
		*wire = 'n';
		return 0;
	case XS_PERMISSION_READ:
		*wire = 'r';
		return 0;
	case XS_PERMISSION_WRITE:
		*wire = 'w';
		return 0;
	case XS_PERMISSION_READ_WRITE:
		*wire = 'b';
		return 0;
	default:
		return -EINVAL;
	}
}

/* Convert XenStore's one-character permission form to the public enum. */
static int perm_from_wire(char wire, enum xs_permission *perm)
{
	if (!perm) {
		return -EINVAL;
	}

	switch (wire) {
	case 'n':
		*perm = XS_PERMISSION_NONE;
		return 0;
	case 'r':
		*perm = XS_PERMISSION_READ;
		return 0;
	case 'w':
		*perm = XS_PERMISSION_WRITE;
		return 0;
	case 'b':
		*perm = XS_PERMISSION_READ_WRITE;
		return 0;
	default:
		return -EINVAL;
	}
}

/* Parse a NUL-separated XS_GET_PERMS payload into typed permission entries. */
static ssize_t perm_parse_wire(const char *raw, size_t raw_len, struct xs_permission_entry *perms,
			       size_t perms_num)
{
	size_t copied = 0;

	if (!raw || !perms || perms_num == 0) {
		return -EINVAL;
	}

	for (size_t off = 0; off < raw_len;) {
		enum xs_permission perm;
		unsigned long domid;
		const char *entry = raw + off;
		size_t entry_len = strnlen(entry, raw_len - off);
		char *endptr;
		int ret;

		if (entry_len == (raw_len - off)) {
			return -EPROTO;
		}

		if (entry_len < 2) {
			return -EPROTO;
		}

		if (copied >= perms_num) {
			return -ENOSPC;
		}

		ret = perm_from_wire(entry[0], &perm);
		if (ret < 0) {
			return ret;
		}

		if (!isdigit((unsigned char)entry[1])) {
			return -EPROTO;
		}

		errno = 0;
		domid = strtoul(entry + 1, &endptr, 10);
		if ((endptr == (entry + 1)) || (*endptr != '\0') || (errno == ERANGE) ||
		    (domid > UINT32_MAX)) {
			return -EPROTO;
		}

		perms[copied].domid = (uint32_t)domid;
		perms[copied].perm = perm;
		copied++;
		off += entry_len + 1;
	}

	return copied;
}

/* Reset the staged response frame state. */
static void frame_reset(struct xenstore_client *xs)
{
	xs->hdr_pos = 0;
	xs->to_discard = 0;
	xs->frame.pos = 0;
	xs->frame.len = 0;
	xs->frame.expected_type = XS_ERROR;
}

/*
 * Pending-response helpers manage caller-owned waiters while the response
 * worker matches backend replies by req_id and wakes exactly the blocked
 * request thread.
 */

/* Find a pending response waiter by request id. */
static struct pending_response *find_pending_and_lock(struct xenstore_client *xs, uint32_t req_id,
						      k_spinlock_key_t *key)
{
	sys_snode_t *n;

	*key = k_spin_lock(&xs->lock);

	SYS_SLIST_FOR_EACH_NODE(&xs->pending_responses, n) {
		struct pending_response *resp = CONTAINER_OF(n, struct pending_response, node);

		if (resp->req_id == req_id) {
			return resp;
		}
	}

	k_spin_unlock(&xs->lock, *key);

	return NULL;
}

/* Release a response-list lookup. */
static void unlock_pending(struct xenstore_client *xs, k_spinlock_key_t key)
{
	k_spin_unlock(&xs->lock, key);
}

static size_t pending_count_locked(struct xenstore_client *xs)
{
	size_t count = 0;
	sys_snode_t *n;

	SYS_SLIST_FOR_EACH_NODE(&xs->pending_responses, n) {
		count++;
	}

	return count;
}

static size_t timed_out_count_locked(struct xenstore_client *xs)
{
	size_t count = 0;

	for (size_t i = 0; i < XS_TIMED_OUT_REQ_IDS_MAX; i++) {
		if (xs->timed_out_req_ids[i] != 0) {
			count++;
		}
	}

	return count;
}

static bool request_slots_full_locked(struct xenstore_client *xs)
{
	return (pending_count_locked(xs) + timed_out_count_locked(xs)) >= XS_TIMED_OUT_REQ_IDS_MAX;
}

/* Publish one caller-owned waiter before writing its request frame. */
static int publish_pending(struct xenstore_client *xs, struct pending_response *resp)
{
	k_spinlock_key_t key;
	int err = 0;

	key = k_spin_lock(&xs->lock);
	if (request_slots_full_locked(xs)) {
		err = -EBUSY;
	} else {
		sys_slist_append(&xs->pending_responses, &resp->node);
	}
	k_spin_unlock(&xs->lock, key);

	return err;
}

/* Remember an abandoned, already-submitted request id while xs->lock is held. */
static bool remember_timed_out_locked(struct xenstore_client *xs, uint32_t req_id)
{
	size_t slot = XS_TIMED_OUT_REQ_IDS_MAX;

	for (size_t i = 0; i < XS_TIMED_OUT_REQ_IDS_MAX; i++) {
		if (xs->timed_out_req_ids[i] == req_id) {
			return true;
		}

		if ((slot == XS_TIMED_OUT_REQ_IDS_MAX) && (xs->timed_out_req_ids[i] == 0)) {
			slot = i;
		}
	}

	if (slot == XS_TIMED_OUT_REQ_IDS_MAX) {
		return false;
	}

	xs->timed_out_req_ids[slot] = req_id;
	return true;
}

/* Remove one caller-owned waiter after submit failure or local timeout. */
static void remove_pending(struct xenstore_client *xs, struct pending_response *resp)
{
	k_spinlock_key_t key;

	key = k_spin_lock(&xs->lock);
	(void)sys_slist_find_and_remove(&xs->pending_responses, &resp->node);
	k_spin_unlock(&xs->lock, key);
}

/* Move a submitted waiter to the timeout tombstone set. */
static void timeout_pending(struct xenstore_client *xs, struct pending_response *resp)
{
	k_spinlock_key_t key;
	bool tombstone_missing = false;

	key = k_spin_lock(&xs->lock);
	if (sys_slist_find_and_remove(&xs->pending_responses, &resp->node)) {
		if (!remember_timed_out_locked(xs, resp->req_id)) {
			tombstone_missing = true;
		}
	}
	k_spin_unlock(&xs->lock, key);

	if (tombstone_missing) {
		LOG_ERR("No tombstone slot for timed-out req_id=%u", resp->req_id);
	}
}

/* Consume a timed-out request id when its late backend response arrives. */
static bool consume_timed_out(struct xenstore_client *xs, uint32_t req_id)
{
	k_spinlock_key_t key;
	bool found = false;

	key = k_spin_lock(&xs->lock);
	for (size_t i = 0; i < XS_TIMED_OUT_REQ_IDS_MAX; i++) {
		if (xs->timed_out_req_ids[i] == req_id) {
			xs->timed_out_req_ids[i] = 0;
			found = true;
			break;
		}
	}
	k_spin_unlock(&xs->lock, key);

	return found;
}

/* Check whether any synchronous caller is still waiting for a reply. */
static bool has_pending_waiters(struct xenstore_client *xs)
{
	bool has_pending;
	k_spinlock_key_t key;

	key = k_spin_lock(&xs->lock);
	has_pending = !sys_slist_is_empty(&xs->pending_responses);
	k_spin_unlock(&xs->lock, key);

	return has_pending;
}

/* Wake every caller still waiting for a synchronous response. */
static void fail_all_pending(struct xenstore_client *xs, int err)
{
	k_spinlock_key_t key;
	sys_snode_t *node;

	key = k_spin_lock(&xs->lock);
	SYS_SLIST_FOR_EACH_NODE(&xs->pending_responses, node) {
		struct pending_response *resp = CONTAINER_OF(node, struct pending_response, node);

		resp->err = err;
		resp->pos = 0;
		k_sem_give(&resp->sem);
	}

	sys_slist_init(&xs->pending_responses);
	k_spin_unlock(&xs->lock, key);
}

/*
 * Client readiness helpers publish the boundary between an unmapped transport
 * and a client that may accept public API requests or response work.
 */

/* Return whether transport setup completed. */
static bool is_ready(struct xenstore_client *xs)
{
	bool initialized;
	k_spinlock_key_t key;

	if (!xs) {
		return false;
	}

	key = k_spin_lock(&xs->lock);
	initialized = xs->initialized;
	k_spin_unlock(&xs->lock, key);

	return initialized;
}

/* Publish or revoke client readiness. */
static void set_ready(struct xenstore_client *xs, bool initialized)
{
	k_spinlock_key_t key;

	key = k_spin_lock(&xs->lock);
	xs->initialized = initialized;
	k_spin_unlock(&xs->lock, key);
}

/*
 * Client fatal-error helpers revoke readiness, disconnect the shared transport,
 * and unblock waiters so public API calls do not sleep forever after a protocol
 * or ring error.
 */

/* Tear down transport state. */
static void teardown_transport(struct xenstore_client *xs)
{
	int mutex_err = k_mutex_lock(&xs->req_mutex, K_FOREVER);

	if (mutex_err != 0) {
		LOG_ERR("Failed to lock request mutex during teardown: %d", mutex_err);
		return;
	}

	set_ready(xs, false);
	frame_reset(xs);

	if (xs->evtchn_bound) {
		unbind_event_channel(xs->local_evtchn);
		xs->evtchn_bound = false;
	}

	if (xs->domint) {
		device_unmap((mm_reg_t)xs->domint, XEN_PAGE_SIZE);
		xs->domint = NULL;
	}

	k_mutex_unlock(&xs->req_mutex);
}

/* Tear down transport and wake waiters. */
static void fail_transport(struct xenstore_client *xs, int err)
{
	teardown_transport(xs);
	fail_all_pending(xs, err);
}

/*
 * Response-frame state helpers own the temporary header/payload bookkeeping
 * used while the workqueue assembles one backend frame from the response ring.
 */

/* Prepare workqueue-owned frame state; caller must serialize response-frame parsing. */
static void prepare_frame_buffer(struct xenstore_client *xs, size_t capacity, uint32_t req_id,
				 enum xsd_sockmsg_type expected_type)
{
	xs->frame.len = capacity;
	xs->frame.pos = 0;
	xs->frame.req_id = req_id;
	xs->frame.expected_type = expected_type;

	xs->frame.buf = xs->work_buf;

	if (capacity > 0) {
		memset(xs->frame.buf, 0, capacity);
	}
}

/* Mark unread frame bytes; caller must serialize response-frame parsing. */
static void discard_frame_tail(struct xenstore_client *xs, size_t hdr_len)
{
	xs->hdr_pos = 0;
	/* Remember the unread tail so the worker drains it before parsing again. */
	xs->to_discard = hdr_len;
	xs->frame.pos = 0;
	xs->frame.len = 0;
}

/*
 * Response-ring helpers read backend-produced bytes from the shared page. The
 * response worker owns normal use; xs_init() also uses them before interrupts
 * are enabled to discard any stale boot-time bytes.
 */

/*
 * Read response-ring indexes. Caller must ensure xs->domint stays mapped,
 * either from the response worker or during xs_init() before the event channel
 * is bound.
 */
static inline int response_ring_available(struct xenstore_client *xs, size_t *avail)
{
	struct xenstore_domain_interface *intf = xs->domint;

	z_barrier_dmem_fence_full();

	XENSTORE_RING_IDX cons = intf->rsp_cons;
	XENSTORE_RING_IDX prod = intf->rsp_prod;

	z_barrier_dmem_fence_full();
	if (xenstore_check_indexes(cons, prod)) {
		LOG_ERR("XenStore ring index out of range (rsp): cons=%u prod=%u", (uint32_t)cons,
			(uint32_t)prod);
		*avail = 0;
		return -EIO;
	}

	*avail = prod - cons;
	return 0;
}

/*
 * Read response-ring bytes. Caller must ensure xs->domint stays mapped, either
 * from the response worker or during xs_init() before the event channel is
 * bound.
 */
static int response_ring_read(struct xenstore_client *xenstore, void *data, size_t len)
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

/*
 * Response-frame pump helpers turn raw response-ring bytes into either a
 * completed synchronous reply or a watch event. These helpers run only on the
 * private workqueue, which keeps partial header/payload state serialized.
 */

/* Read enough bytes to complete the response header. */
static int read_frame_header(struct xenstore_client *xs, size_t *avail)
{
	struct xsd_sockmsg *hdr = (struct xsd_sockmsg *)(xs->hdr_buf);
	int ret;

	LOG_DBG("avail=%zu hdr_pos=%zu", *avail, xs->hdr_pos);

	if (xs->hdr_pos < SZ_SOCKMSG) {
		const size_t hdr_to_read = MIN(SZ_SOCKMSG - xs->hdr_pos, *avail);

		ret = response_ring_read(xs, xs->hdr_buf + xs->hdr_pos, hdr_to_read);
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

	if (hdr->len > XENSTORE_PAYLOAD_MAX) {
		LOG_ERR("payload too large: %u > " STRINGIFY(XENSTORE_PAYLOAD_MAX), hdr->len);
		fail_transport(xs, -EMSGSIZE);
		return -EMSGSIZE;
	}

	return 0;
}

/* Select the pending waiter or watch buffer that will receive the payload. */
static int select_frame_buffer(struct xenstore_client *xs)
{
	struct xsd_sockmsg *hdr = (struct xsd_sockmsg *)(xs->hdr_buf);

	if (hdr->type != XS_WATCH_EVENT) {
		struct pending_response *pending;
		k_spinlock_key_t key;

		pending = find_pending_and_lock(xs, hdr->req_id, &key);
		if (!pending) {
			if (consume_timed_out(xs, hdr->req_id)) {
				LOG_DBG("Discarding timed-out response type=%u req_id=%u len=%u",
					hdr->type, hdr->req_id, hdr->len);
			} else {
				LOG_WRN("Discarding stale response type=%u req_id=%u len=%u",
					hdr->type, hdr->req_id, hdr->len);
			}
			discard_frame_tail(xs, hdr->len - MIN(xs->frame.pos, hdr->len));
			return -ENOMSG;
		}

		if (xs->frame.pos == 0) {
			size_t capacity = MIN(pending->len, sizeof(xs->work_buf));

			prepare_frame_buffer(xs, capacity, hdr->req_id, pending->expected_type);
		}

		unlock_pending(xs, key);
	} else {
		if (xs->frame.pos == 0) {
			size_t capacity = MIN(hdr->len, sizeof(xs->work_buf));

			prepare_frame_buffer(xs, capacity, hdr->req_id, XS_WATCH_EVENT);
		}
	}

	return 0;
}

/* Validate the prepared frame before reading its payload. */
static int validate_frame_payload(struct xenstore_client *xs, const struct xsd_sockmsg *hdr,
				  bool *fatal)
{
	*fatal = false;

	if ((hdr->type != XS_WATCH_EVENT) && (hdr->req_id == 0)) {
		LOG_ERR("Invalid response header: req_id must be non-zero");
		*fatal = true;
		return -EPROTO;
	}

	if ((hdr->type == XS_WATCH_EVENT) && (hdr->req_id != 0)) {
		LOG_ERR("Invalid watch header: req_id=%u (expected 0)", hdr->req_id);
		*fatal = true;
		return -EPROTO;
	}

	if ((hdr->type != XS_ERROR) && (hdr->type != xs->frame.expected_type)) {
		LOG_ERR("Unexpected response type: got=%u expected=%u req_id=%u", hdr->type,
			xs->frame.expected_type, hdr->req_id);
		*fatal = true;
		return -EPROTO;
	}

	if (hdr->len > xs->frame.len) {
		LOG_ERR("Response buffer too small: need %u bytes", hdr->len);
		return -EMSGSIZE;
	}

	return 0;
}

/* Read currently available payload bytes from the response ring. */
static int read_available_payload(struct xenstore_client *xs, const struct xsd_sockmsg *hdr,
				  size_t avail, bool *fatal)
{
	const size_t remaining = hdr->len - xs->frame.pos;
	const size_t room = (xs->frame.len > xs->frame.pos) ? xs->frame.len - xs->frame.pos : 0;
	const size_t to_read = MIN(MIN(remaining, avail), room);
	int ret;

	if (to_read == 0) {
		return 0;
	}

	ret = response_ring_read(xs, xs->frame.buf + xs->frame.pos, to_read);
	if (ret < 0) {
		LOG_ERR("ring_read failed while fetching type=%u req_id=%u: %d", hdr->type,
			hdr->req_id, ret);
		*fatal = true;
		return ret;
	}

	xs->frame.pos += ret;

	if (ret < to_read) {
		return -EAGAIN;
	}

	return 0;
}

/* Fail the synchronous waiter associated with the current frame. */
static void fail_pending_from_frame(struct xenstore_client *xs, const struct xsd_sockmsg *hdr,
				    int err)
{
	k_spinlock_key_t key;
	struct pending_response *pending = find_pending_and_lock(xs, hdr->req_id, &key);

	if (pending) {
		(void)sys_slist_find_and_remove(&xs->pending_responses, &pending->node);
		pending->err = err;
		pending->pos = 0;
		k_sem_give(&pending->sem);
		unlock_pending(xs, key);
	}
}

/* Apply a payload-read failure to transport or waiter state. */
static int fail_frame_payload(struct xenstore_client *xs, const struct xsd_sockmsg *hdr, int err,
			      bool fatal)
{
	if (fatal) {
		fail_transport(xs, err);
		return err;
	}

	if (hdr->type != XS_WATCH_EVENT) {
		fail_pending_from_frame(xs, hdr, err);
	}

	discard_frame_tail(xs, hdr->len - MIN(xs->frame.pos, hdr->len));

	return err;
}

/* Read current frame payload; caller must be the serialized response worker. */
static int read_frame_payload(struct xenstore_client *xs, size_t avail)
{
	struct xsd_sockmsg *hdr = (struct xsd_sockmsg *)(xs->hdr_buf);
	bool fatal;
	int ret;

	ret = validate_frame_payload(xs, hdr, &fatal);
	if (ret < 0) {
		return fail_frame_payload(xs, hdr, ret, fatal);
	}

	ret = read_available_payload(xs, hdr, avail, &fatal);
	if (ret < 0) {
		if (ret == -EAGAIN) {
			return ret;
		}

		return fail_frame_payload(xs, hdr, ret, fatal);
	}

	if (xs->frame.pos < hdr->len) {
		return -EAGAIN; /* Wait for more data */
	}

	xs->frame.buf[hdr->len] = '\0';

	return 0;
}

/* Dispatch a completed watch-event frame; caller must be the response worker. */
static void watch_event_dispatch(struct xenstore_client *xs)
{
	const size_t payload_len = xs->frame.pos;
	const char *path = "";
	const char *token = "";
	k_spinlock_key_t key;
	uint32_t dispatch_gen;

	/* Watches ride the same frame path; here we only parse the dual-string payload. */
	if (xs->frame.pos > 0) {
		const char *payload = xs->frame.buf;
		const char *sep = memchr(payload, '\0', payload_len);

		if (sep) {
			size_t token_len = xs->frame.pos - (size_t)(sep - payload) - 1;

			path = payload;
			token = (token_len > 0) ? sep + 1 : "";
		} else {
			/* Malformed payload – hand the raw buffer back as the path. */
			path = payload;
		}
	}

	/*
	 * Start a new dispatch generation for this watch event. Each watcher is
	 * stamped before its callback runs, then the lock is released for the
	 * callback. When control returns, the list may have changed, so the worker
	 * re-scans currently registered watchers and skips descriptors already
	 * stamped with this generation.
	 */
	key = k_spin_lock(&xs->lock);
	dispatch_gen = xs->watch_dispatch_gen + 1;
	if (dispatch_gen == 0) {
		sys_snode_t *node;

		/* Keep zero as the freshly initialized marker after wraparound. */
		SYS_SLIST_FOR_EACH_NODE(&xs->notify_list, node) {
			struct xs_watcher *w = CONTAINER_OF(node, struct xs_watcher, node);

			w->dispatch_gen = 0;
		}

		dispatch_gen = 1;
	}
	xs->watch_dispatch_gen = dispatch_gen;

	while (true) {
		struct xs_watcher *w = NULL;
		sys_snode_t *node;

		SYS_SLIST_FOR_EACH_NODE(&xs->notify_list, node) {
			struct xs_watcher *candidate = CONTAINER_OF(node, struct xs_watcher, node);

			if (candidate->dispatch_gen != dispatch_gen) {
				w = candidate;
				break;
			}
		}

		if (!w) {
			break;
		}

		/* Clear any old completion signal before publishing callback_running. */
		k_sem_reset(&w->callback_idle);
		w->dispatch_gen = dispatch_gen;
		w->callback_running = true;
		k_spin_unlock(&xs->lock, key);

		if (w->cb) {
			w->cb(path, token, w->param);
		}

		key = k_spin_lock(&xs->lock);
		w->callback_running = false;
		k_sem_give(&w->callback_idle);
	}

	k_spin_unlock(&xs->lock, key);

	frame_reset(xs);
}

/* Complete a synchronous response; caller must be the response worker. */
static void complete_pending_from_frame(struct xenstore_client *xs)
{
	struct xsd_sockmsg *hdr = (struct xsd_sockmsg *)(xs->hdr_buf);
	struct pending_response *pending;
	k_spinlock_key_t key;
	int err = 0;

	if (hdr->type == XS_ERROR) {
		err = xenstore_get_error(xs->frame.buf, MIN(xs->frame.pos, sizeof(xs->work_buf)));
		if (err == 0) {
			err = -EINVAL;
		} else {
			err = -err;
		}
	}

	pending = find_pending_and_lock(xs, xs->frame.req_id, &key);
	if (pending) {
		__ASSERT_NO_MSG(xs->frame.pos <= pending->len);

		(void)sys_slist_find_and_remove(&xs->pending_responses, &pending->node);
		pending->pos = 0;
		pending->err = err;

		if (err == 0) {
			if (xs->frame.pos > pending->len) {
				pending->err = -ENOSPC;
			} else {
				memcpy(pending->buf, xs->frame.buf, xs->frame.pos);
				pending->pos = xs->frame.pos;
				if (pending->pos < pending->len) {
					pending->buf[pending->pos] = '\0';
				}
			}
		}

		k_sem_give(&pending->sem);
		unlock_pending(xs, key);
	}

	frame_reset(xs);
}

/*
 * Drop any unread bytes left in the ring after a failed transfer. Caller must
 * be the serialized response worker so frame state cannot change concurrently.
 */
static int drain_frame_tail(struct xenstore_client *xs)
{
	int ret = 0;

	if (xs->to_discard) {
		LOG_DBG("Draining %zu pending bytes", xs->to_discard);

		ret = response_ring_read(xs, NULL, xs->to_discard);
		if (ret < 0) {
			LOG_ERR("Failed to drain %zu pending bytes: %d", xs->to_discard, ret);
			return ret;
		}

		xs->to_discard -= (ret < xs->to_discard) ? ret : xs->to_discard;
	}

	return ret;
}

/*
 * Response-work scheduling helpers are the only places that enqueue the
 * private workqueue. They keep interrupt callbacks, request submitters, and
 * retry paths from knowing the exact Zephyr work item used to drain replies.
 */

/* Schedule the response-ring worker after xs_init() has started the private queue. */
static void submit_response_work(struct xenstore_client *xs)
{
	(void)k_work_submit_to_queue(&xs->workq, &xs->event_work);
}

/* Schedule a soft response-ring retry without busy-waiting on an empty ring. */
static void schedule_response_retry(struct xenstore_client *xs)
{
	(void)k_work_reschedule_for_queue(&xs->workq, &xs->retry_work, XS_RING_RETRY_DELAY);
}

/*
 * Process a single XenStore frame. Caller must be the serialized response
 * worker. The frame pipeline repeats:
 *   1. read_frame_header(): complete the wire header
 *   2. select_frame_buffer(): resolve requester / staging buffer
 *   3. read_frame_payload(): pull body bytes and validate framing
 *   4. dispatch: synchronous waiter vs. watch notification
 * Requests and watches therefore share the same pipeline, differing only
 * at the final dispatch step.
 *
 * Returns 0 on success, -EAGAIN/-ENOMSG when the caller should retry, or any
 * other negative error to break out of the work loop.
 */
static int process_one_response_frame(struct xenstore_client *xs, size_t avail)
{
	struct xsd_sockmsg *hdr = (struct xsd_sockmsg *)(xs->hdr_buf);
	int ret;

	ret = read_frame_header(xs, &avail);
	if (ret < 0) {
		return ret;
	}

	ret = select_frame_buffer(xs);
	if (ret < 0) {
		return ret;
	}

	ret = read_frame_payload(xs, avail);
	if (ret < 0) {
		return ret;
	}

	if (hdr->type != XS_WATCH_EVENT) {
		complete_pending_from_frame(xs);
	} else {
		watch_event_dispatch(xs);
	}

	return 0;
}

/* Workqueue entry point that drains and dispatches response-ring frames. */
static void response_worker(struct k_work *work)
{
	struct xenstore_client *xs = CONTAINER_OF(work, struct xenstore_client, event_work);
	size_t loops = 0;
	size_t avail;
	int ret;

	if (!is_ready(xs)) {
		return;
	}

	/* Single-threaded pump: consume new bytes, parse at most one frame per iteration. */
	while (loops++ < XS_EVENT_WORK_MAX_LOOPS) {
		ret = response_ring_available(xs, &avail);
		if (ret < 0) {
			fail_transport(xs, ret);
			break;
		}

		if (avail == 0) {
			if (has_pending_waiters(xs)) {
				schedule_response_retry(xs);
			}
			break;
		}

		ret = drain_frame_tail(xs);
		if (ret < 0) {
			fail_transport(xs, ret);
			break;
		}

		avail -= ret;
		if (avail == 0) {
			continue;
		}

		ret = process_one_response_frame(xs, avail);
		if ((ret == -EAGAIN) || (ret == -ENOMSG)) {
			continue;
		} else if (ret < 0) {
			if (xs->to_discard && is_ready(xs)) {
				continue;
			}

			break;
		}

		ret = drain_frame_tail(xs);
		if (ret < 0) {
			fail_transport(xs, ret);
			break;
		}
	}

	if ((loops > XS_EVENT_WORK_MAX_LOOPS) && is_ready(xs)) {
		submit_response_work(xs);
		k_yield();
	}
}

/* Delayed retry entry point; keeps empty-ring polling out of the hot path. */
static void response_retry_worker(struct k_work *work)
{
	struct k_work_delayable *dwork = k_work_delayable_from_work(work);
	struct xenstore_client *xs = CONTAINER_OF(dwork, struct xenstore_client, retry_work);

	submit_response_work(xs);
}

/* Event-channel callback; defers response-ring processing to the workqueue. */
static void response_evtchn_cb(void *ptr)
{
	struct xenstore_client *xs = ptr;

	submit_response_work(xs);
}

/*
 * Request-id helpers allocate the non-zero identifiers that bind one submitted
 * request frame to one synchronous waiter in pending_responses.
 */

/* Allocate a non-zero request id used to match one backend reply. */
static inline uint32_t alloc_request_id(void)
{
	uint32_t id = (atomic_inc(&xs_cli.next_req_id) & UINT32_MAX);

	/* id=0 is reserved for watch notification */
	if (id == 0) {
		id = (atomic_inc(&xs_cli.next_req_id) & UINT32_MAX);
	}

	return id;
}

/*
 * Request-ring helpers serialize caller-owned request frames into the shared
 * page while req_mutex keeps teardown and concurrent submissions out of the
 * same producer indexes.
 */

/* Read request-ring indexes; caller must hold xs->req_mutex. */
static inline int request_space_available(struct xenstore_client *xs, size_t *avail)
{
	struct xenstore_domain_interface *intf = xs->domint;

	z_barrier_dmem_fence_full();

	XENSTORE_RING_IDX cons = intf->req_cons;
	XENSTORE_RING_IDX prod = intf->req_prod;

	z_barrier_dmem_fence_full();

	if (xenstore_check_indexes(cons, prod)) {
		LOG_ERR("XenStore ring index out of range (req): cons=%u prod=%u", (uint32_t)cons,
			(uint32_t)prod);
		*avail = 0;
		return -EIO;
	}

	*avail = XENSTORE_RING_SIZE - (prod - cons);
	return 0;
}

/* Wait for request-ring space; caller must hold xs->req_mutex. */
static int wait_for_request_space(struct xenstore_client *xs, size_t needed, k_timepoint_t deadline)
{
	size_t avail;
	int err;

	if (needed > XENSTORE_RING_SIZE) {
		return -EMSGSIZE;
	}

	while (true) {
		err = request_space_available(xs, &avail);
		if (err < 0) {
			return err;
		}

		if (avail >= needed) {
			return 0;
		}

		if (sys_timepoint_expired(deadline)) {
			LOG_ERR("ring_write: timeout waiting for space: %zu < %zu", avail, needed);
			return -ETIMEDOUT;
		}

		k_yield();
	}
}

/* Write all bytes to the request ring; caller must hold xs->req_mutex. */
static int write_all_request_bytes(struct xenstore_client *xs, const void *buf, size_t len,
				   k_timepoint_t deadline, bool *wrote)
{
	const uint8_t *p = buf;
	size_t written = 0;

	while (written < len) {
		int rc = xenstore_ring_write(xs->domint, p + written, len - written, true);

		if (rc < 0) {
			return rc;
		}

		if (rc == 0) {
			if (sys_timepoint_expired(deadline)) {
				return -ETIMEDOUT;
			}

			k_yield();
			continue;
		}

		written += rc;
		*wrote = true;
	}

	return written;
}

/* Request construction and submission helpers. */

/* Return the serialized size of one request payload parameter. */
static size_t param_size(const char *const *params, const size_t *param_lens, size_t param_num,
			 size_t index)
{
	if (!params || (index >= param_num)) {
		return 0;
	}

	if (param_lens) {
		return param_lens[index];
	}

	return strlen(params[index]) + 1;
}

/* Populate a XenStore request header after validating total payload size. */
static int prepare_request_header(struct xsd_sockmsg *hdr, enum xsd_sockmsg_type type,
				  const char *const *params, const size_t *param_lens,
				  size_t param_num, uint32_t req_id, uint32_t tx_id)
{
	size_t payload_len = 0;

	/* Header construction is pure: fail fast if the aggregate payload is too large. */
	for (size_t i = 0; i < param_num; i++) {
		size_t add = param_size(params, param_lens, param_num, i);

		if (add > (XENSTORE_PAYLOAD_MAX - payload_len)) {
			LOG_ERR("payload too large: %zu > " STRINGIFY(XENSTORE_PAYLOAD_MAX),
								      payload_len + add);
			return -ENAMETOOLONG;
		}

		payload_len += add;
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

/* Request frame write and synchronous execution helpers. */

/* Write one prepared request frame; caller must hold xs->req_mutex. */
static int write_request_frame(struct xenstore_client *xs, const struct xsd_sockmsg *hdr,
			       const char *const *params, const size_t *param_lens,
			       size_t param_num, k_timepoint_t deadline, bool *partial)
{
	int err;

	*partial = false;
	err = write_all_request_bytes(xs, hdr, sizeof(*hdr), deadline, partial);
	if (err < 0) {
		LOG_ERR("write_all_request_bytes(hdr) failed: %d", err);
		return err;
	}

	for (size_t i = 0; i < param_num; i++) {
		const size_t param_len = param_size(params, param_lens, param_num, i);

		err = write_all_request_bytes(xs, params[i], param_len, deadline, partial);
		if (err < 0) {
			LOG_ERR("write_all_request_bytes(param) failed: %d", err);
			return err;
		}
	}

	return 0;
}

/* Serialize and submit one request frame. */
static int submit_request(struct xenstore_client *xs, enum xsd_sockmsg_type type,
			  const char *const *params, const size_t *param_lens, size_t param_num,
			  uint32_t req_id, uint32_t tx_id, k_timepoint_t deadline)
{
	struct xsd_sockmsg hdr = {0};
	size_t frame_len;
	bool partial = false;
	int err;
	bool fail_after_unlock = false;
	int mutex_err;

	err = prepare_request_header(&hdr, type, params, param_lens, param_num, req_id, tx_id);
	if (err < 0) {
		return err;
	}

	mutex_err = k_mutex_lock(&xs->req_mutex, K_FOREVER);
	if (mutex_err != 0) {
		LOG_ERR("Failed to lock request mutex: %d", mutex_err);
		return mutex_err;
	}

	if (!xs->domint) {
		err = -ENODEV;
		goto end;
	}

	frame_len = SZ_SOCKMSG + hdr.len;
	err = wait_for_request_space(xs, frame_len, deadline);
	if (err < 0) {
		goto end;
	}

	err = write_request_frame(xs, &hdr, params, param_lens, param_num, deadline, &partial);
	if (err >= 0) {
		err = notify_evtchn(xs->local_evtchn);
		if (err < 0) {
			LOG_ERR("notify_evtchn(%u) failed: %d", xs->local_evtchn, err);
			goto end;
		}
		submit_response_work(xs);
	} else if (partial) {
		fail_after_unlock = true;
	}

end:
	k_mutex_unlock(&xs->req_mutex);

	if (fail_after_unlock) {
		fail_transport(xs, err);
	}

	return err;
}

/*
 * Submit one synchronous request and wait for the matching response waiter.
 * params are serialized as the request payload; param_lens == NULL means every
 * parameter is a NUL-terminated string, otherwise each length is explicit.
 */
static ssize_t execute_request(struct xenstore_client *xs, enum xsd_sockmsg_type type,
			       const char *const *params, const size_t *param_lens,
			       size_t params_num, char *buf, size_t len, uint32_t tx_id,
			       k_timeout_t timeout)
{
	/* Stack-allocated waiter: appended to pending_responses, woken when matching response
	 * finalizes. */
	struct pending_response resp_local = {
		.node = {0},
		.buf = (uint8_t *)buf,
		.len = len,
		.pos = 0,
		.req_id = 0,
		.expected_type = type,
		.err = 0,
	};
	k_timepoint_t deadline;
	ssize_t result = 0;
	int err;

	if (!is_ready(xs)) {
		LOG_ERR("XenStore client not initialized");
		return -ENODEV;
	}

	resp_local.node.next = NULL;
	k_sem_init(&resp_local.sem, 0, 1);
	resp_local.req_id = alloc_request_id();
	deadline = sys_timepoint_calc(timeout);

	/* Publish our waiter to the worker thread – it owns unblocking us. */
	err = publish_pending(xs, &resp_local);
	if (err < 0) {
		LOG_ERR("Timed-out response tombstone slots exhausted: %d", err);
		return err;
	}

	err = submit_request(xs, type, params, param_lens, params_num, resp_local.req_id, tx_id,
			     deadline);
	if (err < 0) {
		LOG_ERR("Failed to submit request: %d", err);
		remove_pending(xs, &resp_local);
		return err;
	}

	err = k_sem_take(&resp_local.sem, sys_timepoint_timeout(deadline));
	if (err != 0) {
		LOG_ERR("k_sem_take error: %d", err);
		timeout_pending(xs, &resp_local);
		submit_response_work(xs);
		return -ETIMEDOUT;
	}

	if (resp_local.err < 0) {
		LOG_DBG("Error response: %d", resp_local.err);
		return resp_local.err;
	}

	if (resp_local.pos > 0) {
		result = MIN(len, resp_local.pos);
	}

	return result;
}

/* Public client lifecycle API. */

int xs_init(void)
{
	const struct k_work_queue_config qcfg = {.name = "xenstore-wq"};
	uint64_t paddr = 0;
	uint64_t value = 0;
	mm_reg_t vaddr = 0;
	int err;

	err = k_mutex_lock(&xs_init_lock, K_FOREVER);
	if (err != 0) {
		LOG_ERR("Failed to lock init mutex: %d", err);
		return err;
	}

	if (is_ready(&xs_cli)) {
		err = 0;
		goto out;
	}

	atomic_set(&xs_cli.next_req_id, 1);
	xs_cli.workq_priority = CONFIG_XEN_STORE_CLI_WORKQ_PRIORITY;

	k_work_init(&xs_cli.event_work, response_worker);
	k_work_init_delayable(&xs_cli.retry_work, response_retry_worker);
	k_mutex_init(&xs_cli.req_mutex);

	if (!xs_cli.workq_started) {
		k_work_queue_init(&xs_cli.workq);
		k_work_queue_start(&xs_cli.workq, xs_workq_stack,
				   K_THREAD_STACK_SIZEOF(xs_workq_stack), xs_cli.workq_priority,
				   &qcfg);
		xs_cli.workq_started = true;
	}

	sys_slist_init(&xs_cli.notify_list);
	sys_slist_init(&xs_cli.pending_responses);
	memset(xs_cli.timed_out_req_ids, 0, sizeof(xs_cli.timed_out_req_ids));

	err = hvm_get_parameter(HVM_PARAM_STORE_EVTCHN, DOMID_SELF, &value);
	if (err) {
		LOG_ERR("hvm_get_parameter(STORE_EVTCHN) failed: %d", err);
		err = -ENODEV;
		goto out;
	}
	xs_cli.local_evtchn = value;

	err = hvm_get_parameter(HVM_PARAM_STORE_PFN, DOMID_SELF, &paddr);
	if (err) {
		LOG_ERR("hvm_get_param(STORE_PFN) failed: err=%d", err);
		err = -EIO;
		goto out;
	}

	device_map(&vaddr, XEN_PFN_PHYS(paddr), XEN_PAGE_SIZE, K_MEM_CACHE_WB | K_MEM_PERM_RW);
	if (vaddr == 0) {
		LOG_ERR("device_map failed.");
		err = -EIO;
		goto out;
	}

	xs_cli.domint = (struct xenstore_domain_interface *)vaddr;

	while (true) {
		size_t avail;

		err = response_ring_available(&xs_cli, &avail);
		if (err < 0) {
			teardown_transport(&xs_cli);
			goto out;
		}

		if (avail == 0) {
			break;
		}

		(void)response_ring_read(&xs_cli, NULL, avail);
	}

	err = bind_event_channel(xs_cli.local_evtchn, response_evtchn_cb, &xs_cli);
	if (err) {
		LOG_ERR("bind_event_channel failed: %d", err);
		teardown_transport(&xs_cli);
		err = (err < 0) ? err : -EIO;
		goto out;
	}
	xs_cli.evtchn_bound = true;

	err = unmask_event_channel(xs_cli.local_evtchn);
	if (err) {
		LOG_ERR("unmask_event_channel failed: %d", err);
		teardown_transport(&xs_cli);
		goto out;
	}

	xs_set_default_timeout(K_FOREVER);
	set_ready(&xs_cli, true);
	err = 0;

out:
	k_mutex_unlock(&xs_init_lock);

	return err;
}

/* Public timeout API. */

void xs_set_default_timeout(k_timeout_t tout)
{
	k_spinlock_key_t key = k_spin_lock(&xs_cli.lock);

	xs_cli.default_timeout = tout;

	k_spin_unlock(&xs_cli.lock, key);
}

/* Return a synchronized snapshot for default-timeout wrapper APIs. */
static k_timeout_t xs_default_timeout_get(void)
{
	k_timeout_t tout;
	k_spinlock_key_t key = k_spin_lock(&xs_cli.lock);

	tout = xs_cli.default_timeout;

	k_spin_unlock(&xs_cli.lock, key);

	return tout;
}

/* Public watcher API. */

void xs_watcher_init(struct xs_watcher *w, xs_watch_cb cb, void *param)
{
	if (!w) {
		return;
	}

	w->node.next = NULL;
	w->cb = cb;
	w->param = param;
	k_sem_init(&w->callback_idle, 0, 1);
	w->dispatch_gen = 0;
	w->registered = false;
	w->callback_running = false;
}

int xs_watcher_register(struct xs_watcher *w)
{
	k_spinlock_key_t key;

	if (!w || !w->cb) {
		return -EINVAL;
	}

	key = k_spin_lock(&xs_cli.lock);

	if (!xs_cli.initialized) {
		k_spin_unlock(&xs_cli.lock, key);
		return -ENODEV;
	}

	if (w->registered) {
		k_spin_unlock(&xs_cli.lock, key);
		return -EALREADY;
	}

	sys_slist_append(&xs_cli.notify_list, &w->node);
	/*
	 * A watcher registered while another watch event is being dispatched must
	 * not receive that already in-progress event.
	 */
	w->dispatch_gen = xs_cli.watch_dispatch_gen;
	w->registered = true;
	k_spin_unlock(&xs_cli.lock, key);

	return 0;
}

int xs_watcher_unregister(struct xs_watcher *w)
{
	bool wait_for_callback;
	k_spinlock_key_t key;

	if (!w) {
		return -EINVAL;
	}

	key = k_spin_lock(&xs_cli.lock);
	if (w->registered) {
		(void)sys_slist_find_and_remove(&xs_cli.notify_list, &w->node);
		w->registered = false;
	}
	wait_for_callback =
		w->callback_running && (k_current_get() != k_work_queue_thread_get(&xs_cli.workq));
	k_spin_unlock(&xs_cli.lock, key);

	if (wait_for_callback) {
		(void)k_sem_take(&w->callback_idle, K_FOREVER);
	}

	return 0;
}

/* Public XenStore operation API. */

/* Execute one path-only XenStore request that returns a payload buffer. */
static ssize_t execute_path(enum xsd_sockmsg_type type, const char *path, char *buf, size_t len,
			    uint32_t tx_id, k_timeout_t tout)
{
	const char *const params[] = {path};

	if (!path || !buf || len == 0) {
		return -EINVAL;
	}

	return execute_request(&xs_cli, type, params, NULL, ARRAY_SIZE(params), buf, len, tx_id,
			       tout);
}

/* Execute one path-plus-string XenStore request such as watch/unwatch. */
static ssize_t execute_path_string(enum xsd_sockmsg_type type, const char *path, const char *str,
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
	return execute_path(XS_READ, path, buf, len, tx_id, tout);
}

ssize_t xs_read(const char *path, char *buf, size_t len, uint32_t tx_id)
{
	return execute_path(XS_READ, path, buf, len, tx_id, xs_default_timeout_get());
}

ssize_t xs_rm_timeout(const char *path, char *buf, size_t len, uint32_t tx_id, k_timeout_t tout)
{
	return execute_path(XS_RM, path, buf, len, tx_id, tout);
}

ssize_t xs_rm(const char *path, char *buf, size_t len, uint32_t tx_id)
{
	return execute_path(XS_RM, path, buf, len, tx_id, xs_default_timeout_get());
}

ssize_t xs_directory_timeout(const char *path, char *buf, size_t len, uint32_t tx_id,
			     k_timeout_t tout)
{
	return execute_path(XS_DIRECTORY, path, buf, len, tx_id, tout);
}

ssize_t xs_directory(const char *path, char *buf, size_t len, uint32_t tx_id)
{
	return execute_path(XS_DIRECTORY, path, buf, len, tx_id, xs_default_timeout_get());
}

ssize_t xs_get_permissions_timeout(const char *path, struct xs_permission_entry *perms,
				   size_t perms_num, uint32_t tx_id, k_timeout_t tout)
{
	char *raw;
	size_t raw_len;
	ssize_t ret;

	if (!path || !perms || perms_num == 0) {
		return -EINVAL;
	}

	if (perms_num > (SIZE_MAX / XS_PERM_WIRE_ENTRY_MAX)) {
		return -EOVERFLOW;
	}

	raw_len = perms_num * XS_PERM_WIRE_ENTRY_MAX;

	raw = k_malloc(raw_len);
	if (!raw) {
		return -ENOMEM;
	}

	ret = execute_path(XS_GET_PERMS, path, raw, raw_len, tx_id, tout);
	if (ret >= 0) {
		ret = perm_parse_wire(raw, ret, perms, perms_num);
	}

	k_free(raw);

	return ret;
}

ssize_t xs_get_permissions(const char *path, struct xs_permission_entry *perms, size_t perms_num,
			   uint32_t tx_id)
{
	return xs_get_permissions_timeout(path, perms, perms_num, tx_id, xs_default_timeout_get());
}

ssize_t xs_watch_timeout(const char *path, const char *token, char *buf, size_t len, uint32_t tx_id,
			 k_timeout_t tout)
{
	return execute_path_string(XS_WATCH, path, token, buf, len, tx_id, tout);
}

ssize_t xs_watch(const char *path, const char *token, char *buf, size_t len, uint32_t tx_id)
{
	return execute_path_string(XS_WATCH, path, token, buf, len, tx_id,
				   xs_default_timeout_get());
}

ssize_t xs_unwatch_timeout(const char *path, const char *token, char *buf, size_t len,
			   uint32_t tx_id, k_timeout_t tout)
{
	return execute_path_string(XS_UNWATCH, path, token, buf, len, tx_id, tout);
}

ssize_t xs_unwatch(const char *path, const char *token, char *buf, size_t len, uint32_t tx_id)
{
	return execute_path_string(XS_UNWATCH, path, token, buf, len, tx_id,
				   xs_default_timeout_get());
}

ssize_t xs_write_timeout(const char *path, const char *value, size_t value_len, char *buf,
			 size_t len, uint32_t tx_id, k_timeout_t tout)
{
	if (!path || !value || !buf || len == 0) {
		return -EINVAL;
	}

	const char *const params[] = {path, value};
	const size_t param_lens[] = {
		strlen(path) + 1,
		value_len,
	};

	return execute_request(&xs_cli, XS_WRITE, params, param_lens, ARRAY_SIZE(params), buf, len,
			       tx_id, tout);
}

ssize_t xs_write(const char *path, const char *value, size_t value_len, char *buf, size_t len,
		 uint32_t tx_id)
{
	return xs_write_timeout(path, value, value_len, buf, len, tx_id, xs_default_timeout_get());
}

int xs_set_permissions_timeout(const char *path, const struct xs_permission_entry *perms,
			       size_t perms_num, uint32_t tx_id, k_timeout_t tout)
{
	char response[XS_ERROR_WIRE_MAX];
	ssize_t ret;

	if (!path) {
		return -EINVAL;
	}

	if (perms_num == 0) {
		return -EINVAL;
	}

	if (perms_num > XS_SET_PERMS_MAX_ENTRIES) {
		return -E2BIG;
	}

	if (!perms) {
		return -EINVAL;
	}

	const char *params[XS_SET_PERMS_MAX_ENTRIES + 1];
	char wire_perms[XS_SET_PERMS_MAX_ENTRIES][XS_PERM_WIRE_ENTRY_MAX];

	params[0] = path;

	for (size_t i = 0; i < perms_num; i++) {
		char wire_perm;
		int ret;

		ret = perm_to_wire(perms[i].perm, &wire_perm);
		if (ret < 0) {
			return ret;
		}

		ret = snprintk(wire_perms[i], sizeof(wire_perms[i]), "%c%u", wire_perm,
			       perms[i].domid);
		if ((ret < 0) || ((size_t)ret >= sizeof(wire_perms[i]))) {
			return -ENAMETOOLONG;
		}

		params[i + 1] = wire_perms[i];
	}

	ret = execute_request(&xs_cli, XS_SET_PERMS, (const char *const *)params, NULL,
			      perms_num + 1, response, sizeof(response), tx_id, tout);

	return (ret < 0) ? (int)ret : 0;
}

int xs_set_permissions(const char *path, const struct xs_permission_entry *perms, size_t perms_num,
		       uint32_t tx_id)
{
	return xs_set_permissions_timeout(path, perms, perms_num, tx_id, xs_default_timeout_get());
}
