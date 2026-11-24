// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright (c) 2026 EPAM Systems
 * Copyright (c) 2025 TOKITA Hiroshi
 */

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <xen/public/io/xs_wire.h>
#include <xen/public/xen.h>
#include <xenstore_common.h>
#include <xs.h>

#include <xen/events.h>
#include <xen/generic.h>
#include <xen/hvm.h>
#include <xenlib_osal.h>

XENLIB_OSAL_LOG_MODULE_REGISTER(xenstore_client);

/* XenStore frames always start with struct xsd_sockmsg followed by payload bytes. */
#define SZ_SOCKMSG               sizeof(struct xsd_sockmsg)
/* Longest XenStore wire error name, including its trailing NUL. */
#define XS_ERROR_WIRE_MAX        sizeof("ENOTEMPTY")
/* Bound active requests and the late responses that remain after local timeout. */
#define XS_MAX_OUTSTANDING_REQUESTS CONFIG_XEN_STORE_CLIENT_MAX_OUTSTANDING_REQUESTS
#define XS_EVENT_WORK_MAX_LOOPS  32

/*
 * Per-call waiter for one synchronous request. Caller threads allocate this on
 * their own stack, publish it in xenstore_client.pending_responses, then block
 * on sem. The response thread owns matching replies by req_id and only signals
 * completion.
 */
struct pending_response {
	/* Node in xenstore_client.pending_responses while the caller waits for a reply. */
	xenlib_osal_snode_t node;
	/* Caller-owned response buffer where the response thread copies reply payload. */
	uint8_t *buf;
	/* Capacity of buf in bytes. */
	size_t len;
	/* Number of reply payload bytes copied into buf. */
	size_t pos;
	/* Posted by the response thread when this request completes or fails. */
	xenlib_osal_semaphore_t sem;
	/* Non-zero XenStore request id used to match the backend reply. */
	uint32_t req_id;
	/* Response type expected for this request; XS_ERROR is also accepted. */
	enum xsd_sockmsg_type expected_type;
	/* Completion status; zero on success, negative errno on failure. */
	int err;
};

/*
 * Response-thread-owned frame being assembled from the response ring. It describes
 * the bytes currently staged in xenstore_client.work_buf; it is not a waiter
 * and is never linked into xenstore_client.pending_responses.
 */
struct response_frame {
	/* Staging buffer where the response thread assembles one payload. */
	uint8_t *buf;
	/* Capacity of buf in bytes. */
	size_t len;
	/* Number of payload bytes already copied into buf. */
	size_t pos;
	/* Request id from the frame header. */
	uint32_t req_id;
	/* Expected frame type for the current staged response. */
	enum xsd_sockmsg_type expected_type;
};

/*
 * Private singleton state for the wired XenStore client. Each section
 * documents its ownership and synchronization domain.
 */
struct xenstore_client {
	/*
	 * XenStore transport endpoint and ownership
	 */

	/* Request access and teardown are serialized by req_mutex. */
	struct xenstore_domain_interface *domint;
	evtchn_port_t local_evtchn;
	/* Records ownership of the event-channel binding during teardown. */
	bool evtchn_bound;

	/*
	 * Shared lifecycle state
	 */

	/* Protects readiness, failure, worker activity, pending waiters, and tombstones. */
	xenlib_osal_mutex_t lock;
	/* Published after xs_init() completes. */
	bool initialized;
	/* A failed transport cannot be resynchronized or reused. */
	bool failed;
	/* Set while response work may access the ring; completion signals its exit. */
	bool response_worker_active;
	xenlib_osal_semaphore_t response_worker_done;

	/*
	 * Synchronous request submission and response correlation
	 */

	/* Serializes request-ring writes against transport teardown. */
	xenlib_osal_mutex_t req_mutex;
	/* Wrapping source of non-zero request ids. */
	uint32_t next_req_id;
	/* Waiters are allocated on their caller threads' stacks. */
	xenlib_osal_slist_t pending_responses;
	/* IDs retained to recognize late responses after caller timeout. */
	uint32_t timed_out_req_ids[XS_MAX_OUTSTANDING_REQUESTS];

	/*
	 * Response frame assembly state; worker-owned until teardown quiesces it
	 */

	uint8_t hdr_buf[SZ_SOCKMSG] __attribute__((aligned(4)));
	size_t hdr_pos;
	/* Remaining bytes discarded to restore the next frame boundary. */
	size_t to_discard;
	uint8_t work_buf[XENSTORE_PAYLOAD_MAX + 1];
	/* Metadata for the payload staged in work_buf. */
	struct response_frame frame;

	/*
	 * Response thread lifecycle
	 */

	/* Wakes the response thread from the event callback and request path. */
	xenlib_osal_semaphore_t response_sem;
	xenlib_osal_thread_t response_thread;
	xenlib_osal_tid_t response_tid;
	int response_thread_priority;
	bool state_mutex_initialized;
	bool req_mutex_initialized;
	bool worker_done_initialized;
	bool response_sem_initialized;
	/* Records one-time initialization of mutexes, semaphores, and the thread. */
	bool primitives_initialized;
	/* Prevents the private response thread from being started more than once. */
	bool response_thread_started;
};

static struct xenstore_client xs_cli;
/*
 * Keep the response stack as a platform thread-stack object rather than
 * embedding it in the client state.
 */
static XENLIB_OSAL_THREAD_STACK_DEFINE(xs_response_stack,
				       CONFIG_XEN_STORE_CLIENT_WORKQ_STACK_SIZE);
static XENLIB_OSAL_MUTEX_DEFINE(xs_init_lock);

static inline size_t min_size(size_t lhs, size_t rhs)
{
	return (lhs < rhs) ? lhs : rhs;
}

static inline int osal_error(int err)
{
	return (err < 0) ? err : -EIO;
}

static int initialize_sync_primitives(struct xenstore_client *xs)
{
	int err;

	if (!xs->state_mutex_initialized) {
		err = xenlib_osal_mutex_init(&xs->lock);
		if (err != 0) {
			return osal_error(err);
		}
		xs->state_mutex_initialized = true;
	}

	if (!xs->req_mutex_initialized) {
		err = xenlib_osal_mutex_init(&xs->req_mutex);
		if (err != 0) {
			return osal_error(err);
		}
		xs->req_mutex_initialized = true;
	}

	if (!xs->worker_done_initialized) {
		err = xenlib_osal_semaphore_init(&xs->response_worker_done, 0, 1);
		if (err != 0) {
			return osal_error(err);
		}
		xs->worker_done_initialized = true;
	}

	if (!xs->response_sem_initialized) {
		err = xenlib_osal_semaphore_init(&xs->response_sem, 0, 1);
		if (err != 0) {
			return osal_error(err);
		}
		xs->response_sem_initialized = true;
	}

	xs->primitives_initialized = true;
	return 0;
}

/* Clear partial frame-assembly and discard state. */
static void frame_reset(struct xenstore_client *xs)
{
	xs->hdr_pos = 0;
	xs->to_discard = 0;
	xs->frame.pos = 0;
	xs->frame.len = 0;
	xs->frame.expected_type = XS_ERROR;
}

/*
 * Pending response tracking
 */

/* Caller holds xs->lock; the returned stack waiter is protected until unlock. */
static struct pending_response *find_pending(struct xenstore_client *xs, uint32_t req_id)
{
	struct pending_response *resp;

	XENLIB_OSAL_SLIST_FOR_EACH_CONTAINER(&xs->pending_responses, resp, node) {
		if (resp->req_id == req_id) {
			return resp;
		}
	}

	return NULL;
}

/* Caller holds xs->lock. */
static size_t pending_count(struct xenstore_client *xs)
{
	size_t count = 0;
	struct pending_response *resp;

	XENLIB_OSAL_SLIST_FOR_EACH_CONTAINER(&xs->pending_responses, resp, node) {
		count++;
	}

	return count;
}

/* Caller holds xs->lock. */
static size_t timed_out_count(struct xenstore_client *xs)
{
	size_t count = 0;

	for (size_t i = 0; i < XS_MAX_OUTSTANDING_REQUESTS; i++) {
		if (xs->timed_out_req_ids[i] != 0) {
			count++;
		}
	}

	return count;
}

/* Caller holds xs->lock. */
static bool request_slots_full(struct xenstore_client *xs)
{
	return (pending_count(xs) + timed_out_count(xs)) >=
	       XS_MAX_OUTSTANDING_REQUESTS;
}

/* Caller holds xs->lock. */
static bool request_id_in_use(struct xenstore_client *xs, uint32_t req_id)
{
	if (find_pending(xs, req_id)) {
		return true;
	}

	for (size_t i = 0; i < XS_MAX_OUTSTANDING_REQUESTS; i++) {
		if (xs->timed_out_req_ids[i] == req_id) {
			return true;
		}
	}

	return false;
}

/* Caller holds xs->lock. */
static uint32_t generate_request_id(struct xenstore_client *xs)
{
	uint32_t req_id;

	do {
		req_id = xs->next_req_id++;
	} while ((req_id == 0) || request_id_in_use(xs, req_id));

	return req_id;
}

/* Reserve an ID and publish a stack waiter, or return -EBUSY at capacity. */
static int publish_pending(struct xenstore_client *xs, struct pending_response *resp)
{
	int err = 0;

	(void)xenlib_osal_mutex_lock(&xs->lock, XENLIB_OSAL_WAIT_FOREVER);
	if (request_slots_full(xs)) {
		err = -EBUSY;
	} else {
		resp->req_id = generate_request_id(xs);
		xenlib_osal_slist_append(&xs->pending_responses, &resp->node);
	}
	(void)xenlib_osal_mutex_unlock(&xs->lock);

	return err;
}

/* Caller holds xs->lock. */
static bool remove_pending_locked(struct xenstore_client *xs,
				  struct pending_response *target)
{
	struct pending_response *resp;
	xenlib_osal_snode_t *prev = NULL;

	XENLIB_OSAL_SLIST_FOR_EACH_CONTAINER(&xs->pending_responses, resp, node) {
		if (resp == target) {
			xenlib_osal_slist_remove(&xs->pending_responses, prev, &resp->node);
			return true;
		}
		prev = &resp->node;
	}

	return false;
}

/* Caller holds xs->lock; return false if no reserved tombstone slot remains. */
static bool remember_timed_out(struct xenstore_client *xs, uint32_t req_id)
{
	size_t slot = XS_MAX_OUTSTANDING_REQUESTS;

	for (size_t i = 0; i < XS_MAX_OUTSTANDING_REQUESTS; i++) {
		if (xs->timed_out_req_ids[i] == req_id) {
			return true;
		}

		if ((slot == XS_MAX_OUTSTANDING_REQUESTS) &&
		    (xs->timed_out_req_ids[i] == 0)) {
			slot = i;
		}
	}

	if (slot == XS_MAX_OUTSTANDING_REQUESTS) {
		return false;
	}

	xs->timed_out_req_ids[slot] = req_id;
	return true;
}

/* Remove the caller-owned waiter if it is still pending. */
static void remove_pending(struct xenstore_client *xs, struct pending_response *resp)
{
	(void)xenlib_osal_mutex_lock(&xs->lock, XENLIB_OSAL_WAIT_FOREVER);
	(void)remove_pending_locked(xs, resp);
	(void)xenlib_osal_mutex_unlock(&xs->lock);
}

/* Atomically replace a submitted stack waiter with its late-response tombstone. */
static void timeout_pending(struct xenstore_client *xs, struct pending_response *resp)
{
	bool tombstone_missing = false;

	(void)xenlib_osal_mutex_lock(&xs->lock, XENLIB_OSAL_WAIT_FOREVER);
	if (remove_pending_locked(xs, resp)) {
		if (!remember_timed_out(xs, resp->req_id)) {
			tombstone_missing = true;
		}
	}
	(void)xenlib_osal_mutex_unlock(&xs->lock);

	if (tombstone_missing) {
		XENLIB_OSAL_LOG_ERR("No tombstone slot for timed-out req_id=%u", resp->req_id);
	}
}

/* Remove req_id from the tombstone set and return whether it was present. */
static bool consume_timed_out(struct xenstore_client *xs, uint32_t req_id)
{
	bool found = false;

	(void)xenlib_osal_mutex_lock(&xs->lock, XENLIB_OSAL_WAIT_FOREVER);
	for (size_t i = 0; i < XS_MAX_OUTSTANDING_REQUESTS; i++) {
		if (xs->timed_out_req_ids[i] == req_id) {
			xs->timed_out_req_ids[i] = 0;
			found = true;
			break;
		}
	}
	(void)xenlib_osal_mutex_unlock(&xs->lock);

	return found;
}

/* Remove each stack waiter before waking its caller with err. */
static void fail_all_pending(struct xenstore_client *xs, int err)
{
	struct pending_response *resp;

	(void)xenlib_osal_mutex_lock(&xs->lock, XENLIB_OSAL_WAIT_FOREVER);
	while (!xenlib_osal_slist_is_empty(&xs->pending_responses)) {
		resp = XENLIB_OSAL_SLIST_PEEK_HEAD_CONTAINER(&xs->pending_responses,
							 resp, node);
		xenlib_osal_slist_remove(&xs->pending_responses, NULL, &resp->node);
		resp->err = err;
		resp->pos = 0;
		(void)xenlib_osal_semaphore_signal(&resp->sem);
	}
	(void)xenlib_osal_mutex_unlock(&xs->lock);
}

/*
 * Transport readiness and response-worker lifetime
 */

static bool is_ready(struct xenstore_client *xs)
{
	bool initialized;

	if (!xs) {
		return false;
	}

	(void)xenlib_osal_mutex_lock(&xs->lock, XENLIB_OSAL_WAIT_FOREVER);
	initialized = xs->initialized;
	(void)xenlib_osal_mutex_unlock(&xs->lock);

	return initialized;
}

static void set_ready(struct xenstore_client *xs, bool initialized)
{
	(void)xenlib_osal_mutex_lock(&xs->lock, XENLIB_OSAL_WAIT_FOREVER);
	xs->initialized = initialized;
	(void)xenlib_osal_mutex_unlock(&xs->lock);
}

static bool transport_failed(struct xenstore_client *xs)
{
	bool failed;

	(void)xenlib_osal_mutex_lock(&xs->lock, XENLIB_OSAL_WAIT_FOREVER);
	failed = xs->failed;
	(void)xenlib_osal_mutex_unlock(&xs->lock);

	return failed;
}

static void mark_transport_failed(struct xenstore_client *xs)
{
	(void)xenlib_osal_mutex_lock(&xs->lock, XENLIB_OSAL_WAIT_FOREVER);
	xs->initialized = false;
	xs->failed = true;
	(void)xenlib_osal_mutex_unlock(&xs->lock);
}

/* Enter ring access only while ready, consuming completion from the previous turn. */
static bool response_worker_enter(struct xenstore_client *xs)
{
	bool entered = false;

	(void)xenlib_osal_mutex_lock(&xs->lock, XENLIB_OSAL_WAIT_FOREVER);
	if (!xs->initialized) {
		(void)xenlib_osal_mutex_unlock(&xs->lock);
		return false;
	}
	(void)xenlib_osal_mutex_unlock(&xs->lock);

	/* Only a turn that may enter can consume the previous completion. */
	(void)xenlib_osal_semaphore_wait(&xs->response_worker_done,
					 XENLIB_OSAL_NO_WAIT);

	(void)xenlib_osal_mutex_lock(&xs->lock, XENLIB_OSAL_WAIT_FOREVER);
	if (xs->initialized) {
		xs->response_worker_active = true;
		entered = true;
	}
	(void)xenlib_osal_mutex_unlock(&xs->lock);

	return entered;
}

/* Revoke ring access before signaling teardown waiters. */
static void response_worker_exit(struct xenstore_client *xs)
{
	(void)xenlib_osal_mutex_lock(&xs->lock, XENLIB_OSAL_WAIT_FOREVER);
	xs->response_worker_active = false;
	(void)xenlib_osal_mutex_unlock(&xs->lock);
	(void)xenlib_osal_semaphore_signal(&xs->response_worker_done);
}

/* Wait until no response-worker turn can still access domint. */
static void wait_for_response_worker(struct xenstore_client *xs)
{
	for (;;) {
		bool active;

		(void)xenlib_osal_mutex_lock(&xs->lock, XENLIB_OSAL_WAIT_FOREVER);
		active = xs->response_worker_active;
		(void)xenlib_osal_mutex_unlock(&xs->lock);

		if (active) {
			(void)xenlib_osal_semaphore_wait(&xs->response_worker_done,
						 XENLIB_OSAL_WAIT_FOREVER);
			continue;
		}

		return;
	}
}

/*
 * Fatal transport shutdown
 */

/* Revoke readiness, optionally quiesce response work, then unbind and unmap. */
static void teardown_transport(struct xenstore_client *xs, bool wait_for_worker)
{
	int mutex_err;

	set_ready(xs, false);
	if (wait_for_worker) {
		wait_for_response_worker(xs);
	}

	mutex_err = xenlib_osal_mutex_lock(&xs->req_mutex, XENLIB_OSAL_WAIT_FOREVER);

	if (mutex_err != 0) {
		XENLIB_OSAL_LOG_ERR("Failed to lock request mutex during teardown: %d", mutex_err);
		return;
	}

	frame_reset(xs);

	if (xs->evtchn_bound) {
		unbind_event_channel(xs->local_evtchn);
		xs->evtchn_bound = false;
	}

	if (xs->domint) {
		xenlib_osal_unmap_phys_memory(xs->domint, XEN_PAGE_SIZE);
		xs->domint = NULL;
	}

	(void)xenlib_osal_mutex_unlock(&xs->req_mutex);
}

/* Permanently fail the transport; worker context must not wait for itself. */
static void fail_transport(struct xenstore_client *xs, int err, bool response_worker_context)
{
	int mutex_err = xenlib_osal_mutex_lock(&xs_init_lock, XENLIB_OSAL_WAIT_FOREVER);

	if (mutex_err != 0) {
		XENLIB_OSAL_LOG_ERR("Failed to lock init mutex during fatal teardown: %d", mutex_err);
		fail_all_pending(xs, err);
		return;
	}

	mark_transport_failed(xs);
	(void)xenlib_osal_mutex_unlock(&xs_init_lock);

	/* The failed flag now prevents xs_init(); do not hold init_lock while quiescing work. */
	teardown_transport(xs, !response_worker_context);
	fail_all_pending(xs, err);
}

/*
 * Response frame state
 */

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

/* Reset assembly and record payload bytes that must be drained before the next header. */
static void discard_frame_tail(struct xenstore_client *xs, size_t payload_tail_len)
{
	xs->hdr_pos = 0;
	/* Remember the unread tail so the worker drains it before parsing again. */
	xs->to_discard = payload_tail_len;
	xs->frame.pos = 0;
	xs->frame.len = 0;
}

/*
 * Response ring I/O
 */

/* Return the number of response bytes currently available in the shared ring. */
static inline int response_ring_available(struct xenstore_client *xs, size_t *avail)
{
	struct xenstore_domain_interface *intf = xs->domint;

	xenlib_osal_dmem_fence_full();

	XENSTORE_RING_IDX cons = intf->rsp_cons;
	XENSTORE_RING_IDX prod = intf->rsp_prod;

	xenlib_osal_dmem_fence_full();
	if (xenstore_check_indexes(cons, prod)) {
		XENLIB_OSAL_LOG_ERR("XenStore ring index out of range (rsp): cons=%u prod=%u",
				    (uint32_t)cons, (uint32_t)prod);
		*avail = 0;
		return -EIO;
	}

	*avail = prod - cons;
	return 0;
}

/* Consume response bytes and report a following notification failure separately. */
static int response_ring_read(struct xenstore_client *xenstore, void *data, size_t len,
			      int *notify_err)
{
	int ret;

	*notify_err = 0;
	if (len == 0) {
		return 0;
	}

	ret = xenstore_ring_read(xenstore->domint, data, len, true);

	if (ret > 0) {
		*notify_err = notify_evtchn(xenstore->local_evtchn);
		if (*notify_err < 0) {
			XENLIB_OSAL_LOG_ERR("notify_evtchn(%u) failed after response read: %d",
					    xenstore->local_evtchn, *notify_err);
		}
	}

	return ret;
}

/*
 * Response frame parsing and waiter completion
 */

static int read_frame_header(struct xenstore_client *xs, size_t *avail)
{
	struct xsd_sockmsg *hdr = (struct xsd_sockmsg *)(xs->hdr_buf);
	int notify_err;
	int ret;

	XENLIB_OSAL_LOG_DBG("avail=%zu hdr_pos=%zu", *avail, xs->hdr_pos);

	if (xs->hdr_pos < SZ_SOCKMSG) {
		const size_t hdr_to_read = min_size(SZ_SOCKMSG - xs->hdr_pos, *avail);

		ret = response_ring_read(xs, xs->hdr_buf + xs->hdr_pos, hdr_to_read,
					 &notify_err);
		if (ret < 0) {
			XENLIB_OSAL_LOG_ERR("ring_read failed: %d", ret);
			return ret;
		}

		xs->hdr_pos += ret;
		*avail -= ret;
		if (notify_err < 0) {
			fail_transport(xs, notify_err, true);
			return notify_err;
		}

		if (xs->hdr_pos < SZ_SOCKMSG) {
			XENLIB_OSAL_LOG_DBG("header not ready");
			return -EAGAIN;
		}
	}

	if (hdr->len > XENSTORE_PAYLOAD_MAX) {
		XENLIB_OSAL_LOG_ERR("payload too large: %u > %u", hdr->len,
				     (unsigned int)XENSTORE_PAYLOAD_MAX);
		fail_transport(xs, -EMSGSIZE, true);
		return -EMSGSIZE;
	}

	return 0;
}

static int select_frame_buffer(struct xenstore_client *xs)
{
	struct xsd_sockmsg *hdr = (struct xsd_sockmsg *)(xs->hdr_buf);
	struct pending_response *pending;

	(void)xenlib_osal_mutex_lock(&xs->lock, XENLIB_OSAL_WAIT_FOREVER);
	pending = find_pending(xs, hdr->req_id);
	if (!pending) {
		(void)xenlib_osal_mutex_unlock(&xs->lock);
		if (consume_timed_out(xs, hdr->req_id)) {
			XENLIB_OSAL_LOG_DBG("Discarding timed-out response type=%u req_id=%u len=%u",
					    hdr->type, hdr->req_id, hdr->len);
		} else {
			XENLIB_OSAL_LOG_WRN("Discarding stale response type=%u req_id=%u len=%u",
					    hdr->type, hdr->req_id, hdr->len);
		}
		discard_frame_tail(xs, hdr->len - min_size(xs->frame.pos, hdr->len));
		return -ENOMSG;
	}

	if (xs->frame.pos == 0) {
		size_t capacity = min_size(pending->len, sizeof(xs->work_buf));

		prepare_frame_buffer(xs, capacity, hdr->req_id, pending->expected_type);
	}

	(void)xenlib_osal_mutex_unlock(&xs->lock);

	return 0;
}

static int validate_frame_payload(struct xenstore_client *xs, const struct xsd_sockmsg *hdr,
				  bool *fatal)
{
	*fatal = false;

	if (hdr->req_id == 0) {
		XENLIB_OSAL_LOG_ERR("Invalid response header: req_id must be non-zero");
		*fatal = true;
		return -EPROTO;
	}

	if ((hdr->type != XS_ERROR) && (hdr->type != xs->frame.expected_type)) {
		XENLIB_OSAL_LOG_ERR("Unexpected response type: got=%u expected=%u req_id=%u",
				     hdr->type, xs->frame.expected_type, hdr->req_id);
		*fatal = true;
		return -EPROTO;
	}

	if (hdr->len > xs->frame.len) {
		XENLIB_OSAL_LOG_ERR("Response buffer too small: need %u bytes", hdr->len);
		return -EMSGSIZE;
	}

	return 0;
}

static int read_available_payload(struct xenstore_client *xs, const struct xsd_sockmsg *hdr,
				  size_t avail, bool *fatal)
{
	const size_t remaining = hdr->len - xs->frame.pos;
	const size_t room = (xs->frame.len > xs->frame.pos) ? xs->frame.len - xs->frame.pos : 0;
	const size_t to_read = min_size(min_size(remaining, avail), room);
	int notify_err;
	int ret;

	if (to_read == 0) {
		return 0;
	}

	ret = response_ring_read(xs, xs->frame.buf + xs->frame.pos, to_read, &notify_err);
	if (ret < 0) {
		XENLIB_OSAL_LOG_ERR("ring_read failed while fetching type=%u req_id=%u: %d",
				     hdr->type, hdr->req_id, ret);
		*fatal = true;
		return ret;
	}

	xs->frame.pos += ret;
	if (notify_err < 0) {
		*fatal = true;
		return notify_err;
	}

	if (ret < to_read) {
		return -EAGAIN;
	}

	return 0;
}

/* Wake the matching waiter with err, or consume its timeout tombstone. */
static void complete_pending_with_error(struct xenstore_client *xs, uint32_t req_id, int err)
{
	struct pending_response *pending;

	(void)xenlib_osal_mutex_lock(&xs->lock, XENLIB_OSAL_WAIT_FOREVER);
	pending = find_pending(xs, req_id);

	if (pending) {
		(void)remove_pending_locked(xs, pending);
		pending->err = err;
		pending->pos = 0;
		(void)xenlib_osal_semaphore_signal(&pending->sem);
		(void)xenlib_osal_mutex_unlock(&xs->lock);
	} else {
		(void)xenlib_osal_mutex_unlock(&xs->lock);
		/* The caller may have timed out after this frame was selected. */
		(void)consume_timed_out(xs, req_id);
	}
}

static int fail_frame_payload(struct xenstore_client *xs, const struct xsd_sockmsg *hdr, int err,
			      bool fatal)
{
	if (fatal) {
		fail_transport(xs, err, true);
		return err;
	}

	complete_pending_with_error(xs, hdr->req_id, err);

	discard_frame_tail(xs, hdr->len - min_size(xs->frame.pos, hdr->len));

	return err;
}

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
		return -EAGAIN;
	}

	xs->frame.buf[hdr->len] = '\0';

	return 0;
}

/*
 * Response completion and work scheduling
 */

static void complete_pending_from_frame(struct xenstore_client *xs)
{
	struct xsd_sockmsg *hdr = (struct xsd_sockmsg *)(xs->hdr_buf);
	struct pending_response *pending;
	int err = 0;

	if (hdr->type == XS_ERROR) {
		err = xenstore_get_error(xs->frame.buf,
					 min_size(xs->frame.pos, sizeof(xs->work_buf)));
		if (err == 0) {
			err = -EINVAL;
		} else {
			err = -err;
		}
	}

	(void)xenlib_osal_mutex_lock(&xs->lock, XENLIB_OSAL_WAIT_FOREVER);
	pending = find_pending(xs, xs->frame.req_id);
	if (pending) {
		XENLIB_OSAL_ASSERT_NO_MSG(xs->frame.pos <= pending->len);

		(void)remove_pending_locked(xs, pending);
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

		(void)xenlib_osal_semaphore_signal(&pending->sem);
		(void)xenlib_osal_mutex_unlock(&xs->lock);
	} else {
		(void)xenlib_osal_mutex_unlock(&xs->lock);
		/* The caller may have timed out while the payload was being received. */
		(void)consume_timed_out(xs, xs->frame.req_id);
	}

	frame_reset(xs);
}

/* Worker-only: discard the recorded tail before parsing another header. */
static int drain_frame_tail(struct xenstore_client *xs)
{
	int notify_err;
	int ret = 0;

	if (xs->to_discard) {
		XENLIB_OSAL_LOG_DBG("Draining %zu pending bytes", xs->to_discard);

		ret = response_ring_read(xs, NULL, xs->to_discard, &notify_err);
		if (ret < 0) {
			XENLIB_OSAL_LOG_ERR("Failed to drain %zu pending bytes: %d",
					     xs->to_discard, ret);
			return ret;
		}

		xs->to_discard -= (ret < xs->to_discard) ? ret : xs->to_discard;
		if (notify_err < 0) {
			return notify_err;
		}
	}

	return ret;
}

static void submit_response_work(struct xenstore_client *xs)
{
	(void)xenlib_osal_semaphore_signal(&xs->response_sem);
}

/*
 * Worker-only: consume at most one frame and complete its waiter. Return
 * -EAGAIN for partial input, -ENOMSG for an unmatched response, or another
 * negative error after any required waiter, discard, or transport update.
 */
static int process_one_response_frame(struct xenstore_client *xs, size_t avail)
{
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

	complete_pending_from_frame(xs);

	return 0;
}

static void process_response_turn(struct xenstore_client *xs)
{
	size_t loops = 0;
	size_t avail;
	int ret;

	if (!response_worker_enter(xs)) {
		return;
	}

	/* Single-threaded pump: consume new bytes, parse at most one frame per iteration. */
	while (loops++ < XS_EVENT_WORK_MAX_LOOPS) {
		ret = response_ring_available(xs, &avail);
		if (ret < 0) {
			fail_transport(xs, ret, true);
			break;
		}

		if (avail == 0) {
			break;
		}

		ret = drain_frame_tail(xs);
		if (ret < 0) {
			fail_transport(xs, ret, true);
			break;
		}

		avail -= ret;
		if ((avail == 0) || (xs->to_discard != 0)) {
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
			fail_transport(xs, ret, true);
			break;
		}
	}

	if ((loops > XS_EVENT_WORK_MAX_LOOPS) && is_ready(xs)) {
		submit_response_work(xs);
	}

	response_worker_exit(xs);
}

static void response_worker(void *p1, void *p2, void *p3)
{
	struct xenstore_client *xs = p1;

	(void)p2;
	(void)p3;

	for (;;) {
		int err = xenlib_osal_semaphore_wait(&xs->response_sem,
						      XENLIB_OSAL_WAIT_FOREVER);

		if (err != 0) {
			XENLIB_OSAL_LOG_ERR("Failed to wait for response work: %d", err);
			fail_transport(xs, osal_error(err), false);
			return;
		}
		process_response_turn(xs);
	}
}

/* Defer response processing from event-channel IRQ context to the worker. */
static void response_event_channel_callback(void *data)
{
	struct xenstore_client *xs = data;

	submit_response_work(xs);
}

/*
 * Request ring submission
 */

/* Caller holds req_mutex. */
static inline int request_space_available(struct xenstore_client *xs, size_t *avail)
{
	struct xenstore_domain_interface *intf = xs->domint;

	xenlib_osal_dmem_fence_full();

	XENSTORE_RING_IDX cons = intf->req_cons;
	XENSTORE_RING_IDX prod = intf->req_prod;

	xenlib_osal_dmem_fence_full();

	if (xenstore_check_indexes(cons, prod)) {
		XENLIB_OSAL_LOG_ERR("XenStore ring index out of range (req): cons=%u prod=%u",
				    (uint32_t)cons, (uint32_t)prod);
		*avail = 0;
		return -EIO;
	}

	*avail = XENSTORE_RING_SIZE - (prod - cons);
	return 0;
}

/* Caller holds req_mutex. */
static int wait_for_request_space(struct xenstore_client *xs, size_t needed,
				  xenlib_osal_timepoint_t deadline)
{
	size_t avail;
	int err;

	while (true) {
		err = request_space_available(xs, &avail);
		if (err < 0) {
			return err;
		}

		if (avail >= needed) {
			return 0;
		}

		if (xenlib_osal_timepoint_expired(deadline)) {
			XENLIB_OSAL_LOG_ERR("ring_write: timeout waiting for space: %zu < %zu",
					     avail, needed);
			return -ETIMEDOUT;
		}

		xenlib_osal_thread_yield();
	}
}

/* Caller holds req_mutex; write_started tracks whether any frame byte was published. */
static int write_all_request_bytes(struct xenstore_client *xs, const void *buf, size_t len,
				   xenlib_osal_timepoint_t deadline, bool notify_progress,
				   bool *write_started)
{
	const uint8_t *p = buf;
	size_t written = 0;

	while (written < len) {
		int rc = xenstore_ring_write(xs->domint, p + written, len - written, true);

		if (rc < 0) {
			return rc;
		}

		if (rc == 0) {
			if (xenlib_osal_timepoint_expired(deadline)) {
				return -ETIMEDOUT;
			}

			xenlib_osal_thread_yield();
			continue;
		}

		written += rc;
		*write_started = true;

		/*
		 * A frame larger than the ring cannot be published atomically. Notify
		 * after each partial write so the backend can advance req_cons.
		 */
		if (notify_progress) {
			rc = notify_evtchn(xs->local_evtchn);
			if (rc < 0) {
				XENLIB_OSAL_LOG_ERR("notify_evtchn(%u) failed: %d",
						     xs->local_evtchn, rc);
				return rc;
			}
		}
	}

	return written;
}

/*
 * Request construction and synchronous execution
 */

static size_t serialized_param_size(const char *const *params, const size_t *param_lens,
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

static int prepare_request_header(struct xsd_sockmsg *hdr, enum xsd_sockmsg_type type,
				  const char *const *params, const size_t *param_lens,
				  size_t param_num, uint32_t req_id, uint32_t tx_id)
{
	size_t payload_len = 0;

	/* Header construction is pure: fail fast if the aggregate payload is too large. */
	for (size_t i = 0; i < param_num; i++) {
		size_t add = serialized_param_size(params, param_lens, param_num, i);

		if (add > (XENSTORE_PAYLOAD_MAX - payload_len)) {
			XENLIB_OSAL_LOG_ERR("payload too large: %zu > %u", payload_len + add,
					     (unsigned int)XENSTORE_PAYLOAD_MAX);
			return -E2BIG;
		}

		payload_len += add;
	}

	if (payload_len > XENSTORE_PAYLOAD_MAX) {
		XENLIB_OSAL_LOG_ERR("payload too large: %zu > %u", payload_len,
				     (unsigned int)XENSTORE_PAYLOAD_MAX);
		return -E2BIG;
	}

	hdr->type = type;
	hdr->req_id = req_id;
	hdr->tx_id = tx_id;
	hdr->len = payload_len;

	return 0;
}

/* Caller holds req_mutex; set write_started once any frame byte reaches the ring. */
static int write_request_frame(struct xenstore_client *xs, const struct xsd_sockmsg *hdr,
			       const char *const *params, const size_t *param_lens,
			       size_t param_num, xenlib_osal_timepoint_t deadline,
			       bool notify_progress,
			       bool *write_started)
{
	int err;

	*write_started = false;
	err = write_all_request_bytes(xs, hdr, sizeof(*hdr), deadline, notify_progress,
				      write_started);
	if (err < 0) {
		XENLIB_OSAL_LOG_ERR("write_all_request_bytes(hdr) failed: %d", err);
		return err;
	}

	for (size_t i = 0; i < param_num; i++) {
		const size_t param_len = serialized_param_size(params, param_lens, param_num, i);

		err = write_all_request_bytes(xs, params[i], param_len, deadline, notify_progress,
					      write_started);
		if (err < 0) {
			XENLIB_OSAL_LOG_ERR("write_all_request_bytes(param) failed: %d", err);
			return err;
		}
	}

	return 0;
}

static int submit_request(struct xenstore_client *xs, enum xsd_sockmsg_type type,
			  const char *const *params, const size_t *param_lens, size_t param_num,
			  uint32_t req_id, uint32_t tx_id,
			  xenlib_osal_timepoint_t deadline)
{
	struct xsd_sockmsg hdr = {0};
	size_t frame_len;
	bool notify_progress;
	bool write_started = false;
	int err;
	int mutex_err;

	err = prepare_request_header(&hdr, type, params, param_lens, param_num, req_id, tx_id);
	if (err < 0) {
		return err;
	}

	mutex_err = xenlib_osal_mutex_lock(&xs->req_mutex,
					   xenlib_osal_timepoint_timeout(deadline));
	if (mutex_err != 0) {
		if ((mutex_err == -EBUSY) || (mutex_err == -EAGAIN)) {
			return -ETIMEDOUT;
		}

		XENLIB_OSAL_LOG_ERR("Failed to lock request mutex: %d", mutex_err);
		return mutex_err;
	}

	if (!is_ready(xs) || !xs->domint) {
		err = -ENODEV;
		goto end;
	}

	frame_len = SZ_SOCKMSG + hdr.len;
	notify_progress = frame_len > XENSTORE_RING_SIZE;
	/*
	 * Wait for the whole frame only when it can fit in the ring. Larger
	 * frames must be streamed, notifying the backend between partial writes.
	 */
	if (!notify_progress) {
		err = wait_for_request_space(xs, frame_len, deadline);
		if (err < 0) {
			goto end;
		}
	}

	err = write_request_frame(xs, &hdr, params, param_lens, param_num, deadline,
				  notify_progress, &write_started);
	if (err < 0) {
		goto end;
	}

	if (!notify_progress) {
		err = notify_evtchn(xs->local_evtchn);
		if (err < 0) {
			XENLIB_OSAL_LOG_ERR("notify_evtchn(%u) failed: %d",
					     xs->local_evtchn, err);
			goto end;
		}
	}

	submit_response_work(xs);

end:
	if ((err < 0) && write_started) {
		/* Block another submitter before releasing the request-ring lock. */
		mark_transport_failed(xs);
	}
	(void)xenlib_osal_mutex_unlock(&xs->req_mutex);

	if ((err < 0) && write_started) {
		fail_transport(xs, err, false);
	}

	return err;
}

/*
 * Execute one synchronous request. NULL param_lens serializes NUL-terminated
 * strings; otherwise lengths are explicit.
 */
static ssize_t execute_request(struct xenstore_client *xs, enum xsd_sockmsg_type type,
			       const char *const *params, const size_t *param_lens,
			       size_t params_num, char *buf, size_t len, uint32_t tx_id,
			       xenlib_osal_timeout_t timeout)
{
	/*
	 * Stack-allocated waiter: appended to pending_responses, then woken
	 * when the matching response finalizes.
	 */
	struct pending_response resp_local = {
		.node = {0},
		.buf = (uint8_t *)buf,
		.len = len,
		.pos = 0,
		.req_id = 0,
		.expected_type = type,
		.err = 0,
	};
	xenlib_osal_timepoint_t deadline;
	ssize_t result = 0;
	int err;

	if (!is_ready(xs)) {
		XENLIB_OSAL_LOG_ERR("XenStore client not initialized");
		return -ENODEV;
	}

	resp_local.node.next = NULL;
	err = xenlib_osal_semaphore_init(&resp_local.sem, 0, 1);
	if (err != 0) {
		XENLIB_OSAL_LOG_ERR("Failed to initialize request semaphore: %d", err);
		return osal_error(err);
	}
	deadline = xenlib_osal_timepoint_calc(timeout);

	/* Reserve and publish before submission so an immediate response finds its waiter. */
	err = publish_pending(xs, &resp_local);
	if (err < 0) {
		XENLIB_OSAL_LOG_ERR("Request tracking slots exhausted: %d", err);
		return err;
	}

	err = submit_request(xs, type, params, param_lens, params_num, resp_local.req_id, tx_id,
			     deadline);
	if (err < 0) {
		XENLIB_OSAL_LOG_ERR("Failed to submit request: %d", err);
		remove_pending(xs, &resp_local);
		return err;
	}

	err = xenlib_osal_semaphore_wait(&resp_local.sem,
					 xenlib_osal_timepoint_timeout(deadline));
	if (err != 0) {
		XENLIB_OSAL_LOG_DBG("Request req_id=%u timed out while waiting for a reply",
				     resp_local.req_id);
		timeout_pending(xs, &resp_local);
		submit_response_work(xs);
		return -ETIMEDOUT;
	}

	if (resp_local.err < 0) {
		XENLIB_OSAL_LOG_DBG("Error response: %d", resp_local.err);
		return resp_local.err;
	}

	if (resp_local.pos > 0) {
		result = min_size(len, resp_local.pos);
	}

	return result;
}

/*
 * Client initialization
 */

int xs_init(void)
{
	uint64_t paddr = 0;
	uint64_t value = 0;
	void *vaddr = NULL;
	int err;

	err = xenlib_osal_mutex_lock(&xs_init_lock, XENLIB_OSAL_WAIT_FOREVER);
	if (err != 0) {
		XENLIB_OSAL_LOG_ERR("Failed to lock init mutex: %d", err);
		return err;
	}

	if (!xs_cli.primitives_initialized) {
		xs_cli.response_thread_priority = CONFIG_XEN_STORE_CLIENT_WORKQ_PRIORITY;
		err = initialize_sync_primitives(&xs_cli);
		if (err != 0) {
			XENLIB_OSAL_LOG_ERR("Failed to initialize synchronization: %d", err);
			goto out;
		}
	}

	if (is_ready(&xs_cli)) {
		err = 0;
		goto out;
	}

	if (transport_failed(&xs_cli)) {
		XENLIB_OSAL_LOG_ERR("XenStore transport failed and cannot be reinitialized safely");
		err = -EIO;
		goto out;
	}

	xs_cli.next_req_id = 1;

	if (!xs_cli.response_thread_started) {
		xs_cli.response_tid = xenlib_osal_thread_create(
			&xs_cli.response_thread, xs_response_stack,
			CONFIG_XEN_STORE_CLIENT_WORKQ_STACK_SIZE, response_worker,
			&xs_cli, NULL, NULL, xs_cli.response_thread_priority, 0,
			XENLIB_OSAL_NO_WAIT);
		(void)xenlib_osal_thread_name_set(xs_cli.response_tid,
						   "xenstore-response");
		xs_cli.response_thread_started = true;
	}

	xenlib_osal_slist_init(&xs_cli.pending_responses);
	memset(xs_cli.timed_out_req_ids, 0, sizeof(xs_cli.timed_out_req_ids));

	err = hvm_get_parameter(HVM_PARAM_STORE_EVTCHN, DOMID_SELF, &value);
	if (err) {
		XENLIB_OSAL_LOG_ERR("hvm_get_parameter(STORE_EVTCHN) failed: %d", err);
		err = -ENODEV;
		goto out;
	}
	xs_cli.local_evtchn = value;

	err = hvm_get_parameter(HVM_PARAM_STORE_PFN, DOMID_SELF, &paddr);
	if (err) {
		XENLIB_OSAL_LOG_ERR("hvm_get_param(STORE_PFN) failed: err=%d", err);
		err = -EIO;
		goto out;
	}

	err = xenlib_osal_map_phys_memory(&vaddr, XEN_PFN_PHYS(paddr),
					   XEN_PAGE_SIZE,
					   XENLIB_OSAL_MEM_CACHE_WB |
					   XENLIB_OSAL_MEM_PERM_RW);
	if (err != 0) {
		XENLIB_OSAL_LOG_ERR("Failed to map XenStore ring: %d", err);
		goto out;
	}

	xs_cli.domint = (struct xenstore_domain_interface *)vaddr;

	/* Discard responses left in the shared ring by an earlier client lifetime. */
	while (true) {
		size_t avail;
		int notify_err;
		int read;

		err = response_ring_available(&xs_cli, &avail);
		if (err < 0) {
			teardown_transport(&xs_cli, true);
			goto out;
		}

		if (avail == 0) {
			break;
		}

		read = response_ring_read(&xs_cli, NULL, avail, &notify_err);
		if ((read < 0) || (notify_err < 0)) {
			err = (read < 0) ? read : notify_err;
			teardown_transport(&xs_cli, true);
			goto out;
		}
	}

	err = bind_event_channel(xs_cli.local_evtchn, response_event_channel_callback, &xs_cli);
	if (err) {
		XENLIB_OSAL_LOG_ERR("bind_event_channel failed: %d", err);
		teardown_transport(&xs_cli, true);
		err = (err < 0) ? err : -EIO;
		goto out;
	}
	xs_cli.evtchn_bound = true;

	err = unmask_event_channel(xs_cli.local_evtchn);
	if (err) {
		XENLIB_OSAL_LOG_ERR("unmask_event_channel failed: %d", err);
		teardown_transport(&xs_cli, true);
		goto out;
	}

	set_ready(&xs_cli, true);
	err = 0;

out:
	(void)xenlib_osal_mutex_unlock(&xs_init_lock);

	return err;
}

/*
 * XenStore operation helpers
 */

static ssize_t execute_path(enum xsd_sockmsg_type type, const char *path, char *buf, size_t len,
			    uint32_t tx_id, xenlib_osal_timeout_t tout)
{
	const char *const params[] = {path};

	if (!path || !buf || len == 0) {
		return -EINVAL;
	}

	return execute_request(&xs_cli, type, params, NULL,
			       sizeof(params) / sizeof(params[0]), buf, len, tx_id, tout);
}

/* Execute a path-only request whose successful reply payload is not exposed. */
static int execute_path_command(enum xsd_sockmsg_type type, const char *path, uint32_t tx_id,
				xenlib_osal_timeout_t tout)
{
	char response[XS_ERROR_WIRE_MAX];
	ssize_t ret;

	if (!path) {
		return -EINVAL;
	}

	ret = execute_path(type, path, response, sizeof(response), tx_id, tout);

	return (ret < 0) ? (int)ret : 0;
}

/*
 * Public XenStore API
 */

ssize_t xs_read_timeout(const char *path, char *buf, size_t len, uint32_t tx_id,
			xenlib_osal_timeout_t tout)
{
	char *raw;
	ssize_t ret;

	if (!path || (len > 0 && !buf)) {
		return -EINVAL;
	}

	raw = xenlib_osal_memalloc(XENSTORE_PAYLOAD_MAX + 1);
	if (!raw) {
		return -ENOMEM;
	}

	ret = execute_path(XS_READ, path, raw, XENSTORE_PAYLOAD_MAX + 1, tx_id, tout);
	if (ret >= 0 && buf && len > 0) {
		size_t copy_len = min_size((size_t)ret, len - 1);

		memcpy(buf, raw, copy_len);
		buf[copy_len] = '\0';
	}

	xenlib_osal_memfree(raw);

	return ret;
}

ssize_t xs_directory_timeout(const char *path, char *buf, size_t len, uint32_t tx_id,
			     xenlib_osal_timeout_t tout)
{
	char *raw;
	ssize_t ret;

	if (!path || (len > 0 && !buf)) {
		return -EINVAL;
	}

	raw = xenlib_osal_memalloc(XENSTORE_PAYLOAD_MAX + 1);
	if (!raw) {
		return -ENOMEM;
	}

	ret = execute_path(XS_DIRECTORY, path, raw, XENSTORE_PAYLOAD_MAX + 1, tx_id,
			   tout);
	if ((ret > 0) && (raw[ret - 1] != '\0')) {
		ret = -EPROTO;
	} else if (ret >= 0 && buf && len > 0) {
		memcpy(buf, raw, min_size((size_t)ret, len));
	}

	xenlib_osal_memfree(raw);

	return ret;
}

ssize_t xs_get_permissions_timeout(const char *path, struct xs_perm_entry *perms,
				   size_t perms_num, uint32_t tx_id,
				   xenlib_osal_timeout_t tout)
{
	struct xs_perm_entry *parsed = perms;
	char *raw;
	ssize_t count;
	ssize_t ret;

	if (!path || (perms_num > 0 && !perms)) {
		return -EINVAL;
	}

	raw = xenlib_osal_memalloc(XENSTORE_PAYLOAD_MAX + 1);
	if (!raw) {
		return -ENOMEM;
	}

	ret = execute_path(XS_GET_PERMS, path, raw, XENSTORE_PAYLOAD_MAX + 1, tx_id, tout);
	if (ret < 0) {
		goto out;
	}
	if (ret == 0) {
		ret = -EPROTO;
		goto out;
	}

	count = xenstore_perm_parse_wire(raw, (size_t)ret, NULL, 0);
	if (count <= 0 || perms_num == 0) {
		ret = count;
		goto out;
	}

	if ((size_t)count > perms_num) {
		if ((size_t)count > (SIZE_MAX / sizeof(*parsed))) {
			ret = -EOVERFLOW;
			goto out;
		}

		parsed = xenlib_osal_memalloc((size_t)count * sizeof(*parsed));
		if (!parsed) {
			ret = -ENOMEM;
			goto out;
		}
	}

	ret = xenstore_perm_parse_wire(raw, (size_t)ret, parsed, (size_t)count);
	if (ret >= 0 && parsed != perms) {
		memcpy(perms, parsed, perms_num * sizeof(*perms));
	}

	if (parsed != perms) {
		xenlib_osal_memfree(parsed);
	}

out:
	xenlib_osal_memfree(raw);

	return ret;
}

int xs_set_permissions_timeout(const char *path, const struct xs_perm_entry *perms,
			       size_t perms_num, uint32_t tx_id,
			       xenlib_osal_timeout_t tout)
{
	char response[XS_ERROR_WIRE_MAX];
	char *payload;
	size_t payload_len;
	ssize_t ret;

	if (!path || !perms || perms_num == 0) {
		return -EINVAL;
	}

	payload = xenlib_osal_memalloc(XENSTORE_PAYLOAD_MAX);
	if (!payload) {
		return -ENOMEM;
	}

	payload_len = strlen(path) + 1;
	if (payload_len > XENSTORE_PAYLOAD_MAX) {
		ret = -E2BIG;
		goto out;
	}
	memcpy(payload, path, payload_len);

	for (size_t i = 0; i < perms_num; i++) {
		char wire;
		int len;

		if (((uint32_t)perms[i].domid & DOMID_MASK) != (uint32_t)perms[i].domid) {
			ret = -EINVAL;
			goto out;
		}

		ret = xenstore_perm_to_wire(perms[i].perm, &wire);
		if (ret < 0) {
			goto out;
		}

		len = snprintf(payload + payload_len, XENSTORE_PAYLOAD_MAX - payload_len,
			       "%c%u", wire, (uint32_t)perms[i].domid);
		if (len < 0 || (size_t)len >= (XENSTORE_PAYLOAD_MAX - payload_len)) {
			ret = -E2BIG;
			goto out;
		}
		payload_len += (size_t)len + 1;
	}

	const char *const params[] = {payload};
	const size_t param_lens[] = {payload_len};

	ret = execute_request(&xs_cli, XS_SET_PERMS, params, param_lens,
			      sizeof(params) / sizeof(params[0]), response,
			      sizeof(response), tx_id, tout);
	if (ret >= 0) {
		ret = 0;
	}

out:
	xenlib_osal_memfree(payload);

	return (int)ret;
}

int xs_write_timeout(const char *path, const char *value, uint32_t tx_id,
		     xenlib_osal_timeout_t tout)
{
	char response[XS_ERROR_WIRE_MAX];
	ssize_t ret;

	if (!path || !value) {
		return -EINVAL;
	}

	const char *const params[] = {path, value};
	const size_t param_lens[] = {
		strlen(path) + 1,
		strlen(value),
	};

	ret = execute_request(&xs_cli, XS_WRITE, params, param_lens,
			      sizeof(params) / sizeof(params[0]), response,
			      sizeof(response), tx_id, tout);

	return (ret < 0) ? (int)ret : 0;
}

int xs_mkdir_timeout(const char *path, uint32_t tx_id, xenlib_osal_timeout_t tout)
{
	return execute_path_command(XS_MKDIR, path, tx_id, tout);
}

int xs_rm_timeout(const char *path, uint32_t tx_id, xenlib_osal_timeout_t tout)
{
	return execute_path_command(XS_RM, path, tx_id, tout);
}
