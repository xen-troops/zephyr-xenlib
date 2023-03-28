/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <zephyr/xen/events.h>
#include <zephyr/xen/public/hvm/params.h>
#include <zephyr/xen/public/io/xs_wire.h>
#include <zephyr/xen/hvm.h>
#include <zephyr/logging/log.h>

#include "domain.h"
#include "xenstore_srv.h"
#include "xss.h"

LOG_MODULE_REGISTER(xenstore);

#define XENSTORE_STACK_SIZE_PER_DOM (32 * 1024)
K_KERNEL_STACK_DEFINE(xenstore_thrd_stack,
		      XENSTORE_STACK_SIZE_PER_DOM * CONFIG_DOM_MAX);
static int stack_slots[CONFIG_DOM_MAX] = { 0 };

K_MUTEX_DEFINE(xsel_mutex);
K_MUTEX_DEFINE(pfl_mutex);
K_MUTEX_DEFINE(wel_mutex);

sys_dlist_t watch_entry_list = SYS_DLIST_STATIC_INIT(&watch_entry_list);
sys_dlist_t pending_watch_event_list = SYS_DLIST_STATIC_INIT(&pending_watch_event_list);

struct xs_entry root_xenstore;

struct message_handle {
	void (*h)(struct xen_domain *domain, uint32_t id, char *payload, uint32_t sz);
};

struct watch_entry *key_to_watcher(char *key, bool complete, char *token)
{
	struct watch_entry *iter;
	size_t keyl = strlen(key);

	SYS_DLIST_FOR_EACH_CONTAINER (&watch_entry_list, iter, node) {
		if ((!complete || strlen(key) == strlen(iter->key)) &&
		    memcmp(iter->key, key, keyl) == 0 &&
		    (token == NULL || strlen(token) == 0 ||
		     0 == memcmp(iter->token, token, strlen(iter->token)))) {
			return iter;
		}
	}

	return NULL;
}

struct xs_entry *key_to_entry(const char *key)
{
	static const char rootdir[] = "/";

	char *tok, *tok_state;
	struct xs_entry *next, *iter = NULL;
	sys_dlist_t *inspected_list = &root_xenstore.child_list;
	char key_buffer[XENSTORE_ABS_PATH_MAX + 1];
	size_t keyl;

	if (!key)
		return NULL;

	keyl = strlen(key);
	if (keyl > XENSTORE_ABS_PATH_MAX)
		return NULL;

	if (strncmp(rootdir, key, keyl) == 0) {
		return &root_xenstore;
	}

	strncpy(key_buffer, key, keyl + 1);
	for (tok = strtok_r(key_buffer, "/", &tok_state);
	     tok != NULL;
	     tok = strtok_r(NULL, "/", &tok_state)) {
		SYS_DLIST_FOR_EACH_CONTAINER_SAFE (inspected_list, iter, next, node) {
			if (strcmp(iter->key, tok) == 0) {
				break;
			}
		}

		if (iter == NULL) {
			break;
		}

		inspected_list = &iter->child_list;
	}

	return iter;
}

static bool check_indexes(XENSTORE_RING_IDX cons, XENSTORE_RING_IDX prod)
{
	return ((prod - cons) > XENSTORE_RING_SIZE);
}

static size_t get_input_offset(XENSTORE_RING_IDX cons, XENSTORE_RING_IDX prod, size_t *len)
{
	size_t delta = prod - cons;
	*len = XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(cons);

	if (delta < *len) {
		*len = delta;
	}

	return MASK_XENSTORE_IDX(cons);
}

static size_t get_output_offset(XENSTORE_RING_IDX cons, XENSTORE_RING_IDX prod, size_t *len)
{
	size_t delta = XENSTORE_RING_SIZE - cons + prod;
	*len = XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(prod);

	if (delta < *len) {
		*len = delta;
	}

	return MASK_XENSTORE_IDX(prod);
}

void write_xb(struct xenstore_domain_interface *intf, uint8_t *data, uint32_t len)
{
	size_t blen = 0;
	size_t offset = 0;

	do {
		size_t tail = get_output_offset(intf->rsp_cons, intf->rsp_prod, &blen);

		if (blen == 0) {
			continue;
		}

		size_t effect = blen > len ? len : blen;
		memcpy(intf->rsp + tail, data + offset, effect);
		offset += effect;
		len -= effect;
		intf->rsp_prod += effect;
	} while (len > 0);
}

size_t read_xb(struct xen_domain *domain, uint8_t *data, uint32_t len)
{
	size_t blen = 0;
	size_t offset = 0;
	struct xenstore_domain_interface *intf = domain->domint;

	do {
		size_t prod = intf->req_prod;
		size_t ring_offset = get_input_offset(intf->req_cons, prod, &blen);

		if (blen == 0) {
			notify_evtchn(domain->local_xenstore_evtchn);
			return 0;
		}

		size_t effect = (blen > len) ? len : blen;
		memcpy(data + offset, intf->req + ring_offset, effect);
		offset += effect;
		len -= effect;
		intf->req_cons += effect;
	} while (len > 0);

	return offset;
}

void send_reply_sz(struct xen_domain *domain, uint32_t id, uint32_t msg_type, const char *payload,
		   int sz)
{
	struct xenstore_domain_interface *intf = domain->domint;
	struct xsd_sockmsg h = { .req_id = id, .type = msg_type, .len = sz };

	if (check_indexes(intf->rsp_cons, intf->rsp_prod)) {
		intf->rsp_cons = 0;
		intf->rsp_prod = 0;
	}

	write_xb(intf, (uint8_t *)&h, sizeof(struct xsd_sockmsg));
	notify_evtchn(domain->local_xenstore_evtchn);
	write_xb(intf, (uint8_t *)payload, sz);
	notify_evtchn(domain->local_xenstore_evtchn);
}

void send_reply(struct xen_domain *domain, uint32_t id, uint32_t msg_type, const char *payload)
{
	send_reply_sz(domain, id, msg_type, payload, strlen(payload) + 1);
}

void send_reply_read(struct xen_domain *domain, uint32_t id, uint32_t msg_type, char *payload)
{
	send_reply_sz(domain, id, msg_type, payload, strlen(payload));
}

void handle_directory(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len)
{
	size_t data_offset = strlen(payload) + 1;
	const char localpath[] = "/";
	char path[STRING_LENGTH_MAX];

	if (memcmp(payload, localpath, strlen(localpath)) == 0) {
		memcpy(path, payload, data_offset);
	} else {
		snprintf(path, STRING_LENGTH_MAX, "/local/domain/%d/%s", domain->domid, payload);
	}

	char dirlist[256] = { 0 };
	size_t reply_sz = 0;

	k_mutex_lock(&xsel_mutex, K_FOREVER);
	struct xs_entry *entry = key_to_entry(path);

	if (entry) {
		struct xs_entry *iter;

		SYS_DLIST_FOR_EACH_CONTAINER (&entry->child_list, iter, node) {
			size_t keyl = strlen(iter->key) + 1;
			memcpy(dirlist + reply_sz, iter->key, keyl);
			reply_sz += keyl;
		}
	}

	k_mutex_unlock(&xsel_mutex);
	send_reply_sz(domain, id, XS_DIRECTORY, dirlist, reply_sz);
}

void send_errno(struct xen_domain *domain, uint32_t id, int err)
{
	unsigned int i;
	LOG_ERR("Sending error=%d", err);

	for (i = 0; err != xsd_errors[i].errnum; i++) {
		if (i == ARRAY_SIZE(xsd_errors) - 1) {
			LOG_ERR("xenstored: error %i untranslatable", err);
			i = 0; /* EINVAL */
			break;
		}
	}

	send_reply(domain, id, XS_ERROR, xsd_errors[i].errstring);
}

int fire_watcher(struct xen_domain *domain, uint32_t id, char *key)
{
	struct watch_entry *iter, *next;
	size_t kplen = strlen(key);
	char local[STRING_LENGTH_MAX];
	snprintf(local, STRING_LENGTH_MAX, "/local/domain/%d", domain->domid);
	size_t loclen = strlen(local);

	SYS_DLIST_FOR_EACH_CONTAINER_SAFE (&watch_entry_list, iter, next, node) {
		size_t klen = strlen(iter->key);
		if (memcmp(iter->key, key, klen) == 0) {
			size_t ioffset = 1;
			size_t ooffset = 0;
			if (iter->is_relative)
				klen = loclen;
			else {
				klen = 0;
				ioffset = 0;
				ooffset = 1;
			}

			size_t tlen = strlen(iter->token);
			size_t plen = tlen + kplen - klen + 1 + ooffset;
			char *pload = k_malloc(plen);

			memset(pload, 0, plen);
			memcpy(pload, key + klen + ioffset, kplen - klen);
			memcpy(pload + kplen - klen + ooffset, iter->token, tlen);

			send_reply_sz(domain, id, XS_WATCH_EVENT, pload, plen);

			k_free(pload);
		}
	}

	return 1;
}

void xss_do_write(const char *const_path, const char *data)
{
	struct xs_entry *iter = NULL;
	char *path;
	char *tok, *tok_state;
	size_t vall = strlen(data) + 1;
	size_t namelen;

	path = k_malloc(strlen(const_path) + 1);
	strcpy(path, const_path);

	k_mutex_lock(&xsel_mutex, K_FOREVER);
	sys_dlist_t *inspected_list = &root_xenstore.child_list;

	for (tok = strtok_r(path, "/", &tok_state); tok != NULL; tok = strtok_r(NULL, "/", &tok_state)) {
		SYS_DLIST_FOR_EACH_CONTAINER (inspected_list, iter, node) {
			if (strcmp(iter->key, tok) == 0) {
				break;
			}
		}

		if (iter == NULL) {
			iter = k_malloc(sizeof(*iter));

			namelen = strlen(tok);
			iter->key = k_malloc(namelen + 1);
			memcpy(iter->key, tok, namelen);
			iter->key[namelen] = 0;
			iter->value = NULL;

			sys_dlist_init(&iter->child_list);
			sys_dnode_init(&iter->node);
			sys_dlist_append(inspected_list, &iter->node);
		}

		inspected_list = &iter->child_list;
	}

	if (iter && vall > 0) {
		if (iter->value != NULL) {
			k_free(iter->value);
		}

		iter->value = k_malloc(vall);
		memcpy(iter->value, data, vall);
	}

	k_mutex_unlock(&xsel_mutex);
}

int xss_write(const char *path, const char *value)
{
	xss_do_write(path, value);
	return 0;
}

int xss_read(const char *path, char *value, size_t len)
{
	int rc = -ENOENT;
	struct xs_entry *entry;

	k_mutex_lock(&xsel_mutex, K_FOREVER);

	entry = key_to_entry(path);
	if (entry) {
		strncpy(value, entry->value, len);
		rc = 0;
	}

	k_mutex_unlock(&xsel_mutex);
	return rc;
}

int xss_read_integer(const char *path, int *value)
{
	int rc;
	char ns[32] = { 0 };

	rc = xss_read(path, ns, sizeof(ns));
	if (!rc)
		*value = atoi(ns);
	return rc;
}

int xss_set_perm(const char *path, domid_t domid, enum xs_perm perm)
{
	return 0;
}

static void notify_watchers(const char *path, uint32_t caller_domid)
{
	struct watch_entry *iter;
	struct pending_watch_event_entry *pentry;

	k_mutex_lock(&wel_mutex, K_FOREVER);
	SYS_DLIST_FOR_EACH_CONTAINER(&watch_entry_list, iter, node) {
		if (iter->domain->domid == caller_domid ||
		    strncmp(iter->key, path, strlen(iter->key))) {
			continue;
		}

		pentry = k_malloc(sizeof(*pentry));
		if (!pentry) {
			goto pentry_fail;
		}

		pentry->key = k_malloc(strlen(path) + 1);
		if (!pentry->key) {
			goto pkey_fail;
		}

		strcpy(pentry->key, path);
		pentry->domain = iter->domain;

		sys_dnode_init(&pentry->node);
		k_mutex_lock(&pfl_mutex, K_FOREVER);
		sys_dlist_append(&pending_watch_event_list,
				 &pentry->node);
		k_mutex_unlock(&pfl_mutex);

		/* Wake watcher thread up */
		k_sem_give(&iter->domain->xb_sem);

	}
	k_mutex_unlock(&wel_mutex);

	return;

pkey_fail:
	k_free(pentry);
pentry_fail:
	k_mutex_unlock(&wel_mutex);
	LOG_WRN("Failed to notify Domain#%d about path %s, no memory",
		iter->domain->domid, path);
}

void _handle_write(struct xen_domain *domain, uint32_t id, uint32_t msg_type, char *payload,
		   uint32_t len)
{
	char localpath[] = "/";
	char path[STRING_LENGTH_MAX];
	char *data;
	uint32_t data_offset = strlen(payload) + 1;

	data = payload + data_offset;

	if (len < data_offset) {
		LOG_ERR("Data size mismatch");
		send_errno(domain, id, EINVAL);
		return;
	}

	if (memcmp(payload, localpath, strlen(localpath)) == 0) {
		memcpy(path, payload, data_offset);
	} else {
		snprintf(path, STRING_LENGTH_MAX, "/local/domain/%d/%s", domain->domid, payload);
	}

	data[len - data_offset] = 0;
	xss_do_write(path, data);

	send_reply(domain, id, msg_type, "OK");

	notify_watchers(path, domain->domid);
}

void handle_write(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len)
{
	_handle_write(domain, id, XS_WRITE, payload, len);
}

void handle_mkdir(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len)
{
	_handle_write(domain, id, XS_MKDIR, payload, len);
}

void process_pending_watch_events(struct xen_domain *domain, uint32_t id)
{
	struct pending_watch_event_entry *iter, *next;

	k_mutex_lock(&pfl_mutex, K_FOREVER);
	SYS_DLIST_FOR_EACH_CONTAINER_SAFE (&pending_watch_event_list, iter, next, node) {
		/* TODO: check and simplify this if statements if possible */
		if (domain == iter->domain) {
			if (domain->running_transaction == 0 &&
			    fire_watcher(domain, id, iter->key)) {
				if (domain->pending_stop_transaction == true &&
				    domain->stop_transaction_id == 0) {
					continue;
				}

				k_free(iter->key);
				sys_dlist_remove(&iter->node);
				k_free(iter);
			}
		}
	}
	k_mutex_unlock(&pfl_mutex);
}

void handle_control(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len)
{
	send_reply(domain, id, XS_CONTROL, "OK");
}

void handle_get_perms(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len)
{
	send_errno(domain, id, ENOSYS);
}

void handle_set_perms(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len)
{
	send_reply(domain, id, XS_SET_PERMS, "OK");
}

void remove_watch_entry(struct watch_entry *entry)
{
	k_free(entry->key);
	k_free(entry->token);
	sys_dlist_remove(&entry->node);
	k_free(entry);
}

void handle_reset_watches(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len)
{
	struct watch_entry *iter, *next;

	k_mutex_lock(&wel_mutex, K_FOREVER);
	SYS_DLIST_FOR_EACH_CONTAINER_SAFE (&watch_entry_list, iter, next, node) {
		remove_watch_entry(iter);
	}
	k_mutex_unlock(&wel_mutex);

	send_reply(domain, id, XS_RESET_WATCHES, "OK");
}

void handle_read(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len)
{
	const char localpath[] = "/";
	char path[STRING_LENGTH_MAX];
	struct xs_entry *entry;

	if (memcmp(payload, localpath, strlen(localpath)) == 0) {
		memcpy(path, payload, strlen(payload) + 1);
	} else {
		snprintf(path, STRING_LENGTH_MAX, "/local/domain/%d/%s", domain->domid, payload);
	}

	entry = key_to_entry(path);

	if (entry) {
		send_reply_read(domain, id, XS_READ, entry->value ? entry->value : "");
		return;
	}

	send_reply(domain, id, XS_ERROR, "ENOENT");
}

void remove_recurse(sys_dlist_t *chlds)
{
	struct xs_entry *entry, *next;
	SYS_DLIST_FOR_EACH_CONTAINER_SAFE (chlds, entry, next, node) {
		if (entry->key) {
			k_free(entry->key);
			entry->key = NULL;
		}

		if (entry->value) {
			k_free(entry->value);
			entry->value = NULL;
		}

		remove_recurse(&entry->child_list);

		sys_dlist_remove(&entry->node);
		k_free(entry);
	}
}

static int xss_do_rm(struct xs_entry *entry)
{
	if (!entry)
		return -EINVAL;

	if (entry->key) {
		k_free(entry->key);
		entry->key = NULL;
	}

	if (entry->value) {
		k_free(entry->value);
		entry->value = NULL;
	}

	k_mutex_lock(&xsel_mutex, K_FOREVER);
	sys_dlist_remove(&entry->node);
	sys_dlist_t chlds = entry->child_list;

	k_free(entry);
	k_mutex_unlock(&xsel_mutex);

	remove_recurse(&chlds);
	return 0;
}

int xss_rm(const char *path)
{
	return xss_do_rm(key_to_entry(path));
}

void handle_rm(struct xen_domain *domain, uint32_t id, char *payload,
	       uint32_t len)
{
	xss_do_rm(key_to_entry(payload));
	send_reply_read(domain, id, XS_RM, "");
}

void handle_watch(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len)
{
	const char localpath[] = "/";
	char path[STRING_LENGTH_MAX];
	char token[STRING_LENGTH_MAX];
	struct watch_entry *wentry;
	struct pending_watch_event_entry *pentry;
	size_t plen = 0, full_plen;
	bool path_is_relative;

	path_is_relative = !!(memcmp(payload, localpath, strlen(localpath)));

	/*
	 * Path and token come inside payload char * and are separated
	 * with '\0', so we can find path len with strnlen here.
	 */
	plen = strnlen(payload, len) + 1;
	if (plen > STRING_LENGTH_MAX) {
		goto path_fail;
	}

	if (path_is_relative) {
		full_plen = snprintf(path, sizeof(path), "/local/domain/%d/%s",
			 domain->domid, payload);
		if (full_plen < 0) {
			goto path_fail;
		}

		/* Add symbol for trailing '\0', skipped by snprintf */
		full_plen++;
	} else {
		memcpy(path, payload, plen);
		full_plen = plen;
	}

	/* Extract token value from payload (between 'path' and end '\0') */
	memcpy(token, payload + plen, len - plen);

	k_mutex_lock(&wel_mutex, K_FOREVER);
	wentry = key_to_watcher(path, true, token);

	if (wentry) {
		/* Same watch, different path form */
		wentry->is_relative = path_is_relative;
		k_mutex_unlock(&wel_mutex);
	} else {
		/* Watch does not exist, create it */
		k_mutex_unlock(&wel_mutex);

		wentry = k_malloc(sizeof(*wentry));
		if (!wentry) {
			goto wentry_fail;
		}

		wentry->key = k_malloc(full_plen);
		if (!wentry->key) {
			goto wkey_fail;
		}

		wentry->token = k_malloc(len - plen);
		if (!wentry->token) {
			goto wtoken_fail;
		}

		memcpy(wentry->key, path, full_plen);
		memcpy(wentry->token, token, len - plen);
		wentry->domain = domain;
		wentry->is_relative = path_is_relative;
		sys_dnode_init(&wentry->node);

		k_mutex_lock(&wel_mutex, K_FOREVER);
		sys_dlist_append(&watch_entry_list, &wentry->node);
		k_mutex_unlock(&wel_mutex);
	}
	send_reply(domain, id, XS_WATCH, "OK");

	k_mutex_lock(&xsel_mutex, K_FOREVER);
	if (key_to_entry(path)) {
		pentry = k_malloc(sizeof(*pentry));
		if (!pentry) {
			goto pentry_fail;
		}

		pentry->key = k_malloc(full_plen);
		if (!pentry->key) {
			goto pkey_fail;
		}

		memcpy(pentry->key, path, full_plen);
		pentry->domain = domain;
		sys_dnode_init(&pentry->node);

		k_mutex_lock(&pfl_mutex, K_FOREVER);
		sys_dlist_append(&pending_watch_event_list, &pentry->node);
		k_mutex_unlock(&pfl_mutex);

		/* Notify domain thread about new pending event */
		k_sem_give(&domain->xb_sem);
	}
	k_mutex_unlock(&xsel_mutex);

	return;

path_fail:
	LOG_ERR("Failed to add watch for %s, path is too long", payload);
	send_reply(domain, id, XS_ERROR, "ENOMEM");

	return;

wtoken_fail:
	k_free(wentry->key);
wkey_fail:
	k_free(wentry);
wentry_fail:
	LOG_WRN("Failed to create watch for Domain#%d, no memory",
		domain->domid);
	send_reply(domain, id, XS_ERROR, "ENOMEM");

	return;

pkey_fail:
	k_free(pentry);
pentry_fail:
	k_mutex_unlock(&xsel_mutex);
	/*
	 * We can't notify domain that this file already exists,
	 * so leave it without first WATCH_EVENT
	 */
	LOG_WRN("Failed to notify Domain#%d, no memory for event",
		domain->domid);
}

void handle_unwatch(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len)
{
	const char localpath[] = "/";
	char path[STRING_LENGTH_MAX] = { 0 };
	char token[STRING_LENGTH_MAX] = { 0 };
	size_t plen = 0;
	for (; plen < len && payload[plen] != '\0'; ++plen)
		;
	plen += 1;

	if (memcmp(payload, localpath, strlen(localpath)) == 0) {
		memcpy(path, payload, plen);
	} else {
		snprintf(path, STRING_LENGTH_MAX, "/local/domain/%d/%s", domain->domid, payload);
	}

	memcpy(token, payload + plen, len - plen);
	struct watch_entry *entry = key_to_watcher(path, true, token);

	if (entry) {
		if (entry->domain == domain) {
			k_mutex_lock(&wel_mutex, K_FOREVER);
			remove_watch_entry(entry);
			k_mutex_unlock(&wel_mutex);
		}
	}

	send_reply(domain, id, XS_UNWATCH, "");
}

void handle_transaction_start(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len)
{
	char buf[8] = { 0 };

	if (domain->running_transaction)
	{
		LOG_ERR("domid#%u: transaction already started", domain->domid);
		send_errno(domain, id, EBUSY);
		return;
	}

	domain->running_transaction = ++domain->transaction;
	snprintf(buf, 8, "%d", domain->running_transaction);
	send_reply(domain, id, XS_TRANSACTION_START, buf);
}

void handle_transaction_stop(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len)
{
	// TODO check contents, transaction completion, etc
	domain->stop_transaction_id = id;
	domain->pending_stop_transaction = true;
	domain->running_transaction = 0;
}

void handle_get_domain_path(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len)
{
	char path[32] = { 0 };
	char domid[8] = { 0 };
	memcpy(domid, payload, len);
	snprintf(path, 32, "/local/domain/%s", domid);
	send_reply(domain, id, XS_GET_DOMAIN_PATH, path);
}

void xs_evtchn_cb(void *priv)
{
	struct xen_domain *domain = (struct xen_domain *)priv;
	k_sem_give(&domain->xb_sem);
}

int start_domain_stored(struct xen_domain *domain)
{
	size_t slot = 0;
	int rc = 0;

	k_sem_init(&domain->xb_sem, 0, 1);
	rc = bind_interdomain_event_channel(domain->domid,
								       domain->xenstore_evtchn,
								       xs_evtchn_cb,
								       (void *)domain);

	if (rc < 0)
		return rc;

	domain->local_xenstore_evtchn = rc;

	rc = hvm_set_parameter(HVM_PARAM_STORE_EVTCHN, domain->domid, domain->xenstore_evtchn);
	if (rc) {
		LOG_ERR("Failed to set domain xenbus evtchn param (rc=%d)", rc);
		return rc;
	}

	domain->xenstore_thrd_stop = false;

	for (; slot < CONFIG_DOM_MAX && stack_slots[slot] != 0; ++slot)
		;

	if (slot >= CONFIG_DOM_MAX) {
		LOG_ERR("Unable to find memory for xenbus stack (%zu >= MAX:%d)",
			slot, CONFIG_DOM_MAX);
		return 1;
	}

	stack_slots[slot] = domain->domid;
	domain->stack_slot = slot;
	domain->xenstore_tid =
		k_thread_create(&domain->xenstore_thrd,
				xenstore_thrd_stack +
				XENSTORE_STACK_SIZE_PER_DOM * slot,
				K_KERNEL_STACK_SIZEOF(xenstore_thrd_stack) /
				CONFIG_DOM_MAX, xenstore_evt_thrd,
				domain, NULL, NULL, 7, 0, K_NO_WAIT);

	return 0;
}

int stop_domain_stored(struct xen_domain *domain)
{
	int rc = 0;

	LOG_DBG("Destroy domain#%u", domain->domid);
	domain->xenstore_thrd_stop = true;
	k_sem_give(&domain->xb_sem);
	k_thread_join(&domain->xenstore_thrd, K_FOREVER);
	stack_slots[domain->stack_slot] = 0;
	unbind_event_channel(domain->local_xenstore_evtchn);
	rc = evtchn_close(domain->local_xenstore_evtchn);

	if (rc)
	{
		LOG_ERR("Unable to close event channel#%u (rc=%d)", domain->local_xenstore_evtchn, rc);
	}

	return rc;
}

void cleanup_domain_watches(struct xen_domain *domain)
{
	struct watch_entry *iter, *next;
	struct pending_watch_event_entry *pwe_iter, *pwe_next;

	k_mutex_lock(&wel_mutex, K_FOREVER);
	SYS_DLIST_FOR_EACH_CONTAINER_SAFE(&watch_entry_list, iter, next, node) {
		if (iter->domain == domain) {
			remove_watch_entry(iter);
		}
	}
	k_mutex_unlock(&wel_mutex);

	k_mutex_lock(&pfl_mutex, K_FOREVER);
	SYS_DLIST_FOR_EACH_CONTAINER_SAFE(&pending_watch_event_list, pwe_iter,
					  pwe_next, node) {
		if (pwe_iter->domain == domain) {
			sys_dlist_remove(&pwe_iter->node);
			k_free(pwe_iter->key);
			k_free(pwe_iter);
		}
	}
	k_mutex_unlock(&pfl_mutex);
}

const struct message_handle message_handle_list[XS_TYPE_COUNT] = { [XS_CONTROL] = { handle_control },
					    [XS_DIRECTORY] = { handle_directory },
					    [XS_READ] = { handle_read },
					    [XS_GET_PERMS] = { handle_get_perms },
					    [XS_WATCH] = { handle_watch },
					    [XS_UNWATCH] = { handle_unwatch },
					    [XS_TRANSACTION_START] = { handle_transaction_start },
					    [XS_TRANSACTION_END] = { handle_transaction_stop },
					    [XS_INTRODUCE] = { NULL },
					    [XS_RELEASE] = { NULL },
					    [XS_GET_DOMAIN_PATH] = { handle_get_domain_path },
					    [XS_WRITE] = { handle_write },
					    [XS_MKDIR] = { handle_mkdir },
					    [XS_RM] = { handle_rm },
					    [XS_SET_PERMS] = { handle_set_perms },
					    [XS_WATCH_EVENT] = { NULL },
					    [XS_ERROR] = { NULL },
					    [XS_IS_DOMAIN_INTRODUCED] = { NULL },
					    [XS_RESUME] = { NULL },
					    [XS_SET_TARGET] = { NULL },
					    [XS_RESET_WATCHES] = { handle_reset_watches },
					    [XS_DIRECTORY_PART] = { NULL } };

void xenstore_evt_thrd(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	size_t sz;
	size_t delta;
	struct xsd_sockmsg *header;
	char input_buffer[XENSTORE_RING_SIZE];
	struct xen_domain *domain = p1;
	struct xenstore_domain_interface *intf = domain->domint;

	domain->transaction = 0;
	domain->running_transaction = 0;
	domain->stop_transaction_id = 0;
	domain->pending_stop_transaction = false;

	while (!domain->xenstore_thrd_stop) {
		process_pending_watch_events(domain, domain->running_transaction);

		if (domain->pending_stop_transaction) {
			send_reply(domain, domain->stop_transaction_id, XS_TRANSACTION_END, "");
			domain->stop_transaction_id = 0;
			domain->pending_stop_transaction = false;
		}

		if (intf->req_prod <= intf->req_cons)
		{
			k_sem_take(&domain->xb_sem, K_FOREVER);
		}

		header = (struct xsd_sockmsg*)input_buffer;
		sz = 0;

		do {
			delta = read_xb(domain, (uint8_t *)input_buffer + sz, sizeof(struct xsd_sockmsg));

			if (delta == 0)
			{
				/* Missing header data, nothing to read. Perhaps pending watch event from
				 * different domain. */
				break;
			}

			sz += delta;
		} while (sz < sizeof(struct xsd_sockmsg));

		if (sz == 0)
		{
			/* Skip message body processing, as no header received. */
			continue;
		}

		sz = 0;

		do
		{
			delta = read_xb(domain, (uint8_t *)input_buffer + sizeof(struct xsd_sockmsg) + sz, header->len);
			sz += delta;
		} while (sz < header->len);

		if (message_handle_list[header->type].h == NULL) {
			LOG_ERR("Unsupported message type: %u", header->type);
			send_errno(domain, header->req_id, ENOSYS);
		} else {
			message_handle_list[header->type].h(domain, header->req_id,
							 (char *)(header + 1), header->len);
		}

		notify_evtchn(domain->local_xenstore_evtchn);
	}

	/* Need to cleanup all watches and events before destroying */
	cleanup_domain_watches(domain);
}

void init_root(void)
{
	sys_dlist_init(&root_xenstore.child_list);
	sys_dnode_init(&root_xenstore.node);
}
