/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <zephyr/init.h>
#include <zephyr/xen/events.h>
#include <zephyr/xen/public/hvm/params.h>
#include <zephyr/xen/public/io/xs_wire.h>
#include <zephyr/xen/hvm.h>
#include <zephyr/logging/log.h>

#include <mem-mgmt.h>
#include "domain.h"
#include "xenstore_srv.h"
#include "xss.h"

LOG_MODULE_REGISTER(xenstore);

/* max length of string that holds '/local/domain/%domid/' (domid 0-32767) */
#define XENSTORE_MAX_LOCALPATH_LEN	21

#define XENSTORE_STACK_SIZE_PER_DOM	4096
static K_THREAD_STACK_ARRAY_DEFINE(xenstore_thrd_stack,
				   CONFIG_DOM_MAX,
				   XENSTORE_STACK_SIZE_PER_DOM);

static uint32_t used_threads;
static K_MUTEX_DEFINE(xs_stack_lock);
BUILD_ASSERT(sizeof(used_threads) * CHAR_BIT >= CONFIG_DOM_MAX);

K_MUTEX_DEFINE(xsel_mutex);
K_MUTEX_DEFINE(pfl_mutex);
K_MUTEX_DEFINE(wel_mutex);

sys_dlist_t watch_entry_list = SYS_DLIST_STATIC_INIT(&watch_entry_list);
sys_dlist_t pending_watch_event_list = SYS_DLIST_STATIC_INIT(&pending_watch_event_list);

struct xs_entry root_xenstore;

struct message_handle {
	void (*h)(struct xen_domain *domain, uint32_t id, char *payload, uint32_t sz);
};

/* Allocate one stack for external reader thread */
static int get_stack_idx(void)
{
	int ret;

	k_mutex_lock(&xs_stack_lock, K_FOREVER);

	ret = find_lsb_set(~used_threads) - 1;

	/* This might fail only if BUILD_ASSERT above fails also, but
	 * better to be safe than sorry.
	 */
	__ASSERT_NO_MSG(ret >= 0);
	used_threads |= BIT(ret);
	LOG_DBG("Allocated stack with index %d", ret);

	k_mutex_unlock(&xs_stack_lock);

	return ret;
}

/* Free allocated stack */
static void free_stack_idx(int idx)
{
	__ASSERT_NO_MSG(idx < CONFIG_DOM_MAX);

	k_mutex_lock(&xs_stack_lock, K_FOREVER);

	__ASSERT_NO_MSG(used_threads & BIT(idx));
	used_threads &= ~BIT(idx);

	k_mutex_unlock(&xs_stack_lock);
}


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

static bool is_abs_path(const char *path)
{
	if (!path) {
		return false;
	}

	return path[0] == '/';
}

static bool is_root_path(const char *path)
{
	return (is_abs_path(path) && (strlen(path) == 1));
}

/*
 * Should be called with xsel_mutex lock and unlock mutex
 * only after all actions with entry will be performed.
 */
static struct xs_entry *key_to_entry(const char *key)
{
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

	if (is_root_path(key)) {
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

static size_t get_input_offset(XENSTORE_RING_IDX cons, XENSTORE_RING_IDX prod,
			       size_t *len)
{
	size_t delta = prod - cons;
	*len = XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(cons);

	if (delta < *len) {
		*len = delta;
	}

	return MASK_XENSTORE_IDX(cons);
}

static size_t get_output_offset(XENSTORE_RING_IDX cons, XENSTORE_RING_IDX prod,
				size_t *len)
{
	size_t delta = XENSTORE_RING_SIZE - cons + prod;
	*len = XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(prod);

	if (delta < *len) {
		*len = delta;
	}

	return MASK_XENSTORE_IDX(prod);
}

static void write_xb(struct xenstore_domain_interface *intf, uint8_t *data,
		     uint32_t len)
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

static size_t read_xb(struct xen_domain *domain, uint8_t *data, uint32_t len)
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

static void send_reply_sz(struct xen_domain *domain, uint32_t id,
			  uint32_t msg_type, const char *payload,
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

static void send_reply(struct xen_domain *domain, uint32_t id,
		       uint32_t msg_type, const char *payload)
{
	send_reply_sz(domain, id, msg_type, payload, strlen(payload) + 1);
}

static void send_reply_read(struct xen_domain *domain, uint32_t id,
			    uint32_t msg_type, char *payload)
{
	send_reply_sz(domain, id, msg_type, payload, strlen(payload));
}

static void handle_directory(struct xen_domain *domain, uint32_t id,
			     char *payload, uint32_t len)
{
	size_t data_offset = strlen(payload) + 1;
	char path[STRING_LENGTH_MAX];

	if (is_abs_path(payload)) {
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

static void send_errno(struct xen_domain *domain, uint32_t id, int err)
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

static int fire_watcher(struct xen_domain *domain, char *pending_path)
{
	struct watch_entry *iter;
	char local[XENSTORE_MAX_LOCALPATH_LEN];
	size_t pendkey_len, loc_len;

	pendkey_len = strlen(pending_path);

	loc_len = snprintf(local, sizeof(local), "/local/domain/%d/",
			   domain->domid);
	__ASSERT_NO_MSG(loc_len < sizeof(local));

	/* This function should be called when we already hold wel_mutex */
	SYS_DLIST_FOR_EACH_CONTAINER(&watch_entry_list, iter, node) {
		char *payload, *epath_buf = pending_path;
		size_t token_len, payload_len;
		size_t epath_len = pendkey_len + 1;

		if (memcmp(iter->key, epath_buf, strlen(iter->key))) {
			continue;
		}

		token_len = strlen(iter->token);
		payload_len = token_len + 1;

		if (iter->is_relative) {
			/* Send relative part (after "/local/domain/#domid") */
			epath_buf += loc_len;
			epath_len -= loc_len;
		}
		payload_len += epath_len;

		payload = k_malloc(payload_len);
		if (!payload) {
			return -ENOMEM;
		}

		memset(payload, 0, payload_len);
		/* Need to pack payload as "<epath>|<token>|" */
		memcpy(payload, epath_buf, epath_len);
		memcpy(payload + epath_len, iter->token, token_len);

		send_reply_sz(domain, 0, XS_WATCH_EVENT, payload, payload_len);

		k_free(payload);
	}

	return 0;
}

static int xss_do_write(const char *const_path, const char *data)
{
	int rc = 0;
	struct xs_entry *iter = NULL;
	char *path;
	char *tok, *tok_state;
	size_t data_len = strlen(data) + 1;
	size_t namelen;
	sys_dlist_t *inspected_list;

	path = k_malloc(strlen(const_path) + 1);
	if (!path) {
		LOG_ERR("Failed to allocate memory for path\n");
		return -ENOMEM;
	}

	strcpy(path, const_path);
	k_mutex_lock(&xsel_mutex, K_FOREVER);
	inspected_list = &root_xenstore.child_list;

	for (tok = strtok_r(path, "/", &tok_state); tok != NULL; tok = strtok_r(NULL, "/", &tok_state)) {
		SYS_DLIST_FOR_EACH_CONTAINER(inspected_list, iter, node) {
			if (strcmp(iter->key, tok) == 0) {
				break;
			}
		}

		if (iter == NULL) {
			iter = k_malloc(sizeof(*iter));
			if (!iter) {
				LOG_ERR("Failed to allocate memory for xs entry");
				rc = -ENOMEM;
				goto out;
			}

			namelen = strlen(tok);
			iter->key = k_malloc(namelen + 1);
			if (!iter->key) {
				k_free(iter);
				rc = -ENOMEM;
				goto out;
			}
			memcpy(iter->key, tok, namelen);
			iter->key[namelen] = 0;
			iter->value = NULL;

			sys_dlist_init(&iter->child_list);
			sys_dnode_init(&iter->node);
			sys_dlist_append(inspected_list, &iter->node);
		}

		inspected_list = &iter->child_list;
	}

	if (iter && data_len > 0) {
		if (iter->value != NULL) {
			k_free(iter->value);
		}

		iter->value = k_malloc(data_len);
		if (!iter->value) {
			LOG_ERR("Failed to allocate memory for xs entry value");
			rc = -ENOMEM;
			goto out;
		}
		memcpy(iter->value, data, data_len);
	}

out:
	k_mutex_unlock(&xsel_mutex);
	k_free(path);

	return rc;
}

int xss_write(const char *path, const char *value)
{
	int rc = xss_do_write(path, value);

	if (rc) {
		LOG_ERR("Failed to write to xenstore (rc=%d)", rc);
	}

	return rc;
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

static void _handle_write(struct xen_domain *domain, uint32_t id,
			  uint32_t msg_type, char *payload,
			  uint32_t len)
{
	int rc = 0;
	char path[STRING_LENGTH_MAX];
	char *data;
	uint32_t data_offset = strlen(payload) + 1;

	data = payload + data_offset;

	if (len < data_offset) {
		LOG_ERR("Data size mismatch");
		send_errno(domain, id, EINVAL);
		return;
	}

	if (is_abs_path(payload)) {
		memcpy(path, payload, data_offset);
	} else {
		snprintf(path, STRING_LENGTH_MAX, "/local/domain/%d/%s", domain->domid, payload);
	}

	data[len - data_offset] = 0;
	rc = xss_do_write(path, data);
	if (rc) {
		LOG_ERR("Failed to write to xenstore (rc=%d)", rc);
		send_errno(domain, id, rc);
		return;
	}

	send_reply(domain, id, msg_type, "OK");

	notify_watchers(path, domain->domid);
}

static void handle_write(struct xen_domain *domain, uint32_t id, char *payload,
			 uint32_t len)
{
	_handle_write(domain, id, XS_WRITE, payload, len);
}

static void handle_mkdir(struct xen_domain *domain, uint32_t id, char *payload,
			 uint32_t len)
{
	_handle_write(domain, id, XS_MKDIR, payload, len);
}

static void process_pending_watch_events(struct xen_domain *domain)
{
	struct pending_watch_event_entry *iter, *next;

	k_mutex_lock(&wel_mutex, K_FOREVER);
	k_mutex_lock(&pfl_mutex, K_FOREVER);
	SYS_DLIST_FOR_EACH_CONTAINER_SAFE (&pending_watch_event_list, iter, next, node) {
		int rc;

		if (domain != iter->domain) {
			continue;
		}

		rc = fire_watcher(domain, iter->key);
		if (rc < 0) {
			LOG_ERR("Failed to send watch event, err = %d", rc);
			goto out;
		}

		k_free(iter->key);
		sys_dlist_remove(&iter->node);
		k_free(iter);

	}
out:
	k_mutex_unlock(&pfl_mutex);
	k_mutex_unlock(&wel_mutex);
}

static void handle_control(struct xen_domain *domain, uint32_t id,
			   char *payload, uint32_t len)
{
	send_reply(domain, id, XS_CONTROL, "OK");
}

static void handle_get_perms(struct xen_domain *domain, uint32_t id,
			     char *payload, uint32_t len)
{
	send_errno(domain, id, ENOSYS);
}

static void handle_set_perms(struct xen_domain *domain, uint32_t id,
			     char *payload, uint32_t len)
{
	send_reply(domain, id, XS_SET_PERMS, "OK");
}

static void remove_watch_entry(struct watch_entry *entry)
{
	k_free(entry->key);
	k_free(entry->token);
	sys_dlist_remove(&entry->node);
	k_free(entry);
}

static void handle_reset_watches(struct xen_domain *domain, uint32_t id,
				 char *payload, uint32_t len)
{
	struct watch_entry *iter, *next;

	k_mutex_lock(&wel_mutex, K_FOREVER);
	SYS_DLIST_FOR_EACH_CONTAINER_SAFE (&watch_entry_list, iter, next, node) {
		remove_watch_entry(iter);
	}
	k_mutex_unlock(&wel_mutex);

	send_reply(domain, id, XS_RESET_WATCHES, "OK");
}

static void handle_read(struct xen_domain *domain, uint32_t id, char *payload,
			uint32_t len)
{
	char path[STRING_LENGTH_MAX];
	struct xs_entry *entry;

	if (is_abs_path(payload)) {
		memcpy(path, payload, strlen(payload) + 1);
	} else {
		snprintf(path, STRING_LENGTH_MAX, "/local/domain/%d/%s", domain->domid, payload);
	}

	k_mutex_lock(&xsel_mutex, K_FOREVER);
	entry = key_to_entry(path);

	if (entry) {
		send_reply_read(domain, id, XS_READ, entry->value ? entry->value : "");
		k_mutex_unlock(&xsel_mutex);
		return;
	}

	k_mutex_unlock(&xsel_mutex);

	send_reply(domain, id, XS_ERROR, "ENOENT");
}

static void remove_recurse(sys_dlist_t *chlds)
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

static int xss_do_rm(const char *key)
{
	sys_dlist_t child;
	struct xs_entry *entry;

	k_mutex_lock(&xsel_mutex, K_FOREVER);
	entry = key_to_entry(key);
	if (!entry) {
		k_mutex_unlock(&xsel_mutex);
		return -EINVAL;
	}

	if (entry->key) {
		k_free(entry->key);
		entry->key = NULL;
	}

	if (entry->value) {
		k_free(entry->value);
		entry->value = NULL;
	}

	sys_dlist_remove(&entry->node);
	child = entry->child_list;

	k_free(entry);
	k_mutex_unlock(&xsel_mutex);

	remove_recurse(&child);
	return 0;
}

int xss_rm(const char *path)
{
	return xss_do_rm(path);
}

static void handle_rm(struct xen_domain *domain, uint32_t id, char *payload,
	       uint32_t len)
{
	xss_do_rm(payload);
	send_reply_read(domain, id, XS_RM, "");
}

static void handle_watch(struct xen_domain *domain, uint32_t id, char *payload,
			 uint32_t len)
{
	char path[STRING_LENGTH_MAX];
	char token[STRING_LENGTH_MAX];
	struct watch_entry *wentry;
	struct pending_watch_event_entry *pentry;
	size_t plen = 0, full_plen;
	bool path_is_relative = !is_abs_path(payload);

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

static void handle_unwatch(struct xen_domain *domain, uint32_t id,
			   char *payload, uint32_t len)
{
	char path[STRING_LENGTH_MAX] = { 0 };
	char token[STRING_LENGTH_MAX] = { 0 };
	size_t plen = 0;
	for (; plen < len && payload[plen] != '\0'; ++plen)
		;
	plen += 1;

	if (is_abs_path(payload)) {
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

static void handle_transaction_start(struct xen_domain *domain, uint32_t id,
				     char *payload, uint32_t len)
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

static void handle_transaction_stop(struct xen_domain *domain, uint32_t id,
				    char *payload, uint32_t len)
{
	// TODO check contents, transaction completion, etc
	domain->stop_transaction_id = id;
	domain->pending_stop_transaction = true;
	domain->running_transaction = 0;
}

static void handle_get_domain_path(struct xen_domain *domain, uint32_t id,
				   char *payload, uint32_t len)
{
	char path[32] = { 0 };
	char domid[8] = { 0 };
	memcpy(domid, payload, len);
	snprintf(path, 32, "/local/domain/%s", domid);
	send_reply(domain, id, XS_GET_DOMAIN_PATH, path);
}

static void xs_evtchn_cb(void *priv)
{
	struct xen_domain *domain = (struct xen_domain *)priv;
	k_sem_give(&domain->xb_sem);
}

static void cleanup_domain_watches(struct xen_domain *domain)
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

static void xenstore_evt_thrd(void *p1, void *p2, void *p3)
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

	while (!atomic_get(&domain->xenstore_thrd_stop)) {
		if (domain->pending_stop_transaction) {
			send_reply(domain, domain->stop_transaction_id, XS_TRANSACTION_END, "");
			domain->stop_transaction_id = 0;
			domain->pending_stop_transaction = false;
		}

		if (!domain->running_transaction) {
			process_pending_watch_events(domain);
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

int start_domain_stored(struct xen_domain *domain)
{
	int rc = 0, err_ret;

	if (!domain) {
		return -EINVAL;
	}

	rc = xenmem_map_region(domain->domid, 1,
			       XEN_PHYS_PFN(GUEST_MAGIC_BASE) +
			       XENSTORE_PFN_OFFSET,
			       (void **)&domain->domint);
	if (rc < 0) {
		LOG_ERR("Failed to map xenstore ring for domain#%u (rc=%d)",
			domain->domid, rc);
		return rc;
	}

	domain->domint->server_features = XENSTORE_SERVER_FEATURE_RECONNECTION;
	domain->domint->connection = XENSTORE_CONNECTED;

	k_sem_init(&domain->xb_sem, 0, 1);
	rc = bind_interdomain_event_channel(domain->domid,
					    domain->xenstore_evtchn,
					    xs_evtchn_cb,
					    (void *)domain);
	if (rc < 0) {
		LOG_ERR("Failed to bind interdomain event channel (rc=%d)", rc);
		goto unmap_ring;
	}

	domain->local_xenstore_evtchn = rc;

	rc = hvm_set_parameter(HVM_PARAM_STORE_EVTCHN, domain->domid,
			       domain->xenstore_evtchn);
	if (rc) {
		LOG_ERR("Failed to set domain xenbus evtchn param (rc=%d)", rc);
		goto unmap_ring;
	}

	atomic_clear(&domain->xenstore_thrd_stop);

	domain->xs_stack_slot = get_stack_idx();
	domain->xenstore_tid =
		k_thread_create(&domain->xenstore_thrd,
				xenstore_thrd_stack[domain->xs_stack_slot],
				XENSTORE_STACK_SIZE_PER_DOM,
				xenstore_evt_thrd,
				domain, NULL, NULL, 7, 0, K_NO_WAIT);

	return 0;

unmap_ring:
	err_ret = xenmem_unmap_region(1, domain->domint);
	if (err_ret < 0) {
		LOG_ERR("Failed to unmap domain#%u xenstore ring (rc=%d)",
			domain->domid, err_ret);
	}
	return rc;
}

int stop_domain_stored(struct xen_domain *domain)
{
	int rc = 0, err = 0;

	if (!domain) {
		return -EINVAL;
	}

	LOG_DBG("Destroy domain#%u", domain->domid);
	atomic_set(&domain->xenstore_thrd_stop, 1);
	k_sem_give(&domain->xb_sem);
	k_thread_join(&domain->xenstore_thrd, K_FOREVER);
	free_stack_idx(domain->xs_stack_slot);
	unbind_event_channel(domain->local_xenstore_evtchn);

	rc = evtchn_close(domain->local_xenstore_evtchn);
	if (rc) {
		LOG_ERR("Unable to close event channel#%u (rc=%d)",
			domain->local_xenstore_evtchn, rc);
		err = rc;
	}

	rc = xenmem_unmap_region(1, domain->domint);
	if (rc < 0) {
		LOG_ERR("Failed to unmap domain#%u xenstore ring (rc=%d)",
			domain->domid, rc);
		err = rc;
	}

	return err;
}

static int xs_init_root(const struct device *d)
{
	ARG_UNUSED(d);

	sys_dlist_init(&root_xenstore.child_list);
	sys_dnode_init(&root_xenstore.node);

	return 0;
}

SYS_INIT(xs_init_root, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
