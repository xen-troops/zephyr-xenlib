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
#include <zephyr/xen/hvm.h>
#include <zephyr/logging/log.h>

#include <mem-mgmt.h>
#include "domain.h"
#include "xen/public/io/xs_wire.h"
#include "xenstore_srv.h"
#include "xss.h"

LOG_MODULE_REGISTER(xenstore);

/* Max string length of int32_t + terminating null symbol */
#define INT32_MAX_STR_LEN (12)
/* Max string length of uint32_t + terminating null symbol */
#define UINT32_MAX_STR_LEN 11
/* max length of string that holds '/local/domain/%domid/' (domid 0-32767) */
#define XENSTORE_MAX_LOCALPATH_LEN	21

#define XENSTORE_STACK_SIZE_PER_DOM	4096
/*
 * Max number of possible allocated output buffers.
 * This limit is needed to prevent Denial of Service attacks,
 * while domain is not reading responses.
 */
#define XENSTORE_MAX_OUT_BUF_NUM 10
#define INIT_XENSTORE_BUFF_SIZE 80
#define INIT_XENSTORE_UUID_BUF_SIZE 40

struct xs_permissions {
	sys_snode_t node;
	enum xs_perm perms;
	domid_t domid;
};

struct xs_entry {
	char *key;
	char *value;
	sys_slist_t perms;
	sys_dlist_t child_list;

	sys_dnode_t node;
};

struct watch_entry {
	char *key;
	char *token;
	struct xen_domain *domain;
	bool is_relative;

	sys_dnode_t node;
};

struct pending_watch_event_entry {
	char *key;
	struct xen_domain *domain;

	sys_dnode_t node;
};

static K_THREAD_STACK_ARRAY_DEFINE(xenstore_thrd_stack,
				   CONFIG_DOM_MAX,
				   XENSTORE_STACK_SIZE_PER_DOM);

static uint32_t used_threads;
static K_MUTEX_DEFINE(xs_stack_lock);
BUILD_ASSERT(sizeof(used_threads) * CHAR_BIT >= CONFIG_DOM_MAX);

static K_MUTEX_DEFINE(xsel_mutex);
static K_MUTEX_DEFINE(pfl_mutex);
static K_MUTEX_DEFINE(wel_mutex);

static sys_dlist_t watch_entry_list = SYS_DLIST_STATIC_INIT(&watch_entry_list);
static sys_dlist_t pending_watch_event_list =
		   SYS_DLIST_STATIC_INIT(&pending_watch_event_list);

static struct xs_entry root_xenstore;

struct message_handle {
	void (*h)(struct xenstore *xenstore, uint32_t id, char *payload, uint32_t sz);
};

static void free_node(struct xs_entry *entry);
static void send_errno(struct xenstore *xenstore, uint32_t id, int err);

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

/*
 * Should be called with wel_mutex lock and unlock mutex
 * only after all actions with entry will be performed.
 */
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
 * Returns the size of string including terminating NULL symbol.
 */
static inline size_t str_byte_size(const char *str)
{
	if (!str) {
		return 0;
	}

	return strlen(str) + 1;
}

static int construct_path(char *payload, uint32_t domid, char **path)
{
	size_t path_len = str_byte_size(payload);

	if (path_len > XENSTORE_ABS_PATH_MAX) {
		LOG_ERR("Invalid path len (path len = %zu, max = %d)",
			path_len, XENSTORE_ABS_PATH_MAX);
		return -ENOMEM;
	}

	*path = k_malloc(path_len + XENSTORE_MAX_LOCALPATH_LEN);
	if (!*path) {
		LOG_ERR("Failed to allocate memory for path");
		return -ENOMEM;
	}

	if (is_abs_path(payload)) {
		memcpy(*path, payload, path_len);
	} else {
		snprintf(*path, path_len + XENSTORE_MAX_LOCALPATH_LEN,
			 "/local/domain/%d/%s", domid, payload);
	}

	return 0;
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
	char *key_buffer;
	size_t keyl;

	if (!key) {
		return NULL;
	}

	keyl = strlen(key);
	if (keyl > XENSTORE_ABS_PATH_MAX) {
		return NULL;
	}

	if (is_root_path(key)) {
		return &root_xenstore;
	}

	key_buffer = k_malloc(keyl + 1);
	if (!key_buffer) {
		LOG_ERR("Failed to allocate memory for path");
		return NULL;
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

	k_free(key_buffer);

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
	size_t free_space = XENSTORE_RING_SIZE - (prod - cons);

	*len = XENSTORE_RING_SIZE - MASK_XENSTORE_IDX(prod);
	if (free_space < *len) {
		*len = free_space;
	}

	return MASK_XENSTORE_IDX(prod);
}

static int ring_write(struct xenstore *xenstore, const void *data, size_t len)
{
	size_t avail;
	void *dest;
	struct xenstore_domain_interface *intf = xenstore->domint;
	XENSTORE_RING_IDX cons, prod;

	cons = intf->rsp_cons;
	prod = intf->rsp_prod;
	dmb();

	if (check_indexes(cons, prod)) {
		return -EINVAL;
	}

	dest = intf->rsp + get_output_offset(cons, prod, &avail);
	if (avail < len) {
		len = avail;
	}

	memcpy(dest, data, len);
	dmb();
	intf->rsp_prod += len;

	notify_evtchn(xenstore->local_evtchn);

	return len;
}

static void invalidate_client(struct xenstore *xenstore, const char *reason, int err)
{
	LOG_ERR("Domain#%d xenstore is invalid: %s (err=%d)",
		xenstore->domain->domid, reason, err);
	stop_domain_stored(xenstore->domain);
}

static void handle_output(struct xenstore *xenstore)
{
	int ret;
	struct buffered_data *out;

	out = SYS_SLIST_PEEK_HEAD_CONTAINER(&xenstore->out_list, out, node);
	if (out == NULL) {
		return;
	}

	ret = ring_write(xenstore, out->buffer + out->used,
			 out->total_size - out->used);
	if (ret < 0) {
		goto inv_client;
	}

	out->used += ret;
	if (out->used < out->total_size) {
		return;
	}

	/*
	 * This probably won't ever happen, but further code changes
	 * can break something. So it's better to be safe than sorry.
	 */
	__ASSERT_NO_MSG(out->used == out->total_size);
	sys_slist_remove(&xenstore->out_list, NULL, &out->node);
	k_free(out->buffer);
	k_free(out);
	xenstore->used_out_bufs--;

	return;

inv_client:
	invalidate_client(xenstore, "Failed to write message", ret);
}

static bool can_write(struct xenstore *xenstore)
{
	struct xenstore_domain_interface *intf = xenstore->domint;

	return !sys_slist_is_empty(&xenstore->out_list) &&
		((intf->rsp_prod - intf->rsp_cons) < XENSTORE_RING_SIZE);
}

static bool can_read(struct xenstore *xenstore)
{
	struct xenstore_domain_interface *intf = xenstore->domint;

	return (intf->req_prod != intf->req_cons);
}

static void send_reply_sz(struct xenstore *xenstore, uint32_t req_id,
			  enum xsd_sockmsg_type type, const void *data,
			  size_t len)
{
	struct buffered_data *bdata;
	struct xsd_sockmsg header;
	size_t total_size = len + sizeof(header);

	if (xenstore->used_out_bufs > XENSTORE_MAX_OUT_BUF_NUM) {
		/*
		 * TODO: check if we can act more softly than invalidating the client.
		 * Now we invalidate the client, to prevent Denial of Service attacks,
		 * using several domains, that potentially can eat all Dom0 memory.
		 */
		invalidate_client(xenstore,
				  "The maximum number of output buffers is exceeded",
				  -EIO);
		return;
	}

	if (len > XENSTORE_PAYLOAD_MAX) {
		LOG_ERR("Failed to reply: payload size too big (%zu max=%d)",
			len, XENSTORE_PAYLOAD_MAX);
		send_errno(xenstore, req_id, E2BIG);
		return;
	}

	bdata = k_malloc(sizeof(*bdata));
	if (!bdata) {
		LOG_ERR("Failed to allocate memory for output buffer");
		return;
	}

	bdata->used = 0;
	bdata->buffer = k_malloc(total_size);
	if (!bdata->buffer) {
		k_free(bdata);
		LOG_ERR("Failed to allocate memory to store output data");
		return;
	}

	bdata->total_size = total_size;
	header.type = type;
	header.len = len;
	header.req_id = req_id;
	memcpy(bdata->buffer, &header, sizeof(header));
	memcpy(bdata->buffer + sizeof(header), data, len);

	sys_slist_append(&xenstore->out_list, &bdata->node);
	xenstore->used_out_bufs++;
}

static void send_reply(struct xenstore *xenstore, uint32_t id,
		       uint32_t msg_type, const char *payload)
{
	send_reply_sz(xenstore, id, msg_type, payload, str_byte_size(payload));
}

static void send_reply_read(struct xenstore *xenstore, uint32_t id,
			    uint32_t msg_type, char *payload)
{
	send_reply_sz(xenstore, id, msg_type, payload, strlen(payload));
}

static void send_errno(struct xenstore *xenstore, uint32_t id, int err)
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

	send_reply(xenstore, id, XS_ERROR, xsd_errors[i].errstring);
}

static void handle_directory(struct xenstore *xenstore, uint32_t id,
			     char *payload, uint32_t len)
{
	char *dir_list = NULL;
	size_t reply_sz = 0, dir_name_len;
	char *path;
	struct xs_entry *entry, *iter;
	int rc;

	rc = construct_path(payload, xenstore->domain->domid, &path);
	if (rc) {
		LOG_ERR("Failed to construct path (rc=%d)", rc);
		send_errno(xenstore, id, rc);
		return;
	}

	k_mutex_lock(&xsel_mutex, K_FOREVER);
	entry = key_to_entry(path);
	k_free(path);
	if (!entry) {
		goto out;
	}

	/* Calculate total length of dirs child node names */
	SYS_DLIST_FOR_EACH_CONTAINER(&entry->child_list, iter, node) {
		reply_sz += str_byte_size(iter->key);
	}

	dir_list = k_malloc(reply_sz);
	if (!dir_list) {
		LOG_ERR("Failed to allocate memory for dir list");
		send_reply(xenstore, id, XS_ERROR, "ENOMEM");
		k_mutex_unlock(&xsel_mutex);
		return;
	}

	reply_sz = 0;
	SYS_DLIST_FOR_EACH_CONTAINER(&entry->child_list, iter, node) {
		dir_name_len = str_byte_size(iter->key);
		memcpy(dir_list + reply_sz, iter->key, dir_name_len);
		reply_sz += dir_name_len;
	}

out:
	k_mutex_unlock(&xsel_mutex);
	send_reply_sz(xenstore, id, XS_DIRECTORY, dir_list, reply_sz);
	k_free(dir_list);
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

		send_reply_sz(&domain->xenstore, 0, XS_WATCH_EVENT, payload, payload_len);

		k_free(payload);
	}

	return 0;
}

static void free_perms(sys_slist_t *list)
{
	struct xs_permissions *iter, *next;

	SYS_SLIST_FOR_EACH_CONTAINER_SAFE(list, iter, next, node) {
		sys_slist_remove(list, NULL, &iter->node);
		k_free(iter);
	}
}

static void remove_recurse(sys_dlist_t *children)
{
	struct xs_entry *entry, *next;

	SYS_DLIST_FOR_EACH_CONTAINER_SAFE(children, entry, next, node) {
		free_node(entry);
	}
}

/*
 * If entry is a part of root_xenstore, the function
 * must be called with xsel_mutex lock.
 */
static void free_node(struct xs_entry *entry)
{
	if (entry->key) {
		k_free(entry->key);
		entry->key = NULL;
	}

	if (entry->value) {
		k_free(entry->value);
		entry->value = NULL;
	}

	free_perms(&entry->perms);
	sys_dlist_remove(&entry->node);
	remove_recurse(&entry->child_list);
	k_free(entry);
}

static int set_perms_by_array(struct xs_entry *entry,
			      struct xs_permissions *new_perms,
			      size_t perms_num)
{
	size_t i;
	struct xs_permissions *perms, *iter, *next;
	sys_slist_t list_perm;

	sys_slist_init(&list_perm);

	/* Alloc new entries and save it in temporary list before removing old entries */
	for (i = 0; i < perms_num; i++) {
		perms = k_malloc(sizeof(*perms));
		if (!perms) {
			goto alloc_err;
		}
		perms->domid = new_perms[i].domid;
		perms->perms = new_perms[i].perms;
		sys_slist_append(&list_perm, &perms->node);
	}

	free_perms(&entry->perms);
	/* Here we must use SAFE macros, because we're inserting entries to another list */
	SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&list_perm, iter, next, node) {
		sys_slist_append(&entry->perms, &iter->node);
	}

	return 0;

alloc_err:
	free_perms(&list_perm);
	return -ENOMEM;
}

static struct xs_permissions *deserialize_perms(const char *strings, const size_t str_len,
						size_t *perms_num)
{
	struct xs_permissions *perms;
	const char *ptr;
	char *str_endptr;
	size_t i, j;

	if (!strings || !perms_num) {
		return NULL;
	}

	*perms_num = 0;
	ptr = strings;
	/* Count the number of perms to further memory allocation */
	for (i = 0; i < str_len;) {
		i += strlen(ptr + i) + 1;
		(*perms_num)++;
	}

	perms = k_malloc(sizeof(*perms) * (*perms_num));
	if (!perms) {
		return NULL;
	}

	for (i = 0, j = 0; i < str_len && j < (*perms_num); j++) {
		switch (ptr[i]) {
		case 'w':
			perms[j].perms = XS_PERM_WRITE;
			break;
		case 'r':
			perms[j].perms = XS_PERM_READ;
			break;
		case 'b':
			perms[j].perms = (XS_PERM_READ | XS_PERM_WRITE);
			break;
		case 'n':
			perms[j].perms = XS_PERM_NONE;
			break;
		default:
			goto err_free;
		}
		if (i + 1 >= str_len) {
			goto err_free;
		}

		perms[j].domid = strtoul(ptr + i + 1, &str_endptr, 10);
		/* If str_endptr is not pointing to terminating null, conversion is failed */
		if (*str_endptr != '\0') {
			goto err_free;
		}

		if (perms[j].domid >= CONFIG_DOM_MAX) {
			goto err_free;
		}

		i += strlen(ptr + i) + 1;
	}

	return perms;

err_free:
	k_free(perms);
	*perms_num = 0;
	return NULL;
}

static int set_perms_by_strings(struct xs_entry *entry, const char *perm_str,
				const size_t perms_len)
{
	struct xs_permissions *new_perms;
	size_t perms_num;
	int rc;

	new_perms = deserialize_perms(perm_str, perms_len, &perms_num);
	if (!new_perms) {
		return -EINVAL;
	}

	rc = set_perms_by_array(entry, new_perms, perms_num);
	k_free(new_perms);

	return rc;
}

static int inherit_perms(struct xs_entry *entry,
			 struct xs_entry *parent_entry,
			 const uint32_t owner_domid)
{
	struct xs_permissions *perms, *iter;

	/* In case it's root entry, we set initial permissions */
	if (!parent_entry) {
		perms = k_malloc(sizeof(*perms));
		if (!perms) {
			goto ret_err;
		}

		perms->domid = owner_domid;
		perms->perms = XS_PERM_NONE;
		sys_slist_append(&entry->perms, &perms->node);

		return 0;
	}

	SYS_SLIST_FOR_EACH_CONTAINER(&parent_entry->perms, iter, node) {
		perms = k_malloc(sizeof(*perms));
		if (!perms) {
			goto alloc_err;
		}
		perms->domid = iter->domid;
		perms->perms = iter->perms;
		sys_slist_append(&entry->perms, &perms->node);
	}

	return 0;

alloc_err:
	free_perms(&entry->perms);

ret_err:
	return -ENOMEM;
}

static int xss_do_write(const char *const_path, const char *data, uint32_t domid,
			struct xs_permissions *perms, size_t perms_num)
{
	int rc = 0;
	struct xs_entry *iter = NULL, *insert_entry = NULL, *parent_entry = NULL;
	char *path;
	char *tok, *tok_state, *new_value;
	size_t data_len = str_byte_size(data);
	size_t namelen;
	sys_dlist_t *inspected_list;

	path = k_malloc(str_byte_size(const_path));
	if (!path) {
		LOG_ERR("Failed to allocate memory for path\n");
		return -ENOMEM;
	}

	strcpy(path, const_path);
	k_mutex_lock(&xsel_mutex, K_FOREVER);
	inspected_list = &root_xenstore.child_list;

	for (tok = strtok_r(path, "/", &tok_state); tok != NULL; tok = strtok_r(NULL, "/", &tok_state)) {
		SYS_DLIST_FOR_EACH_CONTAINER(inspected_list, iter, node) {
			parent_entry = iter;
			if (strcmp(iter->key, tok) == 0) {
				break;
			}
		}

		if (iter == NULL) {
			iter = k_malloc(sizeof(*iter));
			if (!iter) {
				LOG_ERR("Failed to allocate memory for xs entry");
				rc = -ENOMEM;
				goto free_allocated;
			}

			namelen = strlen(tok);
			iter->key = k_malloc(namelen + 1);
			if (!iter->key) {
				k_free(iter);
				rc = -ENOMEM;
				goto free_allocated;
			}
			memcpy(iter->key, tok, namelen);
			iter->key[namelen] = 0;
			iter->value = NULL;
			sys_slist_init(&iter->perms);

			sys_dlist_init(&iter->child_list);
			sys_dnode_init(&iter->node);
			sys_dlist_append(inspected_list, &iter->node);
			if (perms && perms_num) {
				rc = set_perms_by_array(iter, perms, perms_num);
			} else {
				rc = inherit_perms(iter, parent_entry, domid);
			}
			if (rc) {
				LOG_ERR("Failed to set permissions (rc=%d)", rc);
				goto free_allocated;
			}

			if (!insert_entry) {
				insert_entry = iter;
			}
		}

		inspected_list = &iter->child_list;
	}

	if (iter && data_len > 0) {
		new_value = k_malloc(data_len);
		if (!new_value) {
			LOG_ERR("Failed to allocate memory for xs entry value");
			rc = -ENOMEM;
			goto free_allocated;
		}

		if (iter->value) {
			k_free(iter->value);
		}

		iter->value = new_value;
		memcpy(iter->value, data, data_len);
	}

	k_mutex_unlock(&xsel_mutex);
	k_free(path);

	return rc;

free_allocated:
	if (insert_entry) {
		free_node(insert_entry);
	}

	k_mutex_unlock(&xsel_mutex);
	k_free(path);

	return rc;
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

		pentry->key = k_malloc(str_byte_size(path));
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
		k_sem_give(&iter->domain->xenstore.xb_sem);

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

int xss_write(const char *path, const char *value)
{
	int rc;
	struct xs_permissions perms = {
		.domid = 0,
		.perms = XS_PERM_NONE,
	};

	if (!path || !value) {
		LOG_ERR("Invalid arguments: path or value is NULL");
		return -EINVAL;
	}

	rc = xss_do_write(path, value, 0, &perms, 1);
	if (rc) {
		LOG_ERR("Failed to write to xenstore (rc=%d)", rc);
	} else {
		notify_watchers(path, 0);
	}

	return rc;
}

int xss_write_guest_domain_rw(const char *path, const char *value, uint32_t domid)
{
	int rc;
	struct xs_permissions perms = {
		.domid = domid,
		.perms = XS_PERM_NONE,
	};

	if (!path || !value || (domid >= CONFIG_DOM_MAX)) {
		LOG_ERR("Invalid arguments: path/value is NULL or domid bigger than CONFIG_DOM_MAX");
		return -EINVAL;
	}

	rc = xss_do_write(path, value, 0, &perms, 1);
	if (rc) {
		LOG_ERR("Failed to write to xenstore (rc=%d)", rc);
	} else {
		notify_watchers(path, 0);
	}

	return rc;
}


int xss_write_guest_domain_ro(const char *path, const char *value, uint32_t domid)
{
	int rc;
	struct xs_permissions perms[2] = {
		{
			.domid = 0,
			.perms = XS_PERM_NONE,
		},
		{
			.domid = domid,
			.perms = XS_PERM_READ,
		},
	};

	if (!path || !value || (domid >= CONFIG_DOM_MAX)) {
		LOG_ERR("Invalid arguments: path/value is NULL or domid bigger than CONFIG_DOM_MAX");
		return -EINVAL;
	}

	/*
	 * If the function is invoked for Dom0, there is
	 * no need to set additionally read permission.
	 */
	if (domid == 0) {
		rc = xss_do_write(path, value, 0, perms, 1);
	} else {
		rc = xss_do_write(path, value, 0, perms, 2);
	}
	if (rc) {
		LOG_ERR("Failed to write to xenstore (rc=%d)", rc);
	} else {
		notify_watchers(path, 0);
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
	char ns[INT32_MAX_STR_LEN] = { 0 };

	rc = xss_read(path, ns, sizeof(ns));
	if (!rc)
		*value = atoi(ns);
	return rc;
}

int xss_set_perm(const char *path, domid_t domid, enum xs_perm perm)
{
	int rc;
	struct xs_entry *entry;
	struct xs_permissions permissions = {
		.domid = domid,
		.perms = perm,
	};

	k_mutex_lock(&xsel_mutex, K_FOREVER);
	entry = key_to_entry(path);
	if (!entry) {
		k_mutex_unlock(&xsel_mutex);
		return -ENOENT;
	}

	rc = set_perms_by_array(entry, &permissions, 1);
	k_mutex_unlock(&xsel_mutex);

	return rc;
}

static int construct_data(char *payload, int len, int path_len, char **data)
{
	int data_size = len - path_len;

	if (path_len == len) {
		return 0;
	}

	/* Add space for terminating NULL if not present */
	if (payload[len - 1]) {
		data_size++;
	}

	*data = k_malloc(data_size);
	if (!*data) {
		return -ENOMEM;
	}

	memcpy(*data, payload + path_len, data_size - 1);
	(*data)[data_size - 1] = 0;

	return data_size;
}

static void _handle_write(struct xenstore *xenstore, uint32_t id,
			  uint32_t msg_type, char *payload,
			  uint32_t len)
{
	int rc = 0;
	char *path;
	char *data = NULL;
	size_t path_len = str_byte_size(payload);
	struct xen_domain *domain = xenstore->domain;

	if (len < path_len) {
		LOG_ERR("Write path length (%zu) is bigger than given payload size (%u)",
			path_len, len);
		send_errno(xenstore, id, EINVAL);
		return;
	}

	rc = construct_path(payload, domain->domid, &path);
	if (rc) {
		LOG_ERR("Failed to construct path (rc=%d)", rc);
		send_errno(xenstore, id, rc);
		return;
	}

	rc = construct_data(payload, len, path_len, &data);
	if (rc < 0) {
		send_errno(xenstore, id, -rc);
		goto free_path;
	}

	rc = xss_do_write(path, data, domain->domid, NULL, 0);
	if (rc) {
		LOG_ERR("Failed to write to xenstore (rc=%d)", rc);
		send_errno(xenstore, id, rc);
		goto free_data;
	}

	send_reply(xenstore, id, msg_type, "OK");
	notify_watchers(path, domain->domid);

free_data:
	k_free(data);
free_path:
	k_free(path);
}

static void handle_write(struct xenstore *xenstore, uint32_t id, char *payload,
			 uint32_t len)
{
	_handle_write(xenstore, id, XS_WRITE, payload, len);
}

static void handle_mkdir(struct xenstore *xenstore, uint32_t id, char *payload,
			 uint32_t len)
{
	_handle_write(xenstore, id, XS_MKDIR, payload, len);
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

static void handle_control(struct xenstore *xenstore, uint32_t id,
			   char *payload, uint32_t len)
{
	send_reply(xenstore, id, XS_CONTROL, "OK");
}

static char perm_to_char(const uint32_t perm)
{
	switch (perm & XS_PERM_BOTH) {
	case XS_PERM_WRITE:
		return 'w';
	case XS_PERM_READ:
		return 'r';
	case XS_PERM_BOTH:
		return 'b';
	default:
		return 'n';
	}
}

/* The function allocates memory for the buffer, that should be freed by caller */
static char *serialize_perms(struct xs_entry *entry, size_t *total_size)
{
	struct xs_permissions *iter;
	char *perm_str;
	size_t curr_len = 0, max_len = 0;

	if (!total_size) {
		return NULL;
	}
	*total_size = 0;

	/* Count the maximum needed memory for string at first */
	SYS_SLIST_FOR_EACH_CONTAINER(&entry->perms, iter, node) {
		/* max domid value (it counts terminating NULL) + permission char */
		max_len += UINT32_MAX_STR_LEN + 1;
	}

	perm_str = k_malloc(max_len);
	if (!perm_str) {
		return NULL;
	}

	SYS_SLIST_FOR_EACH_CONTAINER(&entry->perms, iter, node) {
		curr_len = snprintf(&perm_str[*total_size], UINT32_MAX_STR_LEN + 1, "%c%u",
				    perm_to_char(iter->perms), iter->domid);
		/* Add size for terminating NULL */
		*total_size += curr_len + 1;
	}

	return perm_str;
}

static void handle_get_perms(struct xenstore *xenstore, uint32_t id,
			     char *payload, uint32_t len)
{
	char *path;
	char *perm_str;
	struct xs_entry *entry;
	int rc;
	size_t ret_size;

	rc = construct_path(payload, xenstore->domain->domid, &path);
	if (rc) {
		LOG_ERR("Failed to construct path (rc=%d)", rc);
		send_errno(xenstore, id, rc);
		return;
	}

	k_mutex_lock(&xsel_mutex, K_FOREVER);
	entry = key_to_entry(path);
	k_free(path);
	if (!entry) {
		k_mutex_unlock(&xsel_mutex);
		send_reply(xenstore, id, XS_ERROR, "ENOENT");
		return;
	}

	perm_str = serialize_perms(entry, &ret_size);
	k_mutex_unlock(&xsel_mutex);
	if (!perm_str) {
		send_reply(xenstore, id, XS_ERROR, "ENOENT");
		return;
	}

	send_reply_sz(xenstore, id, XS_GET_PERMS, perm_str, ret_size);
	k_free(perm_str);
}

static void handle_set_perms(struct xenstore *xenstore, uint32_t id,
			     char *payload, uint32_t len)
{
	struct xs_entry *entry;
	char *path, *perm_string;
	size_t perms_offset, perms_str_size;
	int rc;

	/*
	 * Path and perms come inside payload char * and are separated
	 * with '\0', so we can find path len with strnlen here.
	 */
	perms_offset = strnlen(payload, len) + 1;
	/* Check if we have at least one permission entry */
	if (perms_offset >= len) {
		send_errno(xenstore, id, EINVAL);
		return;
	}
	perm_string = payload + perms_offset;
	perms_str_size = len - perms_offset;

	rc = construct_path(payload, xenstore->domain->domid, &path);
	if (rc) {
		LOG_ERR("Failed to construct path (rc=%d)", rc);
		send_errno(xenstore, id, rc);
		return;
	}

	k_mutex_lock(&xsel_mutex, K_FOREVER);
	entry = key_to_entry(path);
	k_free(path);
	if (!entry) {
		k_mutex_unlock(&xsel_mutex);
		return;
	}

	rc = set_perms_by_strings(entry, perm_string, perms_str_size);
	k_mutex_unlock(&xsel_mutex);
	if (rc) {
		send_errno(xenstore, id, rc);
		return;
	}

	send_reply(xenstore, id, XS_SET_PERMS, "OK");
}

static void remove_watch_entry(struct watch_entry *entry)
{
	k_free(entry->key);
	k_free(entry->token);
	sys_dlist_remove(&entry->node);
	k_free(entry);
}

static void handle_reset_watches(struct xenstore *xenstore, uint32_t id,
				 char *payload, uint32_t len)
{
	struct watch_entry *iter, *next;

	k_mutex_lock(&wel_mutex, K_FOREVER);
	SYS_DLIST_FOR_EACH_CONTAINER_SAFE (&watch_entry_list, iter, next, node) {
		remove_watch_entry(iter);
	}
	k_mutex_unlock(&wel_mutex);

	send_reply(xenstore, id, XS_RESET_WATCHES, "OK");
}

static void handle_read(struct xenstore *xenstore, uint32_t id, char *payload,
			uint32_t len)
{
	char *path;
	struct xs_entry *entry;
	int rc;

	rc = construct_path(payload, xenstore->domain->domid, &path);
	if (rc) {
		LOG_ERR("Failed to construct path (rc=%d)", rc);
		send_errno(xenstore, id, rc);
		return;
	}

	k_mutex_lock(&xsel_mutex, K_FOREVER);
	entry = key_to_entry(path);
	k_free(path);

	if (entry) {
		send_reply_read(xenstore, id, XS_READ,
				entry->value ? entry->value : "");
		k_mutex_unlock(&xsel_mutex);
		return;
	}

	k_mutex_unlock(&xsel_mutex);

	send_reply(xenstore, id, XS_ERROR, "ENOENT");
}

static int xss_do_rm(const char *key)
{
	struct xs_entry *entry;

	k_mutex_lock(&xsel_mutex, K_FOREVER);
	entry = key_to_entry(key);
	if (!entry) {
		k_mutex_unlock(&xsel_mutex);
		return -EINVAL;
	}

	free_node(entry);
	k_mutex_unlock(&xsel_mutex);

	return 0;
}

int xss_rm(const char *path)
{
	int ret = xss_do_rm(path);

	if (!ret) {
		notify_watchers(path, 0);
	}

	return ret;
}

static void handle_rm(struct xenstore *xenstore, uint32_t id, char *payload,
	       uint32_t len)
{
	if (xss_do_rm(payload)) {
		notify_watchers(payload, xenstore->domain->domid);
		send_reply_read(xenstore, id, XS_RM, "");
	}
}

static void handle_watch(struct xenstore *xenstore, uint32_t id, char *payload,
			 uint32_t len)
{
	char *path;
	char *token;
	struct watch_entry *wentry;
	struct pending_watch_event_entry *pentry;
	size_t path_len = 0, full_plen;
	bool path_is_relative = !is_abs_path(payload);
	int rc;
	struct xen_domain *domain = xenstore->domain;

	/*
	 * Path and token come inside payload char * and are separated
	 * with '\0', so we can find path len with strnlen here.
	 */
	path_len = strnlen(payload, len) + 1;
	if (path_len > XENSTORE_ABS_PATH_MAX) {
		goto path_fail;
	}

	rc = construct_path(payload, xenstore->domain->domid, &path);
	if (rc) {
		goto path_fail;
	}
	full_plen = str_byte_size(path);

	token = payload + path_len;
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

		wentry->token = k_malloc(len - path_len);
		if (!wentry->token) {
			goto wtoken_fail;
		}

		memcpy(wentry->key, path, full_plen);
		memcpy(wentry->token, token, len - path_len);
		wentry->domain = domain;
		wentry->is_relative = path_is_relative;
		sys_dnode_init(&wentry->node);

		k_mutex_lock(&wel_mutex, K_FOREVER);
		sys_dlist_append(&watch_entry_list, &wentry->node);
		k_mutex_unlock(&wel_mutex);
	}
	send_reply(xenstore, id, XS_WATCH, "OK");

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
		k_sem_give(&domain->xenstore.xb_sem);
	}
	k_mutex_unlock(&xsel_mutex);
	k_free(path);

	return;

path_fail:
	LOG_ERR("Failed to add watch for %s, path is too long", payload);
	send_reply(xenstore, id, XS_ERROR, "ENOMEM");

	return;

wtoken_fail:
	k_free(wentry->key);
wkey_fail:
	k_free(wentry);
wentry_fail:
	k_free(path);
	LOG_WRN("Failed to create watch for Domain#%d, no memory",
		domain->domid);
	send_reply(xenstore, id, XS_ERROR, "ENOMEM");

	return;

pkey_fail:
	k_free(pentry);
pentry_fail:
	k_mutex_unlock(&xsel_mutex);
	k_free(path);
	/*
	 * We can't notify domain that this file already exists,
	 * so leave it without first WATCH_EVENT
	 */
	LOG_WRN("Failed to notify Domain#%d, no memory for event",
		domain->domid);
}

static void handle_unwatch(struct xenstore *xenstore, uint32_t id,
			   char *payload, uint32_t len)
{
	char *path;
	char *token;
	struct watch_entry *entry;
	size_t path_len = strnlen(payload, len) + 1;
	int rc;
	struct xen_domain *domain = xenstore->domain;

	rc = construct_path(payload, domain->domid, &path);
	if (rc) {
		LOG_ERR("Failed to construct path (rc=%d)", rc);
		send_errno(xenstore, id, rc);
		return;
	}

	token = payload + path_len;
	k_mutex_lock(&wel_mutex, K_FOREVER);
	entry = key_to_watcher(path, true, token);
	k_free(path);
	if (entry) {
		if (entry->domain == domain) {
			remove_watch_entry(entry);
		}
	}
	k_mutex_unlock(&wel_mutex);

	send_reply(xenstore, id, XS_UNWATCH, "");
}

static void handle_transaction_start(struct xenstore *xenstore, uint32_t id,
				     char *payload, uint32_t len)
{
	char buf[INT32_MAX_STR_LEN] = { 0 };

	if (xenstore->running_transaction) {
		LOG_ERR("domid#%u: transaction already started", xenstore->domain->domid);
		send_errno(xenstore, id, EBUSY);
		return;
	}

	xenstore->running_transaction = ++xenstore->transaction;
	snprintf(buf, sizeof(buf), "%d", xenstore->running_transaction);
	send_reply(xenstore, id, XS_TRANSACTION_START, buf);
}

static void handle_transaction_stop(struct xenstore *xenstore, uint32_t id,
				    char *payload, uint32_t len)
{
	// TODO check contents, transaction completion, etc
	xenstore->stop_transaction_id = id;
	xenstore->pending_stop_transaction = true;
	xenstore->running_transaction = 0;
}

static void handle_get_domain_path(struct xenstore *xenstore, uint32_t id,
				   char *payload, uint32_t len)
{
	char path[XENSTORE_MAX_LOCALPATH_LEN] = { 0 };

	if (!xenstore || !payload) {
		send_errno(xenstore, id, EINVAL);
		return;
	}

	snprintf(path, XENSTORE_MAX_LOCALPATH_LEN,
		 "/local/domain/%.*s", len, payload);
	send_reply(xenstore, id, XS_GET_DOMAIN_PATH, path);
}

static void xs_evtchn_cb(void *priv)
{
	struct xenstore *xenstore = (struct xenstore *)priv;

	k_sem_give(&xenstore->xb_sem);
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

static int ring_read(struct xenstore *xenstore, void *data, size_t len)
{
	size_t avail;
	const void *src;
	struct xenstore_domain_interface *intf = xenstore->domint;
	XENSTORE_RING_IDX cons, prod;

	cons = intf->req_cons;
	prod = intf->req_prod;
	dmb();

	if (check_indexes(cons, prod)) {
		return -EIO;
	}

	src = intf->req + get_input_offset(cons, prod, &avail);
	if (avail < len) {
		len = avail;
	}

	memcpy(data, src, len);
	dmb();
	intf->req_cons += len;

	notify_evtchn(xenstore->local_evtchn);

	return len;
}

static void process_message(struct xenstore *xenstore)
{
	struct xsd_sockmsg *header = (struct xsd_sockmsg *)xenstore->in->buffer;
	enum xsd_sockmsg_type type = header->type;
	char *payload = xenstore->in->buffer + sizeof(*header);
	size_t payload_size = xenstore->in->total_size - sizeof(*header);

	if ((uint32_t)type >= XS_TYPE_COUNT || !message_handle_list[type].h) {
		LOG_ERR("Client unknown operation %i", type);
		send_errno(xenstore, 0, ENOSYS);
		return;
	}

	message_handle_list[type].h(xenstore, header->req_id,
				    payload, payload_size);

	k_free(xenstore->in->buffer);
	k_free(xenstore->in);
	xenstore->in = NULL;
}

static void handle_input(struct xenstore *xenstore)
{
	int ret;
	struct xsd_sockmsg header;

	if (!xenstore->in) {
		xenstore->in = k_malloc(sizeof(*xenstore->in));
		if (!xenstore->in) {
			goto alloc_err;
		}
		memset(xenstore->in, 0, sizeof(*xenstore->in));
		xenstore->in->total_size = sizeof(header);
		xenstore->in->buffer = k_malloc(xenstore->in->total_size);
		if (!xenstore->in->buffer) {
			goto alloc_err;
		}
	}

	if (xenstore->in->used < sizeof(header)) {
		ret = ring_read(xenstore, xenstore->in->buffer + xenstore->in->used,
				sizeof(header) - xenstore->in->used);
		if (ret < 0) {
			goto read_err;
		}
		xenstore->in->used += ret;
		if (xenstore->in->used != sizeof(header)) {
			/* Read the remaining header on the next iteration */
			return;
		}

		memcpy(&header, xenstore->in->buffer, sizeof(header));
		if (header.len > XENSTORE_PAYLOAD_MAX) {
			LOG_ERR("Failed to handle input: payload size is too big (%u max=%d)",
				header.len, XENSTORE_PAYLOAD_MAX);
			k_free(xenstore->in->buffer);
			k_free(xenstore->in);
			xenstore->in = NULL;
			return;
		}

		xenstore->in->total_size += header.len;
		k_free(xenstore->in->buffer);
		xenstore->in->buffer = k_malloc(xenstore->in->total_size);
		if (!xenstore->in->buffer) {
			goto alloc_err;
		}

		memcpy(xenstore->in->buffer, &header, sizeof(header));
	}

	ret = ring_read(xenstore, xenstore->in->buffer + xenstore->in->used,
			xenstore->in->total_size - xenstore->in->used);
	if (ret < 0) {
		goto read_err;
	}

	xenstore->in->used += ret;
	if (xenstore->in->used != xenstore->in->total_size) {
		return;
	}

	process_message(xenstore);
	return;

alloc_err:
	invalidate_client(xenstore, "Failed to allocate memory for input buffer", -ENOMEM);
	return;

read_err:
	invalidate_client(xenstore, "Failed to read input ring buffer", ret);
}

static void xenstore_evt_thrd(void *p1, void *p2, void *p3)
{
	ARG_UNUSED(p2);
	ARG_UNUSED(p3);

	struct xen_domain *domain = p1;
	struct xenstore *xenstore = &domain->xenstore;

	xenstore->transaction = 0;
	xenstore->running_transaction = 0;
	xenstore->stop_transaction_id = 0;
	xenstore->pending_stop_transaction = false;

	while (!atomic_get(&xenstore->thrd_stop)) {
		if (xenstore->pending_stop_transaction) {
			send_reply(xenstore,
				   xenstore->stop_transaction_id,
				   XS_TRANSACTION_END, "");
			xenstore->stop_transaction_id = 0;
			xenstore->pending_stop_transaction = false;
		}

		if (!xenstore->running_transaction) {
			process_pending_watch_events(domain);
		}

		if (!can_read(xenstore) && !can_write(xenstore)) {
			k_sem_take(&xenstore->xb_sem, K_FOREVER);
		}

		if (can_read(xenstore)) {
			handle_input(xenstore);
		}

		if (can_write(xenstore)) {
			handle_output(xenstore);
		}
	}

	/* Need to cleanup all watches and events before destroying */
	cleanup_domain_watches(domain);
}

int start_domain_stored(struct xen_domain *domain)
{
	int rc = 0, err_ret;
	struct xenstore *xenstore;

	if (!domain) {
		return -EINVAL;
	}

	xenstore = &domain->xenstore;
	xenstore->domain = domain;
	xenstore->in = NULL;
	sys_slist_init(&xenstore->out_list);
	xenstore->used_out_bufs = 0;

	rc = xenmem_map_region(domain->domid, 1,
			       XEN_PHYS_PFN(GUEST_MAGIC_BASE) +
			       XENSTORE_PFN_OFFSET,
			       (void **)&xenstore->domint);
	if (rc < 0) {
		LOG_ERR("Failed to map xenstore ring for domain#%u (rc=%d)",
			domain->domid, rc);
		return rc;
	}

	xenstore->domint->server_features = XENSTORE_SERVER_FEATURE_RECONNECTION;
	xenstore->domint->connection = XENSTORE_CONNECTED;

	k_sem_init(&xenstore->xb_sem, 0, 1);
	rc = bind_interdomain_event_channel(domain->domid,
					    xenstore->remote_evtchn,
					    xs_evtchn_cb,
					    (void *)xenstore);
	if (rc < 0) {
		LOG_ERR("Failed to bind interdomain event channel (rc=%d)", rc);
		goto unmap_ring;
	}

	xenstore->local_evtchn = rc;

	rc = hvm_set_parameter(HVM_PARAM_STORE_EVTCHN, domain->domid,
			       xenstore->remote_evtchn);
	if (rc) {
		LOG_ERR("Failed to set domain xenbus evtchn param (rc=%d)", rc);
		goto unmap_ring;
	}

	atomic_clear(&xenstore->thrd_stop);

	xenstore->xs_stack_slot = get_stack_idx();
	k_thread_create(&xenstore->thrd,
			xenstore_thrd_stack[xenstore->xs_stack_slot],
			XENSTORE_STACK_SIZE_PER_DOM,
			xenstore_evt_thrd,
			domain, NULL, NULL, 7, 0, K_NO_WAIT);

	return 0;

unmap_ring:
	err_ret = xenmem_unmap_region(1, xenstore->domint);
	if (err_ret < 0) {
		LOG_ERR("Failed to unmap domain#%u xenstore ring (rc=%d)",
			domain->domid, err_ret);
	}
	return rc;
}

static void free_buffered_data(struct xenstore *xenstore)
{
	struct buffered_data *iter, *next;

	SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&xenstore->out_list, iter, next, node) {
		sys_slist_remove(&xenstore->out_list, NULL, &iter->node);
		k_free(iter->buffer);
		k_free(iter);
		xenstore->used_out_bufs--;
	}

	if (xenstore->in) {
		if (xenstore->in->buffer) {
			k_free(xenstore->in->buffer);
		}
		k_free(xenstore->in);
		xenstore->in = NULL;
	}
}

static void remove_ref_entries_recursive(uint32_t domid, sys_dlist_t *chlds)
{
	struct xs_entry *entry, *next;
	struct xs_permissions *perms, *iter_perm, *next_perm;
	sys_snode_t *prev_node;

	SYS_DLIST_FOR_EACH_CONTAINER_SAFE(chlds, entry, next, node) {
		perms = SYS_SLIST_PEEK_HEAD_CONTAINER(&entry->perms, perms, node);
		if (perms->domid == domid) {
			free_node(entry);
		} else {
			prev_node = NULL;
			SYS_SLIST_FOR_EACH_CONTAINER_SAFE(&entry->perms, iter_perm,
							  next_perm, node) {
				if (iter_perm->domid == domid) {
					sys_slist_remove(&entry->perms,
							 prev_node,
							 &iter_perm->node);
					k_free(iter_perm);
				} else {
					prev_node = &iter_perm->node;
				}
			}
			remove_ref_entries_recursive(domid, &entry->child_list);
		}
	}
}

/*
 * The entries, where domain is owner should be removed with children.
 * Also, remove domid from the other domains permissions
 */
static void remove_ref_entries(uint32_t domid)
{
	k_mutex_lock(&xsel_mutex, K_FOREVER);
	remove_ref_entries_recursive(domid, &root_xenstore.child_list);
	k_mutex_unlock(&xsel_mutex);
}

int stop_domain_stored(struct xen_domain *domain)
{
	int rc = 0, err = 0;
	struct xenstore *xenstore;

	if (!domain) {
		return -EINVAL;
	}

	xenstore = &domain->xenstore;

	LOG_DBG("Destroy domain#%u", domain->domid);
	atomic_set(&xenstore->thrd_stop, 1);
	k_sem_give(&xenstore->xb_sem);
	k_thread_join(&xenstore->thrd, K_FOREVER);
	free_stack_idx(xenstore->xs_stack_slot);
	unbind_event_channel(xenstore->local_evtchn);

	rc = evtchn_close(xenstore->local_evtchn);
	if (rc) {
		LOG_ERR("Unable to close event channel#%u (rc=%d)",
			xenstore->local_evtchn, rc);
		err = rc;
	}

	rc = xenmem_unmap_region(1, xenstore->domint);
	if (rc < 0) {
		LOG_ERR("Failed to unmap domain#%u xenstore ring (rc=%d)",
			domain->domid, rc);
		err = rc;
	}

	free_buffered_data(xenstore);
	remove_ref_entries(domain->domid);

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
