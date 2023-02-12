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

#include "domain.h"
#include "xenstore_srv.h"

#define XENSTORE_STACK_SIZE_PER_DOM (32 * 1024)
K_KERNEL_STACK_DEFINE(xenstore_thrd_stack, XENSTORE_STACK_SIZE_PER_DOM *DOM_MAX);
static int stack_slots[DOM_MAX] = { 0 };

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

struct xs_entry *key_to_entry(char *key)
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
	printk("Sending error=%d\n", err);

	for (i = 0; err != xsd_errors[i].errnum; i++) {
		if (i == ARRAY_SIZE(xsd_errors) - 1) {
			printk("xenstored: error %i untranslatable", err);
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

void xss_do_write(char *const_path, char *data)
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

/*
 * TODO: this function should not be called from anywhere except event channel
 * handler. Need to understand why notify_sibling_domains() works in such way
 * and fix it. Declaration is needed to avoid compiler warnings during build.
 */
void xs_evtchn_cb(void *priv);

//TODO: header, moveto dom0.c
void notify_sibling_domains(uint32_t *sdom_list, size_t len)
{
	struct xen_domain *iter;

	for (size_t sdi=0;sdom_list[sdi];++sdi)
	{
		iter = domid_to_domain(sdom_list[sdi]);

		if (iter)
		{
			xs_evtchn_cb((void*)iter);
		}
	}
}

void _handle_write(struct xen_domain *domain, uint32_t id, uint32_t msg_type, char *payload,
		   uint32_t len)
{
	uint32_t data_offset = strlen(payload) + 1;
	char *data = payload + data_offset;

	if (len < data_offset) {
		printk("SIZES MISMATCH\n");
		send_errno(domain, id, EINVAL);
		return;
	}

	const char localpath[] = "/";
	char path[STRING_LENGTH_MAX];

	if (memcmp(payload, localpath, strlen(localpath)) == 0) {
		memcpy(path, payload, data_offset);
	} else {
		snprintf(path, STRING_LENGTH_MAX, "/local/domain/%d/%s", domain->domid, payload);
	}

	data[len - data_offset] = 0;
	xss_do_write(path, data);

	send_reply(domain, id, msg_type, "OK");

	struct watch_entry *iter;

	uint32_t sibling_domains[DOM_MAX] = {0};
	k_mutex_lock(&wel_mutex, K_FOREVER);
	SYS_DLIST_FOR_EACH_CONTAINER (&watch_entry_list, iter, node) {
		uint32_t iklen = strlen(iter->key);
		if (memcmp(iter->key, path, iklen) == 0) {
			struct pending_watch_event_entry *entry;
			entry = k_malloc(sizeof(*entry));
			size_t keyl = strlen(path) + 1;
			entry->key = k_malloc(keyl);
			memcpy(entry->key, path, keyl);
			entry->key[keyl - 1] = 0;
			entry->domid = iter->domid;

			if (iter->domid != domain->domid)
			{
				for (size_t sdi=0;sdi<DOM_MAX;++sdi)
				{
					if (sibling_domains[sdi] == 0 || sibling_domains[sdi] == iter->domid)
					{
						sibling_domains[sdi] = iter->domid;
						break;
					}
				}
			}

			k_mutex_lock(&pfl_mutex, K_FOREVER);
			sys_dnode_init(&entry->node);
			sys_dlist_append(&pending_watch_event_list, &entry->node);
			k_mutex_unlock(&pfl_mutex);
		}
	}

	k_mutex_unlock(&wel_mutex);

	notify_sibling_domains(sibling_domains, DOM_MAX);
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
		if (domain->domid == iter->domid && domain->running_transaction == 0 && fire_watcher(domain, id, iter->key)) {
			if (domain->pending_stop_transaction == true && domain->stop_transaction_id == 0)
			{
				continue;
			}
			k_free(iter->key);
			sys_dlist_remove(&iter->node);
			k_free(iter);
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

void handle_rm(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len)
{
	struct xs_entry *entry = key_to_entry(payload);

	if (entry) {
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
	}

	send_reply_read(domain, id, XS_RM, "");
}

void handle_watch(struct xen_domain *domain, uint32_t id, char *payload, uint32_t len)
{
	const char localpath[] = "/";
	char path[STRING_LENGTH_MAX];
	char token[STRING_LENGTH_MAX];
	size_t plen = 0;
	bool is_relative = memcmp(payload, localpath, strlen(localpath)) != 0;
	for (; plen < len && payload[plen] != '\0'; ++plen)
		;
	plen += 1;

	if (is_relative) {
		snprintf(path, STRING_LENGTH_MAX, "/local/domain/%d/%s", domain->domid, payload);
	} else {
		memcpy(path, payload, plen);
	}

	memcpy(token, payload + plen, len - plen);

	struct watch_entry *entry = key_to_watcher(path, true, token);
	size_t lpath = strlen(path) + 1;

	if (!entry) {
		entry = k_malloc(sizeof(*entry));
		entry->key = k_malloc(lpath);
		memcpy(entry->key, path, lpath);
		entry->token = k_malloc(len - plen);
		memcpy(entry->token, token, len - plen);
		entry->domid = domain->domid;
		k_mutex_lock(&wel_mutex, K_FOREVER);
		sys_dnode_init(&entry->node);
		sys_dlist_append(&watch_entry_list, &entry->node);
		k_mutex_unlock(&wel_mutex);
	}

	entry->is_relative = is_relative;

	send_reply(domain, id, XS_WATCH, "OK");

	k_mutex_lock(&xsel_mutex, K_FOREVER);

	if (key_to_entry(path)) {
		struct pending_watch_event_entry *entry;
		entry = k_malloc(sizeof(*entry));
		entry->key = k_malloc(lpath);
		memcpy(entry->key, path, lpath);
		entry->domid = domain->domid;
		k_mutex_lock(&pfl_mutex, K_FOREVER);
		sys_dnode_init(&entry->node);
		sys_dlist_append(&pending_watch_event_list, &entry->node);
		k_mutex_unlock(&pfl_mutex);
	}

	k_mutex_unlock(&xsel_mutex);
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
		if (entry->domid == domain->domid) {
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
		printk("%d: transaction already started\n", domain->domid);
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
	domain->local_xenstore_evtchn = bind_interdomain_event_channel(domain->domid,
								       domain->xenstore_evtchn,
								       xs_evtchn_cb,
								       (void *)domain);

	rc = hvm_set_parameter(HVM_PARAM_STORE_EVTCHN, domain->domid, domain->xenstore_evtchn);
	if (rc) {
		printk("Failed to set domain xenbus evtchn param, rc= %d\n", rc);
		return rc;
	}

	domain->xenstore_thrd_stop = false;

	for (; slot < DOM_MAX && stack_slots[slot] != 0; ++slot)
		;

	if (slot >= DOM_MAX) {
		printk("Unable to find memory for xenbus stack (%ld >= MAX:%d)\n", slot, DOM_MAX);
		return 1;
	}

	stack_slots[slot] = domain->domid;
	domain->stack_slot = slot;
	domain->xenstore_tid =
		k_thread_create(&domain->xenstore_thrd, xenstore_thrd_stack + XENSTORE_STACK_SIZE_PER_DOM * slot,
				K_KERNEL_STACK_SIZEOF(xenstore_thrd_stack) / DOM_MAX, xenstore_evt_thrd,
				domain, NULL, NULL, 7, 0, K_NO_WAIT);

	return 0;
}

int stop_domain_stored(struct xen_domain *domain)
{
	int rc = 0;

	printk("Destroy domain=%p\n", domain);
	domain->xenstore_thrd_stop = true;
	k_sem_give(&domain->xb_sem);
	k_thread_join(&domain->xenstore_thrd, K_FOREVER);
	stack_slots[domain->stack_slot] = 0;
	unbind_event_channel(domain->local_xenstore_evtchn);
	rc = evtchn_close(domain->local_xenstore_evtchn);

	if (rc)
	{
		printk("Unable to close event channel %d, rc=%d\n", domain->local_xenstore_evtchn, rc);
	}

	return rc;
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
			printk("Unsupported message type: %d\n", header->type);
			send_errno(domain, header->req_id, ENOSYS);
		} else {
			message_handle_list[header->type].h(domain, header->req_id,
							 (char *)(header + 1), header->len);
		}

		notify_evtchn(domain->local_xenstore_evtchn);
	}
}

void init_root(void)
{
	sys_dlist_init(&root_xenstore.child_list);
	sys_dnode_init(&root_xenstore.node);
}
