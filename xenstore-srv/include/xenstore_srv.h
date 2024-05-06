/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef XENLIB_XENSTORE_SRV_H
#define XENLIB_XENSTORE_SRV_H

#include "xen/public/io/xs_wire.h"

#ifdef __cplusplus
extern "C" {
#endif

struct buffered_data {
	/* Used to link buffers into singly-linked list */
	sys_snode_t node;
	/* The number of bytes that was processed for read/write */
	size_t used;
	/* The total size of message header and payload */
	size_t total_size;
	/* Buffer with header and payload */
	uint8_t *buffer;
};

struct xenstore {
	sys_slist_t out_list;
	struct buffered_data *in;
	/* Count the number of used out buffers to prevent Denial of Service attacks */
	int used_out_bufs;
	struct xenstore_domain_interface *domint;
	struct xen_domain *domain;
	struct k_sem xb_sem;
	struct k_thread thrd;
	atomic_t thrd_stop;
	evtchn_port_t remote_evtchn;
	evtchn_port_t local_evtchn;
	size_t xs_stack_slot;
	int transaction;
	int running_transaction;
	int stop_transaction_id;
	bool pending_stop_transaction;
};

/**
 * Starts the xenstore daemon for the specified domain.
 *
 * @param domain The Xen domain to start.
 * @param store_pfn The Xenstore PFN
 *
 * @return 0 on success, or an error code on failure.
 */
int start_domain_stored(struct xen_domain *domain, xen_pfn_t store_pfn);

/**
 * Stops the xenstore daemon for the specified domain.
 *
 * @param domain The Xen domain to stop.
 * @return 0 on success, or an error code on failure.
 */
int stop_domain_stored(struct xen_domain *domain);

/**
 * Initializes the root node of the global xenstore storage.
 *
 * @return 0 on success, or an error code on failure.
 */
int xs_init_root(void);

#ifdef __cplusplus
}
#endif

#endif
