/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Copyright (c) 2023 EPAM Systems
 *
 */

#ifndef XENLIB_VCH_H
#define XENLIB_VCH_H

#include <zephyr/xen/generic.h>
#include <zephyr/xen/public/event_channel.h>
#include <zephyr/xen/public/grant_table.h>
#include <zephyr/xen/public/xen.h>

#include "xen/public/io/libxenvchan.h"

#ifdef __cplusplus
extern "C" {
#endif

struct vch_handle {
	evtchn_port_t evtch;
	grant_ref_t gref;
	grant_handle_t grant_handle;
	bool blocking;
	struct k_sem sem;
	bool is_server;
	struct vchan_interface *ring;
	struct ring_shared *write;
	uint8_t *write_cbuf;
	unsigned int write_ord;
	struct ring_shared *read;
	unsigned int read_ord;
	uint8_t *read_cbuf;
	char path[CONFIG_VCH_PATH_MAXLEN];
};

/**
 * Set up vchannel, allocate & grant page(s), initialize vchannel object
 * @param domid ID of domain from which connection is expected
 * @param path xenstore base path for exchanging grant/event IDs
 * @param min_rs minimum size (in bytes) of the server side receiving ring
 * @param min_ws minimum size (in bytes) of the server side sending ring
 * @param handle pre-allocated vchannel object to be initialized
 * @return 0 on success, a negative errno value on error.
 */
int vch_open(domid_t domid, const char *path, size_t min_rs, size_t min_ws,
	     struct vch_handle *handle);

/**
 * Connect to an existing opened vchannel.
 *
 * @param domid ID of domain to connect to
 * @param path xenstore base path for exchanging grant/event IDs
 * @param handle pre-allocated vchannel object to be initialized
 * @return 0 on success, a negative errno value on error.
 */

int vch_connect(domid_t domid, const char *path,  struct vch_handle *handle);

/*
 * Close a vchannel, free its resources and notify the other side.
 * @param handle vchannel object
 */
void vch_close(struct vch_handle *handle);

/**
 * Stream-based receive: reads as much data as possible.
 * @param handle vchannel object
 * @param buf pre-allocated buffer to copy received data to
 * @param size size of the buffer
 * @return amount of data read or negative errno on error
 */

int vch_read(struct vch_handle *handle, void *buf, size_t size);

/**
 * Stream-based send: send as much data as possible.
 * @param handle vchannel object
 * @param buf buffer to copy sent data from
 * @param size size of the buffer
 * @return amount of data sent or negative errno on error
 */

int vch_write(struct vch_handle *handle, const void *buf, size_t size);

#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* XENLIB_VCH_H */
