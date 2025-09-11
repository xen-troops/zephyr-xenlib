/*
 * Copyright (c) 2023 EPAM Systems
 * Copyright (c) 2025 TOKITA Hiroshi
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <xenstore_common.h>

int xenstore_ring_write(struct xenstore_domain_interface *intf, const void *data, size_t len,
			bool client)
{
	size_t avail;
	void *dest;
	XENSTORE_RING_IDX cons, prod;

	cons = client ? intf->req_cons : intf->rsp_cons;
	prod = client ? intf->req_prod : intf->rsp_prod;
	z_barrier_dmem_fence_full();

	if (xenstore_check_indexes(cons, prod)) {
		return -EINVAL;
	}

	dest = (client ? intf->req : intf->rsp) + get_output_offset(cons, prod, &avail);
	if (avail < len) {
		len = avail;
	}

	memcpy(dest, data, len);
	z_barrier_dmem_fence_full();
	if (client) {
		intf->req_prod += len;
	} else {
		intf->rsp_prod += len;
	}

	return len;
}

int xenstore_ring_read(struct xenstore_domain_interface *intf, void *data, size_t len, bool client)
{
	size_t avail;
	const void *src;
	XENSTORE_RING_IDX cons, prod;

	cons = client ? intf->rsp_cons : intf->req_cons;
	prod = client ? intf->rsp_prod : intf->req_prod;
	z_barrier_dmem_fence_full();

	if (xenstore_check_indexes(cons, prod)) {
		return -EIO;
	}

	src = (client ? intf->rsp : intf->req) + xenstore_get_input_offset(cons, prod, &avail);
	if (avail < len) {
		len = avail;
	}

	if (data) {
		memcpy(data, src, len);
	}

	z_barrier_dmem_fence_full();
	if (client) {
		intf->rsp_cons += len;
	} else {
		intf->req_cons += len;
	}

	return len;
}

int xenstore_get_error(const char *errstr, size_t len)
{
	size_t i;

	for (i = 0; i < ARRAY_SIZE(xsd_errors); i++) {
		if (strncmp(errstr, xsd_errors[i].errstring, len) == 0) {
			return xsd_errors[i].errnum;
		}
	}

	return 0;
}
