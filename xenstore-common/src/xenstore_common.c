/*
 * Copyright (c) 2023 EPAM Systems
 * Copyright (c) 2025 TOKITA Hiroshi
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>

#include <xenstore_common.h>

int xenstore_perm_to_wire(enum xs_perm perm, char *wire)
{
	if (!wire) {
		return -EINVAL;
	}

	switch (perm & XS_PERM_BOTH) {
	case XS_PERM_WRITE:
		*wire = 'w';
		return 0;
	case XS_PERM_READ:
		*wire = 'r';
		return 0;
	case XS_PERM_BOTH:
		*wire = 'b';
		return 0;
	default:
		*wire = 'n';
		return 0;
	}
}

int xenstore_perm_from_wire(char wire, enum xs_perm *perm)
{
	if (!perm) {
		return -EINVAL;
	}

	switch (wire) {
	case 'w':
		*perm = XS_PERM_WRITE;
		return 0;
	case 'r':
		*perm = XS_PERM_READ;
		return 0;
	case 'b':
		*perm = XS_PERM_BOTH;
		return 0;
	case 'n':
		*perm = XS_PERM_NONE;
		return 0;
	default:
		return -EINVAL;
	}
}

ssize_t xenstore_perm_parse_wire(const char *raw, size_t raw_len, struct xs_perm_entry *perms,
				 size_t perms_num)
{
	size_t copied = 0;

	if (!raw || (!perms && perms_num != 0)) {
		return -EINVAL;
	}

	for (size_t off = 0; off < raw_len;) {
		enum xs_perm perm;
		unsigned long domid;
		const char *entry = raw + off;
		size_t entry_len = strnlen(entry, raw_len - off);
		char *endptr;
		int ret;

		if (entry_len == (raw_len - off) || entry_len < 2) {
			return -EPROTO;
		}

		if (perms && copied >= perms_num) {
			return -ENOSPC;
		}

		ret = xenstore_perm_from_wire(entry[0], &perm);
		if (ret < 0) {
			return ret;
		}

		errno = 0;
		domid = strtoul(entry + 1, &endptr, 10);
		if ((endptr == (entry + 1)) || (*endptr != '\0') || (errno == ERANGE) ||
		    ((domid & DOMID_MASK) != domid)) {
			return -EPROTO;
		}

		if (perms) {
			perms[copied].domid = (domid_t)domid;
			perms[copied].perm = perm;
		}
		copied++;
		off += entry_len + 1;
	}

	return copied;
}

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

	if (!errstr) {
		return 0;
	}

	for (i = 0; i < ARRAY_SIZE(xsd_errors); i++) {
		const char *known = xsd_errors[i].errstring;
		size_t known_len = strlen(known);

		if (len == known_len && memcmp(errstr, known, known_len) == 0) {
			return xsd_errors[i].errnum;
		}
		if (len == known_len + 1 && memcmp(errstr, known, known_len) == 0 &&
		    errstr[known_len] == '\0') {
			return xsd_errors[i].errnum;
		}
	}

	return 0;
}
