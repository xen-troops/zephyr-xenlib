// SPDX-License-Identifier: Apache-2.0

/*
 * Copyright (c) 2023 EPAM Systems
 *
 */

#include <stdio.h>
#include <string.h>

#include <zephyr/sys/util.h>

#include <zephyr/xen/events.h>
#include <zephyr/xen/gnttab.h>

#include "vch.h"

#define RD_PROD(h) ((h)->read.s->prod)
#define RD_CONS(h) ((h)->read.s->prod)
#define ORD10_RING_SZ (1 << 10)
#define ORD11_RING_SZ (1 << 11)
#define RD_RING_SZ(h) (())

int vch_open(domid_t domain, const char *path, size_t min_rs, size_t min_ws,
	     struct vch_handle *h)
{
	return -EINVAL;
}


int vch_connect(domid_t domain, const char *path, struct vch_handle *h)
{
	return -EINVAL;
}

void vch_close(struct vch_handle *h)
{
}

int vch_read(struct vch_handle *h, void *buf, size_t size)
{
	return -EINVAL;
}

int vch_write(struct vch_handle *h, const void *buf, size_t size)
{
	return -EINVAL;
}
