/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Copyright (c) 2023 EPAM Systems
 *
 */

#pragma once
#include <zephyr/xen/public/xen.h>

enum xs_perm {
	XS_PERM_NONE = 0x0,
	XS_PERM_READ = 0x1,
	XS_PERM_WRITE = 0x2,
	XS_PERM_BOTH = XS_PERM_WRITE | XS_PERM_READ
};

/*
 * Read the value associated with a path.
 *
 * @param path Xenstore path
 * @param value pre-allocated buffer for Xenstore value
 * @param len size of pre-allocated buffer
 * @return 0 on success, a negative errno value on error.
 */
int xss_read(const char *path, char *value, size_t len);

/*
 * Associates a value with a path.
 *
 * @param path Xenstore path
 * @param value Xenstore value
 * @return 0 on success, a negative errno value on error.
 */
int xss_write(const char *path, const char *value);

/*
 * Read path and parse it as an integer.
 *
 * @param path Xenstore path
 * @param value Returned int value
 * @return 0 on success, a negative errno value on error.
 */
int xss_read_integer(const char *path, int *value);

/*
 * Sets permissions for input path and domid.
 *
 * @param path Xenstore path
 * @param domid Domain ID
 * @param perm Permission value
 * @return 0 on success, a negative errno value on error.
 */
int xss_set_perm(const char *path, domid_t domid, enum xs_perm perm);

