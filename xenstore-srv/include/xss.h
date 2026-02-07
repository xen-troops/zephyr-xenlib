/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Copyright (c) 2023 EPAM Systems
 *
 */
/**
 * @file xss.h
 */
#ifndef XENLIB_XSS_H
#define XENLIB_XSS_H

#include <xen/public/xen.h>

/**
 * @brief Xenstore access control Interface
 * @defgroup xen_xenstore_xss Xenstore access control Interface
 * @{
 */
#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Xenstore entry access permissions
 */
enum xs_perm {
	/** Xenstore entry owner permissions */
	XS_PERM_NONE = 0x0,
	/** Xenstore entry read permissions for quest domain */
	XS_PERM_READ = 0x1,
	/** Xenstore entry write permissions for quest domain */
	XS_PERM_WRITE = 0x2,
	/** Xenstore entry both RW permissions for quest domain */
	XS_PERM_BOTH = XS_PERM_WRITE | XS_PERM_READ
};

/**
 * Read the value associated with a path.
 *
 * @param path Xenstore path
 * @param value pre-allocated buffer for Xenstore value
 * @param len size of pre-allocated buffer
 * @return 0 on success, a negative errno value on error.
 */
int xss_read(const char *path, char *value, size_t len);

/**
 * Associates a value with a path.
 *
 * @param path Xenstore path
 * @param value Xenstore value
 * @return 0 on success, a negative errno value on error.
 */
int xss_write(const char *path, const char *value);

/**
 * Associates a value with a path and set read-write permissions for given domid.
 *
 * @param path Xenstore path
 * @param value Xenstore value
 * @param domid domain id with XS_PERM_BOTH
 * @return 0 on success, a negative errno value on error.
 */
int xss_write_guest_domain_rw(const char *path, const char *value, uint32_t domid);

/**
 * Associates a value with a path and set read-only permissions for given domid.
 *
 * @param path Xenstore path
 * @param value Xenstore value
 * @param domid domain id with XS_PERM_READ
 * @return 0 on success, a negative errno value on error.
 */
int xss_write_guest_domain_ro(const char *path, const char *value, uint32_t domid);

/**
 * Associates a value with a path and set none for domid1 and read-only for domid2
 * permissions.
 *
 * @param path Xenstore path
 * @param value Xenstore value
 * @param domid1 domain id with XS_PERM_NONE
 * @param domid2 domain id with XS_PERM_READ
 * @return 0 on success, a negative errno value on error.
 */
int xss_write_guest_with_permissions(const char *path, const char *value, uint32_t domid1,
				     uint32_t domid2);

/**
 * Read path and parse it as an integer.
 *
 * @param path Xenstore path
 * @param value Returned int value
 * @return 0 on success, a negative errno value on error.
 */
int xss_read_integer(const char *path, int *value);

/**
 * Sets permissions for input path and domid.
 *
 * @param path Xenstore path
 * @param domid Domain ID
 * @param perm Permission value
 * @return 0 on success, a negative errno value on error.
 */
int xss_set_perm(const char *path, domid_t domid, enum xs_perm perm);

/**
 * Removes the value associated with a path.
 *
 * @param path Xenstore path
 * @return 0 on success, a negative errno value on error.
 */
int xss_rm(const char *path);

/**
 * @typedef xss_traverse_callback_t
 * @brief Xenstore traverse callback
 * @see xss_list_traverse()
 *
 * @param[in] data User data passed in xss_list_traverse()
 * @param[in] key Xenstore entry name
 * @param[in] value Xenstore entry value, NULL if not set
 * @param[in] depth Xenstore tree current depth, starting from 0 (root)
 */
typedef void (*xss_traverse_callback_t)(void *data, const char *key, const char *value, int depth);

/**
 * @brief Traverses all entries in a directory recursively
 *
 * This function traverses all Xenstore entries starting from @p path and calls
 * user callback @p cb for each entry.
 *
 * @param[in] path Xenstore path
 * @param[in] cb traverse callback #xss_traverse_callback_t
 * @param[in] data to be passed in @p cb
 *
 * @retval 0 If successful
 * @retval -EINVAL if @p cb not provided
 * @retval -ENOENT if @p path not found
 */
int xss_list_traverse(const char *path, xss_traverse_callback_t cb, void *data);

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif /* XENLIB_XSS_H */
