/*
 * Copyright (c) 2025 TOKITA Hiroshi
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef XENLIB_XENSTORE_CLI_H_
#define XENLIB_XENSTORE_CLI_H_

#include <sys/types.h>
#include <stdint.h>
#include <string.h>

#include <xen/public/io/xs_wire.h>
#include <xen/public/memory.h>
#include <xen/public/xen.h>

#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>
#include <zephyr/spinlock.h>
#include <zephyr/sys/slist.h>
#include <zephyr/sys/device_mmio.h>
#include <zephyr/xen/events.h>
#include <zephyr/xen/generic.h>
#include <zephyr/xen/hvm.h>

#include <xenstore_common.h>

/** Convenience constant for requests issued outside a XenStore transaction. */
#define XS_TRANSACTION_NONE 0U

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Watch notification callback.
 *
 * Invoked when a XenStore watch fires.
 *
 * @param path   Absolute XenStore path that triggered the watch.
 * @param token  User-supplied token associated with the watch registration.
 * @param param  Opaque user pointer provided at watcher initialization.
 */
typedef void (*xs_watch_cb)(const char *path, const char *token, void *param);

/**
 * @brief XenStore watcher descriptor.
 *
 * Initialize with xs_watcher_init() and register with ::xs_watcher_register().
 * A watcher can be registered at most once at a time. Callbacks are invoked
 * from the Xen event context; keep handlers short and non-blocking.
 */
struct xs_watcher {
	sys_snode_t node;
	xs_watch_cb cb;
	void *param;
};

/**
 * @brief Initialize the XenStore client.
 * Safe to call multiple times.
 *
 * @retval 0       Initialization succeeded or was already active.
 * @retval -errno  Initialization failed.
 */
int xs_init(void);

/**
 * @brief Set the default timeout for XenStore operations.
 *
 * Operations that do not take an explicit timeout parameter will use this value.
 * K_FOREVER is the default, causing the calling thread to block indefinitely.
 *
 * @param tout  Default timeout to use for XenStore operations.
 */
void xs_set_default_timeout(k_timeout_t tout);

/**
 * @brief Prepare a watcher.
 *
 * @param w     Pointer of watcher descriptor to initialize.
 * @param cb    Callback function invoked for watch notifications.
 * @param param Opaque user data passed to the callback.
 */
void xs_watcher_init(struct xs_watcher *w, xs_watch_cb cb, void *param);

/**
 * @brief Register a watcher callback.
 *
 * @param w Watcher descriptor.
 *
 * @retval 0      Succeed to register the watcher.
 * @retval -errno Failed to register.
 */
int xs_watcher_register(struct xs_watcher *w);

/**
 * @brief Read a XenStore path.
 *
 * @param path     The path to read the value.
 * @param buf      A string buffer to store the result.
 * @param len      The length of @p buf in bytes.
 * @param tx_id    XenStore transaction identifier (0 when not in a transaction).
 * @param tout     Timeout to wait for the response; use K_FOREVER to block
 *                 indefinitely.
 *
 * @retval >=0     Number of bytes copied into @p buf (terminator excluded).
 * @retval -errno  Request failed.
 */
ssize_t xs_read_timeout(const char *path, char *buf, size_t len, uint32_t tx_id, k_timeout_t tout);

/**
 * @brief Remove a XenStore entry.
 *
 * @param path     The path to entry to remove.
 * @param buf      A string buffer to store the result.
 * @param len      The length of @p buf in bytes.
 * @param tx_id    XenStore transaction identifier (0 when not in a transaction).
 *
 * @retval >=0     Number of bytes copied into @p buf (terminator excluded).
 * @retval -errno  Request failed.
 *
 * @see xs_rm_timeout().
 */
ssize_t xs_rm_timeout(const char *path, char *buf, size_t len, uint32_t tx_id, k_timeout_t tout);

/**
 * @brief Write a value to XenStore entry.
 *
 * @param path       The path to write the value.
 * @param value      The value to write.
 * @param value_len  The bytes of @p value.
 * @param buf        A string buffer to store the result.
 * @param len        The length of @p buf in bytes.
 * @param tx_id      XenStore transaction identifier (0 when not in a transaction).
 * @param tout       Timeout to wait for the response.
 *
 * @retval >=0       Number of bytes copied into @p buf (terminator excluded).
 * @retval -errno    Request failed.
 *
 * @see xs_write_timeout().
 */
ssize_t xs_write_timeout(const char *path, const char *value, size_t value_len, char *buf,
			 size_t len, uint32_t tx_id, k_timeout_t tout);

/**
 * @brief Set permission of XenStore entry.
 *
 * @param path       The path to set permission.
 * @param perms      The list of permission specifier.
 * @param perms_num  The number of @p perms entries.
 * @param buf        A string buffer to store the result.
 * @param len        The length of @p buf in bytes.
 * @param tx_id      XenStore transaction identifier (0 when not in a transaction).
 * @param tout       Timeout to wait for the response.
 *
 * @retval >=0       Number of bytes copied into @p buf (terminator excluded).
 * @retval -errno    Request failed.
 *
 * @see xs_set_permissions_timeout().
 */
ssize_t xs_set_permissions_timeout(const char *path, const char **perms, size_t perms_num,
				   char *buf, size_t len, uint32_t tx_id, k_timeout_t tout);

/**
 * @brief Get permission of XenStore entry.
 *
 * @param path     The path to get permission.
 * @param buf      A string buffer to store the result.
 * @param len      The length of @p buf in bytes.
 * @param tx_id    XenStore transaction identifier (0 when not in a transaction).
 * @param tout     Timeout to wait for the response.
 *
 * @retval >=0     Number of bytes copied into @p buf (terminator excluded).
 * @retval -errno  Request failed.
 *
 * @see xs_get_permissions_timeout().
 */
ssize_t xs_get_permissions_timeout(const char *path, char *buf, size_t len, uint32_t tx_id,
				   k_timeout_t tout);

/**
 * @brief Enumerate a XenStore directory.
 *
 * @param path     The absolute directory path to enumerate.
 * @param buf      A buffer to store the result.
 *                 The directory-entries are returned as a byte sequence of
 *                 NUL-separated strings.
 * @param len      The length of @p buf in bytes.
 * @param tx_id    XenStore transaction identifier (0 when not in a transaction).
 * @param tout     Timeout to wait for the response.
 *
 * @retval >=0     Number of bytes copied into @p buf (terminator excluded).
 * @retval -errno  Request failed.
 */
ssize_t xs_directory_timeout(const char *path, char *buf, size_t len, uint32_t tx_id,
			     k_timeout_t tout);

/**
 * @brief Start to watch the XenStore value changes.
 *
 * @param path     The absolute path to watch.
 * @param token    A user token to identify watch request.
 * @param buf      A buffer to store the result.
 * @param len      The length of @p buf in bytes.
 * @param tx_id    XenStore transaction identifier (0 when not in a transaction).
 * @param tout     Timeout to wait for the response.
 *
 * @retval >=0     Number of bytes copied into @p buf (terminator excluded).
 * @retval -errno  Request failed.
 */
ssize_t xs_watch_timeout(const char *path, const char *token, char *buf, size_t len, uint32_t tx_id,
			 k_timeout_t tout);

/**
 * @brief Stop to watch the XenStore value changes.
 *
 * @param path     Absolute path to unwatch.
 * @param token    A user token to identify watch request.
 * @param buf      A string buffer to store the result.
 * @param len      The length of @p buf in bytes.
 * @param tx_id    XenStore transaction identifier (0 when not in a transaction).
 * @param tout     Timeout to wait for the response.
 *
 * @retval >=0     Number of bytes copied into @p buf (terminator excluded).
 * @retval -errno  Request failed.
 *
 * @see xs_watch_timeout().
 */
ssize_t xs_unwatch_timeout(const char *path, const char *token, char *buf, size_t len,
			   uint32_t tx_id, k_timeout_t tout);

/**
 * @brief Read a XenStore path with the default timeout.
 *
 * @param path     The path to read the value.
 * @param buf      A string buffer to store the result.
 * @param len      The length of @p buf in bytes.
 * @param tx_id    XenStore transaction identifier (0 when not in a transaction).
 *
 * @retval >=0     Number of bytes copied into @p buf (terminator excluded).
 * @retval -errno  Request failed.
 *
 * @see xs_read_timeout().
 */
ssize_t xs_read(const char *path, char *buf, size_t len, uint32_t tx_id);

/**
 * @brief Remove a XenStore entry with the default timeout.
 *
 * @param path     The path to entry to remove.
 * @param buf      A string buffer to store the result.
 * @param len      The length of @p buf in bytes.
 * @param tx_id    XenStore transaction identifier (0 when not in a transaction).
 *
 * @retval >=0     Number of bytes copied into @p buf (terminator excluded).
 * @retval -errno  Request failed.
 *
 * @see xs_rm_timeout().
 */
ssize_t xs_rm(const char *path, char *buf, size_t len, uint32_t tx_id);

/**
 * @brief Write a value to XenStore entry with the default timeout.
 *
 * @param path       The path to write the value.
 * @param value      The value to write.
 * @param value_len  The bytes of @p value.
 * @param buf        A string buffer to store the result.
 * @param len        The length of @p buf in bytes.
 * @param tx_id      XenStore transaction identifier (0 when not in a transaction).
 *
 * @retval >=0       Number of bytes copied into @p buf (terminator excluded).
 * @retval -errno    Request failed.
 *
 * @see xs_write_timeout().
 */
ssize_t xs_write(const char *path, const char *value, size_t value_len, char *buf, size_t len,
		 uint32_t tx_id);

/**
 * @brief Set permission of XenStore entry with the default timeout.
 *
 * @param path       The path to set permission.
 * @param perms      The list of permission specifier.
 * @param perms_num  The number of @p perms entries.
 * @param buf        A string buffer to store the result.
 * @param len        The length of @p buf in bytes.
 * @param tx_id      XenStore transaction identifier (0 when not in a transaction).
 *
 * @retval >=0       Number of bytes copied into @p buf (terminator excluded).
 * @retval -errno    Request failed.
 *
 * @see xs_set_permissions_timeout().
 */
ssize_t xs_set_permissions(const char *path, const char **perms, size_t perms_num, char *buf,
			   size_t len, uint32_t tx_id);

/**
 * @brief Get permission of XenStore entry with the default timeout.
 *
 * @param path       The path to get permission.
 * @param buf        A string buffer to store the result.
 * @param len        The length of @p buf in bytes.
 * @param tx_id      XenStore transaction identifier (0 when not in a transaction).
 *
 * @retval >=0       Number of bytes copied into @p buf (terminator excluded).
 * @retval -errno    Request failed.
 *
 * @see xs_get_permissions_timeout().
 */
ssize_t xs_get_permissions(const char *path, char *buf, size_t len, uint32_t tx_id);

/**
 * @brief Enumerate a XenStore directory with the default timeout.
 *
 * @param path     The directory path to enumerate.
 * @param buf      A string buffer to store the result.
 * @param len      The length of @p buf in bytes.
 * @param tx_id    XenStore transaction identifier (0 when not in a transaction).
 *
 * @retval >=0     Number of bytes copied into @p buf (terminator excluded).
 * @retval -errno  Request failed.
 *
 * @see xs_directory_timeout().
 */
ssize_t xs_directory(const char *path, char *buf, size_t len, uint32_t tx_id);

/**
 * @brief Start to watch the XenStore value changes with the default timeout.
 *
 * @param path     Absolute path to watch.
 * @param token    A user token to identify watch request.
 * @param buf      A string buffer to store the result.
 * @param len      The length of @p buf in bytes.
 * @param tx_id    XenStore transaction identifier (0 when not in a transaction).
 *
 * @retval >=0     Number of bytes copied into @p buf (terminator excluded).
 * @retval -errno  Request failed.
 *
 * @see xs_watch_timeout().
 */
ssize_t xs_watch(const char *path, const char *token, char *buf, size_t len, uint32_t tx_id);

/**
 * @brief Stop to watch the XenStore value changes with the default timeout.
 *
 * @param path     Absolute path to unwatch.
 * @param token    A user token to identify watch request.
 * @param buf      A string buffer to store the result.
 * @param len      The length of @p buf in bytes.
 * @param tx_id    XenStore transaction identifier (0 when not in a transaction).
 *
 * @retval >=0     Number of bytes copied into @p buf (terminator excluded).
 * @retval -errno  Request failed.
 *
 * @see xs_watch_timeout().
 */
ssize_t xs_unwatch(const char *path, const char *token, char *buf, size_t len, uint32_t tx_id);

#ifdef __cplusplus
}
#endif

#endif
