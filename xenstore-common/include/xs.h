/*
 * Copyright (c) 2026 EPAM Systems
 * Copyright (c) 2025 TOKITA Hiroshi
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef XENLIB_XS_H
#define XENLIB_XS_H

#include <stdint.h>
#include <sys/types.h>

#include <zephyr/kernel.h>

#include <xenstore_common.h>

/** Convenience constant for requests issued outside a XenStore transaction. */
#define XS_TRANSACTION_NONE 0U

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Set the default timeout used by non-timeout API variants.
 *
 * @param[in]     tout       Default timeout for operations that wait for a XenStore reply.
 */
void xs_set_default_timeout(k_timeout_t tout);

/**
 * @brief Initialize the XenStore API implementation.
 *
 * @retval 0 on success.
 * @retval -errno on failure.
 */
int xs_init(void);

/**
 * @brief Read the value stored at a XenStore path.
 *
 * When @p buf is not large enough for the full value, the implementation
 * copies the longest prefix that fits and NUL-terminates @p buf. The return
 * value is still the full value length, so callers can detect truncation with
 * @c ret >= len when @p len is greater than 0.
 *
 * @param[in]     path       XenStore path.
 * @param[out]    buf        Destination buffer for the value. May be NULL when @p len is 0
 *                           and the caller only needs the required value length.
 * @param[in]     len        Size of @p buf in bytes.
 * @param[in]     tx_id      Transaction identifier, or XS_TRANSACTION_NONE outside a
 *                           transaction.
 * @param[in]     tout       Maximum time to wait for the operation.
 *
 * @return Value length in bytes on success, even when @p buf is too small.
 * @retval -errno on failure.
 */
ssize_t xs_read_timeout(const char *path, char *buf, size_t len, uint32_t tx_id,
			k_timeout_t tout);

/**
 * @brief Read the value stored at a XenStore path using the default timeout.
 *
 * When @p buf is not large enough for the full value, the implementation
 * copies the longest prefix that fits and NUL-terminates @p buf. The return
 * value is still the full value length, so callers can detect truncation with
 * @c ret >= len when @p len is greater than 0.
 *
 * @param[in]     path       XenStore path.
 * @param[out]    buf        Destination buffer for the value. May be NULL when @p len is 0.
 * @param[in]     len        Size of @p buf in bytes.
 * @param[in]     tx_id      Transaction identifier, or XS_TRANSACTION_NONE.
 *
 * @return Value length in bytes on success, even when @p buf is too small.
 * @retval -errno on failure.
 */
ssize_t xs_read(const char *path, char *buf, size_t len, uint32_t tx_id);

/**
 * @brief Write a value to a XenStore path.
 *
 * @param[in]     path       XenStore path.
 * @param[in]     value      NUL-terminated value to write.
 * @param[in]     tx_id      Transaction identifier, or XS_TRANSACTION_NONE.
 * @param[in]     tout       Maximum time to wait for the operation.
 *
 * @retval 0 on success.
 * @retval -errno on failure.
 */
int xs_write_timeout(const char *path, const char *value, uint32_t tx_id, k_timeout_t tout);

/**
 * @brief Write a value to a XenStore path using the default timeout.
 *
 * @param[in]     path       XenStore path.
 * @param[in]     value      NUL-terminated value to write.
 * @param[in]     tx_id      Transaction identifier, or XS_TRANSACTION_NONE.
 *
 * @retval 0 on success.
 * @retval -errno on failure.
 */
int xs_write(const char *path, const char *value, uint32_t tx_id);

/**
 * @brief Remove a XenStore path.
 *
 * @param[in]     path       XenStore path to remove.
 * @param[in]     tx_id      Transaction identifier, or XS_TRANSACTION_NONE.
 * @param[in]     tout       Maximum time to wait for the operation.
 *
 * @retval 0 on success.
 * @retval -errno on failure.
 */
int xs_rm_timeout(const char *path, uint32_t tx_id, k_timeout_t tout);

/**
 * @brief Remove a XenStore path using the default timeout.
 *
 * @param[in]     path       XenStore path to remove.
 * @param[in]     tx_id      Transaction identifier, or XS_TRANSACTION_NONE.
 *
 * @retval 0 on success.
 * @retval -errno on failure.
 */
int xs_rm(const char *path, uint32_t tx_id);

/**
 * @brief List child names below a XenStore path.
 *
 * The returned byte stream contains NUL-separated child names.
 *
 * If @p buf is too small, the implementation copies bytes from the beginning
 * of the directory stream until @p buf is full. The return value is still the
 * full directory stream length, so callers can detect truncation with @c ret >
 * len.
 *
 * @param[in]     path       XenStore path.
 * @param[out]    buf        Destination buffer for the directory stream. May be NULL when
 *                           @p len is 0 and the caller only needs the required length.
 * @param[in]     len        Size of @p buf in bytes.
 * @param[in]     tx_id      Transaction identifier, or XS_TRANSACTION_NONE.
 * @param[in]     tout       Maximum time to wait for the operation.
 *
 * @return Directory stream length in bytes on success, even when @p buf is too
 *         small.
 * @retval -errno on failure.
 */
ssize_t xs_directory_timeout(const char *path, char *buf, size_t len, uint32_t tx_id,
			     k_timeout_t tout);

/**
 * @brief List child names below a XenStore path using the default timeout.
 *
 * If @p buf is too small, the implementation copies bytes from the beginning
 * of the directory stream until @p buf is full. The return value is still the
 * full directory stream length, so callers can detect truncation with @c ret >
 * len.
 *
 * @param[in]     path       XenStore path.
 * @param[out]    buf        Destination buffer for the NUL-separated directory stream. May
 *                           be NULL when @p len is 0.
 * @param[in]     len        Size of @p buf in bytes.
 * @param[in]     tx_id      Transaction identifier, or XS_TRANSACTION_NONE.
 *
 * @return Directory stream length in bytes on success, even when @p buf is too
 *         small.
 * @retval -errno on failure.
 */
ssize_t xs_directory(const char *path, char *buf, size_t len, uint32_t tx_id);

/**
 * @brief Read permissions assigned to a XenStore path.
 *
 * If @p perms is too small, the implementation fills the available entries
 * from the beginning of the permission list. The return value is still the
 * full permission entry count, so callers can detect truncation with @c ret >
 * perms_num.
 *
 * @param[in]     path       XenStore path.
 * @param[out]    perms      Destination array for permission entries. May be NULL when
 *                           @p perms_num is 0 and the caller only needs the entry
 *                           count.
 * @param[in]     perms_num  Number of entries available in @p perms.
 * @param[in]     tx_id      Transaction identifier, or XS_TRANSACTION_NONE.
 * @param[in]     tout       Maximum time to wait for the operation.
 *
 * @return Total number of permission entries on success, even when @p perms is
 *         too small.
 * @retval -errno on failure.
 */
ssize_t xs_get_permissions_timeout(const char *path, struct xs_perm_entry *perms,
				   size_t perms_num, uint32_t tx_id, k_timeout_t tout);

/**
 * @brief Read permissions assigned to a XenStore path using the default timeout.
 *
 * If @p perms is too small, the implementation fills the available entries
 * from the beginning of the permission list. The return value is still the
 * full permission entry count, so callers can detect truncation with @c ret >
 * perms_num.
 *
 * @param[in]     path       XenStore path.
 * @param[out]    perms      Destination array for permission entries. May be NULL when
 *                           @p perms_num is 0.
 * @param[in]     perms_num  Number of entries available in @p perms.
 * @param[in]     tx_id      Transaction identifier, or XS_TRANSACTION_NONE.
 *
 * @return Total number of permission entries on success, even when @p perms is
 *         too small.
 * @retval -errno on failure.
 */
ssize_t xs_get_permissions(const char *path, struct xs_perm_entry *perms, size_t perms_num,
			   uint32_t tx_id);

/**
 * @brief Replace permissions assigned to a XenStore path.
 *
 * @param[in]     path       XenStore path.
 * @param[in]     perms      Permission entries to store.
 * @param[in]     perms_num  Number of entries in @p perms.
 * @param[in]     tx_id      Transaction identifier, or XS_TRANSACTION_NONE.
 * @param[in]     tout       Maximum time to wait for the operation.
 *
 * @retval 0 on success.
 * @retval -errno on failure.
 */
int xs_set_permissions_timeout(const char *path, const struct xs_perm_entry *perms,
			       size_t perms_num, uint32_t tx_id, k_timeout_t tout);

/**
 * @brief Replace permissions assigned to a XenStore path using the default
 *        timeout.
 *
 * @param[in]     path       XenStore path.
 * @param[in]     perms      Permission entries to store.
 * @param[in]     perms_num  Number of entries in @p perms.
 * @param[in]     tx_id      Transaction identifier, or XS_TRANSACTION_NONE.
 *
 * @retval 0 on success.
 * @retval -errno on failure.
 */
int xs_set_permissions(const char *path, const struct xs_perm_entry *perms, size_t perms_num,
		       uint32_t tx_id);

/**
 * @brief Create a XenStore directory path.
 *
 * @param[in]     path       XenStore path to create.
 * @param[in]     tx_id      Transaction identifier, or XS_TRANSACTION_NONE.
 * @param[in]     tout       Maximum time to wait for the operation.
 *
 * @retval 0 on success.
 * @retval -errno on failure.
 */
int xs_mkdir_timeout(const char *path, uint32_t tx_id, k_timeout_t tout);

/**
 * @brief Create a XenStore directory path using the default timeout.
 *
 * @param[in]     path       XenStore path to create.
 * @param[in]     tx_id      Transaction identifier, or XS_TRANSACTION_NONE.
 *
 * @retval 0 on success.
 * @retval -errno on failure.
 */
int xs_mkdir(const char *path, uint32_t tx_id);

#ifdef __cplusplus
}
#endif

#endif /* XENLIB_XS_H */
