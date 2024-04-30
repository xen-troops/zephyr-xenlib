/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2023 EPAM Systems
 */

#ifndef XENLIB_XRUN_STORAGE_H
#define XENLIB_XRUN_STORAGE_H

#include <sys/types.h>
#include <zephyr/types.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief Read buffer fron file on storage
 *
 * @param fpath - absolute path to the file
 * @param buf - pointer to buffer
 * @param size - size of the buffer
 * @param skip - skip first n bytes before start reading
 *
 * @return - 0 on success and errno on error
 */
ssize_t xrun_read_file(const char *fpath, char *buf,
		       size_t size, int skip);

/**
 * @brief Get size of the file on storage
 *
 * @param fpath - absolute path to the file
 *
 * @return - file size or -errno on error
 */
ssize_t xrun_get_file_size(const char *fpath);

#ifdef __cplusplus
}
#endif

#endif /* XENLIB_XRUN_STORAGE_H */
