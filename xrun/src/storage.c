// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2024 EPAM Systems
 */
#include <stdio.h>

#include <zephyr/device.h>
#include <zephyr/fs/fs.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <storage.h>

LOG_MODULE_REGISTER(storage);

#if CONFIG_XRUN_STORAGE_DMA_DEBOUNCE > 0

static uint8_t debounce_buf[KB(CONFIG_XRUN_STORAGE_DMA_DEBOUNCE)]
			    __aligned(CONFIG_SDHC_BUFFER_ALIGNMENT) __nocache;
static K_MUTEX_DEFINE(debounce_lock);

static ssize_t xrun_file_read_debounce(struct fs_file_t *file, uint8_t *buf, size_t read_size)
{
	ssize_t read;
	size_t count;
	ssize_t ret = 0;

	k_mutex_lock(&debounce_lock, K_FOREVER);

	count = read_size;

	while (count) {
		read = MIN(count, sizeof(debounce_buf));

		read = fs_read(file, debounce_buf, read);
		if (read < 0) {
			LOG_ERR("read failed (%zd)", read);
			ret = read;
			break;
		}

		memcpy(buf, debounce_buf, read);
		LOG_DBG("file count %zd read %zd", count, read);
		count -= read;
		buf += read;
		if (count && read < sizeof(debounce_buf)) {
			ret = read_size - count;
			break;
		}
	}

	k_mutex_unlock(&debounce_lock);
	return count ? ret : read_size;
}
#endif /* CONFIG_XRUN_STORAGE_DMA_DEBOUNCE */

ssize_t xrun_read_file(const char *fpath, char *buf,
		       size_t size, int skip)
{
	struct fs_file_t file;
	ssize_t rc;
	int ret;

	if (!buf || size == 0) {
		LOG_ERR("FAIL: Invalid input parameters");
		return -EINVAL;
	}

	if (!fpath || strlen(fpath) == 0) {
		LOG_ERR("FAIL: Invalid file path");
		return -EINVAL;
	}

	fs_file_t_init(&file);
	rc = fs_open(&file, fpath, FS_O_READ);
	if (rc < 0) {
		LOG_ERR("FAIL: open %s: %ld", fpath, rc);
		return rc;
	}

	if (skip) {
		rc = fs_seek(&file, skip, FS_SEEK_SET);
		if (rc < 0) {
			LOG_ERR("FAIL: seek %s: %ld", fpath, rc);
			goto out;
		}
	}

#if CONFIG_XRUN_STORAGE_DMA_DEBOUNCE > 0
	rc = xrun_file_read_debounce(&file, buf, size);
#else
	rc = fs_read(&file, buf, size);
#endif /* CONFIG_XRUN_STORAGE_DMA_DEBOUNCE */
	if (rc < 0) {
		LOG_ERR("FAIL: read %s: [rc:%ld]", fpath, rc);
		goto out;
	}

 out:
	ret = fs_close(&file);
	if (ret < 0) {
		LOG_ERR("FAIL: close %s: %d", fpath, ret);
		rc = (rc < 0) ? rc : ret;
	}

	return rc;
}

ssize_t xrun_get_file_size(const char *fpath)
{
	int rc;
	struct fs_dirent dirent;

	if (!fpath || strlen(fpath) == 0) {
		LOG_ERR("FAIL: Invalid file path");
		return -EINVAL;
	}

	rc = fs_stat(fpath, &dirent);
	if (rc < 0) {
		LOG_ERR("FAIL: stat %s: %d", fpath, rc);
		return rc;
	}

	/* Check if it's a file */
	if (dirent.type != FS_DIR_ENTRY_FILE) {
		LOG_ERR("File: %s not found", fpath);
		return -ENOENT;
	}

	return dirent.size;
}
