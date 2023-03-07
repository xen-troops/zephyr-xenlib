// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2023 EPAM Systems
 */
#include <stdio.h>

#include <zephyr/device.h>
#include <zephyr/fs/fs.h>
#include <zephyr/fs/littlefs.h>
#include <zephyr/kernel.h>
#include <zephyr/logging/log.h>

#include <storage.h>

LOG_MODULE_REGISTER(storage);

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

	rc = fs_read(&file, buf, size);
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
	if (rc == 0 && dirent.type != FS_DIR_ENTRY_FILE) {
		LOG_ERR("File: %s not found", fpath);
		return -ENOENT;
	}

	return dirent.size;
}
