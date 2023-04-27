/*
 * Copyright (C) 2023 Renesas Electronics Corporation.
 * Copyright (C) 2023 EPAM Systems, Inc.
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <errno.h>
#include <storage.h>
#include <string.h>

extern char *test_json_contents;
extern char *test_dtb_contents;

ssize_t xrun_read_file(const char *fpath, char *buf,
		       size_t size, int skip)
{
	if (strstr(fpath, "config.json")) {
		memcpy(buf, test_json_contents, strlen(test_json_contents));
		return strlen(test_json_contents) > size ?
			size : strlen(test_json_contents);
	}

	if (strstr(fpath, ".dtb")) {
		memcpy(buf, test_dtb_contents, strlen(test_dtb_contents));
		return strlen(test_dtb_contents) > size ?
			size : strlen(test_dtb_contents);
	}

	return -EINVAL;
}

ssize_t xrun_get_file_size(const char *fpath)
{

	if (strstr(fpath, "config.json")) {
		return strlen(test_json_contents);
	}

	if (strstr(fpath, ".dtb")) {
		return strlen(test_dtb_contents);
	}

	return -EINVAL;
}
