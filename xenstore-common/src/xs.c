/*
 * Copyright (c) 2026 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <xs.h>

static k_timeout_t default_timeout = K_FOREVER;

void xs_set_default_timeout(k_timeout_t tout)
{
	default_timeout = tout;
}

static k_timeout_t xs_default_timeout(void)
{
	return default_timeout;
}

ssize_t xs_read(const char *path, char *buf, size_t len, uint32_t tx_id)
{
	return xs_read_timeout(path, buf, len, tx_id, xs_default_timeout());
}

int xs_write(const char *path, const char *value, uint32_t tx_id)
{
	return xs_write_timeout(path, value, tx_id, xs_default_timeout());
}

int xs_rm(const char *path, uint32_t tx_id)
{
	return xs_rm_timeout(path, tx_id, xs_default_timeout());
}

ssize_t xs_directory(const char *path, char *buf, size_t len, uint32_t tx_id)
{
	return xs_directory_timeout(path, buf, len, tx_id, xs_default_timeout());
}

ssize_t xs_get_permissions(const char *path, struct xs_perm_entry *perms, size_t perms_num,
			   uint32_t tx_id)
{
	return xs_get_permissions_timeout(path, perms, perms_num, tx_id, xs_default_timeout());
}

int xs_set_permissions(const char *path, const struct xs_perm_entry *perms, size_t perms_num,
		       uint32_t tx_id)
{
	return xs_set_permissions_timeout(path, perms, perms_num, tx_id, xs_default_timeout());
}

int xs_mkdir(const char *path, uint32_t tx_id)
{
	return xs_mkdir_timeout(path, tx_id, xs_default_timeout());
}

int xs_watch(const char *path, const char *token, xs_watch_cb cb, void *param)
{
	return xs_watch_timeout(path, token, cb, param, xs_default_timeout());
}

int xs_unwatch(const char *path, const char *token)
{
	return xs_unwatch_timeout(path, token, xs_default_timeout());
}
