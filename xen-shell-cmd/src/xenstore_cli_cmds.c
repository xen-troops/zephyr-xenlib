/*
 * Copyright (c) 2025 TOKITA Hiroshi
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/shell/shell.h>

#include <errno.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/sys/util.h>

#include <xenstore_cli.h>

#include <zephyr/logging/log.h>
LOG_MODULE_REGISTER(xenstore_shell, CONFIG_LOG_DEFAULT_LEVEL);

#define ARG_PARSE_BEGIN()                                                                          \
	{                                                                                          \
		size_t idx__ = 1;                                                                  \
		uint32_t opts__ = 0;                                                               \
		while (idx__ < argc) {                                                             \
			if (false) {                                                               \
			}

#define ARG_PARSE_OPT(x)                                                                           \
	else if (strncmp(argv[idx__], "-" STRINGIFY(x), 2) == 0)                                   \
	{                                                                                          \
		opts__ |= UTIL_CAT(OPT_, x);                                                       \
	}

#define ARG_PARSE_END(idx, opts)                                                                   \
	else                                                                                       \
	{                                                                                          \
		break;                                                                             \
	}                                                                                          \
	idx__++;                                                                                   \
	}                                                                                          \
	if (OPT_EN(h, opts__) || idx__ == argc) {                                                  \
		shell_help(sh);                                                                    \
		return 0;                                                                          \
	}                                                                                          \
	idx = idx__;                                                                               \
	opts = opts__;                                                                             \
	}

#define OPT_h BIT(0)
#define OPT_p BIT(1)
#define OPT_f BIT(2)
#define OPT_t BIT(3)
#define OPT_r BIT(4)

#define OPT_EN(x, opt) (!!((opt) & UTIL_CAT(OPT_, x)))

#define XENSTORE_LS_P_PADDING_END 60

struct cmd_xenstore_watcher {
	struct xs_watcher watcher;
	struct k_sem sem;
	const struct shell *sh;
	size_t count;
	bool registered;
};

const char *space_string(size_t len)
{
	static const char *space =
		"                                                                   "
		"                                                                   "
		"                                                                   "
		"                                                                   ";

	const size_t slen = strlen(space);

	if (len >= slen) {
		return space;
	}

	return space + (slen - len);
}

/**
 * Get the nth string from a null-separated string buffer
 */
static const char *xenstore_next_str(const char *current, const char *buf, size_t len)
{
	if (buf == NULL || len == 0) {
		return NULL;
	}

	if (current == NULL) {
		return buf;
	}

	ptrdiff_t idx = current - buf;

	if (idx < 0 || (size_t)idx >= len) {
		return NULL;
	}

	for (size_t i = ((size_t)idx) + 1; i < len; i++) {
		if ((buf[i] == '\0') && ((i + 1) < len)) {
			return &buf[i + 1];
		}
	}

	return NULL;
}

static bool get_parent_path(const char *path, char *parent, size_t parent_size)
{
	size_t len;
	size_t last;

	if (!path || !parent || parent_size == 0) {
		return false;
	}

	len = strlen(path);

	if (len == 0) {
		return false;
	}

	while ((len > 1) && (path[len - 1] == '/')) {
		len--;
	}

	if (len <= 1) {
		return false;
	}

	last = len;
	while ((last > 0) && (path[last - 1] != '/')) {
		last--;
	}

	if ((last <= 1) || (last > parent_size)) {
		return false;
	}

	memcpy(parent, path, last - 1);
	parent[last - 1] = '\0';

	return true;
}

static int cmd_xenstore_init(const struct shell *sh, size_t argc, char **argv)
{
	xs_init();

	return 0;
}

static int cmd_xenstore_list(const struct shell *sh, size_t argc, char **argv)
{
	uint32_t opts;
	size_t idx;
	char *buffer;

	ARG_PARSE_BEGIN()
	ARG_PARSE_OPT(h)
	ARG_PARSE_OPT(p)
	ARG_PARSE_END(idx, opts)

	buffer = k_malloc(XENSTORE_PAYLOAD_MAX + 1);
	if (buffer == NULL) {
		shell_error(sh, "failed to allocate buffer");
		return -ENOMEM;
	}

	for (; idx < argc; idx++) {
		const ssize_t resp_len = xs_directory(argv[idx], buffer, XENSTORE_PAYLOAD_MAX, 0);
		const char *path = argv[idx];
		const char *ptr = NULL;

		if (resp_len < 0) {
			shell_error(sh, "xs_directory: %ld: %s", resp_len, argv[idx]);
			continue;
		}

		buffer[resp_len] = '\0';
		while ((ptr = xenstore_next_str(ptr, buffer, resp_len))) {
			if (OPT_EN(p, opts)) {
				shell_print(sh, "%s/%s", path, ptr);
			} else {
				shell_print(sh, "%s", ptr);
			}
		}
	}

	k_free(buffer);

	return 0;
}

static int get_perms(const struct shell *sh, char *path_buf, char *perm_buffer)
{
	ssize_t resp_len;
	size_t src_off = 0;
	size_t dst_off = 0;
	bool first = true;

	resp_len = xs_get_permissions(path_buf, perm_buffer, XENSTORE_PAYLOAD_MAX, 0);
	if (resp_len < 0) {
		shell_warn(sh, "get_perms %s: %ld", path_buf, resp_len);
		return resp_len;
	}

	perm_buffer[resp_len] = '\0';
	while (src_off < resp_len) {
		const char *entry = &perm_buffer[src_off];
		size_t entry_len = strlen(entry);

		if (entry_len == 0) {
			break;
		}

		if (!first) {
			perm_buffer[dst_off++] = ',';
		}

		memmove(&perm_buffer[dst_off], entry, entry_len);
		dst_off += entry_len;
		src_off += entry_len + 1;
		first = false;
	}

	perm_buffer[dst_off] = '\0';

	return 0;
}

static int cmd_xenstore_ls_recur(const struct shell *sh, size_t level, const char *path,
				 bool show_path, bool show_perms)
{
	char *buffer = NULL;
	char *path_buf = NULL;
	char *read_buffer = NULL;
	char *perm_buffer = NULL;
	ssize_t resp_len;
	const char *ptr = NULL;
	ssize_t ret = 0;

	buffer = k_malloc(XENSTORE_PAYLOAD_MAX + 1);
	path_buf = k_malloc(XENSTORE_ABS_PATH_MAX + 1);

	if (buffer == NULL || path_buf == NULL) {
		shell_error(sh, "alloc buffer");
		return -ENOMEM;
	}

	resp_len = xs_directory(path, buffer, XENSTORE_PAYLOAD_MAX, 0);

	if (resp_len < 0) {
		shell_error(sh, "xs_directory: %ld: %s", resp_len, path);
		ret = (int)resp_len;
		goto cleanup;
	}

	buffer[resp_len] = '\0';
	while ((ptr = xenstore_next_str(ptr, buffer, resp_len))) {
		ssize_t read_len;
		const char *perms_display = NULL;
		int child_ret;
		int path_len;

		path_len = snprintf(path_buf, XENSTORE_ABS_PATH_MAX, "%s/%s", path, ptr);

		if ((path_len < 0) || ((size_t)path_len >= XENSTORE_ABS_PATH_MAX)) {
			shell_warn(sh, "path truncated: %s/%s", path, ptr);
			continue;
		}

		read_buffer = k_malloc(XENSTORE_PAYLOAD_MAX + 1);
		if (!read_buffer) {
			shell_error(sh, "unable to allocate read buffer");
			ret = -ENOMEM;
			goto cleanup;
		}

		read_len = xs_read(path_buf, read_buffer, XENSTORE_PAYLOAD_MAX, 0);
		if (read_len < 0) {
			shell_warn(sh, "read %s: %ld", path_buf, read_len);
			continue;
		}
		read_buffer[read_len] = '\0';

		if (!show_perms) {
			if (show_path) {
				shell_print(sh, "%s/%s = \"%s\"", path, ptr, read_buffer);
			} else {
				shell_print(sh, "%s%s = \"%s\"", space_string(level), ptr,
					    read_buffer);
			}
		} else {
			perm_buffer = k_malloc(XENSTORE_PAYLOAD_MAX + 1);
			if (!perm_buffer) {
				shell_error(sh, "unable to allocate permissions buffer");
				ret = -ENOMEM;
				goto cleanup;
			}

			ret = get_perms(sh, path_buf, perm_buffer);
			if (ret < 0) {
				continue;
			}
			perms_display = perm_buffer;

			if (show_path) {
				shell_print(sh, "%s/%s = \"%s\"   (%s)", path, ptr, read_buffer,
					    perms_display);
			} else {
				size_t wlen = 0;
				char *msgbuf = k_malloc(XENSTORE_ABS_PATH_MAX);

				if (!msgbuf) {
					shell_error(sh, "unable to allocate msg buffer");
					ret = -ENOMEM;
					goto cleanup;
				}

				memset(msgbuf, 0, XENSTORE_ABS_PATH_MAX);
				wlen += sprintf(msgbuf, "%s%s = \"%s\"", space_string(level), ptr,
						read_buffer);
				shell_fprintf_normal(sh, "%s", msgbuf);

				if (wlen < XENSTORE_LS_P_PADDING_END) {
					if (wlen % 2) {
						shell_fprintf_normal(sh, "%s", " ");
						wlen += 1;
					}
					while ((XENSTORE_LS_P_PADDING_END - wlen) > 0) {
						shell_fprintf_normal(sh, "%s", " .");
						wlen += 2;
					}
				}

				shell_fprintf_normal(sh, "  (%s)\n", perm_buffer);

				k_free(msgbuf);
			}

			k_free(perm_buffer);
			perm_buffer = NULL;
		}

		k_free(read_buffer);
		read_buffer = NULL;

		child_ret = cmd_xenstore_ls_recur(sh, level + 1, path_buf, show_path, show_perms);
		if ((child_ret < 0) && (ret == 0)) {
			ret = child_ret;
		}
	}

cleanup:
	k_free(perm_buffer);
	k_free(read_buffer);
	k_free(path_buf);
	k_free(buffer);

	return ret;
}

static int cmd_xenstore_ls(const struct shell *sh, size_t argc, char **argv)
{
	uint32_t opts;
	size_t idx;

	ARG_PARSE_BEGIN()
	ARG_PARSE_OPT(h)
	ARG_PARSE_OPT(p)
	ARG_PARSE_OPT(f)
	ARG_PARSE_END(idx, opts)

	return cmd_xenstore_ls_recur(sh, 0, argv[idx], OPT_EN(f, opts), OPT_EN(p, opts));
}

static int cmd_xenstore_read(const struct shell *sh, size_t argc, char **argv)
{
	char *buffer;
	uint32_t opts;
	size_t idx;

	ARG_PARSE_BEGIN()
	ARG_PARSE_OPT(h)
	ARG_PARSE_OPT(p)
	ARG_PARSE_END(idx, opts)

	buffer = k_malloc(XENSTORE_PAYLOAD_MAX + 1);

	for (; idx < argc; idx++) {
		const char *path = argv[idx];
		const ssize_t resp_len = xs_read(path, buffer, XENSTORE_PAYLOAD_MAX, 0);

		if (resp_len < 0) {
			shell_error(sh, "xs_read: %s: %ld", path, resp_len);
			continue;
		}

		if (OPT_EN(p, opts)) {
			shell_print(sh, "%s: %s", path, buffer);
		} else {
			shell_print(sh, "%s", buffer);
		}
	}

	k_free(buffer);

	return 0;
}

static int cmd_xenstore_write(const struct shell *sh, size_t argc, char **argv)
{
	char *buffer;
	uint32_t opts;
	size_t idx;

	ARG_PARSE_BEGIN()
	ARG_PARSE_OPT(h)
	ARG_PARSE_END(idx, opts)

	buffer = k_malloc(XENSTORE_PAYLOAD_MAX + 1);

	if (((argc - idx) % 2) != 0) {
		shell_error(sh, "invalid argument pair");
	}

	for (; idx < argc; idx += 2) {
		const char *path = argv[idx];
		const char *value = argv[idx + 1];
		const ssize_t resp_len =
			xs_write(path, value, strlen(value), buffer, XENSTORE_PAYLOAD_MAX, 0);

		if (resp_len < 0) {
			shell_error(sh, "xs_write: %s: %ld", path, resp_len);
			continue;
		}
	}

	k_free(buffer);

	return 0;
}

static int cmd_xenstore_rm(const struct shell *sh, size_t argc, char **argv)
{
	const char *path;
	size_t path_len;
	char *current_path;
	char *parent_path;
	char *buffer;
	uint32_t opts;
	size_t idx;
	ssize_t ret;

	ARG_PARSE_BEGIN()
	ARG_PARSE_OPT(h)
	ARG_PARSE_OPT(t)
	ARG_PARSE_END(idx, opts)

	path = argv[idx];
	path_len = strlen(path) + 1;

	buffer = k_malloc(XENSTORE_PAYLOAD_MAX + 1);
	if (!buffer) {
		shell_error(sh, "failed to allocate buffer");
		return -ENOMEM;
	}

	ret = xs_rm(path, buffer, XENSTORE_PAYLOAD_MAX, 0);

	if (ret < 0 || !OPT_EN(t, opts)) {
		if (ret < 0) {
			shell_error(sh, "xs_rm: %ld %s", ret, path);
		}
		k_free(buffer);
		return ret;
	}

	current_path = k_malloc(path_len);
	parent_path = k_malloc(path_len);

	if (!current_path || !parent_path) {
		shell_error(sh, "failed to allocate path buffer");
		ret = -ENOMEM;
		goto end;
	}

	strncpy(current_path, path, path_len);

	while (get_parent_path(current_path, parent_path, path_len)) {
		const ssize_t resp_len = xs_directory(parent_path, buffer, XENSTORE_PAYLOAD_MAX, 0);

		if (resp_len < 0) {
			ret = resp_len;
			break;
		}

		if (resp_len != 0) {
			break;
		}

		ret = xs_rm(parent_path, buffer, XENSTORE_PAYLOAD_MAX, 0);
		if (ret < 0) {
			break;
		}

		strncpy(current_path, parent_path, path_len);
	}

end:
	k_free(current_path);
	k_free(parent_path);
	k_free(buffer);

	return ret;
}

static ssize_t cmd_xenstore_chmod_recur(const struct shell *sh, char *path_buf, size_t path_len,
					const char **perms, size_t perms_num, bool recursive)
{
	const char *ptr = NULL;
	char *buffer;
	ssize_t resp_len;
	ssize_t ret;

	buffer = k_malloc(XENSTORE_PAYLOAD_MAX + 1);

	if (buffer == NULL) {
		shell_error(sh, "alloc buffer");
		return -ENOMEM;
	}

	memset(buffer, 0, XENSTORE_PAYLOAD_MAX + 1);

	ret = xs_set_permissions(path_buf, perms, perms_num, buffer, XENSTORE_PAYLOAD_MAX, 0);
	if (ret < 0) {
		shell_fprintf_error(sh, "xs_set_permissions %ld %s", ret, path_buf);
		for (size_t i = 0; i < perms_num; i++) {
			shell_fprintf_error(sh, ", %s", perms[i]);
		}
		shell_fprintf_error(sh, "\n");
		goto out;
	}

	ret = 0;

	if (!recursive) {
		goto out;
	}

	resp_len = xs_directory(path_buf, buffer, XENSTORE_PAYLOAD_MAX, 0);
	if (resp_len < 0) {
		shell_error(sh, "xs_directory: %s: %ld", path_buf, resp_len);
		ret = (int)resp_len;
		goto out;
	}

	buffer[resp_len] = '\0';
	while ((ptr = xenstore_next_str(ptr, buffer, resp_len))) {
		size_t child_len;
		bool needs_sep;
		size_t sep_len;
		size_t required;
		size_t write_pos;
		size_t new_len;

		child_len = strlen(ptr);
		needs_sep = (path_len > 1U) && (path_buf[path_len - 1] != '/');
		sep_len = needs_sep ? 1U : 0U;
		required = path_len + sep_len + child_len + 1U;

		if (required > (XENSTORE_ABS_PATH_MAX + 1U)) {
			shell_warn(sh, "path truncated: %s/%s", path_buf, ptr);
			continue;
		}

		write_pos = path_len;
		if (needs_sep) {
			path_buf[write_pos++] = '/';
		}

		memcpy(&path_buf[write_pos], ptr, child_len + 1U);
		new_len = write_pos + child_len;

		ret = cmd_xenstore_chmod_recur(sh, path_buf, new_len, perms, perms_num, recursive);
		path_buf[path_len] = '\0';
		if (ret < 0) {
			break;
		}
	}

out:
	k_free(buffer);

	return ret;
}

static int cmd_xenstore_chmod(const struct shell *sh, size_t argc, char **argv)
{
	const char **perms;
	char *path_buf;
	size_t perms_num;
	char *path;
	uint32_t opts;
	size_t idx;
	size_t path_len;
	ssize_t ret;

	ARG_PARSE_BEGIN()
	ARG_PARSE_OPT(h)
	ARG_PARSE_OPT(r)
	ARG_PARSE_END(idx, opts)

	path = argv[idx];
	idx++;
	perms = (const char **)&argv[idx];

	perms_num = argc - idx;

	path_len = strlen(path);
	if (path_len > XENSTORE_ABS_PATH_MAX) {
		shell_error(sh, "path too long: %s", path);
		return -ENAMETOOLONG;
	}

	path_buf = k_malloc(XENSTORE_ABS_PATH_MAX + 1U);
	if (path_buf == NULL) {
		shell_error(sh, "alloc buffer");
		return -ENOMEM;
	}

	memcpy(path_buf, path, path_len + 1U);

	ret = cmd_xenstore_chmod_recur(sh, path_buf, path_len, perms, perms_num, OPT_EN(r, opts));

	k_free(path_buf);

	return ret;
}

static void watcher_callback(const char *path, const char *token, void *param)
{
	struct cmd_xenstore_watcher *w = param;

	w->count--;

	shell_print(w->sh, "%s:%s %ld", path, token, w->count);

	if (w->count == 0) {
		k_sem_give(&w->sem);
	}
}

static int cmd_xenstore_watch(const struct shell *sh, size_t argc, char **argv)
{
	static struct cmd_xenstore_watcher watcher;
	size_t max_events = 1;
	char *buffer;
	char *path;
	uint32_t opts;
	size_t idx;
	ssize_t ret;

	ARG_PARSE_BEGIN()
	ARG_PARSE_OPT(h)
	else if (strncmp(argv[idx__], "-n", 2) == 0)
	{
		if ((idx__ + 1) == argc) {
			shell_error(sh, "missing path argument");
			return -1;
		}
		max_events = strtol(argv[++idx__], NULL, 10);
	}
	ARG_PARSE_END(idx, opts)

	path = argv[idx];

	if (!watcher.registered) {
		xs_watcher_init(&watcher.watcher, watcher_callback, &watcher);
		ret = xs_watcher_register(&watcher.watcher);
		if (ret < 0) {
			shell_error(sh, "xs_watcher_register %ld", ret);
			return ret;
		}
		watcher.registered = true;
	}

	watcher.sh = sh;
	watcher.count = max_events;

	k_sem_init(&watcher.sem, 0, 1);

	buffer = k_malloc(XENSTORE_PAYLOAD_MAX + 1);
	if (buffer == NULL) {
		shell_error(sh, "alloc buffer");
		return -ENOMEM;
	}
	memset(buffer, 0, XENSTORE_PAYLOAD_MAX + 1);

	ret = xs_watch(path, path, buffer, XENSTORE_PAYLOAD_MAX, 0);
	if (ret < 0) {
		shell_error(sh, "xs_watch: %ld", ret);
		goto end;
	}
	k_sem_take(&watcher.sem, K_FOREVER);

	ret = xs_unwatch(path, path, buffer, XENSTORE_PAYLOAD_MAX, 0);
	if (ret < 0) {
		shell_error(sh, "xs_unwatch: %ld", ret);
		goto end;
	}

end:
	k_free(buffer);

	return (int)ret;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	sub_xenstore_cmds,
	SHELL_CMD_ARG(init, NULL, "Usage: xenstore init", cmd_xenstore_init, 0, 0),
	SHELL_CMD_ARG(list, NULL, "Usage: xenstore list [-h] [-p] key [...]", cmd_xenstore_list, 1,
		      UINT8_MAX),
	SHELL_CMD_ARG(ls, NULL, "Usage: xenstore ls [-h] [-f] [-p] path", cmd_xenstore_ls, 1, 3),
	SHELL_CMD_ARG(read, NULL, "Usage: xenstore read [-h] [-p] [-R] path", cmd_xenstore_read, 1,
		      UINT8_MAX),
	SHELL_CMD_ARG(write, NULL, "Usage: xenstore write [-h] [-R] key value [...]",
		      cmd_xenstore_write, 2, UINT8_MAX),
	SHELL_CMD_ARG(rm, NULL, "Usage: xenstore rm [-h] [-t] key [...]", cmd_xenstore_rm, 1,
		      UINT8_MAX),
	SHELL_CMD_ARG(chmod, NULL, "Usage: xenstore chmod [-h] [-u] [-r] key mode [modes...]",
		      cmd_xenstore_chmod, 1, UINT8_MAX),
	SHELL_CMD_ARG(watch, NULL, "Usage: xenstore watch [-h] [-n NR] key", cmd_xenstore_watch, 1,
		      UINT8_MAX),
	SHELL_SUBCMD_SET_END /* Array terminated. */
);

SHELL_CMD_REGISTER(xenstore, &sub_xenstore_cmds, "XenStore client commands", NULL);
