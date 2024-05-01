/*
 * Copyright (c) 2024 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/shell/shell.h>
#include <zephyr/logging/log.h>
#include <stdlib.h>
#include <string.h>
#include <xss.h>

static int xs_read(const struct shell *shell, size_t argc, char **argv)
{
	char buf[CONFIG_XENSTORE_SHELL_READ_SIZE];
	int rc;

	if (argc != 2) {
		return -EINVAL;
	}

	rc = xss_read(argv[1], buf, CONFIG_XENSTORE_SHELL_READ_SIZE);
	/* Null terminate the buffer */
	buf[CONFIG_XENSTORE_SHELL_READ_SIZE-1] = 0;

	if (!rc) {
		shell_print(shell, "%s", buf);
	} else {
		shell_error(shell, "Failed to read xenstore path %s", argv[1]);
	}

	return 0;
}

static int xs_write(const struct shell *shell, size_t argc, char **argv)
{
	int rc;

	if (argc != 3) {
		return -EINVAL;
	}

	rc = xss_write(argv[1], argv[2]);
	if (rc) {
		shell_error(shell, "Failed to write xenstore path %s", argv[1]);
	}

	return rc;
}

static void xs_ls_cb(void *data, const char *key, const char *value, int depth)
{
	const struct shell *shell = data;

	if (!key) {
		shell_print(shell, "%d: root", depth);
		return;
	}

	if (value) {
		shell_print(shell, "%d: %*s%s = %s", depth, depth * 2, " ", key, value);
	} else {
		shell_print(shell, "%d: %*s%s", depth, depth * 2, " ", key);
	}
}

static int xs_ls(const struct shell *shell, size_t argc, char **argv)
{
	int rc;

	if (argc != 2) {
		return -EINVAL;
	}

	rc = xss_list_traverse(argv[1], xs_ls_cb, (struct shell *)shell);
	if (rc) {
		shell_error(shell, "Failed to list xenstore path %s (%d)", argv[1], rc);
	}

	return rc;
}

static int xs_rm(const struct shell *shell, size_t argc, char **argv)
{
	int rc;

	if (argc != 2) {
		return -EINVAL;
	}

	rc = xss_rm(argv[1]);
	if (rc) {
		shell_error(shell, "Failed to remove xenstore path %s", argv[1]);
	}

	return rc;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	subcmd_xs,
	SHELL_CMD_ARG(read, NULL,
			" Read from xenstore\n"
			" Usage: read <path>\n",
			xs_read, 2, 0),
	SHELL_CMD_ARG(write, NULL,
			" Write to xenstore\n"
			" Usage: write <path> <value>\n",
			xs_write, 3, 0),
	SHELL_CMD_ARG(ls, NULL,
			" List xenstore\n",
			xs_ls, 2, 0),
	SHELL_CMD_ARG(rm, NULL,
			" Remove from xenstore\n"
			" Usage: rm <path>\n",
			xs_rm, 2, 0),
	SHELL_SUBCMD_SET_END);

SHELL_CMD_ARG_REGISTER(xs, &subcmd_xs, "Xenstore commands", NULL, 2, 0);
