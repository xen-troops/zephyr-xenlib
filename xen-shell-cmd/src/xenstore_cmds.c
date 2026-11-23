/*
 * Copyright (c) 2024 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <stdlib.h>
#include <string.h>
#include <xss.h>
#include <xenlib_osal.h>

static int xenstore_shell_read(const xenlib_osal_shell_t *shell, size_t argc,
			   char **argv)
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
		xenlib_osal_shell_print(shell, "%s", buf);
	} else {
		xenlib_osal_shell_error(shell, "Failed to read xenstore path %s",
					   argv[1]);
	}

	return 0;
}

static int xenstore_shell_write(const xenlib_osal_shell_t *shell, size_t argc,
				   char **argv)
{
	int rc;

	if (argc != 3) {
		return -EINVAL;
	}

	rc = xss_write(argv[1], argv[2]);
	if (rc) {
		xenlib_osal_shell_error(shell, "Failed to write xenstore path %s",
					   argv[1]);
	}

	return rc;
}

static void xenstore_shell_ls_cb(void *data, const char *key, const char *value, int depth)
{
	const xenlib_osal_shell_t *shell = data;

	if (!key) {
		xenlib_osal_shell_print(shell, "%d: root", depth);
		return;
	}

	if (value) {
		xenlib_osal_shell_print(shell, "%d: %*s%s = %s", depth, depth * 2, " ",
					   key, value);
	} else {
		xenlib_osal_shell_print(shell, "%d: %*s%s", depth, depth * 2, " ", key);
	}
}

static int xenstore_shell_ls(const xenlib_osal_shell_t *shell, size_t argc,
			   char **argv)
{
	int rc;

	if (argc != 2) {
		return -EINVAL;
	}

	rc = xss_list_traverse(argv[1], xenstore_shell_ls_cb,
				   (xenlib_osal_shell_t *)shell);
	if (rc) {
		xenlib_osal_shell_error(shell, "Failed to list xenstore path %s (%d)",
					   argv[1], rc);
	}

	return rc;
}

static int xenstore_shell_rm(const xenlib_osal_shell_t *shell, size_t argc,
				   char **argv)
{
	int rc;

	if (argc != 2) {
		return -EINVAL;
	}

	rc = xss_rm(argv[1]);
	if (rc) {
		xenlib_osal_shell_error(shell, "Failed to remove xenstore path %s",
				   argv[1]);
	}

	return rc;
}

XENLIB_OSAL_SHELL_STATIC_SUBCMD_SET_CREATE(
	subcmd_xs,
	XENLIB_OSAL_SHELL_CMD_ARG(read, NULL,
			" Read from xenstore\n"
			" Usage: read <path>\n",
			xenstore_shell_read, 2, 0),
	XENLIB_OSAL_SHELL_CMD_ARG(write, NULL,
			" Write to xenstore\n"
			" Usage: write <path> <value>\n",
			xenstore_shell_write, 3, 0),
	XENLIB_OSAL_SHELL_CMD_ARG(ls, NULL,
			" List xenstore\n",
			xenstore_shell_ls, 2, 0),
	XENLIB_OSAL_SHELL_CMD_ARG(rm, NULL,
			" Remove from xenstore\n"
			" Usage: rm <path>\n",
			xenstore_shell_rm, 2, 0),
	XENLIB_OSAL_SHELL_SUBCMD_SET_END);

XENLIB_OSAL_SHELL_CMD_ARG_REGISTER(xs, &subcmd_xs, "Xenstore commands", NULL, 2,
			   0);
