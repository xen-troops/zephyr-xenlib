/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <string.h>
#include <xstat.h>
#include <xenlib_osal.h>

static int xstat_shell_vers(const xenlib_osal_shell_t *shell, size_t argc,
			   char **argv)
{
	struct xenstat stat;
	int ret;

	ret = xstat_getstat(&stat);
	if (ret < 0) {
		xenlib_osal_shell_error(shell, "xstat_getstat error %d", ret);
		return ret;
	}
	xenlib_osal_shell_print(shell, "XEN version %s", stat.xen_version);
	return 0;
}

static int xstat_shell_physinfo(const xenlib_osal_shell_t *shell, size_t argc,
			   char **argv)
{
	struct xenstat stat;
	int ret;

	ret = xstat_getstat(&stat);
	if (ret < 0) {
		xenlib_osal_shell_error(shell, "xstat_getstat error %d", ret);
		return ret;
	}
	xenlib_osal_shell_print(shell, "XEN version %s", stat.xen_version);
	xenlib_osal_shell_print(shell, "CPUs         : %d", stat.num_cpus);
	xenlib_osal_shell_print(shell, "CPU freq(kHz): %lld", stat.cpu_hz / 1000);
	xenlib_osal_shell_print(shell, "Total mem(K) : %llu", stat.tot_mem / 1024);
	xenlib_osal_shell_print(shell, "Free mem(K)  : %llu", stat.free_mem / 1024);

	return ret;
}

XENLIB_OSAL_SHELL_STATIC_SUBCMD_SET_CREATE(
	subcmd_xstat,
	XENLIB_OSAL_SHELL_CMD_ARG(version, NULL,
		      " Version command\n",
		      xstat_shell_vers, 1, 0),
	XENLIB_OSAL_SHELL_CMD_ARG(physinfo, NULL,
		      " stat command\n",
		      xstat_shell_physinfo, 1, 0),
	XENLIB_OSAL_SHELL_SUBCMD_SET_END);

XENLIB_OSAL_SHELL_CMD_ARG_REGISTER(xstat, &subcmd_xstat, "XStat commands", NULL,
			   2, 0);
