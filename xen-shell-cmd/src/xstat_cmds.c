/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <stdio.h>
#include <string.h>
#include <xstat.h>
#include <zephyr/sys/util.h>
#include <zephyr/shell/shell.h>

struct status_func {
	unsigned int (*get_status)(int state);
	char ch;
};

/* Get domain states */
static unsigned int xstat_dying(int state)
{
	return (state & XEN_DOMINF_dying) == XEN_DOMINF_dying;
}

static unsigned int xstat_crashed(int state)
{
	return ((state & XEN_DOMINF_shutdown) == XEN_DOMINF_shutdown) &&
		(((state >> XEN_DOMINF_shutdownshift) &
		XEN_DOMINF_shutdownmask) == SHUTDOWN_crash);
}

static unsigned int xstat_shutdown(int state)
{
	return ((state & XEN_DOMINF_shutdown) == XEN_DOMINF_shutdown) &&
		(((state >> XEN_DOMINF_shutdownshift) &
		XEN_DOMINF_shutdownmask) != SHUTDOWN_crash);
}

static unsigned int xstat_paused(int state)
{
	return (state & XEN_DOMINF_paused) == XEN_DOMINF_paused;
}

static unsigned int xstat_blocked(int state)
{
	return (state & XEN_DOMINF_blocked) == XEN_DOMINF_blocked;
}

static unsigned int xstat_running(int state)
{
	return (state & XEN_DOMINF_running) == XEN_DOMINF_running;
}

static const struct status_func status_funcs[] = {
	{ xstat_dying,    'd' },
	{ xstat_shutdown, 's' },
	{ xstat_blocked,  'b' },
	{ xstat_crashed,  'c' },
	{ xstat_paused,   'p' },
	{ xstat_running,  'r' }
};

const unsigned int NUM_STATES = ARRAY_SIZE(status_funcs);

static char *print_state(struct xenstat_domain *domain, char *buff)
{
	unsigned int i;
	char *c;

	if (!buff) {
		return NULL;
	}
	buff[NUM_STATES] = 0;
	for (i = 0, c = buff; i < NUM_STATES; i++) {
		*c++ = status_funcs[i].get_status(domain->state) ? status_funcs[i].ch : '-';
	}
	return buff;
}

static int xstat_shell_vers(const struct shell *shell, size_t argc, char **argv)
{
	struct xenstat stat;
	int ret;

	ret = xstat_getstat(&stat);
	if (ret < 0) {
		shell_error(shell, "xstat_getstat error %d", ret);
		return ret;
	}
	shell_print(shell, "XEN version %s", stat.xen_version);
	return 0;
}

static int xstat_shell_stat(const struct shell *shell, size_t argc, char **argv)
{
	struct xenstat stat;
	int ret;
	char buff[NUM_STATES + 1];
	struct xenstat_domain domain;
	int max_domid;

	ret = xstat_getstat(&stat);
	if (ret < 0) {
		shell_error(shell, "xstat_getstat error %d", ret);
		return ret;
	}
	shell_print(shell, "XEN version %s", stat.xen_version);
	shell_print(shell, "CPUs         : %d", stat.num_cpus);
	shell_print(shell, "CPU freq(kHz): %lld", stat.cpu_hz / 1000);
	shell_print(shell, "Total mem(K) : %llu", stat.tot_mem / 1024);
	shell_print(shell, "Free mem(K)  : %llu", stat.free_mem / 1024);
	max_domid = 0;
	while (1) {
		ret = xstat_getdominfo(&domain, max_domid, 1);
		if (ret < 0) {
			shell_error(shell, "Cold not get info for domain %d", max_domid);
			break;
		}
		if (ret == 0) {
			break;
		}
		if (domain.id + 1 > max_domid) {
			max_domid = domain.id + 1;
		}
		shell_print(shell, "Domain #%3d     : %s", domain.id, domain.name);
		shell_print(shell, "State           : %s", print_state(&domain, buff));
		shell_print(shell, "CPU ns          : %lld", domain.cpu_ns);
		shell_print(shell, "VCPUs           : %d", domain.num_vcpus);
		shell_print(shell, "MEM reserved(K) : %lld", domain.cur_mem / 1024);
		shell_print(shell, "MEM allowed(K)  : %lld",
			    ((long long)domain.max_mem == -1) ? -1
			    : domain.max_mem / 1024);
		shell_print(shell, "SSID            : %d", domain.ssid);
		shell_print(shell, "---------------------------------");
	}

	return ret;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	subcmd_xstat,
	SHELL_CMD_ARG(version, NULL,
		      " Version command\n",
		      xstat_shell_vers, 1, 0),
	SHELL_CMD_ARG(stat, NULL,
		      " stat command\n",
		      xstat_shell_stat, 1, 0),
	SHELL_SUBCMD_SET_END);

SHELL_CMD_ARG_REGISTER(xstat, &subcmd_xstat, "XStat commands", NULL, 2, 0);
