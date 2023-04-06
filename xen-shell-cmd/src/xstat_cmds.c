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

static char *print_state(struct xenstat_domain *domain, char *buff);

/* Field types */
typedef enum field_id {
	FIELD_DOMID,
	FIELD_NAME,
	FIELD_STATE,
	FIELD_CPU,
	FIELD_CPU_PCT,
	FIELD_MEM,
	FIELD_MEM_PCT,
	FIELD_MAXMEM,
	FIELD_MAX_PCT,
	FIELD_VCPUS,
	FIELD_NETS,
	FIELD_NET_TX,
	FIELD_NET_RX,
	FIELD_VBDS,
	FIELD_VBD_OO,
	FIELD_VBD_RD,
	FIELD_VBD_WR,
	FIELD_VBD_RSECT,
	FIELD_VBD_WSECT,
	FIELD_SSID
} field_id;

typedef struct field {
	field_id num;
	const char *header;
	unsigned int default_width;
	int (*compare)(struct xenstat_domain *domain1, struct xenstat_domain *domain2);
	void (*print)(const struct shell *shell, struct xenstat_domain *domain);
} field;

struct {
	unsigned int (*get)(struct xenstat_domain *domain);
	char ch;
} state_funcs[] = {
	{ xenstat_domain_dying,    'd' },
	{ xenstat_domain_shutdown, 's' },
	{ xenstat_domain_blocked,  'b' },
	{ xenstat_domain_crashed,  'c' },
	{ xenstat_domain_paused,   'p' },
	{ xenstat_domain_running,  'r' }
};
const unsigned int NUM_STATES = ARRAY_SIZE(state_funcs);

static char *print_state(struct xenstat_domain *domain, char *buff)
{
	unsigned int i;
	char *c;

	memset(buff, 0, sizeof(char)*(NUM_STATES+1));
	for (i = 0, c = buff; i < NUM_STATES; i++) {
		*c++ = state_funcs[i].get(domain) ? state_funcs[i].ch : '-';
	}
	return buff;
}

static int xstat_shell_vers(const struct shell *shell, size_t argc, char **argv)
{
	struct xenstat stat;
	int ret;

	ret = xstat_getstat(&stat);
	if (ret < 0) {
		shell_error(shell, "getnode error %d", ret);
		return ret;
	}
	shell_print(shell, "XEN version %s", stat.xen_version);
	return 0;
}

static int xstat_shell_top(const struct shell *shell, size_t argc, char **argv)
{
	struct xenstat stat;
	int ret;
	char buff[NUM_STATES+1];
	struct xenstat_domain domains[2];
	int dom, i;

	ret = xstat_getstat(&stat);
	if (ret < 0) {
		shell_error(shell, "getnode error %d", ret);
		return ret;
	}
	shell_print(shell, "XEN version %s", stat.xen_version);
	shell_print(shell, "CPUs         : %d", stat.num_cpus);
	shell_print(shell, "CPU freq(kHz): %lld", stat.cpu_hz/1000);
	shell_print(shell, "Total mem(K) : %llu", stat.tot_mem/1024);
	shell_print(shell, "Free mem(K)  : %llu", stat.free_mem/1024);
	dom = 0;
	while (1) {
		ret = xstat_getdominfo(domains, dom, 2);
		if (ret < 0) {
			shell_error(shell, "Cold not get info for domain %d", dom);
			break;
		}
		if (ret == 0) {
			break;
		}
		for (i = 0; i < ret; i++) {
			shell_print(shell, "Domain #%3d     : %d (%s)", dom, domains[i].id,
					domains[i].name);
			shell_print(shell, "State           : %s", print_state(&domains[i], buff));
			shell_print(shell, "CPU ns          : %lld", domains[i].cpu_ns);
			shell_print(shell, "VCPUs           : %d", domains[i].num_vcpus);
			shell_print(shell, "MEM reserved(K) : %lld", domains[i].cur_mem/1024);
			shell_print(shell, "MEM allowed(K)  : %lld",
					((long long)domains[i].max_mem == -1) ? -1
					: domains[i].max_mem/1024);
			shell_print(shell, "SSID            : %d", domains[i].ssid);
			shell_print(shell, "---------------------------------");
			dom++;
		}
	}

	return ret;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	subcmd_xstat,
	SHELL_CMD_ARG(version, NULL,
		" Version command\n",
		xstat_shell_vers, 1, 0),
	SHELL_CMD_ARG(top, NULL,
		" top command\n",
		xstat_shell_top, 1, 0),
	SHELL_SUBCMD_SET_END);

SHELL_CMD_ARG_REGISTER(xstat, &subcmd_xstat, "XStat commands", NULL, 2, 0);
