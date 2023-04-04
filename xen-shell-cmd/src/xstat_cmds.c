// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2023 EPAM Systems
 */
#include <stdio.h>
#include <string.h>
#include <xstat.h>
#include <zephyr/shell/shell.h>

#if 0
static const char *get_param(size_t argc, char **argv, char opt)
{
	int pos;

	for (pos = 1; pos < argc; pos++) {
		if (argv[pos][0] == '-' && argv[pos][1] == opt) {
			/* Take next value after option */
			pos++;
			return argv[pos];
		}
	}

	/* Use NULL as invalid value */
	return NULL;
}
#endif
static char *print_state(xenstat_domain *domain, char *buff);

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
	int (*compare)(xenstat_domain *domain1, xenstat_domain *domain2);
	void (*print)(const struct shell *shell, xenstat_domain *domain);
} field;

struct {
	unsigned int (*get)(xenstat_domain *);
	char ch;
} state_funcs[] = {
	{ xenstat_domain_dying,    'd' },
	{ xenstat_domain_shutdown, 's' },
	{ xenstat_domain_blocked,  'b' },
	{ xenstat_domain_crashed,  'c' },
	{ xenstat_domain_paused,   'p' },
	{ xenstat_domain_running,  'r' }
};
const unsigned int NUM_STATES = sizeof(state_funcs)/sizeof(*state_funcs);

static char *print_state(xenstat_domain *domain, char *buff)
{
	unsigned int i;
	char *c;

	memset(buff, 0, sizeof(char)*(NUM_STATES+1));
	for(i = 0, c = buff; i < NUM_STATES; i++)
		*c++ = state_funcs[i].get(domain) ? state_funcs[i].ch : '-';
	return buff;
}

static int xstat_shell_vers(const struct shell *shell, size_t argc, char **argv)
{
	xstat_version(shell);
	return 0;
}

static int xstat_shell_sysctl(const struct shell *shell, size_t argc, char **argv)
{
	xstat_sysctl(shell);
	return 0;
}

static int xstat_shell_dominfo(const struct shell *shell, size_t argc, char **argv)
{
	xstat_dominfo(shell);
	return 0;
}

static int xstat_shell_top(const struct shell *shell, size_t argc, char **argv)
{
	xenstat_node node;
	int ret;
	char buff[NUM_STATES+1];
	int dom;

	ret = xstat_getnode(&node, 0, MAX_DOMAINS);
	if (ret < 0) {
		shell_error(shell, "getnode error %d", ret);
		return ret;
	}
	shell_print(shell, "XEN version %s", node.xen_version);
	shell_print(shell, "CPUs         : %d", node.num_cpus);
	shell_print(shell, "CPU freq(kHz): %lld", node.cpu_hz/1000);
	shell_print(shell, "Total mem(K) : %llu", node.tot_mem/1024);
	shell_print(shell, "Free mem(K)  : %llu", node.free_mem/1024);
	shell_print(shell, "Domains (%d):", node.num_domains);
	for (dom = 0; dom < node.num_domains; dom++)
	{
		shell_print(shell, "Domain          : %d (%s)", node.domains[dom].id, node.domains[dom].name);
		shell_print(shell, "State           : %s", print_state(&node.domains[dom], buff));
		shell_print(shell, "CPU ns          : %lld", node.domains[dom].cpu_ns);
		shell_print(shell, "VCPUs           : %d", node.domains[dom].num_vcpus);
		shell_print(shell, "MEM reserved(K) : %lld", node.domains[dom].cur_mem/1024);
		shell_print(shell, "MEM allowed(K)  : %lld", ((long long)node.domains[dom].max_mem == -1)?-1:node.domains[dom].max_mem/1024);
		shell_print(shell, "SSID            : %d", node.domains[dom].ssid);
		shell_print(shell, "---------------------------------");
	}

	return 0;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	subcmd_xstat,
	SHELL_CMD_ARG(version, NULL,
		" Version command\n",
		xstat_shell_vers, 1, 0),
	SHELL_CMD_ARG(sysctl, NULL,
		" sysctl command\n",
		xstat_shell_sysctl, 1, 0),
	SHELL_CMD_ARG(dominfo, NULL,
		" dominfo command\n",
		xstat_shell_dominfo, 1, 0),
	SHELL_CMD_ARG(top, NULL,
		" top command\n",
		xstat_shell_top, 1, 0),
	SHELL_SUBCMD_SET_END);

SHELL_CMD_ARG_REGISTER(xstat, &subcmd_xstat, "XStat commands", NULL, 3, 0);
