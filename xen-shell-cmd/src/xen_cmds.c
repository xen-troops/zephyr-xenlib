/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/shell/shell.h>
#include <zephyr/logging/log.h>
#include <zephyr/xen/dom0/sysctl.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <xen_dom_mgmt.h>
#ifdef CONFIG_XEN_CONSOLE_SRV
#include <xen_console.h>
#endif

LOG_MODULE_REGISTER(xen_shell);
static struct xen_domctl_getdomaininfo infos[CONFIG_DOMU_MAX];

static struct xen_domain_cfg domcfg_tmp;

#if defined(CONFIG_XEN_DOMCFG_READ_PDT)

static uint8_t pfdt_read_buf[CONFIG_PARTIAL_DEVICE_TREE_SIZE] __aligned(8);

static int xen_cmd_read_pfdt(struct xen_domain_cfg *domcfg)
{
	size_t pfdt_size;
	int ret;

	if (domcfg->dtb_start && domcfg->dtb_end) {
		return 0;
	}

	if (!domcfg->image_dt_get_size && !domcfg->image_dt_read) {
		LOG_DBG("PDT read callback not provided");
		return 0;
	}

	LOG_INF("PDT not provided, attempt to read from storage");

	ret = domcfg->image_dt_get_size(domcfg->image_info, &pfdt_size);
	if (ret) {
		LOG_ERR("PDT get size failed (%d)", ret);
		return ret;
	}

	if (!pfdt_size) {
		LOG_ERR("wrong PDT size");
		return -ENOEXEC;
	}

	if (pfdt_size > sizeof(pfdt_read_buf)) {
		LOG_ERR("PDT size is too big %zd", pfdt_size);
		return -EFBIG;
	}

	ret = domcfg->image_dt_read(pfdt_read_buf, pfdt_size, 0, domcfg->image_info);
	if (ret) {
		LOG_ERR("PDT read failed (%d)", ret);
		return ret;
	}

	LOG_DBG("PDT read magic:%08x", *(uint32_t *)pfdt_read_buf);

	domcfg->dtb_start = pfdt_read_buf;
	domcfg->dtb_end = pfdt_read_buf + pfdt_size;

	return 0;
}
#endif /* CONFIG_XEN_DOMCFG_READ_PDT */

uint32_t parse_domid(size_t argc, char **argv)
{
	/* first would be the cmd name, start from second */
	int i;

	for (i = 0; i < argc - 1; i++) {
		if (argv[i][0] == '-' && argv[i][1] == 'd') {
			/* Take next value after "-d" option */
			i++;
			return atoi(argv[i]);
		}
	}

	/* Use zero as invalid value */
	return 0;
}

void parse_and_fill_flags(size_t argc, char **argv, struct xen_domain_cfg *cfg)
{
	int i;

	for (i = 0; i < argc; i++) {
		/* check if domain should remain paused after creation */
		if (argv[i][0] == '-' && argv[i][1] == 'p') {
			cfg->f_paused = 1;
		}
	}
}

static bool is_all_numbers(char *str)
{
	int i;

	for (i = 0; str[i] != '\0'; i++) {
		if (!isdigit(str[i])) {
			return false;
		}
	}

	return true;
}

static uint32_t parse_domid_or_name(char *arg)
{
	if (is_all_numbers(arg)) {
		return atoi(arg);
	}

	return find_domain_by_name(arg);
}

static int domu_create(const struct shell *shell, int argc, char **argv)
{
	int ret;
	uint32_t domid;
	char *name;
	struct xen_domain_cfg *cfg;

	if (argc < 2)
		return -EINVAL;

	domid = parse_domid(argc, argv);

	name = argv[1];
	if (!name) {
		shell_error(shell, "Invalid config passed to create cmd");
		return -EINVAL;
	}

	cfg = domain_find_config(name);
	if (!cfg) {
		shell_error(shell, "Config %s not found", name);
		return -EINVAL;
	}
	/* Made a copy of domain cfg to avoid modification of original cfg by below code */
	domcfg_tmp = *cfg;

	parse_and_fill_flags(argc, argv, &domcfg_tmp);

#if defined(CONFIG_XEN_DOMCFG_READ_PDT)
	ret = xen_cmd_read_pfdt(&domcfg_tmp);
	if (ret) {
		return ret;
	}
#endif /* CONFIG_XEN_DOMCFG_READ_PDT */

	ret = domain_create(&domcfg_tmp, domid);
	if (ret < 0) {
		return ret; /* domain_create should care about error logs */
	}

	domid = ret;
	ret = domain_post_create(&domcfg_tmp, domid);
	if (ret) {
		return ret;
	}

	shell_info(shell, "domain:%u created", domid);
	return 0;
}

int domu_destroy(const struct shell *shell, size_t argc, char **argv)
{
	int ret;
	uint32_t domid = 0;

	if (argc != 2)
		return -EINVAL;

	domid = parse_domid_or_name(argv[1]);
	if (!domid) {
		shell_error(shell, "Invalid domid passed to destroy cmd\n");
		return -EINVAL;
	}

	ret = domain_destroy(domid);
	if (ret) {
		return ret;
	}

	shell_info(shell, "domain:%u destroyed", domid);
	return 0;
}

#ifdef CONFIG_XEN_CONSOLE_SRV
int domu_console_attach(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t domid = 0;
	struct xen_domain *domain;

	if (argc != 2)
		return -EINVAL;

	domid = parse_domid_or_name(argv[1]);
	if (!domid) {
		shell_error(shell, "Invalid domid passed to create cmd\n");
		return -EINVAL;
	}

	domain = get_domain(domid);
	if (!domain) {
		shell_error(shell, "domid#%u is not found", domid);
		/* Domain with requested domid is not present in list */
		return -EINVAL;
	}

	return xen_attach_domain_console(shell, domain);
}
#endif

int domu_pause(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t domid = 0;
	int ret;

	if (argc != 2)
		return -EINVAL;

	domid = parse_domid_or_name(argv[1]);
	if (!domid) {
		shell_error(shell, "Invalid domid passed to destroy cmd\n");
		return -EINVAL;
	}

	ret = domain_pause(domid);
	if (ret) {
		return ret;
	}

	shell_info(shell, "domain:%u paused", domid);
	return 0;
}

int domu_unpause(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t domid = 0;
	int ret;

	if (argc != 2)
		return -EINVAL;

	domid = parse_domid_or_name(argv[1]);
	if (!domid) {
		shell_error(shell, "Invalid domid passed to unpause cmd\n");
		return -EINVAL;
	}

	ret = domain_unpause(domid);
	if (ret) {
		return ret;
	}

	shell_info(shell, "domain:%u unpaused", domid);
	return 0;
}

int xen_config_list(const struct shell *shell, size_t argc, char **argv)
{
	__maybe_unused struct xen_domain_cfg *cfg;
	int i;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	for (i = 0; i < domain_get_user_cfg_count(); i++) {
		cfg = domain_get_user_cfg(i);
		shell_print(shell, "%s", cfg->name);
	}

#ifdef CONFIG_XEN_DOMCFG_SECTION
	for (cfg = _domain_configs_start; cfg < _domain_configs_end; cfg++) {
		shell_print(shell, "%s", cfg->name);
	}
#endif

	return 0;
}
static int domain_list(const struct shell *shell, size_t argc, char **argv)
{
	int i, ret;
	char domname[CONTAINER_NAME_SIZE];
	unsigned long memkb;

	ARG_UNUSED(argc);
	ARG_UNUSED(argv);

	ret = xen_sysctl_getdomaininfo(infos, 0, CONFIG_DOMU_MAX);
	if (ret < 0) {
		goto out;
	}
	shell_fprintf(shell, SHELL_NORMAL,
			"Name                                        ID   Mem VCPUs\tState\tTime(s)\n");
	for (i = 0; i < ret; i++) {
		if (get_domain_name(infos[i].domain, domname, CONTAINER_NAME_SIZE)) {
			strncpy(domname, "(NULL)", CONTAINER_NAME_SIZE);
		}
		memkb = infos[i].tot_pages * XEN_PAGE_SIZE / 1024;
		shell_fprintf(shell, SHELL_NORMAL, "%-40s %5d %5lu %5d      %c%c%c%c%c  %8.1f\n",
					  domname,
					  infos[i].domain,
					  (unsigned long) (memkb / 1024),
					  infos[i].nr_online_vcpus,
					  infos[i].flags & XEN_DOMINF_running ? 'r' : '-',
					  infos[i].flags & XEN_DOMINF_blocked ? 'b' : '-',
					  infos[i].flags & XEN_DOMINF_paused ? 'p' : '-',
					  infos[i].flags & XEN_DOMINF_shutdown ? 's' : '-',
					  infos[i].flags & XEN_DOMINF_dying ? 'd' : '-',
					  ((double)infos[i].cpu_time / 1e9));
	}
out:
	return ret;
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	subcmd_xu,
	SHELL_CMD_ARG(create, NULL,
		      " Create Xen domain\n"
		      " Usage: create cfg_name [-d <domid>] [-p]\n",
		      domu_create, 2, 3),
	SHELL_CMD_ARG(destroy, NULL,
		      " Destroy Xen domain\n"
		      " Usage: destroy <domid|name>\n",
		      domu_destroy, 2, 0),
	SHELL_CMD_ARG(pause, NULL,
		      " Pause Xen domain\n"
		      " Usage: pause <domid|name>\n",
		      domu_pause, 2, 0),
	SHELL_CMD_ARG(unpause, NULL,
		      " Unpause Xen domain\n"
		      " Usage: unpause <domid|name>\n",
		      domu_unpause, 2, 0),
	SHELL_CMD_ARG(config_list, NULL,
		      " List available domain configurations\n",
		      xen_config_list, 1, 0),
#ifdef CONFIG_XEN_CONSOLE_SRV
	SHELL_CMD_ARG(console, NULL,
		      " Attach to a domain console.\n"
		      " Press CTRL+] to detach from console\n"
		      " Usage: console <domid|name>\n",
		      domu_console_attach, 2, 0),
#endif
	SHELL_CMD_ARG(list, NULL,
		      " List all Xen domains\n"
			  " Usage: list\n",
		      domain_list, 1, 0),
	SHELL_SUBCMD_SET_END);

SHELL_CMD_ARG_REGISTER(xu, &subcmd_xu, "Xenutils commands", NULL, 2, 0);
