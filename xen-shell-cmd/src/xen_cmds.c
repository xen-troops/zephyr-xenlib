/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/shell/shell.h>
#include <zephyr/logging/log.h>
#include <stdlib.h>
#include <string.h>

#include <xen_dom_mgmt.h>
#ifdef CONFIG_XEN_CONSOLE_SRV
#include <xen_console.h>
#endif

LOG_MODULE_REGISTER(xen_shell);

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

	ret = domain_create(cfg, domid);
	if (ret) {
		return ret; /* domain_create should care about error logs */
	}

	return domain_post_create(cfg, domid);
}

int domu_destroy(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t domid = 0;

	if (argc != 2)
		return -EINVAL;

	domid = atoi(argv[1]);
	if (!domid) {
		shell_error(shell, "Invalid domid passed to destroy cmd\n");
		return -EINVAL;
	}

	return domain_destroy(domid);
}

#ifdef CONFIG_XEN_CONSOLE_SRV
int domu_console_attach(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t domid = 0;
	struct xen_domain *domain;

	if (argc != 2)
		return -EINVAL;

	domid = atoi(argv[1]);
	if (!domid) {
		shell_error(shell, "Invalid domid passed to create cmd\n");
		return -EINVAL;
	}

	domain = domid_to_domain(domid);
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

	if (argc != 2)
		return -EINVAL;

	domid = atoi(argv[1]);
	if (!domid) {
		shell_error(shell, "Invalid domid passed to destroy cmd\n");
		return -EINVAL;
	}

	return domain_pause(domid);
}

int domu_unpause(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t domid = 0;

	if (argc != 2)
		return -EINVAL;

	domid = atoi(argv[1]);
	if (!domid) {
		shell_error(shell, "Invalid domid passed to unpause cmd\n");
		return -EINVAL;
	}

	return domain_unpause(domid);
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	subcmd_xu,
	SHELL_CMD_ARG(create, NULL,
		      " Create Xen domain\n"
		      " Usage: create cfg_name [-d <domid>]\n",
		      domu_create, 2, 2),
	SHELL_CMD_ARG(destroy, NULL,
		      " Destroy Xen domain\n"
		      " Usage: destroy <domid>\n",
		      domu_destroy, 2, 0),
	SHELL_CMD_ARG(pause, NULL,
		      " Pause Xen domain\n"
		      " Usage: pause <domid>\n",
		      domu_pause, 2, 0),
	SHELL_CMD_ARG(unpause, NULL,
		      " Unpause Xen domain\n"
		      " Usage: unpause <domid>\n",
		      domu_unpause, 2, 0),
#ifdef CONFIG_XEN_CONSOLE_SRV
	SHELL_CMD_ARG(console, NULL,
		      " Attach to a domain console.\n"
		      " Press CTRL+] to detach from console\n"
		      " Usage: console <domid>\n",
		      domu_console_attach, 2, 0),
#endif
	SHELL_SUBCMD_SET_END);

SHELL_CMD_ARG_REGISTER(xu, &subcmd_xu, "Xenutils commands", NULL, 2, 0);
