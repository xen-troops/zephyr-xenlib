/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/shell/shell.h>
#include <zephyr/logging/log.h>
#include <stdlib.h>

#include <xen_dom_mgmt.h>
#ifdef CONFIG_XEN_CONSOLE_SRV
#include <xen_console.h>
#endif

LOG_MODULE_REGISTER(xen_shell);

extern struct xen_domain_cfg domd_cfg;

uint32_t parse_domid(size_t argc, char **argv)
{
	/* first would be the cmd name, start from second */
	int pos = 1;

	if (argv[pos][0] == '-' && argv[pos][1] == 'd') {
		/* Take next value after "-d" option */
		pos++;
		return atoi(argv[pos]);
	}

	/* Use zero as invalid value */
	return 0;
}

static int domu_create(const struct shell *shell, int argc, char **argv)
{
	int ret;
	uint32_t domid;

	if (argc != 3)
		return -EINVAL;

	domid = parse_domid(argc, argv);
	if (!domid) {
		LOG_ERR("Invalid domid passed to create cmd");
		return -EINVAL;
	}
	/*
	 * TODO: this should be changed in app code.
	 * Not all domains using domd config
	 */
	ret = domain_create(&domd_cfg, domid);
	if (ret) {
		return ret; /* domain_create should care about error logs */
	}

	return domain_post_create(&domd_cfg, domid);
}

int domu_destroy(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t domid = 0;

	if (argc != 3)
		return -EINVAL;

	domid = parse_domid(argc, argv);
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

	if (argc != 3)
		return -EINVAL;

	domid = parse_domid(argc, argv);
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

	if (argc != 3)
		return -EINVAL;

	domid = parse_domid(argc, argv);
	if (!domid) {
		shell_error(shell, "Invalid domid passed to destroy cmd\n");
		return -EINVAL;
	}

	return domain_pause(domid);
}

int domu_unpause(const struct shell *shell, size_t argc, char **argv)
{
	uint32_t domid = 0;

	if (argc != 3)
		return -EINVAL;

	domid = parse_domid(argc, argv);
	if (!domid) {
		shell_error(shell, "Invalid domid passed to unpause cmd\n");
		return -EINVAL;
	}

	shell_print(shell, "domid=%d\n", domid);

	return domain_unpause(domid);
}

SHELL_STATIC_SUBCMD_SET_CREATE(
	subcmd_xu,
	SHELL_CMD_ARG(create, NULL,
		      " Create Xen domain\n"
		      " Usage: create -d <domid>\n",
		      domu_create, 3, 0),
	SHELL_CMD_ARG(destroy, NULL,
		      " Destroy Xen domain\n"
		      " Usage: destroy -d <domid>\n",
		      domu_destroy, 3, 0),
	SHELL_CMD_ARG(pause, NULL,
		      " Pause Xen domain\n"
		      " Usage: pause -d <domid>\n",
		      domu_pause, 3, 0),
	SHELL_CMD_ARG(unpause, NULL,
		      " Unpause Xen domain\n"
		      " Usage: unpause -d <domid>\n",
		      domu_unpause, 3, 0),
#ifdef CONFIG_XEN_CONSOLE_SRV
	SHELL_CMD_ARG(console_attach, NULL,
		      " Attach to a domain console.\n"
		      " Press CTRL+] to detach from console\n"
		      " Usage: console_attach -d <domid>\n",
		      domu_console_attach, 3, 0),
#endif
	SHELL_SUBCMD_SET_END);

SHELL_CMD_ARG_REGISTER(xu, &subcmd_xu, "Xenutils commands", NULL, 2, 0);
