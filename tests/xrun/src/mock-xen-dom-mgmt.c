/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <domain.h>
#include <string.h>

#include <zephyr/tc_util.h>
#include <zephyr/ztest.h>

#include <xen_dom_mgmt.h>
extern struct xen_domain_cfg g_cfg;

int domain_create(struct xen_domain_cfg *domcfg, uint32_t domid)
{
	memcpy(&g_cfg, domcfg, sizeof(*domcfg));
	return 0;
}

int domain_destroy(uint32_t domid)
{
	return 0;
}

int domain_pause(uint32_t domid)
{
	return 0;
}

int domain_unpause(uint32_t domid)
{
	return 0;
}
