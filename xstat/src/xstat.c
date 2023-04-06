/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <string.h>
#include <stdio.h>
#include <zephyr/shell/shell.h>
#include <zephyr/arch/arm64/hypercall.h>
#include <zephyr/xen/dom0/version.h>
#include <zephyr/xen/dom0/domctl.h>
#include <zephyr/xen/dom0/sysctl.h>
#include <zephyr/xen/public/sched.h>
#include <xstat.h>

int xstat_getvcpu(struct xenstat_vcpu *info, uint16_t dom, uint16_t vcpu)
{
	struct xen_domctl_getvcpuinfo vcpuinfo;
	int ret;

	if (!info) {
		return -EINVAL;
	}

	memset(info, 0, sizeof(*info));
	ret = xen_domctl_getvcpu(dom, vcpu, &vcpuinfo);
	if (ret < 0) {
		return ret;
	}

	info->online = vcpuinfo.online;
	info->cpu_time = vcpuinfo.cpu_time;
	return 0;
}

int xstat_getdominfo(struct xenstat_domain *domains, uint16_t first, uint16_t num)
{
	struct xen_domctl_getdomaininfo *infos;
	int i, ret;

	if (!domains) {
		return -EINVAL;
	}

	if (num > CONFIG_DOM_MAX) {
		num = CONFIG_DOM_MAX;
	}

	infos = k_malloc(sizeof(*infos) * num);
	if (!infos) {
		ret = -ENOMEM;
		goto out;
	}
	ret = xen_sysctl_getdomaininfo(infos, first, num);
	if (ret < 0) {
		goto out_free;
	}

	for (i = 0; i < ret; i++) {
		domains[i].id = infos[i].domain;
		domains[i].state = infos[i].flags;
		domains[i].cpu_ns = infos[i].cpu_time;
		domains[i].num_vcpus = (infos[i].max_vcpu_id + 1);
		domains[i].cur_mem = infos[i].tot_pages * XEN_PAGE_SIZE;
		if (infos->max_pages == (unsigned long long)-1) {
			domains[i].max_mem = (unsigned long long)-1;
		} else {
			domains[i].max_mem = infos[i].max_pages * XEN_PAGE_SIZE;
		}
		domains[i].ssid = infos[i].ssidref;
	}
out_free:
	k_free(infos);
out:
	return ret;
}

int xstat_getstat(struct xenstat *stat)
{
	struct xen_sysctl_physinfo *info;
	int ret;
	char extra[XEN_EXTRAVERSION_LEN];
	uint16_t major, minor;

	if (!stat) {
		return -EINVAL;
	}

	ret = xen_version();
	if (ret < 0) {
		return ret;
	}

	major = ret >> 16;
	minor = ret & 0xffff;
	ret = xen_version_extraversion(extra, XEN_EXTRAVERSION_LEN);
	if (ret < 0) {
		return ret;
	}

	snprintf(stat->xen_version, VERSION_SIZE, "%d.%d%s",
		 major, minor, extra);
	info = k_malloc(sizeof(struct xen_sysctl_physinfo));
	if (!info) {
		ret = -ENOMEM;
		goto out;
	}
	ret = xen_sysctl_physinfo(info);
	if (ret < 0) {
		goto out_free;
	}

	stat->cpu_hz = (unsigned long long)info->cpu_khz * 1000;
	stat->num_cpus = info->nr_cpus;
	stat->tot_mem = (unsigned long long)info->total_pages * XEN_PAGE_SIZE;
	stat->free_mem = (unsigned long long)info->free_pages * XEN_PAGE_SIZE;

out_free:
	k_free(info);
out:
	return ret;
}

