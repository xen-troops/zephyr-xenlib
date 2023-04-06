/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <string.h>
#include <stdio.h>
#include <zephyr/shell/shell.h>
#include <zephyr/arch/arm64/hypercall.h>
#include <zephyr/xen/public/version.h>
#include <zephyr/xen/public/sysctl.h>
#include <zephyr/xen/public/sched.h>
#include <xstat.h>
#include <xss.h>

static int xenstat_get_domain_name(unsigned int domain_id, char *name, int len)
{
	char path[25];

	snprintf(path, sizeof(path), "/local/domain/%i/name", domain_id);
	return xss_read(path, name, len);
}

/* Get domain states */
unsigned int xenstat_domain_dying(struct xenstat_domain *domain)
{
	if (!domain) {
		return -EINVAL;
	}
	return (domain->state & XEN_DOMINF_dying) == XEN_DOMINF_dying;
}

unsigned int xenstat_domain_crashed(struct xenstat_domain *domain)
{
	if (!domain) {
		return -EINVAL;
	}
	return ((domain->state & XEN_DOMINF_shutdown) == XEN_DOMINF_shutdown)
	    && (((domain->state >> XEN_DOMINF_shutdownshift)
		 & XEN_DOMINF_shutdownmask) == SHUTDOWN_crash);
}

unsigned int xenstat_domain_shutdown(struct xenstat_domain *domain)
{
	if (!domain) {
		return -EINVAL;
	}
	return ((domain->state & XEN_DOMINF_shutdown) == XEN_DOMINF_shutdown)
	    && (((domain->state >> XEN_DOMINF_shutdownshift)
		 & XEN_DOMINF_shutdownmask) != SHUTDOWN_crash);
}

unsigned int xenstat_domain_paused(struct xenstat_domain *domain)
{
	if (!domain) {
		return -EINVAL;
	}
	return (domain->state & XEN_DOMINF_paused) == XEN_DOMINF_paused;
}

unsigned int xenstat_domain_blocked(struct xenstat_domain *domain)
{
	if (!domain) {
		return -EINVAL;
	}
	return (domain->state & XEN_DOMINF_blocked) == XEN_DOMINF_blocked;
}

unsigned int xenstat_domain_running(struct xenstat_domain *domain)
{
	if (!domain) {
		return -EINVAL;
	}
	return (domain->state & XEN_DOMINF_running) == XEN_DOMINF_running;
}

int xstat_getvcpu(struct xenstat_vcpu *info, int dom, int vcpu)
{
	struct xen_domctl domctl;
	int ret;

	if (!info) {
		return -EINVAL;
	}

	memset(&info, 0, sizeof(*info));
	domctl.cmd = XEN_DOMCTL_getvcpuinfo;
	domctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
	domctl.domain = dom;
	domctl.u.getvcpuinfo.vcpu  = vcpu;
	ret = HYPERVISOR_domctl(&domctl);
	if (ret < 0) {
		return ret;
	}
	info->online = domctl.u.getvcpuinfo.online;
	info->ns = domctl.u.getvcpuinfo.cpu_time;
	return 0;
}

int xstat_getdominfo(struct xenstat_domain *domains, int first, int num)
{
	struct xen_sysctl sysctl;
	struct xen_domctl_getdomaininfo *domaininfo;
	struct xen_domctl_getdomaininfo infos[CONFIG_DOM_MAX];
	int i, ret;

	if (!domains) {
		return -EINVAL;
	}

	if (num > CONFIG_DOM_MAX) {
		num = CONFIG_DOM_MAX;
	}

	memset(&sysctl, 0, sizeof(sysctl));
	sysctl.cmd = XEN_SYSCTL_getdomaininfolist;
	sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
	sysctl.u.getdomaininfolist.first_domain = first;
	sysctl.u.getdomaininfolist.max_domains  = num;
	sysctl.u.getdomaininfolist.buffer.p  = infos;
	ret = HYPERVISOR_sysctl(&sysctl);
	if (ret < 0) {
		return ret;
	}

	domaininfo = sysctl.u.getdomaininfolist.buffer.p;
	for (i = 0; i < sysctl.u.getdomaininfolist.num_domains; i++) {
		domains[i].id = domaininfo[i].domain;
		memset(domains[i].name, 0, CONFIG_MAX_DOM_NAME_SIZE);
		xenstat_get_domain_name(domaininfo[i].domain, domains[i].name,
				CONFIG_MAX_DOM_NAME_SIZE);
		domains[i].state = domaininfo[i].flags;
		domains[i].cpu_ns = domaininfo[i].cpu_time;
		domains[i].num_vcpus = (domaininfo[i].max_vcpu_id+1);
		domains[i].cur_mem = ((unsigned long long)domaininfo[i].tot_pages) *
				CONFIG_MMU_PAGE_SIZE;
		domains[i].max_mem = domaininfo->max_pages == UINT_MAX
			? (unsigned long long)-1
			: (unsigned long long)(domaininfo[i].max_pages * CONFIG_MMU_PAGE_SIZE);
		domains[i].ssid = domaininfo[i].ssidref;
	}
	return sysctl.u.getdomaininfolist.num_domains;
}

int xstat_getstat(struct xenstat *stat)
{
	struct xen_sysctl sysctl;
	int ret;
	char extra[XEN_EXTRAVERSION_LEN];
	uint16_t major, minor;

	if (!stat) {
		return -EINVAL;
	}

	ret = HYPERVISOR_xen_version(XENVER_version, NULL);
	if (ret < 0) {
		return ret;
	}

	major = ret >> 16;
	minor = ret & 0xffff;
	memset(extra, 0, sizeof(extra));
	ret = HYPERVISOR_xen_version(XENVER_extraversion, extra);
	if (ret < 0) {
		return ret;
	}

	snprintf(stat->xen_version, VERSION_SIZE, "%d.%d%s", major, minor, extra);

	memset(&sysctl, 0, sizeof(sysctl));
	sysctl.cmd = XEN_SYSCTL_physinfo;
	sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
	ret = HYPERVISOR_sysctl(&sysctl);
	if (ret < 0) {
		return ret;
	}

	stat->cpu_hz = (unsigned long long)sysctl.u.physinfo.cpu_khz * 1000ULL;
	stat->num_cpus = sysctl.u.physinfo.nr_cpus;
	stat->tot_mem = (unsigned long long)sysctl.u.physinfo.total_pages * CONFIG_MMU_PAGE_SIZE;
	stat->free_mem = (unsigned long long)sysctl.u.physinfo.free_pages * CONFIG_MMU_PAGE_SIZE;

	return ret;
}

