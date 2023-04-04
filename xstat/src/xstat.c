#include <string.h>
#include <stdio.h>
#include <zephyr/shell/shell.h>
#include <zephyr/arch/arm64/hypercall.h>
#include <zephyr/xen/public/version.h>
#include <zephyr/xen/public/sysctl.h>
#include <zephyr/xen/public/sched.h>
#include <xstat.h>
#include <xss.h>

int xstat_dominfo(const struct shell *shell)
{
	return 0;
}

int xstat_sysctl(const struct shell *shell)
{
	return 0;
}

int xenstat_collect_vbds(xenstat_node * node)
{
	return 1;
}

int xenstat_collect_networks(xenstat_node * node)
{
	return 1;
}

static int xenstat_get_domain_name(unsigned int domain_id, char *name, int len)
{
	char path[80];

	snprintf(path, sizeof(path),"/local/domain/%i/name", domain_id);
	return xss_read(path, name, len);
}

/* Get domain states */
unsigned int xenstat_domain_dying(xenstat_domain * domain)
{
	return (domain->state & XEN_DOMINF_dying) == XEN_DOMINF_dying;
}

unsigned int xenstat_domain_crashed(xenstat_domain * domain)
{
	return ((domain->state & XEN_DOMINF_shutdown) == XEN_DOMINF_shutdown)
	    && (((domain->state >> XEN_DOMINF_shutdownshift)
		 & XEN_DOMINF_shutdownmask) == SHUTDOWN_crash);
}

unsigned int xenstat_domain_shutdown(xenstat_domain * domain)
{
	return ((domain->state & XEN_DOMINF_shutdown) == XEN_DOMINF_shutdown)
	    && (((domain->state >> XEN_DOMINF_shutdownshift)
		 & XEN_DOMINF_shutdownmask) != SHUTDOWN_crash);
}

unsigned int xenstat_domain_paused(xenstat_domain * domain)
{
	return (domain->state & XEN_DOMINF_paused) == XEN_DOMINF_paused;
}

unsigned int xenstat_domain_blocked(xenstat_domain * domain)
{
	return (domain->state & XEN_DOMINF_blocked) == XEN_DOMINF_blocked;
}

unsigned int xenstat_domain_running(xenstat_domain * domain)
{
	return (domain->state & XEN_DOMINF_running) == XEN_DOMINF_running;
}

int xstat_getnode(xenstat_node *node, int first, int num)
{
	struct xen_sysctl sysctl;
	xenstat_domain *domain;
	struct xen_domctl_getdomaininfo *domaininfo;
	struct xen_domctl_getdomaininfo infos[MAX_DOMAINS]; 
	int i, ret;
	char extra[XEN_EXTRAVERSION_LEN];
	int major, minor;

	ret = HYPERVISOR_xen_version(XENVER_version, NULL);
	if (ret < 0)
		return ret;
	major = ret >> 16;
	minor = ret & 0xffff;
	memset(extra, 0, sizeof(extra));
	ret = HYPERVISOR_xen_version(XENVER_extraversion, extra);
	if (ret < 0) {
		return ret;
	}
	sprintf(node->xen_version, "%d.%d%s", major, minor, extra);

	memset(&sysctl, 0, sizeof(sysctl));
	sysctl.cmd = XEN_SYSCTL_physinfo;
	sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
	ret = HYPERVISOR_sysctl(&sysctl);
	if (ret < 0)
	{
		return ret;
	}
	node->cpu_hz = ((unsigned long long)sysctl.u.physinfo.cpu_khz) * 1000ULL;
	node->num_cpus = sysctl.u.physinfo.nr_cpus;
	node->page_size = CONFIG_MMU_PAGE_SIZE;
	node->tot_mem = ((unsigned long long)sysctl.u.physinfo.total_pages) * node->page_size;
	node->free_mem = ((unsigned long long)sysctl.u.physinfo.free_pages) * node->page_size;


	memset(&sysctl, 0, sizeof(sysctl));
	sysctl.cmd = XEN_SYSCTL_getdomaininfolist;
	sysctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
	sysctl.u.getdomaininfolist.first_domain = first;
	sysctl.u.getdomaininfolist.max_domains  = num;
	sysctl.u.getdomaininfolist.buffer.p  = infos;
	ret = HYPERVISOR_sysctl(&sysctl);
	if (ret < 0)
	{
		return ret;
	}
	domain = node->domains;
	domaininfo = sysctl.u.getdomaininfolist.buffer.p;
	i = sysctl.u.getdomaininfolist.num_domains;
	node->num_domains = sysctl.u.getdomaininfolist.num_domains;
	ret = 0;
	while (i > 0)
	{
		uint16_t vcpu;
		struct xen_domctl domctl;

		domain->id = domaininfo->domain;
		memset(domain->name, 0, MAX_DOMAIN_NAME);
		ret = xenstat_get_domain_name(domaininfo->domain, domain->name, MAX_DOMAIN_NAME);
		if (ret < 0)
			printk("Domain name error %d", ret);
		printk("Domain: %d name %s\n", domain->id, domain->name);
		domain->state = domaininfo->flags;
		domain->cpu_ns = domaininfo->cpu_time;
		domain->num_vcpus = (domaininfo->max_vcpu_id+1);
		domain->cur_mem = ((unsigned long long)domaininfo->tot_pages) * node->page_size;
		domain->max_mem = domaininfo->max_pages == UINT_MAX
			? (unsigned long long)-1
			: (unsigned long long)(domaininfo->max_pages * node->page_size);
		domain->ssid = domaininfo->ssidref;
		domain->num_networks = 0;
		domain->networks = NULL;
		domain->num_vbds = 0;
		domain->vbds = NULL;
		memset(&domain->vcpus, 0, sizeof(domain->vcpus));
		for (vcpu = 0; vcpu < domain->num_vcpus; vcpu++)
		{
			domctl.cmd = XEN_DOMCTL_getvcpuinfo;
			domctl.interface_version = XEN_SYSCTL_INTERFACE_VERSION;
			domctl.domain = domain->id;
			domctl.u.getvcpuinfo.vcpu  = vcpu;
			ret = HYPERVISOR_domctl(&domctl);
			if (ret < 0)
			{
				printk("domctl for domain %d vcpu %d error %d\n", domain->id, vcpu, ret);
				break;
			}
		}
		domain++;
		domaininfo++;
		i--;
	}
	return ret;
}

int xstat_version(const struct shell *shell)
{
	int ret;
	char extra[XEN_EXTRAVERSION_LEN];
	int major, minor;
	/*
#define XENVER_version      0

#define XENVER_extraversion 1
typedef char xen_extraversion_t[16];
#define XEN_EXTRAVERSION_LEN (sizeof(xen_extraversion_t))
	 */
	ret = HYPERVISOR_xen_version(XENVER_version, NULL);
	if (ret < 0)
		return ret;
	major = ret >> 16;
	minor = ret & 0xffff;
	memset(extra, 0, sizeof(extra));
	ret = HYPERVISOR_xen_version(XENVER_extraversion, extra);
	if (ret < 0) {
		shell_error(shell, "extravesion error %d", ret);
	}

	shell_print(shell, "Version: %d.%d%s", major, minor, extra);
	return ret;
}
