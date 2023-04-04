#ifndef _XSTAT_H
#define _XSTAT_H

#include <zephyr/shell/shell.h>
#include <zephyr/xen/public/version.h>

#define SHORT_ASC_LEN 5                 /* length of 65535 */
#define VERSION_SIZE (2 * SHORT_ASC_LEN + 1 + sizeof(xen_extraversion_t) + 1)

#define MAX_DOMAINS 5
#define MAX_VCPUS 8
#define MAX_DOMAIN_NAME 20
/* Opaque handles */
typedef struct xenstat_handle xenstat_handle;
typedef struct xenstat_domain xenstat_domain;
typedef struct xenstat_node xenstat_node;
typedef struct xenstat_vcpu xenstat_vcpu;
typedef struct xenstat_network xenstat_network;
typedef struct xenstat_vbd xenstat_vbd;

struct xenstat_vcpu {
	unsigned int online;
	unsigned long long ns;
};

struct xenstat_domain {
	unsigned int id;
	char name[MAX_DOMAIN_NAME];
	unsigned int state;
	unsigned long long cpu_ns;
	unsigned int num_vcpus;			/* No. vcpus configured for domain */
	xenstat_vcpu vcpus[MAX_VCPUS];		/* Array of length num_vcpus */
	unsigned long long cur_mem;		/* Current memory reservation */
	unsigned long long max_mem;		/* Total memory allowed */
	unsigned int ssid;
	unsigned int num_networks;
	xenstat_network *networks;		/* Array of length num_networks */
	unsigned int num_vbds;
	xenstat_vbd *vbds;
};

struct xenstat_network {
	unsigned int id;
	/* Received */
	unsigned long long rbytes;
	unsigned long long rpackets;
	unsigned long long rerrs;
	unsigned long long rdrop;
	/* Transmitted */
	unsigned long long tbytes;
	unsigned long long tpackets;
	unsigned long long terrs;
	unsigned long long tdrop;
};

struct xenstat_vbd {
	unsigned int back_type;
	unsigned int dev;
	unsigned int error;
	unsigned long long oo_reqs;
	unsigned long long rd_reqs;
	unsigned long long wr_reqs;
	unsigned long long rd_sects;
	unsigned long long wr_sects;
};

struct xenstat_node {
	xenstat_handle *handle;
	unsigned int num_cpus;
	unsigned long long cpu_hz;
	unsigned long long tot_mem;
	unsigned long long free_mem;
	unsigned int num_domains;
	xenstat_domain domains[MAX_DOMAINS];	/* Array of length num_domains */
	int page_size;
	char xen_version[VERSION_SIZE];		/* xen version running on this node */
};

#define XENSTAT_VCPU 0x1                                                                                                                                                                               
#define XENSTAT_NETWORK 0x2
#define XENSTAT_XEN_VERSION 0x4
#define XENSTAT_VBD 0x8
#define XENSTAT_ALL (XENSTAT_VCPU|XENSTAT_NETWORK|XENSTAT_XEN_VERSION|XENSTAT_VBD)

/* Get domain states */
unsigned int xenstat_domain_dying(xenstat_domain * domain);
unsigned int xenstat_domain_crashed(xenstat_domain * domain);
unsigned int xenstat_domain_shutdown(xenstat_domain * domain);
unsigned int xenstat_domain_paused(xenstat_domain * domain);
unsigned int xenstat_domain_blocked(xenstat_domain * domain);
unsigned int xenstat_domain_running(xenstat_domain * domain);

int xstat_sysctl(const struct shell *shell);
int xstat_version(const struct shell *shell);
int xstat_getnode(xenstat_node *node, int first, int num);
int xstat_dominfo(const struct shell *shell);

#endif
