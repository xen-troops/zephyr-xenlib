/* libxenstat: statistics-collection library for Xen
 * Copyright (C) International Business Machines Corp., 2005
 * Authors: Josh Triplett <josh@kernel.org>
 *          Judy Fischbach <jfisch@cs.pdx.edu>
 *          David Hendricks <cro_marmot@comcast.net>
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 */

#ifndef _XSTAT_H
#define _XSTAT_H

#include <zephyr/shell/shell.h>
#include <zephyr/xen/public/version.h>
#include <domain.h>

#define SHORT_ASC_LEN 5                 /* length of 65535 */
#define VERSION_SIZE (2 * SHORT_ASC_LEN + 1 + sizeof(xen_extraversion_t) + 1)

/* Opaque handles */
struct xenstat_vcpu {
	unsigned int online;
	unsigned long long ns;
};

struct xenstat_domain {
	unsigned int id;
	char name[CONFIG_MAX_DOM_NAME_SIZE];
	unsigned int state;
	unsigned long long cpu_ns;
	unsigned int num_vcpus;			/* No. vcpus configured for domain */
	unsigned long long cur_mem;		/* Current memory reservation */
	unsigned long long max_mem;		/* Total memory allowed */
	unsigned int ssid;
	unsigned int num_networks;
	struct xenstat_network *networks;		/* Array of length num_networks */
	unsigned int num_vbds;
	struct xenstat_vbd *vbds;
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

struct xenstat {
	unsigned int num_cpus;
	unsigned long long cpu_hz;
	unsigned long long tot_mem;
	unsigned long long free_mem;
	char xen_version[VERSION_SIZE];		/* xen version running on this node */
};

#define XENSTAT_VCPU 0x1
#define XENSTAT_NETWORK 0x2
#define XENSTAT_XEN_VERSION 0x4
#define XENSTAT_VBD 0x8
#define XENSTAT_ALL (XENSTAT_VCPU|XENSTAT_NETWORK|XENSTAT_XEN_VERSION|XENSTAT_VBD)

/* Get domain states */
unsigned int xenstat_domain_dying(struct xenstat_domain *domain);
unsigned int xenstat_domain_crashed(struct xenstat_domain *domain);
unsigned int xenstat_domain_shutdown(struct xenstat_domain *domain);
unsigned int xenstat_domain_paused(struct xenstat_domain *domain);
unsigned int xenstat_domain_blocked(struct xenstat_domain *domain);
unsigned int xenstat_domain_running(struct xenstat_domain *domain);

int xstat_getstat(struct xenstat *stat);
int xstat_getdominfo(struct xenstat_domain *info, int first, int num);
int xstat_getvcpu(struct xenstat_vcpu *info, int dom, int vcpu);
#endif
