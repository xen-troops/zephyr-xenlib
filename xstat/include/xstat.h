/*
 * Copyright (c) 2023 EPAM Systems
 *
 * work based on the libxenstat library from xen-tools
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef _XSTAT_H
#define _XSTAT_H

#include <zephyr/xen/public/version.h>
#include <zephyr/xen/public/domctl.h>
#include <zephyr/xen/public/sched.h>
#include <zephyr/xen/generic.h>
#include <domain.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SHORT_ASC_LEN 5                 /* length of 65535 */
#define VERSION_SIZE (2 * SHORT_ASC_LEN + 1 + XEN_EXTRAVERSION_LEN + 1)

struct xenstat_vcpu {
	bool online;
	unsigned long long cpu_time;
};

struct xenstat_domain {
	unsigned short id;
	char name[CONTAINER_NAME_SIZE];
	/* XEN_DOMCTL_* flags are defined in include/zephyr/xen/public/domctl.h */
	unsigned int state;
	unsigned long long cpu_ns;
	unsigned int num_vcpus;		/* No. vcpus configured for domain */
	unsigned long long cur_mem;	/* Current memory reservation */
	unsigned long long max_mem;	/* Total memory allowed */
	unsigned int ssid;
};

struct xenstat {
	unsigned int num_cpus;
	unsigned long long cpu_hz;
	unsigned long long tot_mem;
	unsigned long long free_mem;
	char xen_version[VERSION_SIZE];	/* xen version running on this node */
};

/**
 * Retrieves the Xen statistics for the specified domain.
 *
 * @param stat The pointer to the struct where the Xen statistics will be stored.
 * @return 0 on success, or a negative error code on failure.
 */
int xstat_getstat(struct xenstat *stat);

/**
 * Retrieves information about the specified domains.
 *
 * @param info The pointer to the struct where the domain information will be stored.
 * @param first The ID of the first domain to retrieve information for.
 * @param num The maximum number of domains to retrieve information for.
 * @return 0 on success, or a negative error code on failure.
 */
int xstat_getdominfo(struct xenstat_domain *info, uint16_t first, uint16_t num);

/**
 * Retrieves information about the specified VCPU of a domain.
 *
 * @param info The pointer to the struct where the VCPU information will be stored.
 * @param dom The ID of the domain.
 * @param vcpu The ID of the VCPU.
 * @return 0 on success, or a negative error code on failure.
 */
int xstat_getvcpu(struct xenstat_vcpu *info, uint16_t dom, uint16_t vcpu);

#ifdef __cplusplus
}
#endif

#endif
