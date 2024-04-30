/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef XENLIB_XEN_DOM_MGMT_H
#define XENLIB_XEN_DOM_MGMT_H

#include <domain.h>

#ifdef __cplusplus
extern "C" {
#endif


/**
 * Creates a new domain with the specified configuration.
 *
 * @param domcfg The configuration for the new domain.
 * @param domid The ID of the new domain.
 * @return 0 on success, or an error code on failure.
 */
int domain_create(struct xen_domain_cfg *domcfg, uint32_t domid);

/**
 * Destroys the specified domain.
 *
 * @param domid The ID of the domain to destroy.
 * @return 0 on success, or an error code on failure.
 */
int domain_destroy(uint32_t domid);

/**
 * Pauses the specified domain.
 *
 * @param domid The ID of the domain to pause.
 * @return 0 on success, or an error code on failure.
 */
int domain_pause(uint32_t domid);

/**
 * Unpauses the specified domain.
 *
 * @param domid The ID of the domain to unpause.
 * @return 0 on success, or an error code on failure.
 */
int domain_unpause(uint32_t domid);

/**
 * Performs post-creation operations for the specified domain.
 *
 * @param domcfg The configuration for the domain.
 * @param domid The ID of the domain.
 * @return 0 on success, or an error code on failure.
 */
int domain_post_create(const struct xen_domain_cfg *domcfg, uint32_t domid);

#ifdef __cplusplus
}
#endif

#endif
