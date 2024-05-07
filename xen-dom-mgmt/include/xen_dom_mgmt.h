/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */
/**
 * @file xen_dom_mgmt.h
 */
#ifndef XENLIB_XEN_DOM_MGMT_H
#define XENLIB_XEN_DOM_MGMT_H

/**
 * @brief Xen domain control Interface
 * @defgroup xen_domctrl Xen domain control Interface
 * @{
 */
#include <domain.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Creates a new domain with the specified configuration.
 *
 * @param domcfg The configuration for the new domain.
 * @param domid The ID of the new domain.
 * @return domid on success, or a negative error code on failure.
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

/**
 * Find the configuration for a Xen domain by name.
 *
 * @param name The name of the Xen domain to search for.
 * @return A pointer to the Xen domain configuration if found, NULL otherwise.
 */
struct xen_domain_cfg *domain_find_config(const char *name);

/**
 * This function returns the count of user configurations for a domain.
 *
 * The function is defined as weak, so it can be overridden by the user.
 * @return The count of user configurations.
 */
int domain_get_user_cfg_count(void);

/**
 * This function returns the user configuration for a domain specified by the given index.
 *
 * The function is defined as weak, so it can be overridden by the user.
 * @param id The ID of the domain.
 * @return The user configuration for the domain, or NULL if not found.
 */
struct xen_domain_cfg *domain_get_user_cfg(int index);

/**
 * This function fetches the domain name by domain ID.
 *
 * @param domain_id The ID of the domain.
 * @param name The buffer to store the domain name.
 * @param len The length of the buffer.
 * @return 0 on success, or an error code on failure.
 */
int get_domain_name(unsigned short domain_id, char *name, int len);

#ifdef CONFIG_XEN_DOMCFG_SECTION
#define DECL_CONFIG static __section(".domain_configs") __used
extern struct xen_domain_cfg _domain_configs_start[];
extern struct xen_domain_cfg _domain_configs_end[];
#else
#define DECL_CONFIG
#endif

#ifdef __cplusplus
}
#endif

/**
 * @}
 */

#endif
