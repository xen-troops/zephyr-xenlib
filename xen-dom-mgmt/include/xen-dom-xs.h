/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Copyright (c) 2024 EPAM Systems
 *
 */

#ifndef XENLIB_XEN_DOM_XS_H
#define XENLIB_XEN_DOM_XS_H

/**
 * Deinitializes the XenStore for a specific domain.
 *
 * @param domid The ID of the domain.
 */
void xs_deinitialize_domain_xenstore(uint32_t domid);

/**
 * Adds a PV block backend to the XenStore for a specific domain.
 *
 * @param cfg The configuration of the PV block backend.
 * @param domid The ID of the domain.
 * @return 0 on success, negative error code on failure.
 */
int xs_add_pvblock_xenstore(const struct pv_block_configuration *cfg, int domid);

/**
 * Removes all XenStore backends for a specific domain.
 *
 * @param domain The Xen domain structure.
 * @return 0 on success, negative error code on failure.
 */
int xs_remove_xenstore_backends(struct xen_domain *domain);

/**
 * Adds a PV network backend to the XenStore for a specific domain.
 *
 * @param cfg The configuration of the PV network backend.
 * @param domid The ID of the domain.
 * @param instance_id The instance ID of the PV network backend.
 * @return 0 on success, negative error code on failure.
 */
int xs_add_pvnet_xenstore(const struct pv_net_configuration *cfg, int domid, int instance_id);

/**
 * Initializes the XenStore for a specific domain.
 *
 * @param domid The ID of the domain.
 * @param domain The Xen domain structure.
 * @return 0 on success, negative error code on failure.
 */
int xs_initialize_xenstore(uint32_t domid, const struct xen_domain *domain);

#endif /* XENLIB_XEN_DOM_XS_H */
