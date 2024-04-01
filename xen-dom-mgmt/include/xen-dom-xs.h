/* SPDX-License-Identifier: Apache-2.0 */

/*
 * Copyright (c) 2024 EPAM Systems
 *
 */

#ifndef XENLIB_XEN_DOM_XS_H
#define XENLIB_XEN_DOM_XS_H

void xs_deinitialize_domain_xenstore(uint32_t domid);
int xs_add_pvblock_xenstore(const struct pv_block_configuration *cfg, int domid);
int xs_remove_xenstore_backends(int domid);
int xs_add_pvnet_xenstore(const struct pv_net_configuration *cfg, int domid, int instance_id);
int xs_initialize_xenstore(uint32_t domid, const struct xen_domain *domain);

#endif /* XENLIB_XEN_DOM_XS_H */
