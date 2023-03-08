/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2023 EPAM Systems
 */

#ifndef XENLIB_XEN_DOM_FDT_H
#define XENLIB_XEN_DOM_FDT_H

#include <domain.h>

int gen_domain_fdt(struct xen_domain_cfg *domcfg, void **fdtaddr,
		size_t *fdtsize, int xen_major, int xen_minor, void *pfdt,
		size_t pfdt_size, int domid);

#endif /* XENLIB_XEN_DOM_FDT_H */
