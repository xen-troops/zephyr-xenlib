/* SPDX-License-Identifier: Apache-2.0
 *
 * Copyright (c) 2023 EPAM Systems
 */

#ifndef XENLIB_XEN_DOM_FDT_H
#define XENLIB_XEN_DOM_FDT_H

#include <domain.h>

#ifdef __cplusplus
extern "C" {
#endif

int gen_domain_fdt(struct xen_domain_cfg *domcfg, void **fdtaddr,
		size_t *fdtsize, int xen_major, int xen_minor, void *pfdt,
		size_t pfdt_size, int domid);

void free_domain_fdt(void *fdt);

#ifdef __cplusplus
}
#endif

#endif /* XENLIB_XEN_DOM_FDT_H */
