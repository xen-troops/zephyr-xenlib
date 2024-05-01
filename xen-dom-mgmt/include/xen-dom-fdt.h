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

/**
 * Generates the device tree blob (FDT) for a Xen domain.
 *
 * @param domcfg The domain configuration.
 * @param fdtaddr Pointer to store the address of the generated FDT.
 * @param fdtsize Pointer to store the size of the generated FDT.
 * @param xen_major The major version of Xen.
 * @param xen_minor The minor version of Xen.
 * @param pfdt Pointer to a partial FDT
 * @param pfdt_size The size of the partial FDT
 * @param domid The domain ID.
 * @return Returns 0 on success, or a negative error code on failure.
 */
int gen_domain_fdt(struct xen_domain_cfg *domcfg, void **fdtaddr,
		size_t *fdtsize, int xen_major, int xen_minor, void *pfdt,
		size_t pfdt_size, int domid);

/**
 * Frees the memory allocated for a device tree blob (FDT).
 *
 * @param fdt Pointer to the FDT to be freed.
 */
void free_domain_fdt(void *fdt);

#ifdef __cplusplus
}
#endif

#endif /* XENLIB_XEN_DOM_FDT_H */
