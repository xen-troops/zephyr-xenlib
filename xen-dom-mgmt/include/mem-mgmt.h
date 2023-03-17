/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2023 EPAM Systems
 */

#ifndef XENLIB_XEN_MEM_MGMT_H
#define XENLIB_XEN_MEM_MGMT_H

#include <domain.h>

#define LPAE_SHIFT (9)
#define PFN_4K_SHIFT (0)
#define PFN_2M_SHIFT (PFN_4K_SHIFT + LPAE_SHIFT)
#define PFN_1G_SHIFT (PFN_2M_SHIFT + LPAE_SHIFT)

#define PFN_4K_SIZE (4096)
#define PFN_2M_SIZE (PFN_4K_SIZE << LPAE_SHIFT)
#define PFN_1G_SIZE (PFN_2M_SIZE << LPAE_SHIFT)

/*
 * Allocates memory in Dom0 and maps guest memory to this region.
 * In case of any error, the function will try to restore
 * memory and return error code.
 *
 * @param domid - domain ID which memory will be mapped
 * @param nr_pages - number of pages with XEN_PAGE_SIZE that will be mapped
 * @param base_pfn - PFN from which memory will be mapped
 * @param mapped_addr - result pointer for pointer with mapped memory
 *
 * @return - zero on success, negative errno on failure
 */
int xenmem_map_region(int domid, uint64_t nr_pages,
		      xen_pfn_t base_pfn, void **mapped_addr);

/*
 * Unmaps previously mapped quest memory by xenmem_map_region from Dom0.
 *
 * @param nr_pages - number of pages with XEN_PAGE_SIZE that will be unmapped
 * @param mapped_addr - pointer to memory which will be unmapped
 *
 * @return - zero on success, negative errno on failure
 */
int xenmem_unmap_region(uint64_t nr_pages, void *mapped_addr);

/*
 * Flushes PFNs mapped to Dom0
 *
 * @param nr_pages - number of pages with XEN_PAGE_SIZE for which
 * cache will be flushed
 * @param base_pfn - PFN from which cache will be flushed
 *
 * @return - zero on success, negative errno on failure
 */
int xenmem_cacheflush_mapped_pfns(uint64_t nr_pages, uint64_t base_pfn);

/*
 * Helper function to populate PFNs for given @domid.
 * Unlike standard xendom_populate_physmap this function
 * doesn't require passing array as one of the parameters,
 * so it helps to avoid using VLA or dynamic memory.
 *
 * @param domid - domain ID for which memory should be populated
 * @param base_pfn - PFN from which memory will be populated
 * @param pfn_shift - the order of PFNs that will be populated.
 * Acceptable values are: @PFN_4K_SHIFT, @PFN_2M_SHIFT or @PFN_1G_SHIFT
 * @nr_pages - number of pages with XEN_PAGE_SIZE that will be populated
 *
 * @return - number of pages that were successfully populated
 */
uint64_t xenmem_populate_physmap(int domid,
				 uint64_t base_pfn,
				 uint64_t pfn_shift,
				 uint64_t nr_pages);

#endif
