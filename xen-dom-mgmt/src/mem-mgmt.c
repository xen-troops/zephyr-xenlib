// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2023 EPAM Systems
 */

#include <zephyr/xen/dom0/domctl.h>
#include <zephyr/xen/memory.h>
#include <zephyr/logging/log.h>

#include <mem-mgmt.h>

LOG_MODULE_DECLARE(xen_dom_mgmt);
K_MUTEX_DEFINE(chunks_mutex);
static uint64_t gfns[CONFIG_PFN_CHUNK_SIZE];
static uint64_t pfns[CONFIG_PFN_CHUNK_SIZE];
static int err_codes[CONFIG_PFN_CHUNK_SIZE];

static uint64_t xendom_add_to_physmap_batch_by_chunks(int domid,
						      uint64_t base_pfn,
						      uint64_t base_gfn,
						      uint64_t nr_pages)
{
	int rc;
	uint64_t i = 0;
	int j, iter;

	k_mutex_lock(&chunks_mutex, K_FOREVER);
	while (i < nr_pages) {
		iter = MIN(nr_pages - i, CONFIG_PFN_CHUNK_SIZE);

		for (j = 0; j < iter; j++) {
			pfns[j] = base_pfn + j;
			gfns[j] = base_gfn + j;
		}

		rc = xendom_add_to_physmap_batch(DOMID_SELF, domid,
						 XENMAPSPACE_gmfn_foreign,
						 iter, gfns,
						 pfns, err_codes);
		if (rc < 0) {
			k_mutex_unlock(&chunks_mutex);
			LOG_ERR("Failed to add to physmap batch for domain#%u (rc=%d)",
				domid, rc);
			return i;
		}

		/* Check error codes for every page frame */
		for (j = 0; j < iter; j++) {
			if (err_codes[j]) {
				k_mutex_unlock(&chunks_mutex);
				/*
				 * Return the last successfully added
				 * PFN number.
				 */
				if (!i) {
					return 0;
				}
				return (i - 1);
			}
			i++;
		}
		base_pfn += iter;
		base_gfn += iter;
	}
	k_mutex_unlock(&chunks_mutex);

	return i;
}

uint64_t xenmem_populate_physmap(int domid,
				 uint64_t base_pfn,
				 uint64_t pfn_shift,
				 uint64_t nr_pages)
{
	uint64_t i = 0, j;
	unsigned int populate_iter;
	int ret;

	k_mutex_lock(&chunks_mutex, K_FOREVER);
	while (i < nr_pages) {
		populate_iter = MIN(nr_pages - i, CONFIG_PFN_CHUNK_SIZE);

		for (j = 0; j < populate_iter; j++) {
			pfns[j] = base_pfn + (j << pfn_shift);
		}

		ret = xendom_populate_physmap(domid, pfn_shift, populate_iter,
					      0, pfns);
		i += ret;
		if (ret != populate_iter) {
			k_mutex_unlock(&chunks_mutex);
			LOG_ERR("Failed to populate physmap (rc=%d)", ret);
			return i;
		}
		base_pfn += (populate_iter << pfn_shift);
	}
	k_mutex_unlock(&chunks_mutex);

	return i;
}

int xenmem_map_region(int domid, uint64_t nr_pages,
		      uint64_t base_gfn, void **mapped_addr)
{
	uint64_t nr_added_pfns, nr_pfn_removed, base_pfn, i, populated_pfns;
	int rc = -ENOMEM;

	if (!mapped_addr) {
		return -EINVAL;
	}

	*mapped_addr = k_aligned_alloc(XEN_PAGE_SIZE,
				       XEN_PAGE_SIZE * nr_pages);
	if (!*mapped_addr) {
		LOG_ERR("Failed to alloc memory for mapping");
		return -ENOMEM;
	}

	base_pfn = xen_virt_to_gfn(*mapped_addr);
	for (i = 0, nr_pfn_removed = 0; i < nr_pages; i++, nr_pfn_removed++) {
		rc = xendom_remove_from_physmap(DOMID_SELF, base_pfn + i);
		if (rc < 0) {
			LOG_ERR("Failed to remove PFN#%llu (0x%llx) from physmap (rc=%d)",
				i, base_pfn + i, rc);
			/*
			 * We failed at the first iteration,
			 * so just free memory
			 */
			if (!nr_pfn_removed)
				goto err_out;
			goto pfn_remove_err;
		}
	}

	nr_added_pfns = xendom_add_to_physmap_batch_by_chunks(domid,
							      base_pfn,
							      base_gfn,
							      nr_pages);
	if (nr_added_pfns != nr_pages) {
		goto gfn_add_err;
	}

	return 0;

gfn_add_err:
	for (i = 0; i < nr_added_pfns; i++) {
		rc = xendom_remove_from_physmap(DOMID_SELF, base_pfn + i);
		if (rc < 0) {
			LOG_ERR("Failed to remove PFN#%llu (0x%llx) from physmap while restoring Dom0 physmap (rc=%d)",
				i, base_pfn + i, rc);
			return rc;
		}
	}

pfn_remove_err:
	populated_pfns = xenmem_populate_physmap(DOMID_SELF, base_pfn,
						 PFN_4K_SHIFT, nr_pfn_removed);
	if (populated_pfns != nr_pfn_removed) {
		LOG_ERR("Failed to populate physmap while restoring Dom0 physmap (populated only %llu instead of %llu)",
			populated_pfns, nr_pfn_removed);
		return -EFAULT;
	}

err_out:
	k_free(*mapped_addr);

	return rc;
}

int xenmem_unmap_region(uint64_t nr_pages, void *mapped_addr)
{
	uint64_t base_pfn, populated_pfns, i;
	int rc;

	base_pfn = xen_virt_to_gfn(mapped_addr);
	/* Needed to remove mapped DomU pages from Dom0 physmap */
	for (i = 0; i < nr_pages; i++) {
		rc = xendom_remove_from_physmap(DOMID_SELF, base_pfn + i);
		if (rc < 0) {
			LOG_ERR("Failed to remove PFN#%llu (0x%llx) from physmap (rc=%d)",
				i, base_pfn + i, rc);
			return rc;
		}
	}

	populated_pfns = xenmem_populate_physmap(DOMID_SELF, base_pfn,
						 PFN_4K_SHIFT, nr_pages);
	if (populated_pfns != nr_pages) {
		LOG_ERR("Failed to populate physmap (populated only %llu instead of %llu)",
			populated_pfns, nr_pages);
		return -EFAULT;
	}

	k_free(mapped_addr);

	return 0;
}

int xenmem_cacheflush_mapped_pfns(uint64_t nr_pages, uint64_t base_pfn)
{
	struct xen_domctl_cacheflush cacheflush;
	int rc;

	cacheflush.start_pfn = base_pfn;
	cacheflush.nr_pfns = nr_pages;
	rc = xen_domctl_cacheflush(0, &cacheflush);
	if (rc) {
		LOG_ERR("Failed to flush cache for PFN [%llx-%llx] (rc=%d)",
			base_pfn, base_pfn + nr_pages, rc);
	}

	return rc;
}
