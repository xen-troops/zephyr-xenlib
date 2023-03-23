/*
 * Copyright (c) 2021 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/sys/byteorder.h>
#include <zephyr/xen/dom0/domctl.h>
#include <zephyr/xen/dom0/zimage.h>
#include <zephyr/xen/dom0/uimage.h>
#include <zephyr/xen/generic.h>
#include <zephyr/xen/hvm.h>
#include <zephyr/xen/memory.h>
#include <zephyr/xen/public/hvm/hvm_op.h>
#include <zephyr/xen/public/hvm/params.h>
#include <zephyr/xen/public/domctl.h>
#include <zephyr/xen/public/xen.h>

#include <zephyr/xen/public/io/console.h>
#include <zephyr/xen/public/io/xs_wire.h>
#include <zephyr/xen/events.h>
#include <zephyr/logging/log.h>

#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include "domain.h"
#include "xen-dom-fdt.h"
#include "mem-mgmt.h"

#include <xenstore_srv.h>
#include <xen_console.h>
#include <xss.h>

LOG_MODULE_REGISTER(xen_dom_mgmt);

extern struct xen_domain_cfg domd_cfg;

struct modules_address {
  uint64_t ventry;
  uint64_t dtb_addr;
};

/* Number of active domains, used as an indicator to not exhaust allocated stack area.
 * This variable used during shell command execution, thus requires no sync. */
static int dom_num = 0;

#define DOMID_DOMD 1

/* Define major and minor versions if was not provided */
#ifndef XEN_VERSION_MAJOR
#define XEN_VERSION_MAJOR 4
#endif

#ifndef XEN_VERSION_MINOR
#define XEN_VERSION_MINOR 16
#endif

static sys_dlist_t domain_list = SYS_DLIST_STATIC_INIT(&domain_list);
K_MUTEX_DEFINE(dl_mutex);

static void arch_prepare_domain_cfg(struct xen_domain_cfg *dom_cfg,
				    struct xen_arch_domainconfig *arch_cfg)
{
	int i;
	int max_irq = dom_cfg->nr_irqs ? dom_cfg->irqs[0] : 0;

	arch_cfg->gic_version = dom_cfg->gic_version;
	arch_cfg->tee_type = dom_cfg->tee_type;

	/*
	 * xen_arch_domainconfig 'nr_spis' should be >= than biggest
	 * absolute irq number.
	 */
	for (i = 1; i < dom_cfg->nr_irqs; i++) {
		if (max_irq < dom_cfg->irqs[i]) {
			max_irq = dom_cfg->irqs[i];
		}
	}
	arch_cfg->nr_spis = max_irq;
}

static void prepare_domain_cfg(struct xen_domain_cfg *dom_cfg,
			       struct xen_domctl_createdomain *create)
{
	create->flags = dom_cfg->flags;
	create->max_vcpus = dom_cfg->max_vcpus;
	create->max_evtchn_port = dom_cfg->max_evtchns;
	create->max_grant_frames = dom_cfg->gnt_frames;
	create->max_maptrack_frames = dom_cfg->max_maptrack_frames;

	arch_prepare_domain_cfg(dom_cfg, &create->arch);
}

static int allocate_domain_evtchns(struct xen_domain *domain)
{
	int rc;

	/* TODO: Alloc all required evtchns */
	rc = alloc_unbound_event_channel_dom0(domain->domid, 0);
	if (rc < 0) {
		LOG_ERR("Failed to alloc evtchn for domain#%u xenstore (rc=%d)", domain->domid,
		       rc);
		return rc;
	}
	domain->xenstore_evtchn = rc;

	LOG_DBG("Generated remote_domid=%d, xenstore_evtchn = %d", domain->domid,
	       domain->xenstore_evtchn);

	rc = alloc_unbound_event_channel_dom0(domain->domid, 0);
	if (rc < 0) {
		LOG_ERR("Failed to alloc evtchn for domain#%u console (rc=%d)", domain->domid,
		       rc);
		return rc;
	}
	domain->console_evtchn = rc;

	LOG_DBG("Generated remote_domid = %u, console evtchn = %u", domain->domid,
	       domain->console_evtchn);

	return 0;
}

static int allocate_magic_pages(int domid)
{
	int rc = -ENOMEM, err_cache_flush = 0;
	void *mapped_magic;
	uint64_t populated_gfn;

	populated_gfn = xenmem_populate_physmap(domid,
						XEN_PHYS_PFN(GUEST_MAGIC_BASE),
						PFN_4K_SHIFT,
						NR_MAGIC_PAGES);
	if (populated_gfn != NR_MAGIC_PAGES) {
		LOG_ERR("Failed to populate magic pages for domid#%d (ret=%llu expected=%u)",
			domid, populated_gfn, NR_MAGIC_PAGES);
			return rc;
	}

	rc = xenmem_map_region(domid, NR_MAGIC_PAGES,
			       XEN_PHYS_PFN(GUEST_MAGIC_BASE), &mapped_magic);
	if (rc) {
		LOG_ERR("Failed to map GFN to Dom0 (rc=%d)", rc);
		return rc;
	}

	memset(mapped_magic, 0, XEN_PAGE_SIZE * NR_MAGIC_PAGES);
	/*
	 * This is not critical, so try to restore memory to dom0
	 * and then return error code.
	 */
	rc = xenmem_cacheflush_mapped_pfns(NR_MAGIC_PAGES,
					   XEN_PHYS_PFN(GUEST_MAGIC_BASE));
	if (rc) {
		LOG_ERR("Failed to flush memory for domid#%d (rc=%d)",
			domid, rc);
		err_cache_flush = rc;
	}

	rc = xenmem_unmap_region(NR_MAGIC_PAGES, mapped_magic);
	if (rc) {
		LOG_ERR("Failed to unmap memory for domid#%d (rc=%d)",
			domid, rc);
	}
	/*
	 * We postponed this to unmap DomU magic region as we failed to
	 * flush cache for domain pages. We need to leave now to prevent
	 * DomU from using dirty pages passed with HVM params.
	 */
	if (err_cache_flush) {
		return err_cache_flush;
	}

	rc = hvm_set_parameter(HVM_PARAM_CONSOLE_PFN, domid,
			       XEN_PHYS_PFN(GUEST_MAGIC_BASE) +
			       CONSOLE_PFN_OFFSET);
	if (rc) {
		LOG_ERR("Failed to set HVM_PARAM_CONSOLE_PFN for domid#%d (rc=%d)",
			domid, rc);
		return rc;
	}

	rc = hvm_set_parameter(HVM_PARAM_STORE_PFN, domid,
			       XEN_PHYS_PFN(GUEST_MAGIC_BASE) +
			       XENSTORE_PFN_OFFSET);
	if (rc) {
		LOG_ERR("Failed to set HVM_PARAM_STORE_PFN for domid#%d (rc=%d)",
			domid, rc);
	}

	return rc;
}

/* We need to populate magic pages and memory map here */
static int prepare_domain_physmap(int domid, uint64_t base_pfn, struct xen_domain_cfg *cfg)
{
	int rc;
	uint64_t populated_gfn;
	uint64_t nr_mem_exts =
		ceiling_fraction(cfg->mem_kb * 1024, PFN_2M_SIZE);

	rc = allocate_magic_pages(domid);
	if (rc) {
		LOG_ERR("Failed to allocate magic pages for domid#%d (rc=%d)",
			domid, rc);
		return rc;
	}

	populated_gfn = xenmem_populate_physmap(domid, base_pfn, PFN_2M_SHIFT,
						nr_mem_exts);
	if (populated_gfn != nr_mem_exts) {
		LOG_ERR("Failed to populate physmap for domid#%d (populated only %llu instead of %llu)",
			domid, populated_gfn, nr_mem_exts);
		return -ENOMEM;
	}

	return 0;
}

static uint64_t get_dtb_addr(uint64_t rambase, uint64_t ramsize,
							 uint64_t kernbase, uint64_t kernsize,
							 uint64_t dtbsize)
{
	const uint64_t dtb_len = ROUND_UP(dtbsize, MB(2));
	const uint64_t ramend = rambase + ramsize;
	const uint64_t ram128mb = rambase + MB(128);
	const uint64_t kernsize_aligned = ROUND_UP(kernsize, MB(2));
	const uint64_t kernend = kernbase + kernsize;
	const uint64_t modsize = dtb_len;
	uint64_t modbase;

	LOG_INF("rambase = %llx, ramsize = %llu", rambase, ramsize);
	LOG_INF("kernbase = %llx kernsize = %llu, dtbsize = %llu",
		   kernbase, kernsize, dtbsize);
	LOG_INF("kernsize_aligned = %lld", kernsize_aligned);

	if (modsize + kernsize_aligned > ramsize) {
		LOG_ERR("Not enough memory in the first bank for the kernel+dtb+initrd");
		return 0;
	}

	/*
	 * Comment was taken from XEN source code from function
	 * place_modules (xen/arch/arm/kernel.c) and added here for the
	 * better understanding why this algorithm was used.
	 * DTB must be loaded such that it does not conflict with the
	 * kernel decompressor. For 32-bit Linux Documentation/arm/Booting
	 * recommends just after the 128MB boundary while for 64-bit Linux
	 * the recommendation in Documentation/arm64/booting.txt is below
	 * 512MB.
	 *
	 * If the bootloader provides an initrd, it will be loaded just
	 * after the DTB.
	 *
	 * We try to place dtb+initrd at 128MB or if we have less RAM
	 * as high as possible. If there is no space then fallback to
	 * just before the kernel.
	 *
	 * If changing this then consider
	 * tools/libxc/xc_dom_arm.c:arch_setup_meminit as well.
	 */

	/*
	 * According to the Linux Documentation/arm64/booting.rst Header notes:
	 * Decompressed kernel image has Bit 3 in kernel flags:
	 * Bit 3		Kernel physical placement
	 *
	 *  0
	 *     2MB aligned base should be as close as possible
	 *     to the base of DRAM, since memory below it is not
	 *     accessible via the linear mapping
	 *  1
	 *     2MB aligned base may be anywhere in physical
	 *     memory
	 * When Bit 3 was set to 0 - then the memory below kernel base address
	 * is not accessible by the kernel. That's why dtb should be placed
	 * somewhere after kernel base address.
	 */

	if (ramend >= ram128mb + modsize && kernend < ram128mb)
		modbase = ram128mb;
	else if (ramend - modsize > kernsize_aligned)
		modbase = ramend - modsize;
	else if (kernbase - rambase > modsize)
		modbase = kernbase - modsize;
	else {
		LOG_ERR("Unable to find suitable location for dtb+initrd");
		return 0;
	}

	return modbase;
};

static int load_dtb(int domid, uint64_t dtb_addr, const char *dtb_start,
		    const char *dtb_end)
{
	void *mapped_dtb_addr;
	int rc, err_cache_flush = 0;
	uint64_t dtb_size = dtb_end - dtb_start;
	uint64_t nr_pages = ceiling_fraction(dtb_size, XEN_PAGE_SIZE);
	uint64_t dtb_pfn;

	rc = xenmem_map_region(domid, nr_pages,
				XEN_PHYS_PFN(dtb_addr), &mapped_dtb_addr);
	if (rc) {
		LOG_ERR("Failed to map domain dtb region to Dom0 (rc=%d)", rc);
		return rc;
	}

	dtb_pfn = XEN_PHYS_PFN((uint64_t)mapped_dtb_addr);
	LOG_DBG("DTB start addr = %p, end addr = %p, binary size = 0x%llx", dtb_start,
	       dtb_end, dtb_size);
	LOG_INF("DTB will be placed on addr = %p", (void *)dtb_addr);

	/* Copy binary to domain pages and flush cache */
	memcpy(mapped_dtb_addr, dtb_start, dtb_size);
	/*
	 * This is not critical, so try to restore memory to dom0
	 * and then return error code.
	 */
	rc = xenmem_cacheflush_mapped_pfns(nr_pages, dtb_pfn);
	if (rc) {
		LOG_ERR("Failed to flush memory for domid#%d (rc=%d)",
			domid, rc);
		err_cache_flush = rc;
	}

	rc = xenmem_unmap_region(nr_pages, mapped_dtb_addr);
	if (rc) {
		LOG_ERR("Failed to unmap memory for domid#%d (rc=%d)",
			domid, rc);
	}
	/*
	 * We postponed this to unmap DomU memory region as we failed to flush
	 * cache for domain pages. We need to return error code to prevent
	 * DomU from using dirty pages for DTB.
	 */
	if (err_cache_flush) {
		return err_cache_flush;
	}

	return rc;
}

static int probe_zimage(int domid, uint64_t base_addr,
			uint64_t image_load_offset,
			struct xen_domain_cfg *domcfg,
			struct modules_address *modules)
{
	int rc, err_cache_flush = 0;
	void *mapped_domd;
	uint64_t dtb_addr;
	const char *img_start = domcfg->img_start + image_load_offset;
	const char *img_end = domcfg->img_end;
	uint64_t domd_size = img_end - img_start;
	uint64_t nr_pages = ceiling_fraction(domd_size, XEN_PAGE_SIZE);
	char *fdt;
	size_t fdt_size;
	struct zimage64_hdr *zhdr = (struct zimage64_hdr *)img_start;
	uint64_t load_addr = base_addr + zhdr->text_offset;
	uint64_t load_gfn = XEN_PHYS_PFN(load_addr), base_pfn;

	LOG_DBG("zImage header info: text_offset = %llx, base_addr = %llx, pages = %llu size = %llu",
		zhdr->text_offset, base_addr, nr_pages,
		nr_pages * XEN_PAGE_SIZE);
	rc = gen_domain_fdt(domcfg, (void **)&fdt, &fdt_size,
			   XEN_VERSION_MAJOR, XEN_VERSION_MINOR,
			   (void *)domcfg->dtb_start,
			   domcfg->dtb_end - domcfg->dtb_start, domid);
	if (rc || fdt_size == 0) {
		LOG_ERR("Failed to generate domain FDT (rc=%d)", rc);
		return (rc) ? rc : -ENOMEM;
	}

	dtb_addr = get_dtb_addr(base_addr, KB(domcfg->mem_kb), load_addr,
				domcfg->img_end - domcfg->img_start, fdt_size);
	if (!dtb_addr) {
		LOG_ERR("Failed to get dtb addr for domid#%d", domid);
		goto out_dtb;
	}

	modules->dtb_addr = dtb_addr;
	rc = load_dtb(domid, dtb_addr, fdt, fdt + fdt_size);
	if (rc) {
		LOG_ERR("Failed to load dtb dor domid#%d (rc=%d)", domid, rc);
		goto out_dtb;
	}

	rc = xenmem_map_region(domid, nr_pages, load_gfn, &mapped_domd);
	if (rc) {
		LOG_ERR("Failed to map GFN to Dom0 (rc=%d)", rc);
		goto out_dtb;
	}
	base_pfn = XEN_PHYS_PFN((uint64_t)mapped_domd);
	LOG_DBG("Zephyr DomD start addr = %p, end addr = %p size = 0x%llx",
		img_start, img_end, domd_size);

	/* Copy binary to domain pages and clear cache */
	memcpy(mapped_domd, img_start, domd_size);
	LOG_DBG("Kernel image is copied");
	/*
	 * This is not critical, so try to restore memory to dom0
	 * and then return error code.
	 */
	rc = xenmem_cacheflush_mapped_pfns(nr_pages, base_pfn);
	if (rc) {
		LOG_ERR("Failed to flush memory for domid#%d (rc=%d)",
			domid, rc);
		err_cache_flush = rc;
	}

	rc = xenmem_unmap_region(nr_pages, mapped_domd);
	if (rc) {
		LOG_ERR("Failed to unmap memory for domid#%d (rc=%d)",
			domid, rc);
		goto out_dtb;
	}
	/*
	 * We postponed this to unmap DomU memory region as we failed to flush
	 * cache for domain pages. We need to return error code to prevent
	 * DomU from using dirty pages.
	 */
	if (err_cache_flush) {
		rc = err_cache_flush;
		goto out_dtb;
	}

	/* .text start address in domU memory */
	modules->ventry = load_addr;
	rc = 0;
 out_dtb:
	free_domain_fdt(fdt);

	return rc;
}


int probe_uimage(int domid, struct xen_domain_cfg *domcfg,
				 struct modules_address *modules)
{
	uint32_t len;
	uint64_t base_addr;
	uint64_t mem_size = KB(domcfg->mem_kb);
	struct uimage_hdr *uhdr = (struct uimage_hdr *)domcfg->img_start;

	/*
	 * We expect Image to be loaded only in RAM0 Bank
	 * ignoring space > GUEST_RAM0_SIZE
	 */
	if (mem_size > GUEST_RAM0_SIZE)
		mem_size = GUEST_RAM0_SIZE;

	if (sys_be32_to_cpu(uhdr->magic_be32) != UIMAGE_MAGIC)
		return -EINVAL;

	len = sys_be32_to_cpu(uhdr->size_be32);
	base_addr = sys_be32_to_cpu(uhdr->load_be32);
	if (base_addr < GUEST_RAM0_BASE ||
		base_addr > GUEST_RAM0_BASE + mem_size)
		return -EINVAL;

	if (base_addr + len > GUEST_RAM0_BASE + mem_size)
		return -EINVAL;

	return probe_zimage(domid, base_addr, sizeof(*uhdr), domcfg, modules);
}

int load_modules(int domid, struct xen_domain_cfg *domcfg,
				 struct modules_address *modules)
{
	int rc;
	uint64_t base_addr = GUEST_RAM0_BASE;
	uint64_t base_pfn = XEN_PHYS_PFN(base_addr);

	rc = prepare_domain_physmap(domid, base_pfn, domcfg);
	if (rc) {
		LOG_ERR("Error preparing physmap (rc=%d)", rc);
		return rc;
	}

	rc = probe_uimage(domid, domcfg, modules);
	if (rc) {
		rc = probe_zimage(domid, base_addr, 0, domcfg, modules);
		if (rc) {
			LOG_ERR("Error loading image, unsupported format");
			return rc;
		}
	}

	return 0;
}

int share_domain_iomems(int domid, struct xen_domain_iomem *iomems, int nr_iomem)
{
	int i, rc = 0;

	for (i = 0; i < nr_iomem; i++) {
		rc = xen_domctl_iomem_permission(domid, iomems[i].first_mfn, iomems[i].nr_mfns, 1);
		if (rc) {
			LOG_ERR("Failed to allow iomem access to mfn 0x%llx, (rc=%d)",
			       iomems[i].first_mfn, rc);
		}

		if (!iomems[i].first_gfn) {
			/* Map to same location as machine frame number */
			rc = xen_domctl_memory_mapping(domid, iomems[i].first_mfn,
						       iomems[i].first_mfn, iomems[i].nr_mfns, 1);
		} else {
			/* Map to specified location */
			rc = xen_domctl_memory_mapping(domid, iomems[i].first_gfn,
						       iomems[i].first_mfn, iomems[i].nr_mfns, 1);
		}
		if (rc) {
			LOG_ERR("Failed to map mfn 0x%llx (rc=%d)", iomems[i].first_mfn, rc);
		}
	}

	return rc;
}

int bind_domain_irqs(int domid, uint32_t *irqs, int nr_irqs)
{
	int i, rc = 0;

	for (i = 0; i < nr_irqs; i++) {
		rc = xen_domctl_bind_pt_irq(domid, irqs[i], PT_IRQ_TYPE_SPI, 0, 0, 0, 0, irqs[i]);
		if (rc) {
			LOG_ERR("Failed to bind irq#%u, (rc=%d)", irqs[i], rc);
			/*return rc;*/
		}
	}

	return rc;
}

int assign_dtdevs(int domid, char *dtdevs[], int nr_dtdevs)
{
	int i, rc = 0;

	for (i = 0; i < nr_dtdevs; i++) {
		rc = xen_domctl_assign_dt_device(domid, dtdevs[i]);
		if (rc) {
			LOG_ERR("Failed to assign dtdev %s (rc=%d)", dtdevs[i], rc);
			return rc;
		}
	}

	return rc;
}

int map_domain_xenstore_ring(struct xen_domain *domain)
{
	void *mapped_ring;
	xen_pfn_t ring_pfn, idx;
	int err, rc;
	struct xenstore_domain_interface *intf;

	mapped_ring = k_aligned_alloc(XEN_PAGE_SIZE, XEN_PAGE_SIZE);
	if (!mapped_ring) {
		LOG_ERR("Failed to alloc memory for domain#%u console ring buffer",
		       domain->domid);
		return -ENOMEM;
	}

	memset(mapped_ring, 0, XEN_PAGE_SIZE);
	ring_pfn = xen_virt_to_gfn(mapped_ring);
	idx = XEN_PHYS_PFN(GUEST_MAGIC_BASE) + XENSTORE_PFN_OFFSET;

	/* adding single page, but only xatpb can map with foreign domid */
	rc = xendom_add_to_physmap_batch(DOMID_SELF, domain->domid, XENMAPSPACE_gmfn_foreign, 1,
					 &idx, &ring_pfn, &err);
	if (rc) {
		LOG_ERR("Failed to map xenstore ring buffer for domain#%u (rc=%d)",
		       domain->domid, rc);
		k_free(mapped_ring);
		return rc;
	}

	domain->domint = mapped_ring;
	intf = (struct xenstore_domain_interface *)domain->domint;
	intf->server_features = XENSTORE_SERVER_FEATURE_RECONNECTION;
	intf->connection = XENSTORE_CONNECTED;

	return 0;
}

int map_domain_console_ring(struct xen_domain *domain)
{
	void *mapped_ring;
	xen_pfn_t ring_pfn, idx;
	int err, rc;

	mapped_ring = k_aligned_alloc(XEN_PAGE_SIZE, XEN_PAGE_SIZE);
	if (!mapped_ring) {
		LOG_ERR("Failed to alloc memory for domain#%u console ring buffer",
		       domain->domid);
		return -ENOMEM;
	}

	ring_pfn = xen_virt_to_gfn(mapped_ring);
	memset(mapped_ring, 0, XEN_PAGE_SIZE);
	idx = XEN_PHYS_PFN(GUEST_MAGIC_BASE) + CONSOLE_PFN_OFFSET;

	/* adding single page, but only xatpb can map with foreign domid */
	rc = xendom_add_to_physmap_batch(DOMID_SELF, domain->domid, XENMAPSPACE_gmfn_foreign, 1,
					 &idx, &ring_pfn, &err);
	if (rc) {
		LOG_ERR("Failed to map console ring buffer for domain#%u (rc=%d)", domain->domid,
		       rc);
		return rc;
	}

	domain->intf = mapped_ring;

	return 0;
}

/*
 * TODO: Access to domain_list and domains should be protected, considering that it may be
 * destroyed after receiving pointer to actual domain. So all accesses to domains structs should be
 * protected globally or via refcounts. This requires code audit in all libs, that are using this
 * function (currently xenstore-srv and xen_shell).
 */
struct xen_domain *domid_to_domain(uint32_t domid)
{
	struct xen_domain *iter;

	SYS_DLIST_FOR_EACH_CONTAINER (&domain_list, iter, node) {
		if (iter->domid == domid) {
			return iter;
		}
	}

	return NULL;
}

int domain_console_start(uint32_t domid)
{
	struct xen_domain *domain;

	domain = domid_to_domain(domid);
	if (!domain) {
		LOG_ERR("domid#%u is not found", domid);
		/* Domain with requested domid is not present in list */
		return -EINVAL;
	}

	return start_domain_console(domain);
}

int domain_console_stop(uint32_t domid)
{
	struct xen_domain *domain;

	domain = domid_to_domain(domid);
	if (!domain) {
		LOG_ERR("domid#%u is not found", domid);
		/* Domain with requested domid is not present in list */
		return -EINVAL;
	}

	return stop_domain_console(domain);
}

void initialize_xenstore(uint32_t domid, const struct xen_domain_cfg *domcfg, const struct xen_domain *domain)
{
	char lbuffer[256] = { 0 };
	char rbuffer[256] = { 0 };
	char uuid[40];
	char basepref[] = "/local/domain";
	char *dirs[] = { "data",
			 "drivers",
			 "feature",
			 "attr",
			 "error",
			 "control",
			 "control/shutdown",
			 "control/feature-poweroff",
			 "control/feature-reboot",
			 "control/feature-suspend",
			 "control/sysrq",
			 "device/vbd",
			 "device/suspend/event-channel",
			 NULL };

	// TODO: generate properly
	snprintf(uuid, 40, "00000000-0000-0000-0000-%012d", domid);

	xss_write("/tool/xenstored", "");

	for (int i = 0; i < domcfg->max_vcpus; ++i) {
		sprintf(lbuffer, "%s/%d/cpu/%d/availability", basepref, domid, i);
		xss_write(lbuffer, "online");
	}

	sprintf(lbuffer, "%s/%d/memory/static-max", basepref, domid);
	sprintf(rbuffer, "%lld", domain->max_mem_kb);
	xss_write(lbuffer, rbuffer);
	sprintf(lbuffer, "%s/%d/memory/target", basepref, domid);
	xss_write(lbuffer, rbuffer);
	sprintf(lbuffer, "%s/%d/memory/videoram", basepref, domid);
	xss_write(lbuffer, "-1");
	sprintf(lbuffer, "%s/%d/control/platform-feature-multiprocessor-suspend", basepref, domid);
	xss_write(lbuffer, "1");
	sprintf(lbuffer, "%s/%d/control/platform-feature-xs_reset_watches", basepref, domid);
	xss_write(lbuffer, "1");

	sprintf(lbuffer, "%s/%d/vm", basepref, domid);
	xss_write(lbuffer, uuid);

	sprintf(lbuffer, "/vm/%s/name", uuid);
	sprintf(rbuffer, "zephyr-%d", domid);
	xss_write(lbuffer, rbuffer);
	sprintf(lbuffer, "/local/domain/%d/name", domid);
	xss_write(lbuffer, rbuffer);
	sprintf(lbuffer, "/vm/%s/start_time", uuid);
	xss_write(lbuffer, "0");
	sprintf(lbuffer, "/vm/%s/uuid", uuid);
	xss_write(lbuffer, uuid);

	sprintf(lbuffer, "%s/%d/domid", basepref, domid);
	sprintf(rbuffer, "%d", domid);
	xss_write(lbuffer, rbuffer);

	for (int i = 0; dirs[i]; ++i) {
		sprintf(lbuffer, "%s/%d/%s", basepref, domid, dirs[i]);
		xss_write(lbuffer, "");
	}

	sprintf(lbuffer, "/libxl/%d/dm-version", domid);
	xss_write(lbuffer, "qemu_xen_traditional");
	sprintf(lbuffer, "/libxl/%d/type", domid);
	xss_write(lbuffer, "pvh");
}

int domain_create(struct xen_domain_cfg *domcfg, uint32_t domid)
{
	int rc = 0;
	struct xen_domctl_createdomain config;
	struct vcpu_guest_context vcpu_ctx;
	struct xen_domctl_scheduler_op sched_op;
	struct xen_domain *domain;
	char *domdtdevs;
	struct modules_address modules = {0};

	if (dom_num >= DOM_MAX) {
		LOG_ERR("Runtime exceeds maximum number of domains");
		return -EINVAL;
	}

	domdtdevs = domcfg->dtdevs;

	memset(&config, 0, sizeof(config));
	prepare_domain_cfg(domcfg, &config);
	config.grant_opts = XEN_DOMCTL_GRANT_version(1);

	rc = xen_domctl_createdomain(domid, &config);
	LOG_DBG("Return code = %d creation", rc);
	if (rc) {
		return rc;
	}

	domain = k_malloc(sizeof(*domain));
	__ASSERT(domain, "Can not allocate memory for domain struct");
	memset(domain, 0, sizeof(*domain));
	domain->domid = domid;

	rc = xen_domctl_max_vcpus(domid, domcfg->max_vcpus);
	LOG_DBG("Return code = %d max_vcpus", rc);
	domain->num_vcpus = domcfg->max_vcpus;

	rc = xen_domctl_set_address_size(domid, 64);
	LOG_DBG("Return code = %d set_address_size", rc);
	domain->address_size = 64;

	domain->max_mem_kb = domcfg->mem_kb + (domcfg->gnt_frames + NR_MAGIC_PAGES) * XEN_PAGE_SIZE;
	rc = xen_domctl_max_mem(domid, domain->max_mem_kb);

	/* Calculation according to xl.cfg manual for shadow memory (1MB/CPU + 8KB for every 1MB RAM */
	rc = xen_domctl_set_paging_mempool_size(domid, domcfg->max_vcpus * 1024 * 1024 + 8 * domcfg->mem_kb);
	LOG_DBG("Return code = %d xen_domctl_set_paging_mempool_size", rc);

	rc = allocate_domain_evtchns(domain);
	LOG_DBG("Return code = %d allocate_domain_evtchns", rc);

	rc = load_modules(domid, domcfg, &modules);
	if (rc || modules.ventry == NULL)
	{
		LOG_ERR("Unable to load image, insufficient memory");
		return 10;
	}

	rc = share_domain_iomems(domid, domcfg->iomems, domcfg->nr_iomems);

	rc = bind_domain_irqs(domid, domcfg->irqs, domcfg->nr_irqs);

	rc = assign_dtdevs(domid, domdtdevs, domcfg->nr_dtdevs);

	memset(&vcpu_ctx, 0, sizeof(vcpu_ctx));
	vcpu_ctx.user_regs.x0 = modules.dtb_addr;
	vcpu_ctx.user_regs.pc64 = modules.ventry;
	vcpu_ctx.user_regs.cpsr = PSR_GUEST64_INIT;
	vcpu_ctx.sctlr = SCTLR_GUEST_INIT;
	vcpu_ctx.flags = VGCF_online;

	rc = xen_domctl_setvcpucontext(domid, 0, &vcpu_ctx);
	LOG_DBG("Set VCPU context return code = %d", rc);

	memset(&vcpu_ctx, 0, sizeof(vcpu_ctx));
	rc = xen_domctl_getvcpucontext(domid, 0, &vcpu_ctx);
	LOG_DBG("Return code = %d getvcpucontext", rc);
	LOG_INF("VCPU PC = 0x%llx, x0 = 0x%llx, x1 = %llx", vcpu_ctx.user_regs.pc64,
	       vcpu_ctx.user_regs.x0, vcpu_ctx.user_regs.x1);

	memset(&sched_op, 0, sizeof(sched_op));
	sched_op.sched_id = XEN_SCHEDULER_CREDIT2;
	sched_op.cmd = XEN_DOMCTL_SCHEDOP_getinfo;

	rc = xen_domctl_scheduler_op(domid, &sched_op);
	LOG_DBG("Return code = %d SCHEDOP_getinfo", rc);

	sched_op.u.credit2.cap = 0;
	sched_op.u.credit2.weight = 256;
	sched_op.cmd = XEN_DOMCTL_SCHEDOP_putinfo;

	rc = xen_domctl_scheduler_op(domid, &sched_op);
	LOG_DBG("Return code = %d SCHEDOP_putinfo", rc);

	k_mutex_lock(&dl_mutex, K_FOREVER);
	sys_dnode_init(&domain->node);
	sys_dlist_append(&domain_list, &domain->node);
	k_mutex_unlock(&dl_mutex);

	rc = map_domain_xenstore_ring(domain);

	if (rc) {
		LOG_ERR("Unable to map domain xenstore ring (rc=%d)", rc);
		return rc;
	}

	rc = start_domain_stored(domain);
	if (rc) {
		return rc;
	}

	/* TODO: do this on console creation */
	rc = map_domain_console_ring(domain);
	if (rc) {
		return rc;
	}
	LOG_DBG("Map domain ring succeeded");

	/* TODO: for debug, remove this or set as optional */
	rc = init_domain_console(domain);

	if (rc) {
		LOG_ERR("Unable to init domain console (rc=%d)", rc);
		return rc;
	}

	rc = start_domain_console(domain);

	if (rc) {
		LOG_ERR("Unable to start domain console (rc=%d)", rc);
		return rc;
	}

	initialize_xenstore(domid, domcfg, domain);

	if (domid == DOMID_DOMD) {
		rc = xen_domctl_unpausedomain(domid);
		LOG_INF("Return code = %d XEN_DOMCTL_unpausedomain", rc);
	} else {
		LOG_INF("Created domain is paused\nTo unpause issue: xu unpause -d %u", domid);
	}

	++dom_num;

	return rc;
}

void unmap_domain_ring(void *p)
{
	xen_pfn_t ring_pfn = xen_virt_to_gfn(p);
	int rc = xendom_remove_from_physmap(DOMID_SELF, ring_pfn);
	LOG_DBG("Return code for xendom_remove_from_physmap = %d [%p]", rc, p);

	rc = xendom_populate_physmap(DOMID_SELF, 0, 1, 0, &ring_pfn);
	LOG_DBG("Return code for xendom_populate_physmap = %d [%p]", rc, p);

	k_free(p);
}

int domain_destroy(uint32_t domid)
{
	int rc;
	struct xen_domain *domain = NULL;

	domain = domid_to_domain(domid);
	if (!domain) {
		LOG_ERR("Domain with domid#%u is not found", domid);
		/* Domain with requested domid is not present in list */
		return -EINVAL;
	}

	stop_domain_stored(domain);
	/* TODO: do this on console destroying */
	stop_domain_console(domain);

	unmap_domain_ring(domain->intf);
	unmap_domain_ring(domain->domint);

	rc = xen_domctl_destroydomain(domid);
	LOG_DBG("Return code = %d XEN_DOMCTL_destroydomain", rc);

	k_mutex_lock(&dl_mutex, K_FOREVER);
	sys_dlist_remove(&domain->node);
	k_mutex_unlock(&dl_mutex);

	k_free(domain);

	--dom_num;

	return rc;
}

int domain_pause(uint32_t domid)
{
	int rc;
	struct xen_domain *domain = NULL;

	domain = domid_to_domain(domid);
	if (!domain) {
		LOG_ERR("Domain with domid#%u is not found", domid);
		/* Domain with requested domid is not present in list */
		return -EINVAL;
	}

	rc = xen_domctl_pausedomain(domid);

	return rc;
}

int domain_unpause(uint32_t domid)
{
	struct xen_domain *domain = NULL;

	domain = domid_to_domain(domid);
	if (!domain) {
		LOG_ERR("Domain with domid#%u is not found", domid);
		/* Domain with requested domid is not present in list */
		return -EINVAL;
	}

	return xen_domctl_unpausedomain(domid);
}
