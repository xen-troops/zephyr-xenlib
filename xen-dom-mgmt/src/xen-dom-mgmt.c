/*
 * Copyright (c) 2021 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#include <zephyr/init.h>
#include <zephyr/sys/byteorder.h>
#include <zephyr/xen/dom0/domctl.h>
#include <zephyr/xen/generic.h>
#include <zephyr/xen/hvm.h>
#include <zephyr/xen/memory.h>
#include <zephyr/xen/public/hvm/hvm_op.h>
#include <zephyr/xen/public/hvm/params.h>
#include <zephyr/xen/public/domctl.h>
#include <zephyr/xen/public/xen.h>

#include <zephyr/xen/public/io/console.h>
#include <zephyr/xen/events.h>
#include <zephyr/logging/log.h>

#include <zephyr/init.h>
#include <zephyr/kernel.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>

#include <domain.h>
#include <xen-dom-fdt.h>
#include <mem-mgmt.h>
#include <uimage.h>
#include <zimage.h>

#include <xenstore_srv.h>
#ifdef CONFIG_XEN_CONSOLE_SRV
#include <xen_console.h>
#endif
#include <xss.h>
#ifdef CONFIG_XSTAT
#include <xstat.h>
#endif

LOG_MODULE_REGISTER(xen_dom_mgmt);

#define DOM0_XENSTORE_PRIORITY 45
#define INIT_XENSTORE_BUFF_SIZE 80
#define INIT_XENSTORE_UUID_BUF_SIZE 40
BUILD_ASSERT(DOM0_XENSTORE_PRIORITY > CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);

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

/*
 * According to: https://xenbits.xen.org/docs/unstable/man/xen-vbd-interface.7.html
 * XEN_XVD_DP_NOMINAL_TYPE represents block devices as xvd-type,
 * whith disks and up to 15 partitions.
 *
 * XEN_XVD_DP_DISK_MAX_INDEX is a maximum number of disks, for the
 * XEN_XVD_DP_NOMINAL_TYPE.
 */
#define XEN_XVD_DP_NOMINAL_TYPE (202 << 8)
#define XEN_XVD_DP_DISK_MAX_INDEX ((1 << 20) - 1)

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
	domain->xenstore.remote_evtchn = rc;

	LOG_DBG("Generated remote_domid=%d, remote_evtchn = %d", domain->domid,
		domain->xenstore.remote_evtchn);

	rc = alloc_unbound_event_channel_dom0(domain->domid, 0);
	if (rc < 0) {
		LOG_ERR("Failed to alloc evtchn for domain#%u console (rc=%d)", domain->domid,
		       rc);
		return rc;
	}
	domain->console.evtchn = rc;

	LOG_DBG("Generated remote_domid = %u, console evtchn = %u", domain->domid,
	       domain->console.evtchn);

	return 0;
}

static int allocate_magic_pages(int domid)
{
	int rc = -ENOMEM, err_cache_flush = 0;
	void *mapped_magic;
	uint64_t populated_gfn;
	const uint64_t gfn_magic_base = XEN_PHYS_PFN(GUEST_MAGIC_BASE);

	populated_gfn = xenmem_populate_physmap(domid,
						gfn_magic_base,
						PFN_4K_SHIFT,
						NR_MAGIC_PAGES);
	if (populated_gfn != NR_MAGIC_PAGES) {
		LOG_ERR("Failed to populate magic pages for domid#%d (ret=%llu expected=%u)",
			domid, populated_gfn, NR_MAGIC_PAGES);
			return rc;
	}

	rc = xenmem_map_region(domid, NR_MAGIC_PAGES,
			       gfn_magic_base, &mapped_magic);
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
					   gfn_magic_base);
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
			       gfn_magic_base + CONSOLE_PFN_OFFSET);
	if (rc) {
		LOG_ERR("Failed to set HVM_PARAM_CONSOLE_PFN for domid#%d (rc=%d)",
			domid, rc);
		return rc;
	}

	rc = hvm_set_parameter(HVM_PARAM_STORE_PFN, domid,
			       gfn_magic_base + XENSTORE_PFN_OFFSET);
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
			uint64_t image_read_offset,
			struct xen_domain_cfg *domcfg,
			struct modules_address *modules)
{
	int rc, err_cache_flush = 0;
	void *mapped_image;
	uint64_t dtb_addr;
	uint64_t load_gfn;
	uint64_t domain_size = 0;
	uint64_t nr_pages;
	char *fdt;
	size_t fdt_size;

	struct zimage64_hdr zhdr;
	uint64_t load_addr;

	if (!domcfg->load_image_bytes || !domcfg->get_image_size) {
		LOG_ERR("Image callbacks were not set\n");
		return -EINVAL;
	}

	rc = domcfg->load_image_bytes((uint8_t *)&zhdr, sizeof(zhdr),
					image_read_offset, domcfg->image_info);
	if (rc < 0) {
		LOG_ERR("Error calling load_image_bytes rc: %d\n", rc);
		return rc;
	}

	load_addr = base_addr + zhdr.text_offset;
	load_gfn = XEN_PHYS_PFN(load_addr);

	rc = domcfg->get_image_size(domcfg->image_info, &domain_size);
	if (rc < 0 || domain_size == 0) {
		LOG_ERR("Error calling get_image_size rc: %d\n", rc);
		return rc;
	}

	nr_pages = ceiling_fraction(domain_size, XEN_PAGE_SIZE);
	LOG_DBG("zImage header info: text_offset = %llx, base_addr = %llx, pages = %llu size = %llu",
		zhdr.text_offset, base_addr, nr_pages,
		nr_pages * XEN_PAGE_SIZE);

	rc = gen_domain_fdt(domcfg, (void **)&fdt, &fdt_size,
			   XEN_VERSION_MAJOR, XEN_VERSION_MINOR,
			   (void *)domcfg->dtb_start,
			   domcfg->dtb_end - domcfg->dtb_start, domid);
	if (rc || fdt_size == 0) {
		LOG_ERR("Failed to generate domain FDT (rc=%d)", rc);
		return -ENOMEM;
	}

	dtb_addr = get_dtb_addr(base_addr, KB(domcfg->mem_kb), load_addr,
				domain_size, fdt_size);
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

	rc = xenmem_map_region(domid, nr_pages, load_gfn, &mapped_image);
	if (rc) {
		LOG_ERR("Failed to map GFN to Dom0 (rc=%d)", rc);
		goto out_dtb;
	}

	LOG_DBG("Zephyr Domain start addr = %p, binary size = 0x%llx",
		mapped_image, domain_size);

	/* Copy binary to domain pages and clear cache */
	rc = domcfg->load_image_bytes(mapped_image, domain_size,
				      image_read_offset, domcfg->image_info);
	if (rc < 0) {
		LOG_ERR("Error calling load_image_bytes rc: %d", rc);
		goto out_dtb;
	}

	LOG_DBG("Kernel image is copied");
	/*
	 * This is not critical, so try to restore memory to dom0
	 * and then return error code.
	 */
	rc = xenmem_cacheflush_mapped_pfns(nr_pages,
					   xen_virt_to_gfn(mapped_image));
	if (rc) {
		LOG_ERR("Failed to flush memory for domid#%d (rc=%d)",
			domid, rc);
		err_cache_flush = rc;
	}

	rc = xenmem_unmap_region(nr_pages, mapped_image);
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


static int probe_uimage(int domid, struct xen_domain_cfg *domcfg,
			struct modules_address *modules)
{
	int rc;
	uint32_t len;
	uint64_t base_addr;
	uint64_t mem_size = KB(domcfg->mem_kb);
	struct uimage_hdr uhdr;

	if (!domcfg->load_image_bytes) {
		LOG_ERR("load_image_bytes callback is not set");
		return -EINVAL;
	}

	rc = domcfg->load_image_bytes((uint8_t *)&uhdr, sizeof(uhdr), 0,
				      domcfg->image_info);
	if (rc < 0) {
		LOG_ERR("Error calling load_image_bytes rc: %d", rc);
		return rc;
	}

	/*
	 * We expect Image to be loaded only in RAM0 Bank
	 * ignoring space > GUEST_RAM0_SIZE
	 */
	if (mem_size > GUEST_RAM0_SIZE)
		mem_size = GUEST_RAM0_SIZE;

	if (sys_be32_to_cpu(uhdr.magic_be32) != UIMAGE_MAGIC)
		return -EINVAL;

	len = sys_be32_to_cpu(uhdr.size_be32);
	base_addr = sys_be32_to_cpu(uhdr.load_be32);
	if (base_addr < GUEST_RAM0_BASE ||
		base_addr > GUEST_RAM0_BASE + mem_size)
		return -EINVAL;

	if (base_addr + len > GUEST_RAM0_BASE + mem_size)
		return -EINVAL;

	return probe_zimage(domid, base_addr, sizeof(uhdr), domcfg, modules);
}

static int load_modules(int domid, struct xen_domain_cfg *domcfg,
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

static int share_domain_iomems(int domid, struct xen_domain_iomem *iomems,
			       int nr_iomem)
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

static int bind_domain_irqs(int domid, uint32_t *irqs, int nr_irqs)
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

static int assign_dtdevs(int domid, char *dtdevs[], int nr_dtdevs)
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

static void deinitialize_domain_xenstore(uint32_t domid)
{
	char uuid[INIT_XENSTORE_UUID_BUF_SIZE] = { 0 };
	char path[INIT_XENSTORE_BUFF_SIZE] = { 0 };

	// TODO: generate properly
	snprintf(uuid, INIT_XENSTORE_UUID_BUF_SIZE, "00000000-0000-0000-0000-%012d", domid);

	sprintf(path, "/local/domain/%d", domid);
	xss_rm(path);

	snprintf(path, INIT_XENSTORE_BUFF_SIZE, "/vm/%s", uuid);
	xss_rm(path);

	snprintf(path, INIT_XENSTORE_BUFF_SIZE, "/libxl/%d", domid);
	xss_rm(path);
}

/* According to: https://xenbits.xen.org/docs/unstable/man/xen-vbd-interface.7.html */
static int get_xvd_disk_id(const char *vname)
{
	int index, vname_length;
	int part = 0;

	if (!vname)
		return 0;

	vname_length = strlen(vname);

	if ((vname_length > 4) || strncmp(vname, "xvd", 3) ||
		vname[3] < 'a' || vname[3] > 'z')
		return 0;

	index = vname[3] - 'a';

	if (index > XEN_XVD_DP_DISK_MAX_INDEX)
		return 0;

	return XEN_XVD_DP_NOMINAL_TYPE | (index << 4) | part;
}

static int add_pvblock_xenstore(const struct pv_block_configuration *cfg, int domid)
{
	char lbuffer[INIT_XENSTORE_BUFF_SIZE] = { 0 };
	char rbuffer[INIT_XENSTORE_BUFF_SIZE] = { 0 };
	static const char basepref[] = "/local/domain";
	int rc, backendid, vbd_id;

	if (!cfg->configured)
		return 0;

	backendid = cfg->backend_domain_id;
	vbd_id = get_xvd_disk_id(cfg->vdev);

	if (!vbd_id)
		return -EINVAL;

	/* Backend domain part */

	sprintf(lbuffer, "%s/%d/backend", basepref, backendid);
	rc = xss_write_guest_domain_ro(lbuffer, "", backendid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vbd", basepref, backendid);
	rc = xss_write_guest_domain_ro(lbuffer, "", backendid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vbd/%d", basepref, backendid, domid);
	rc = xss_write_guest_domain_ro(lbuffer, "", backendid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vbd/%d/%d", basepref, backendid, domid, vbd_id);
	rc = xss_write_guest_with_permissions(lbuffer, "", backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vbd/%d/%d/frontend", basepref, backendid, domid, vbd_id);
	sprintf(rbuffer, "/local/domain/%d/device/vbd/%d", domid, vbd_id);
	rc = xss_write_guest_with_permissions(lbuffer, rbuffer, backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vbd/%d/%d/params", basepref, backendid, domid, vbd_id);
	rc = xss_write_guest_with_permissions(lbuffer, cfg->target, backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vbd/%d/%d/script", basepref, backendid, domid, vbd_id);
	rc = xss_write_guest_with_permissions(lbuffer, cfg->script, backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vbd/%d/%d/frontend-id", basepref, backendid, domid, vbd_id);
	sprintf(rbuffer, "%d", domid);
	rc = xss_write_guest_with_permissions(lbuffer, rbuffer, backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vbd/%d/%d/online", basepref, backendid, domid, vbd_id);
	rc = xss_write_guest_with_permissions(lbuffer, "1", backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vbd/%d/%d/removable", basepref, backendid, domid, vbd_id);
	rc = xss_write_guest_with_permissions(lbuffer, "0", backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vbd/%d/%d/bootable", basepref, backendid, domid, vbd_id);
	rc = xss_write_guest_with_permissions(lbuffer, "1", backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vbd/%d/%d/dev", basepref, backendid, domid, vbd_id);
	rc = xss_write_guest_with_permissions(lbuffer, cfg->vdev, backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vbd/%d/%d/type", basepref, backendid, domid, vbd_id);
	rc = xss_write_guest_with_permissions(lbuffer, cfg->backendtype, backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vbd/%d/%d/mode", basepref, backendid, domid, vbd_id);

	if (!strcmp("rw", cfg->access) || !strcmp("w", cfg->access)) {
		rc = xss_write_guest_with_permissions(lbuffer, "w", backendid, domid);
	} else if (!strcmp("ro", cfg->access) || !strcmp("r", cfg->access)) {
		rc = xss_write_guest_with_permissions(lbuffer, "r", backendid, domid);
	} else {
		LOG_ERR("Incorrect format of access field (%s). vdev %s target %s",
			cfg->access, cfg->vdev, cfg->target);
		return -EINVAL;
	}

	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vbd/%d/%d/device-type", basepref, backendid, domid, vbd_id);
	rc = xss_write_guest_with_permissions(lbuffer, "disk", backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vbd/%d/%d/discard-enable",
			basepref, backendid, domid, vbd_id);
	rc = xss_write_guest_with_permissions(lbuffer, "1", backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vbd/%d/%d/multi-queue-max-queues",
			basepref, backendid, domid, vbd_id);
	rc = xss_write_guest_with_permissions(lbuffer, "4", backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vbd/%d/%d/state", basepref, backendid, domid, vbd_id);
	rc = xss_write_guest_with_permissions(lbuffer, "1", backendid, domid);
	if (rc) {
		return rc;
	}

	/* Guest domain part */

	sprintf(lbuffer, "%s/%d/device/vbd/%d", basepref, domid, vbd_id);
	rc = xss_write_guest_with_permissions(lbuffer, "", domid, backendid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/device/vbd/%d/backend", basepref, domid, vbd_id);
	sprintf(rbuffer, "%s/%d/backend/vbd/%d/%d", basepref, backendid, domid, vbd_id);
	rc = xss_write_guest_with_permissions(lbuffer, rbuffer, domid, backendid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/device/vbd/%d/backend-id", basepref, domid, vbd_id);
	sprintf(rbuffer, "%d", backendid);
	rc = xss_write_guest_with_permissions(lbuffer, rbuffer, domid, backendid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/device/vbd/%d/virtual-device", basepref, domid, vbd_id);
	sprintf(rbuffer, "%d", vbd_id);
	rc = xss_write_guest_with_permissions(lbuffer, rbuffer, domid, backendid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/device/vbd/%d/device-type", basepref, domid, vbd_id);
	rc = xss_write_guest_with_permissions(lbuffer, "disk", domid, backendid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/device/vbd/%d/event-channel", basepref, domid, vbd_id);
	rc = xss_write_guest_with_permissions(lbuffer, "", domid, backendid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/device/vbd/%d/state", basepref, domid, vbd_id);
	rc = xss_write_guest_with_permissions(lbuffer, "1", domid, backendid);
	if (rc) {
		return rc;
	}

	return 0;
}

static int remove_xenstore_backends(int domid)
{
	char lbuffer[INIT_XENSTORE_BUFF_SIZE] = { 0 };
	static const char basepref[] = "/local/domain";
	int rc = 0, i;
	struct xen_domain *domain = NULL;

	domain = domid_to_domain(domid);

	for (i = 0; i < MAX_PV_NET_DEVICES; i++) {
		if (domain->back_state.vifs[i].functional) {
			/*
			 * Removing whole backend/vif/domainid node, if we have
			 * at least one fucntional vif backend.
			 */
			sprintf(lbuffer, "%s/%d/backend/vif/%d", basepref,
				domain->back_state.vifs[i].backend_domain_id, domid);
			rc = xss_rm(lbuffer);
			if (rc) {
				LOG_ERR("Failed to remove node  %s (rc=%d)", lbuffer, rc);
			}
			break;
		}
	}

	for (i = 0; i < MAX_PV_BLOCK_DEVICES; i++) {
		if (domain->back_state.disks[i].functional) {
			/*
			 * Removing whole backend/vbd/domainid node, if we have
			 * at least one fucntional vbd backend.
			 */
			sprintf(lbuffer, "%s/%d/backend/vbd/%d", basepref,
				domain->back_state.disks[i].backend_domain_id, domid);
			rc = xss_rm(lbuffer);
			if (rc) {
				LOG_ERR("Failed to remove node  %s (rc=%d)", lbuffer, rc);
			}
			break;
		}
	}

	memset(&domain->back_state, 0, sizeof(domain->back_state));

	return rc;
}

static int add_pvnet_xenstore(const struct pv_net_configuration *cfg, int domid, int instance_id)
{
	char lbuffer[INIT_XENSTORE_BUFF_SIZE] = { 0 };
	char rbuffer[INIT_XENSTORE_BUFF_SIZE] = { 0 };
	static const char basepref[] = "/local/domain";
	int rc, backendid;

	if (!cfg->configured)
		return 0;

	backendid = cfg->backend_domain_id;

	/* VIF Backend domain part */

	sprintf(lbuffer, "%s/%d/backend/vif", basepref, backendid);
	rc = xss_write_guest_with_permissions(lbuffer, "", backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vif/%d", basepref, backendid, domid);
	rc = xss_write_guest_with_permissions(lbuffer, "", backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vif/%d/%d", basepref, backendid, domid, instance_id);
	rc = xss_write_guest_with_permissions(lbuffer, "", backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vif/%d/%d/frontend",
			basepref, backendid, domid, instance_id);
	sprintf(rbuffer, "/local/domain/%d/device/vif/%d", domid, instance_id);
	rc = xss_write_guest_with_permissions(lbuffer, rbuffer, backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vif/%d/%d/frontend-id",
			basepref, backendid, domid, instance_id);
	sprintf(rbuffer, "%d", domid);
	rc = xss_write_guest_with_permissions(lbuffer, rbuffer, backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vif/%d/%d/online", basepref, backendid, domid, instance_id);
	rc = xss_write_guest_with_permissions(lbuffer, "1", backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vif/%d/%d/script", basepref, backendid, domid, instance_id);
	rc = xss_write_guest_with_permissions(lbuffer, cfg->script, backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vif/%d/%d/mac", basepref, backendid, domid, instance_id);
	rc = xss_write_guest_with_permissions(lbuffer, cfg->mac, backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vif/%d/%d/bridge", basepref, backendid, domid, instance_id);
	rc = xss_write_guest_with_permissions(lbuffer, cfg->bridge, backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vif/%d/%d/handle", basepref, backendid, domid, instance_id);
	sprintf(rbuffer, "%d", instance_id);
	rc = xss_write_guest_with_permissions(lbuffer, rbuffer, backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vif/%d/%d/type", basepref, backendid, domid, instance_id);
	rc = xss_write_guest_with_permissions(lbuffer, cfg->type, backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/backend/vif/%d/%d/hotplug-status",
			basepref, backendid, domid, instance_id);
	rc = xss_write_guest_with_permissions(lbuffer, "", backendid, domid);
	if (rc) {
		return rc;
	}

	if (cfg->ip[0]) {
		sprintf(lbuffer, "%s/%d/backend/vif/%d/%d/ip",
				basepref, backendid, domid, instance_id);
		rc = xss_write_guest_with_permissions(lbuffer, cfg->ip, backendid, domid);
		if (rc) {
			return rc;
		}
	}

	sprintf(lbuffer, "%s/%d/backend/vif/%d/%d/state", basepref, backendid, domid, instance_id);
	rc = xss_write_guest_with_permissions(lbuffer, "1", backendid, domid);
	if (rc) {
		return rc;
	}

	/* VIF domain part */

	sprintf(lbuffer, "%s/%d/device/vif", basepref, domid);
	rc = xss_write_guest_with_permissions(lbuffer, "", domid, backendid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/device/vif/%d", basepref, domid, instance_id);
	rc = xss_write_guest_with_permissions(lbuffer, "", domid, backendid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/device/vif/%d/backend", basepref, domid, instance_id);
	sprintf(rbuffer, "/local/domain/%d/backend/vif/%d/%d", backendid, domid, instance_id);
	rc = xss_write_guest_with_permissions(lbuffer, rbuffer, domid, backendid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/device/vif/%d/backend-id", basepref, domid, instance_id);
	sprintf(rbuffer, "%d", backendid);
	rc = xss_write_guest_with_permissions(lbuffer, rbuffer, domid, backendid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/device/vif/%d/handle", basepref, domid, instance_id);
	sprintf(rbuffer, "%d", instance_id);
	rc = xss_write_guest_with_permissions(lbuffer, rbuffer, domid, backendid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/device/vif/%d/mac", basepref, domid, instance_id);
	rc = xss_write_guest_with_permissions(lbuffer, cfg->mac, domid, backendid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/device/vif/%d/mtu", basepref, domid, instance_id);
	rc = xss_write_guest_with_permissions(lbuffer, "1500", backendid, domid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/device/vif/%d/multi-queue-num-queues",
			basepref, domid, instance_id);
	rc = xss_write_guest_with_permissions(lbuffer, "1", domid, backendid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/device/vif/%d/request-rx-copy", basepref, domid, instance_id);
	rc = xss_write_guest_with_permissions(lbuffer, "1", domid, backendid);
	if (rc) {
		return rc;
	}

	sprintf(lbuffer, "%s/%d/device/vif/%d/state", basepref, domid, instance_id);
	rc = xss_write_guest_with_permissions(lbuffer, "1", domid, backendid);

	return rc;
}

static int initialize_xenstore(uint32_t domid,
			       const struct xen_domain_cfg *domcfg,
			       const struct xen_domain *domain)
{
	char lbuffer[INIT_XENSTORE_BUFF_SIZE] = { 0 };
	char rbuffer[INIT_XENSTORE_BUFF_SIZE] = { 0 };
	char uuid[INIT_XENSTORE_UUID_BUF_SIZE];
	int rc;
	static const char basepref[] = "/local/domain";
	static const char * const rw_dirs[] = { "data",
			 "drivers",
			 "feature",
			 "attr",
			 "error",
			 "control/shutdown",
			 "control/feature-poweroff",
			 "control/feature-reboot",
			 "control/feature-suspend",
			 "control/sysrq",
			 "device/suspend/event-channel",
			 NULL };

	// TODO: generate properly
	snprintf(uuid, INIT_XENSTORE_UUID_BUF_SIZE, "00000000-0000-0000-0000-%012d", domid);

	for (int i = 0; i < domcfg->max_vcpus; ++i) {
		sprintf(lbuffer, "%s/%d/cpu/%d/availability", basepref, domid, i);
		rc = xss_write_guest_domain_ro(lbuffer, "online", domid);
		if (rc) {
			goto deinit;
		}
	}

	sprintf(lbuffer, "%s/%d/memory/static-max", basepref, domid);
	sprintf(rbuffer, "%lld", domain->max_mem_kb);
	rc = xss_write_guest_domain_ro(lbuffer, rbuffer, domid);
	if (rc) {
		goto deinit;
	}

	sprintf(lbuffer, "%s/%d/memory/target", basepref, domid);
	rc = xss_write_guest_domain_ro(lbuffer, rbuffer, domid);
	if (rc) {
		goto deinit;
	}

	sprintf(lbuffer, "%s/%d/memory/videoram", basepref, domid);
	rc = xss_write_guest_domain_ro(lbuffer, "-1", domid);
	if (rc) {
		goto deinit;
	}

	sprintf(lbuffer, "%s/%d/control/platform-feature-multiprocessor-suspend", basepref, domid);
	rc = xss_write_guest_domain_ro(lbuffer, "1", domid);
	if (rc) {
		goto deinit;
	}

	sprintf(lbuffer, "%s/%d/control/platform-feature-xs_reset_watches", basepref, domid);
	rc = xss_write_guest_domain_ro(lbuffer, "1", domid);
	if (rc) {
		goto deinit;
	}

	sprintf(lbuffer, "%s/%d/vm", basepref, domid);
	rc = xss_write_guest_domain_ro(lbuffer, uuid, domid);
	if (rc) {
		goto deinit;
	}

	sprintf(lbuffer, "/vm/%s/name", uuid);
	if (domain->name[0]) {
		snprintf(rbuffer, INIT_XENSTORE_BUFF_SIZE, "%s", domain->name);
	} else {
		sprintf(rbuffer, "zephyr-%d", domid);
	}
	rc = xss_write_guest_domain_ro(lbuffer, rbuffer, domid);
	if (rc) {
		goto deinit;
	}

	sprintf(lbuffer, "%s/%d/name", basepref, domid);
	rc = xss_write_guest_domain_ro(lbuffer, rbuffer, domid);
	if (rc) {
		goto deinit;
	}

	sprintf(lbuffer, "/vm/%s/start_time", uuid);
	rc = xss_write_guest_domain_ro(lbuffer, "0", domid);
	if (rc) {
		goto deinit;
	}

	sprintf(lbuffer, "/vm/%s/uuid", uuid);
	rc = xss_write_guest_domain_ro(lbuffer, uuid, domid);
	if (rc) {
		goto deinit;
	}

	sprintf(lbuffer, "%s/%d/domid", basepref, domid);
	sprintf(rbuffer, "%d", domid);
	rc = xss_write_guest_domain_ro(lbuffer, rbuffer, domid);
	if (rc) {
		goto deinit;
	}

	sprintf(lbuffer, "%s/%d/control", basepref, domid);
	rc = xss_write_guest_domain_ro(lbuffer, "", domid);
	if (rc) {
		goto deinit;
	}

	sprintf(lbuffer, "%s/%d/device/vbd", basepref, domid);
	rc = xss_write_guest_domain_ro(lbuffer, "", domid);
	if (rc) {
		goto deinit;
	}

	for (int i = 0; rw_dirs[i]; ++i) {
		sprintf(lbuffer, "%s/%d/%s", basepref, domid, rw_dirs[i]);
		rc = xss_write_guest_domain_rw(lbuffer, "", domid);
		if (rc) {
			goto deinit;
		}
	}

	sprintf(lbuffer, "/libxl/%d/dm-version", domid);
	rc = xss_write(lbuffer, "qemu_xen_traditional");
	if (rc) {
		goto deinit;
	}

	sprintf(lbuffer, "/libxl/%d/type", domid);
	rc = xss_write(lbuffer, "pvh");
	if (rc) {
		goto deinit;
	}

	return 0;

deinit:
	deinitialize_domain_xenstore(domid);
	LOG_ERR("Failed to initialize xenstore for domid#%u (rc=%d)", domid, rc);
	return rc;
}

static int initialize_dom0_xenstore(__attribute__ ((unused)) const struct device *dev)
{
	int ret = 0;
	struct xen_domain_cfg *dom0cfg = NULL;
	struct xen_domain *dom0 = NULL;
#ifdef CONFIG_XSTAT
	struct xenstat_domain *dom0stat = NULL;

	dom0stat = k_malloc(sizeof(struct xenstat_domain));
	if (!dom0stat) {
		ret = -ENOMEM;
		LOG_ERR("Can't allocate memory (line=%d)", __LINE__);
		goto out;
	}
	ret = xstat_getdominfo(dom0stat, 0, 1);
	if (ret < 0) {
		LOG_ERR("Failed to get info for dom0 (rc=%d)", ret);
		goto out;
	}
	if (ret == 0) {
		/* Theoretically impossible */
		ret = -EINVAL;
		goto out;
	}
#endif
	dom0cfg = k_malloc(sizeof(struct xen_domain_cfg));
	memset(dom0cfg, 0, sizeof(*dom0cfg));
	dom0 = k_malloc(sizeof(struct xen_domain));
	memset(dom0, 0, sizeof(*dom0));
	if (!dom0cfg || !dom0) {
		ret = -ENOMEM;
		LOG_ERR("Can't allocate memory (line=%d)", __LINE__);
		goto out;
	}
	snprintf(dom0cfg->name, CONTAINER_NAME_SIZE, "%s", DOM0_NAME);
	snprintf(dom0->name, CONTAINER_NAME_SIZE, "%s", DOM0_NAME);
#ifdef CONFIG_XSTAT
	dom0cfg->max_vcpus = dom0stat->num_vcpus;
	dom0cfg->mem_kb = dom0stat->cur_mem / 1024;
	dom0->max_mem_kb = dom0stat->cur_mem / 1024;
#else
	dom0cfg->max_vcpus = 0;
	dom0cfg->mem_kb = 0;
	dom0->max_mem_kb = 0;
#endif
	xss_write("/tool/xenstored", "");
	ret = initialize_xenstore(0, dom0cfg, dom0);
out:
#ifdef CONFIG_XSTAT
	k_free(dom0stat);
#endif
	k_free(dom0cfg);
	k_free(dom0);
	return ret;
}

int domain_create(struct xen_domain_cfg *domcfg, uint32_t domid)
{
	int rc = 0;
	struct xen_domctl_createdomain config;
	struct vcpu_guest_context vcpu_ctx;
	struct xen_domain *domain;
	struct modules_address modules = {0};

	if (dom_num >= CONFIG_DOM_MAX) {
		LOG_ERR("Runtime exceeds maximum number of domains");
		return -EINVAL;
	}

	memset(&config, 0, sizeof(config));
	prepare_domain_cfg(domcfg, &config);
	config.grant_opts = XEN_DOMCTL_GRANT_version(1);
	rc = xen_domctl_createdomain(domid, &config);
	if (rc) {
		LOG_ERR("Failed to create domain#%u (rc=%d)", domid, rc);
		return rc;
	}

	domain = k_malloc(sizeof(*domain));
	if (domain == NULL) {
		LOG_ERR("Can not allocate memory for domain#%u struct", domid);
		goto destroy_domain;
	}
	memset(domain, 0, sizeof(*domain));
	domain->domid = domid;

	snprintf(domain->name, CONTAINER_NAME_SIZE, "%s", domcfg->name);
	rc = xen_domctl_max_vcpus(domid, domcfg->max_vcpus);
	if (rc) {
		LOG_ERR("Failed to set max vcpus for domain#%u (rc=%d)", domid, rc);
		goto domain_free;
	}
	domain->num_vcpus = domcfg->max_vcpus;

	rc = xen_domctl_set_address_size(domid, 64);
	if (rc) {
		LOG_ERR("Failed to set adress size for domain#%u (rc=%d)", domid, rc);
		goto domain_free;
	}
	domain->address_size = 64;

	domain->max_mem_kb = domcfg->mem_kb + (domcfg->gnt_frames + NR_MAGIC_PAGES) * XEN_PAGE_SIZE;
	rc = xen_domctl_max_mem(domid, domain->max_mem_kb);
	if (rc) {
		LOG_ERR("Failed to set max memory for domain#%u (rc=%d)", domid, rc);
		goto domain_free;
	}

	/* Calculation according to xl.cfg manual for shadow memory (1MB/CPU + 8KB for every 1MB RAM */
	rc = xen_domctl_set_paging_mempool_size(domid, domcfg->max_vcpus * 1024 * 1024 + 8 * domcfg->mem_kb);
	if (rc) {
		LOG_ERR("Failed to set paging mempool size for domain#%u (rc=%d)", domid, rc);
		goto domain_free;
	}

	rc = allocate_domain_evtchns(domain);
	if (rc) {
		LOG_ERR("Failed to allocate event channel for domain#%u (rc=%d)", domid, rc);
		goto domain_free;
	}

	rc = load_modules(domid, domcfg, &modules);
	if (rc) {
		LOG_ERR("Unable to load image for domain#%u, insufficient memory (rc=%d)", domid, rc);
		goto domain_free;
	}
	if (!modules.ventry) {
		LOG_ERR("Modules ventry is not set");
		rc = -EINVAL;
		goto domain_free;
	}

	rc = share_domain_iomems(domid, domcfg->iomems, domcfg->nr_iomems);
	if (rc) {
		LOG_ERR("Unable to share domain#%u iomems (rc=%d)", domid, rc);
		goto domain_free;
	}

	rc = bind_domain_irqs(domid, domcfg->irqs, domcfg->nr_irqs);
	if (rc) {
		LOG_ERR("Failed to bind irq for domain#%u (rc=%d)", domid, rc);
		goto domain_free;
	}

	rc = assign_dtdevs(domid, domcfg->dtdevs, domcfg->nr_dtdevs);
	if (rc) {
		LOG_ERR("Failed to assign dtdevs for domain#%u (rc=%d)", domid, rc);
		goto domain_free;
	}

	memset(&vcpu_ctx, 0, sizeof(vcpu_ctx));
	vcpu_ctx.user_regs.x0 = modules.dtb_addr;
	vcpu_ctx.user_regs.pc64 = modules.ventry;
	vcpu_ctx.user_regs.cpsr = PSR_GUEST64_INIT;
	vcpu_ctx.sctlr = SCTLR_GUEST_INIT;
	vcpu_ctx.flags = VGCF_online;

	rc = xen_domctl_setvcpucontext(domid, 0, &vcpu_ctx);
	if (rc) {
		LOG_ERR("Failed to set VCPU context for domain#%u (rc=%d)", domid, rc);
		goto domain_free;
	}

	rc = start_domain_stored(domain);
	if (rc) {
		LOG_ERR("Failed to start domain#%u stored (rc=%d)", domid, rc);
		goto domain_free;
	}

#ifdef CONFIG_XEN_CONSOLE_SRV
	rc = xen_start_domain_console(domain);
	if (rc) {
		LOG_ERR("Failed to start domain#%u console (rc=%d)", domid, rc);
		goto free_domain_stored;
	}
#endif

	rc = initialize_xenstore(domid, domcfg, domain);
	if (rc) {
		goto stop_domain_console;
	}

	if (domid == DOMID_DOMD) {
		rc = xen_domctl_unpausedomain(domid);
		if (rc) {
			LOG_ERR("Failed to unpause domain#%u (rc=%d)", domid, rc);
			goto stop_domain_console;
		}
	} else {
		LOG_INF("Created domain is paused\nTo unpause issue: xu unpause -d %u", domid);
	}

	k_mutex_lock(&dl_mutex, K_FOREVER);
	sys_dnode_init(&domain->node);
	sys_dlist_append(&domain_list, &domain->node);
	++dom_num;
	k_mutex_unlock(&dl_mutex);

	return rc;

stop_domain_console:
#ifdef CONFIG_XEN_CONSOLE_SRV
	xen_stop_domain_console(domain);
free_domain_stored:
#endif
	stop_domain_stored(domain);
domain_free:
	k_free(domain);
destroy_domain:
	xen_domctl_destroydomain(domid);

	return rc;
}

int domain_destroy(uint32_t domid)
{
	int rc, err = 0;
	struct xen_domain *domain = NULL;

	domain = domid_to_domain(domid);
	if (!domain) {
		LOG_ERR("Domain with domid#%u is not found", domid);
		/* Domain with requested domid is not present in list */
		return -EINVAL;
	}

	rc = remove_xenstore_backends(domid);
	if (rc) {
		LOG_ERR("Failed to remove_xenstore_backends domain#%u (rc=%d)", domain->domid, rc);
		err = rc;
	}

	rc = stop_domain_stored(domain);
	if (rc) {
		LOG_ERR("Failed to stop domain#%u store (rc=%d)", domain->domid, rc);
		err = rc;
	}

	deinitialize_domain_xenstore(domid);

#ifdef CONFIG_XEN_CONSOLE_SRV
	rc = xen_stop_domain_console(domain);
	if (rc) {
		LOG_ERR("Failed to stop domain#%u console (rc=%d)", domain->domid, rc);
		err = rc;
	}
#endif

	rc = xen_domctl_destroydomain(domid);
	if (rc) {
		LOG_ERR("Failed to destroy domain#%u (rc=%d)", domain->domid, rc);
		err = rc;
	}

	k_mutex_lock(&dl_mutex, K_FOREVER);
	sys_dlist_remove(&domain->node);
	--dom_num;
	k_mutex_unlock(&dl_mutex);

	k_free(domain);

	return err;
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

int domain_post_create(const struct xen_domain_cfg *domcfg, uint32_t domid)
{
	int rc, i;
	struct xen_domain *domain = NULL;
	struct backends_state *bs = NULL;
	const struct backend_configuration *bc = NULL;

	domain = domid_to_domain(domid);
	bs = &domain->back_state;
	bc = &domcfg->back_cfg;

	for (i = 0; i < MAX_PV_BLOCK_DEVICES; i++) {
		if (bc->disks[i].configured) {
			rc = add_pvblock_xenstore(&bc->disks[i], domid);
			if (rc) {
				LOG_ERR("Failed to initialize pvblock for domid#%u (rc=%d)",
					domid, rc);
				goto deinit;
			}
			bs->disks[i].functional = true;
			bs->disks[i].backend_domain_id = bc->disks[i].backend_domain_id;
		}
	}

	for (i = 0; i < MAX_PV_NET_DEVICES; i++) {
		if (bc->vifs[i].configured) {
			rc = add_pvnet_xenstore(&bc->vifs[i], domid, i);
			if (rc) {
				LOG_ERR("Failed to initialize pvnet for domid#%u (rc=%d)",
					domid, rc);
				goto deinit;
			}
			bs->vifs[i].functional = true;
			bs->vifs[i].backend_domain_id = bc->vifs[i].backend_domain_id;
		}
	}

	return 0;

deinit:
	LOG_ERR("Failed to initialize xenstore for domid#%u (rc=%d)", domid, rc);
	domain_destroy(domid);
	return rc;
}

SYS_INIT(initialize_dom0_xenstore, APPLICATION, DOM0_XENSTORE_PRIORITY);
