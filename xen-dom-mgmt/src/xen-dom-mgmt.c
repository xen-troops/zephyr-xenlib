/*
 * Copyright (c) 2021 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#undef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200809L

#include <zephyr/sys/byteorder.h>
#include <zephyr/xen/dom0/domctl.h>
#include <zephyr/xen/dom0/sysctl.h>
#include <zephyr/xen/hvm.h>
#include <zephyr/logging/log.h>

#include <xen-dom-fdt.h>
#include <xen-dom-xs.h>
#include <xen_dom_mgmt.h>
#include <mem-mgmt.h>
#include <uimage.h>
#include <zimage.h>

#ifdef CONFIG_XEN_CONSOLE_SRV
#include <xen_console.h>
#endif
#include <xss.h>
#ifdef CONFIG_XSTAT
#include <xstat.h>
#endif

LOG_MODULE_REGISTER(xen_dom_mgmt);

struct modules_address {
  uint64_t ventry;
  uint64_t dtb_addr;
};

/* Number of active domains, used as an indicator to not exhaust allocated stack area.
 * This variable used during shell command execution, thus requires no sync. */
static int dom_num = 0;

/* Define major and minor versions if was not provided */
#ifndef XEN_VERSION_MAJOR
#define XEN_VERSION_MAJOR 4
#endif

#ifndef XEN_VERSION_MINOR
#define XEN_VERSION_MINOR 16
#endif

static sys_dlist_t domain_list = SYS_DLIST_STATIC_INIT(&domain_list);
K_MUTEX_DEFINE(dl_mutex);
K_MUTEX_DEFINE(create_mutex);

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
	create->ssidref = dom_cfg->ssidref;

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
		DIV_ROUND_UP(cfg->mem_kb * 1024, PFN_2M_SIZE);

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
	uint64_t nr_pages = DIV_ROUND_UP(dtb_size, XEN_PAGE_SIZE);
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

	nr_pages = DIV_ROUND_UP(domain_size, XEN_PAGE_SIZE);
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

struct xen_domain *get_domain(uint32_t domid)
{
	struct xen_domain *iter;

	k_mutex_lock(&dl_mutex, K_FOREVER);
	SYS_DLIST_FOR_EACH_CONTAINER (&domain_list, iter, node) {
		if (iter->domid == domid) {
			iter->refcount++;
			break;
		}
	}
	k_mutex_unlock(&dl_mutex);
	return iter;
}

void put_domain(struct xen_domain *domain)
{
	int rc;

	if (!domain) {
		LOG_ERR("Domain is NULL");
		return;
	}
	__ASSERT(!domain->f_dom0less, "dom0less domain#%u operation not supported", domain->domid);

	k_mutex_lock(&dl_mutex, K_FOREVER);
	domain->refcount--;
	if (domain->refcount == 0) {
		rc = xs_remove_xenstore_backends(domain);
		if (rc) {
			LOG_ERR("Failed to remove_xenstore_backends domain#%u (rc=%d)",
					domain->domid, rc);
		}

		rc = stop_domain_stored(domain);
		if (rc) {
			LOG_ERR("Failed to stop domain#%u store (rc=%d)", domain->domid, rc);
		}

		xs_deinitialize_domain_xenstore(domain->domid);

	#ifdef CONFIG_XEN_CONSOLE_SRV
		rc = xen_stop_domain_console(domain);
		if (rc) {
			LOG_ERR("Failed to stop domain#%u console (rc=%d)", domain->domid, rc);
		}
	#endif

		rc = xen_domctl_destroydomain(domain->domid);
		if (rc) {
			LOG_ERR("Failed to destroy domain#%u (rc=%d)", domain->domid, rc);
		}

		sys_dlist_remove(&domain->node);
		--dom_num;
		k_free(domain);
	}
	k_mutex_unlock(&dl_mutex);
}

struct xen_domain_cfg *domain_find_config(const char *name)
{
	__maybe_unused struct xen_domain_cfg *cfg = NULL;
	int i;

	for (i = 0; i < domain_get_user_cfg_count(); i++) {
		cfg = domain_get_user_cfg(i);
		if (strncmp(cfg->name, name, CONTAINER_NAME_SIZE) == 0) {
			return cfg;
		}
	}

#ifdef CONFIG_XEN_DOMCFG_SECTION
	for (cfg = _domain_configs_start; cfg < _domain_configs_end; cfg++) {
		if (strncmp(cfg->name, name, CONTAINER_NAME_SIZE) == 0) {
			return cfg;
		}
	}
#endif

	return NULL;
}

int get_domain_name(unsigned short domain_id, char *name, int len)
{
#ifdef CONFIG_XEN_STORE_SRV
	char path[sizeof("/local/domain/32768/name")];

	snprintf(path, sizeof(path), "/local/domain/%u/name", domain_id);
	return xss_read(path, name, len);
#else
	return -EINVAL;
#endif
}

uint32_t find_domain_by_name(char *arg)
{
	char domname[CONTAINER_NAME_SIZE];
	struct xen_domctl_getdomaininfo infos[CONFIG_DOM_MAX];
	uint32_t domid = 0;
	int i, ret;

	ret = xen_sysctl_getdomaininfo(infos, 0, CONFIG_DOM_MAX);
	if (ret < 0) {
		goto out;
	}

	for (i = 0; i < ret; i++) {
		if (!get_domain_name(infos[i].domain, domname,
					    CONTAINER_NAME_SIZE)) {
			if (strncmp(domname, arg, CONTAINER_NAME_SIZE) == 0) {
				domid = infos[i].domain;
				break;
			}
		}
	}

out:
	return domid;
}

__weak int domain_get_user_cfg_count(void)
{
	return 0;
}

__weak struct xen_domain_cfg *domain_get_user_cfg(int index)
{
	ARG_UNUSED(index);
	return NULL;
}

int domain_create(struct xen_domain_cfg *domcfg, uint32_t domid)
{
	int rc = 0;
	struct xen_domctl_createdomain config;
	struct vcpu_guest_context vcpu_ctx;
	struct xen_domain *domain;
	struct modules_address modules = {0};
	char *name;

	if (dom_num >= CONFIG_DOM_MAX) {
		LOG_ERR("Runtime exceeds maximum number of domains");
		return -EINVAL;
	}

	memset(&config, 0, sizeof(config));
	prepare_domain_cfg(domcfg, &config);
	config.grant_opts = XEN_DOMCTL_GRANT_version(1);
	rc = xen_domctl_createdomain(&domid, &config);
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
	/* Fallback to name if domain_name is not set */
	if (strnlen(domcfg->domain_name, CONTAINER_NAME_SIZE) > 0) {
		name = domcfg->domain_name;
	} else {
		name = domcfg->name;
	}

	snprintf(domain->name, CONTAINER_NAME_SIZE, "%s", name);
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

	rc = start_domain_stored(domain, XEN_PHYS_PFN(GUEST_MAGIC_BASE) + XENSTORE_PFN_OFFSET);
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

	k_mutex_lock(&create_mutex, K_FOREVER);
	if (find_domain_by_name(name) != 0) {
		rc = -EEXIST;
		LOG_ERR("Domain with name %s already exists", name);
		k_mutex_unlock(&create_mutex);
		goto stop_domain_console;
	}

	rc = xs_initialize_xenstore(domid, domain);
	k_mutex_unlock(&create_mutex);

	if (rc) {
		goto stop_domain_console;
	}

	if (!domcfg->f_paused) {
		rc = xen_domctl_unpausedomain(domid);
		if (rc) {
			LOG_ERR("Failed to unpause domain#%u (rc=%d)", domid, rc);
			goto stop_domain_console;
		}
	}

	k_mutex_lock(&dl_mutex, K_FOREVER);
	domain->refcount = 1;
	sys_dnode_init(&domain->node);
	sys_dlist_append(&domain_list, &domain->node);
	++dom_num;
	k_mutex_unlock(&dl_mutex);

	if (rc) {
		return rc;
	}

	return domid;

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
	struct xen_domain *domain = NULL;

	domain = get_domain(domid);
	if (!domain) {
		LOG_ERR("Domain with domid#%u is not found", domid);
		/* Domain with requested domid is not present in list */
		return -EINVAL;
	}

	/* Call put domain twice to drop the original reference and trigger freeing */
	put_domain(domain);
	put_domain(domain);

	return 0;
}

int domain_pause(uint32_t domid)
{
	int rc;
	struct xen_domain *domain = NULL;

	domain = get_domain(domid);
	if (!domain) {
		LOG_ERR("Domain with domid#%u is not found", domid);
		/* Domain with requested domid is not present in list */
		return -EINVAL;
	}

	rc = xen_domctl_pausedomain(domid);
	if (rc) {
		LOG_ERR("domain:%u pause failed (%d)", domid, rc);
	}
	put_domain(domain);

	return rc;
}

int domain_unpause(uint32_t domid)
{
	struct xen_domain *domain = NULL;
	int rc;

	domain = get_domain(domid);
	if (!domain) {
		LOG_ERR("Domain with domid#%u is not found", domid);
		/* Domain with requested domid is not present in list */
		return -EINVAL;
	}

	rc = xen_domctl_unpausedomain(domid);
	if (rc) {
		LOG_ERR("domain:%u unpause failed (%d)", domid, rc);
	}

	put_domain(domain);
	return rc;
}

int domain_post_create(const struct xen_domain_cfg *domcfg, uint32_t domid)
{
	int rc, i;
	struct xen_domain *domain = NULL;
	struct backends_state *bs = NULL;
	const struct backend_configuration *bc = NULL;

	domain = get_domain(domid);
	bs = &domain->back_state;
	bc = &domcfg->back_cfg;

	for (i = 0; i < MAX_PV_BLOCK_DEVICES; i++) {
		if (bc->disks[i].configured) {
			rc = xs_add_pvblock_xenstore(&bc->disks[i], domid);
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
			rc = xs_add_pvnet_xenstore(&bc->vifs[i], domid, i);
			if (rc) {
				LOG_ERR("Failed to initialize pvnet for domid#%u (rc=%d)",
					domid, rc);
				goto deinit;
			}
			bs->vifs[i].functional = true;
			bs->vifs[i].backend_domain_id = bc->vifs[i].backend_domain_id;
		}
	}

	put_domain(domain);
	return 0;

deinit:
	put_domain(domain);
	LOG_ERR("Failed to initialize xenstore for domid#%u (rc=%d)", domid, rc);
	domain_destroy(domid);
	return rc;
}

#ifdef CONFIG_XEN_DOM0LESS_BOOT
static int dom0less_get_next_domain(uint32_t domid_start, struct xen_domctl_getdomaininfo *info)
{
	int i, rc;

	__ASSERT_NO_MSG(info);

	for (i = domid_start; i < CONFIG_DOM_MAX; i++) {
		rc = xen_domctl_getdomaininfo(i, info);
		if (rc && rc != -ESRCH) {
			LOG_ERR("dom0less: getdomaininfo err (%d)", rc);
			break;
		}
		if (!rc) {
			break;
		}
	}

	return rc ? rc : i;
}

static int dom0less_init_domain(uint32_t domid, struct xen_domctl_getdomaininfo *infos)
{
	struct xen_domain *domain;
	xen_pfn_t magic_base_pfn;
	uint64_t value;
	int rc;

	domain = k_malloc(sizeof(*domain));
	if (!domain) {
		LOG_ERR("dom0less:domid:%u Can not allocate memory for domain", domid);
		return -ENOMEM;
	}
	memset(domain, 0, sizeof(*domain));

	domain->domid = domid;
	domain->num_vcpus = infos->max_vcpu_id + 1;
	domain->address_size = 64;
	domain->max_mem_kb = (infos->tot_pages * XEN_PAGE_SIZE) / 1024;
	domain->f_dom0less = true;

	snprintf(domain->name, CONTAINER_NAME_SIZE, "Dom0less-%u", domid);

	/*
	 * Xenstore initialization.
	 * In dom0less boot case the Xenstore event is already allocated and also allocated
	 * XEN_MAGIC pages, so Dom0 here should get them and use to init Xenstore.
	 * At the end Dom0 should set HVM_PARAM_STORE_PFN
	 * to notify guest domain that Xenstore is ready.
	 */
	rc = hvm_get_parameter(HVM_PARAM_STORE_EVTCHN, domain->domid, &value);
	if (rc) {
		LOG_ERR("dom0less:domid:%u Get HVM_PARAM_STORE_EVTCHN err (%d)", domid, rc);
		goto err_free;
	}
	domain->xenstore.remote_evtchn = value;

	LOG_DBG("dom0less: remote_domid=%d, xenstore.remote_evtchn = %d", domain->domid,
		domain->xenstore.remote_evtchn);

	rc = hvm_get_parameter(HVM_PARAM_MAGIC_BASE_PFN, domid, &magic_base_pfn);
	if (rc < 0) {
		LOG_ERR("dom0less:domid:%u Get HVM_PARAM_MAGIC_BASE_PFN err (%d)", domid, rc);
		goto err_free;
	}

	LOG_DBG("dom0less:domid:%u MAGIC_BASE_PFN %llx", domid, magic_base_pfn);
	magic_base_pfn = magic_base_pfn + XENSTORE_PFN_OFFSET;

	/* init Xenstore */
	rc = start_domain_stored(domain, magic_base_pfn);
	if (rc) {
		LOG_ERR("dom0less:domid:%u start Xenstore err (%d)", domid, rc);
		goto err_free;
	}

	rc = hvm_set_parameter(HVM_PARAM_STORE_PFN, domid, magic_base_pfn);
	if (rc) {
		LOG_ERR("dom0less:domid:%u set HVM_PARAM_STORE_PFN err (%d)", domid, rc);
		goto err_free_stored;
	}

	rc = xs_initialize_xenstore(domid, domain);
	if (rc) {
		LOG_ERR("dom0less:domid:%u init Xenstore err (%d)", domid, rc);
		goto err_free_stored;
	}

	notify_evtchn(domain->xenstore.remote_evtchn);

	LOG_DBG("dom0less:domid:%u attached", domid);

	k_mutex_lock(&dl_mutex, K_FOREVER);
	sys_dnode_init(&domain->node);
	sys_dlist_append(&domain_list, &domain->node);
	++dom_num;
	k_mutex_unlock(&dl_mutex);

	/* TODO: console ? */
	return 0;

err_free_stored:
	stop_domain_stored(domain);
err_free:
	k_free(domain);
	return rc;
}

static int dom0less_init(void)
{
	struct xen_domctl_getdomaininfo dominfo;
	uint32_t created_doms = 0;
	uint32_t domid_start = 1;
	int rc;

	do {
		rc = dom0less_get_next_domain(domid_start, &dominfo);
		if (rc < 0) {
			break;
		}
		domid_start = rc;

		rc = dom0less_init_domain(domid_start, &dominfo);
		if (rc) {
			break;
		}

		domid_start++;
		created_doms++;
	} while (rc < CONFIG_DOM_MAX);

	LOG_INF("dom0less: attached %d domains", created_doms);

	return rc == -ESRCH ? 0 : rc;
}
#endif /* CONFIG_XEN_DOM0LESS_BOOT */

static int init_domain0(void)
{
	struct xen_domctl_getdomaininfo dominfo;
	int ret = 0;
	struct xen_domain *dom0 = NULL;

	ret = xen_domctl_getdomaininfo(0, &dominfo);
	if (ret) {
		LOG_ERR("init: getdomaininfo err (%d)", ret);
		return ret;
	}

	dom0 = k_malloc(sizeof(*dom0));
	if (!dom0) {
		ret = -ENOMEM;
		LOG_ERR("Can't allocate memory for dom0 domain struct");
		goto out;
	}
	memset(dom0, 0, sizeof(*dom0));

	snprintf(dom0->name, CONTAINER_NAME_SIZE, "%s", DOM0_NAME);
	dom0->domid = 0;
	dom0->num_vcpus = dominfo.max_vcpu_id + 1;
	dom0->max_mem_kb = (dominfo.tot_pages * XEN_PAGE_SIZE) / 1024;

	ret = xs_init_root();
	if (ret) {
		LOG_ERR("Failed to init Xenstore root node");
		goto out;
	}

	ret = xss_write("/tool/xenstored", "");
	if (ret) {
		LOG_ERR("Failed to create /tool/xenstored node, err = %d", ret);
	}

	ret = xs_initialize_xenstore(0, dom0);
	if (ret) {
		LOG_ERR("Failed to add Domain-0 xenstore entries, err = %d", ret);
	}

#ifdef CONFIG_XEN_DOM0LESS_BOOT
	ret = dom0less_init();
#endif /* CONFIG_XEN_DOM0LESS_BOOT */

out:
	k_free(dom0);

	return ret;
}

SYS_INIT(init_domain0, APPLICATION, CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);
