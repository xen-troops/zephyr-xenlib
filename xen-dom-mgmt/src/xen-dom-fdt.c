// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2023 EPAM Systems
 */
#include <assert.h>
#include <errno.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zephyr/logging/log.h>

#include "domain.h"

LOG_MODULE_DECLARE(xen_dom_mgmt);

#if defined(CONFIG_XEN_LIBFDT)

#include <zephyr/xen/dom0/domctl.h>
#include <zephyr/xen/public/xen.h>

#include <libfdt.h>
#include <xen-dom-fdt.h>

#define GUEST_GIC_PHANDLE (65000)
#define GUEST_ROOT_ADDRESS_CELLS 2
#define GUEST_ROOT_SIZE_CELLS 2
#define FDT_STRING_MAX 50
#define DT_IRQ_TYPE_LEVEL_LOW 0x00000008

#define ALIGN_UP_TO_2MB(x) (((x) + MB(2) - 1) & (~(MB(2) - 1)))
#define EXT_REGION_MIN_SIZE xen_mk_ullong(0x0004000000) /* 64MB */

#define ZSNPRINTF(res, name, size, format, args...) \
	do { \
		memset(name, 0, size); \
		res = snprintf(name, size, format, ##args); \
	} while (0)

#ifndef CONFIG_PARTIAL_DEVICE_TREE_SIZE
#warning "CONFIG_PARTIAL_DEVICE_TREE_SIZE was not set. Using default"
#define CONFIG_PARTIAL_DEVICE_TREE_SIZE 8192
#endif /* CONFIG_PARTIAL_DEVICE_TREE_SIZE */

typedef uint32_t gic_interrupt[3];

static int fdt_property_compat(void *fdt, unsigned int nr_compat, ...)
{
	const char *compats[nr_compat];
	int i;
	size_t sz;
	va_list ap;
	char compat[FDT_STRING_MAX], *p;

	va_start(ap, nr_compat);
	sz = 0;
	for (i = 0; i < nr_compat; i++) {
		const char *c = va_arg(ap, const char *);

		compats[i] = c;
		sz += strlen(compats[i]) + 1;
	}
	va_end(ap);

	if (sz > FDT_STRING_MAX) {
		LOG_ERR("Compatible string is too long");
		return -ENOMEM;
	}

	p = compat;
	memset(compat, 0, sz);

	for (i = 0; i < nr_compat; i++) {
		strcpy(p, compats[i]);
		p += strlen(compats[i]) + 1;
	}

	return fdt_property(fdt, "compatible", compat, sz);
}

static void set_cell(uint32_t **cellp, int size, uint64_t val)
{
	int cells = size;

	while (size--) {
		(*cellp)[size] = cpu_to_fdt32(val);
		val >>= 32;
	}

	(*cellp) += cells;
}

static void set_range(uint32_t **cellp, int address_cells, int size_cells,
					  uint64_t address, uint64_t size)
{
	set_cell(cellp, address_cells, address);
	set_cell(cellp, size_cells, size);
}

static int fdt_property_interrupts(void *fdt, gic_interrupt *intr,
				  unsigned int num_irq)
{
	int res;

	res = fdt_property(fdt, "interrupts", intr, sizeof(intr[0]) * num_irq);
	if (res)
		return res;

	res = fdt_property_cell(fdt, "interrupt-parent", GUEST_GIC_PHANDLE);
	if (res)
		return res;

	return 0;
}

static int create_root(int major, int minor, void *fdt, struct xen_domain_cfg *domcfg)
{
	int res;
	char buf[FDT_STRING_MAX];

	ZSNPRINTF(res, buf, FDT_STRING_MAX, "XENVM-%d.%d", major, minor);
	if (!res)
		return -ENOMEM;

	res = fdt_property_string(fdt, "model", buf);
	if (res)
		return res;

	ZSNPRINTF(res, buf, FDT_STRING_MAX, "xen,xenvm-%d.%d", major, minor);
	if (!res)
		return -ENOMEM;

	/* Check if custom machine compatible is not empty and use it */
	if (domcfg->machine_dt_compat) {
		res = fdt_property_compat(fdt, 2, buf, domcfg->machine_dt_compat);
	} else {
		/* Or left default if custom is NULL */
		res = fdt_property_compat(fdt, 2, buf, "xen,xenvm");
	}
	if (res)
		return res;

	res = fdt_property_cell(fdt, "interrupt-parent", GUEST_GIC_PHANDLE);
	if (res)
		return res;

	res = fdt_property_cell(fdt, "#address-cells",
			GUEST_ROOT_ADDRESS_CELLS);
	if (res)
		return res;

	res = fdt_property_cell(fdt, "#size-cells", GUEST_ROOT_SIZE_CELLS);
	if (res)
		return res;

	return 0;
}

static int fdt_property_regs(void *fdt, unsigned int addr_cells,
			  unsigned int size_cells, unsigned int num_regs, ...)
{
	uint32_t regs[num_regs * (addr_cells + size_cells)];
	uint32_t *cells = regs;
	int i;
	va_list ap;
	uint64_t base, size;

	va_start(ap, num_regs);
	for (i = 0; i < num_regs; i++) {
		base = addr_cells ? va_arg(ap, uint64_t) : 0;
		size = size_cells ? va_arg(ap, uint64_t) : 0;
		set_range(&cells, addr_cells, size_cells, base, size);
	}
	va_end(ap);

	return fdt_property(fdt, "reg", regs, sizeof(regs));
}

static int create_chosen(void *fdt, const char *cmdline)
{
	int res;

	if (!cmdline)
		return 0;

	/* See linux Documentation/devicetree/... */
	res = fdt_begin_node(fdt, "chosen");
	if (res)
		return res;

	LOG_INF("bootargs = %s", cmdline);
	res = fdt_property_string(fdt, "bootargs", cmdline);
	if (res)
		return res;

	res = fdt_end_node(fdt);
	if (res)
		return res;

	return 0;
}

static inline uint64_t get_mpdir(unsigned int cpuid)
{
	/*
	 * According to ARM CPUs bindings, the reg field should match
	 * the MPIDR's affinity bits. We will use AFF0 and AFF1 when
	 * constructing the reg value of the guest at the moment, for it
	 * is enough for the current max vcpu number.
	 */
	return (cpuid & 0x0f) | (((cpuid >> 4) & 0xff) << 8);
}

static int create_cpus(void *fdt, int nr_cpus)
{
	int res, i;
	uint64_t mpidr;

	res = fdt_begin_node(fdt, "cpus");
	if (res)
		return res;

	res = fdt_property_cell(fdt, "#address-cells", 1);
	if (res)
		return res;

	res = fdt_property_cell(fdt, "#size-cells", 0);
	if (res)
		return res;

	for (i = 0; i < nr_cpus; i++) {
		char name[FDT_STRING_MAX];

		mpidr = get_mpdir(i);

		ZSNPRINTF(res, name, FDT_STRING_MAX, "cpu@%llx", mpidr);
		if (!res)
			return -ENOMEM;

		res = fdt_begin_node(fdt, name);
		if (res)
			return res;

		res = fdt_property_string(fdt, "device_type", "cpu");
		if (res)
			return res;

		res = fdt_property_compat(fdt, 1, "arm,armv8");
		if (res)
			return res;

		res = fdt_property_string(fdt, "enable-method", "psci");
		if (res)
			return res;

		res = fdt_property_regs(fdt, 1, 0, 1, mpidr);
		if (res)
			return res;

		res = fdt_end_node(fdt);
		if (res)
			return res;
	}

	res = fdt_end_node(fdt);
	if (res)
		return res;

	return 0;
}

static int create_psci(void *fdt)
{
	int res;

	res = fdt_begin_node(fdt, "psci");
	if (res)
		return res;

	res = fdt_property_compat(fdt, 3, "arm,psci-1.0", "arm,psci-0.2",
							  "arm,psci");
	if (res)
		return res;

	res = fdt_property_string(fdt, "method", "hvc");
	if (res)
		return res;

	res = fdt_property_cell(fdt, "cpu_off", PSCI_cpu_off);
	if (res)
		return res;

	res = fdt_property_cell(fdt, "cpu_on", PSCI_cpu_on);
	if (res)
		return res;

	res = fdt_end_node(fdt);
	if (res)
		return res;

	return 0;
}

static int create_memory(void *fdt, uint64_t memsize)
{
	int res, i;
	char name[FDT_STRING_MAX];
	uint64_t size_left = memsize;
	const uint64_t bankbase[] = GUEST_RAM_BANK_BASES;
	const uint64_t banksize[] = GUEST_RAM_BANK_SIZES;

	for (i = 0; i < GUEST_RAM_BANKS && size_left != 0; i++) {
		uint64_t bank_size;

		bank_size = size_left > banksize[i] ? banksize[i] : size_left;
		size_left -= bank_size;

		ZSNPRINTF(res, name, FDT_STRING_MAX, "memory@%llx",
				  bankbase[i]);
		if (!res)
			return -ENOMEM;

		res = fdt_begin_node(fdt, name);
		if (res)
			return res;

		res = fdt_property_string(fdt, "device_type", "memory");
		if (res)
			return res;

		res = fdt_property_regs(fdt, GUEST_ROOT_ADDRESS_CELLS,
					GUEST_ROOT_SIZE_CELLS, 1,
					bankbase[i], bank_size);
		if (res)
			return res;

		res = fdt_end_node(fdt);
		if (res)
			return res;
	}

	if (size_left) {
		LOG_ERR("Too much memory allocated for the domain");
		return -EINVAL;
	}

	return 0;
}

static int create_gicv2(void *fdt)
{
	int res;
	const uint64_t gicd_base = GUEST_GICD_BASE;
	const uint64_t gicd_size = GUEST_GICD_SIZE;
	const uint64_t gicc_base = GUEST_GICC_BASE;
	const uint64_t gicc_size = GUEST_GICC_SIZE;
	char name[FDT_STRING_MAX];

	ZSNPRINTF(res, name, FDT_STRING_MAX,
			  "interrupt-controller@%llx", gicd_base);
	if (!res)
		return -ENOMEM;

	res = fdt_begin_node(fdt, name);
	if (res)
		return res;

	res = fdt_property_compat(fdt, 2, "arm,cortex-a15-gic",
			  "arm,cortex-a9-gic");
	if (res)
		return res;


	res = fdt_property_cell(fdt, "#interrupt-cells", 3);
	if (res)
		return res;

	res = fdt_property_cell(fdt, "#address-cells", 0);
	if (res)
		return res;

	res = fdt_property(fdt, "interrupt-controller", NULL, 0);
	if (res)
		return res;

	res = fdt_property_regs(fdt, GUEST_ROOT_ADDRESS_CELLS,
			  GUEST_ROOT_SIZE_CELLS, 2, gicd_base, gicd_size,
			  gicc_base, gicc_size);
	if (res)
		return res;

	res = fdt_property_cell(fdt, "linux,phandle", GUEST_GIC_PHANDLE);
	if (res)
		return res;

	res = fdt_property_cell(fdt, "phandle", GUEST_GIC_PHANDLE);
	if (res)
		return res;

	res = fdt_end_node(fdt);
	if (res)
		return res;

	return 0;
}

static int create_gicv3(void *fdt)
{
	int res;
	const uint64_t gicd_base = GUEST_GICV3_GICD_BASE;
	const uint64_t gicd_size = GUEST_GICV3_GICD_SIZE;
	const uint64_t gicr0_base = GUEST_GICV3_GICR0_BASE;
	const uint64_t gicr0_size = GUEST_GICV3_GICR0_SIZE;
	char name[FDT_STRING_MAX];

	ZSNPRINTF(res, name, FDT_STRING_MAX,
			  "interrupt-controller@%llx", gicd_base);
	if (!res)
		return -ENOMEM;

	res = fdt_begin_node(fdt, name);
	if (res)
		return res;

	res = fdt_property_compat(fdt, 1, "arm,gic-v3");
	if (res)
		return res;

	res = fdt_property_cell(fdt, "#interrupt-cells", 3);
	if (res)
		return res;

	res = fdt_property_cell(fdt, "#address-cells", 0);
	if (res)
		return res;

	res = fdt_property(fdt, "interrupt-controller", NULL, 0);
	if (res)
		return res;

	res = fdt_property_regs(fdt,
			  GUEST_ROOT_ADDRESS_CELLS, GUEST_ROOT_SIZE_CELLS,
			  2, gicd_base, gicd_size, gicr0_base, gicr0_size);
	if (res)
		return res;

	res = fdt_property_cell(fdt, "linux,phandle", GUEST_GIC_PHANDLE);
	if (res)
		return res;

	res = fdt_property_cell(fdt, "phandle", GUEST_GIC_PHANDLE);
	if (res)
		return res;

	res = fdt_end_node(fdt);
	if (res)
		return res;

	return 0;
}

static void set_interrupt(gic_interrupt interrupt, unsigned int irq,
				unsigned int cpumask, unsigned int level)
{
	uint32_t *cells = interrupt;
	int is_ppi = (irq < 32);

	/* SGIs are not describe in the device tree */
	assert(irq >= 16);

	irq -= (is_ppi) ? 16 : 32; /* PPIs start at 16, SPIs at 32 */

	/* See linux Documentation/devictree/bindings/arm/gic.txt */
	set_cell(&cells, 1, is_ppi); /* is a PPI? */
	set_cell(&cells, 1, irq);
	set_cell(&cells, 1, (cpumask << 8) | level);
}

static int create_timer(void *fdt, uint32_t frequency)
{
	int res;
	gic_interrupt ints[3];

	res = fdt_begin_node(fdt, "timer");
	if (res)
		return res;

	res = fdt_property_compat(fdt, 1, "arm,armv8-timer");
	if (res)
		return res;

	set_interrupt(ints[0], GUEST_TIMER_PHYS_S_PPI, 0xf,
				  DT_IRQ_TYPE_LEVEL_LOW);
	set_interrupt(ints[1], GUEST_TIMER_PHYS_NS_PPI, 0xf,
				  DT_IRQ_TYPE_LEVEL_LOW);
	set_interrupt(ints[2], GUEST_TIMER_VIRT_PPI, 0xf,
				  DT_IRQ_TYPE_LEVEL_LOW);

	res = fdt_property_interrupts(fdt, ints, 3);
	if (res)
		return res;

	if (frequency) {
		res = fdt_property_u32(fdt, "clock-frequency", frequency);
		if (res)
			return res;
	}

	res = fdt_end_node(fdt);
	if (res)
		return res;

	return 0;
}

static int fill_hypervisor_regs(void *fdt, struct xen_domain_cfg *domcfg,
								int domid)
{
	int i, rc;
	uint64_t size_left = domcfg->mem_kb * 1024;
	const uint64_t bankbase[] = GUEST_RAM_BANK_BASES;
	const uint64_t banksize[] = GUEST_RAM_BANK_SIZES;
	uint64_t region_size[GUEST_RAM_BANKS] = {0},
		region_base[GUEST_RAM_BANKS], bankend[GUEST_RAM_BANKS];
	xen_domctl_getdomaininfo_t info;
	uint32_t regs[(GUEST_ROOT_ADDRESS_CELLS + GUEST_ROOT_SIZE_CELLS) *
				  (GUEST_RAM_BANKS + 1)];
	uint32_t *cells = regs;
	int len, nr_regions = 0;

	rc = xen_domctl_getdomaininfo(domid, &info);
	if (rc)
		return rc;

	if (info.gpaddr_bits > 64)
		return -EINVAL;

	/*
	 * Allocating extended 2MB regions for RAM banks counting
	 * supported guest physical address space and assigned memory
	 */
	for (i = 0; i < GUEST_RAM_BANKS; i++) {
		uint64_t mem_size;

		mem_size = size_left > banksize[i] ? banksize[i] : size_left;

		if (size_left)
			size_left -= mem_size;

		region_base[i] = bankbase[i] + ALIGN_UP_TO_2MB(mem_size);
		bankend[i] = ~0ULL >> (64 - info.gpaddr_bits);
		bankend[i] = MIN(bankend[i], bankbase[i] + banksize[i] - 1);

		if (bankend[i] > region_base[i])
			region_size[i] = bankend[i] - region_base[i] + 1;
	}

	/* Set region 0 for grant table space */
	set_range(&cells, GUEST_ROOT_ADDRESS_CELLS,
			  GUEST_ROOT_SIZE_CELLS,
			  GUEST_GNTTAB_BASE, GUEST_GNTTAB_SIZE);

	for (i = 0; i < GUEST_RAM_BANKS; i++) {
		if (region_size[i] < EXT_REGION_MIN_SIZE)
			continue;

		LOG_INF("Extended region %d: %#" PRIx64 "->%#" PRIx64,
			nr_regions, region_base[i],
			region_base[i] + region_size[i]);

		set_range(&cells, GUEST_ROOT_ADDRESS_CELLS,
				  GUEST_ROOT_SIZE_CELLS,
				  region_base[i], region_size[i]);
		nr_regions++;
	}

	if (!nr_regions) {
		LOG_ERR("Unable to allocate extended regions");
		return -ENOMEM;
	}

	len = sizeof(regs[0]) *
		(GUEST_ROOT_ADDRESS_CELLS + GUEST_ROOT_SIZE_CELLS) *
		(nr_regions + 1);

	return fdt_property(fdt, "reg", regs, len);
}

static int create_hypervisor(void *fdt, int major, int minor,
				struct xen_domain_cfg *domcfg, int domid)
{
	int res;
	gic_interrupt intr;
	char name[FDT_STRING_MAX];

	/* See linux Documentation/devicetree/bindings/arm/xen.txt */
	res = fdt_begin_node(fdt, "hypervisor");
	if (res)
		return res;

	ZSNPRINTF(res, name, FDT_STRING_MAX, "xen,xen-%d.%d",
			  major, minor);
	if (!res)
		return -ENOMEM;

	res = fdt_property_compat(fdt, 2, name, "xen,xen");
	if (res)
		return res;

	res = fill_hypervisor_regs(fdt, domcfg, domid);
	if (res)
		return res;

	/*
	 * interrupts is evtchn upcall:
	 *  - Active-low level-sensitive
	 *  - All cpus
	 */
	set_interrupt(intr, GUEST_EVTCHN_PPI, 0xf, DT_IRQ_TYPE_LEVEL_LOW);

	res = fdt_property_interrupts(fdt, &intr, 1);
	if (res)
		return res;

	res = fdt_end_node(fdt);
	if (res)
		return res;

	return 0;
}

static int create_optee(void *fdt)
{
	int res;

	LOG_INF("Creating OP-TEE node in dtb");

	res = fdt_begin_node(fdt, "firmware");
	if (res)
		return res;

	res = fdt_begin_node(fdt, "optee");
	if (res)
		return res;

	res = fdt_property_compat(fdt, 1, "linaro,optee-tz");
	if (res)
		return res;

	res = fdt_property_string(fdt, "method", "hvc");
	if (res)
		return res;

	res = fdt_end_node(fdt);
	if (res)
		return res;

	res = fdt_end_node(fdt);
	if (res)
		return res;

	return 0;
}

static int check_fdt(void *fdt, size_t size)
{
	int r;

	if (fdt_magic(fdt) != FDT_MAGIC) {
		LOG_ERR("FDT is not a valid");
		return -EINVAL;
	}

	r = fdt_check_header(fdt);
	if (r) {
		LOG_ERR("Failed to check the FDT (rc=%d)", r);
		return -EINVAL;
	}

	if (fdt_totalsize(fdt) > size) {
		LOG_ERR("Partial FDT totalsize is too big");
		return -EINVAL;
	}

	return 0;
}

static int copy_properties(void *fdt, void *pfdt,
						   int nodeoff)
{
	int propoff, nameoff, r;
	const struct fdt_property *prop;

	for (propoff = fdt_first_property_offset(pfdt, nodeoff);
		 propoff >= 0;
		 propoff = fdt_next_property_offset(pfdt, propoff)) {

		prop = fdt_get_property_by_offset(pfdt, propoff, NULL);

		if (!prop)
			return -FDT_ERR_INTERNAL;

		nameoff = fdt32_to_cpu(prop->nameoff);
		r = fdt_property(fdt, fdt_string(pfdt, nameoff), prop->data,
						 fdt32_to_cpu(prop->len));
		if (r)
			return r;
	}

	return (propoff != -FDT_ERR_NOTFOUND) ? propoff : 0;
}

static int copy_node(void *fdt, void *pfdt,
					 int nodeoff, int depth)
{
	int r;

	r = fdt_begin_node(fdt, fdt_get_name(pfdt, nodeoff, NULL));
	if (r)
		return r;

	r = copy_properties(fdt, pfdt, nodeoff);
	if (r)
		return r;

	for (nodeoff = fdt_first_subnode(pfdt, nodeoff);
		 nodeoff >= 0;
		 nodeoff = fdt_next_subnode(pfdt, nodeoff)) {
		r = copy_node(fdt, pfdt, nodeoff, depth + 1);
		if (r)
			return r;
	}

	if (nodeoff != -FDT_ERR_NOTFOUND)
		return nodeoff;

	r = fdt_end_node(fdt);
	if (r)
		return r;

	return 0;
}

static int copy_node_by_path(const char *path,
							 void *fdt, void *pfdt)
{
	int nodeoff, r;
	const char *name = strrchr(path, '/');

	if (!name)
		return -FDT_ERR_INTERNAL;

	name++;

	nodeoff = fdt_path_offset(pfdt, path);
	if (nodeoff < 0)
		return nodeoff;

	if (strcmp(fdt_get_name(pfdt, nodeoff, NULL), name))
		return -FDT_ERR_NOTFOUND;

	r = copy_node(fdt, pfdt, nodeoff, 0);
	if (r)
		return r;

	return 0;
}

static int copy_pfdt(void *fdt, void *pfdt)
{
	int r;

	r = copy_node_by_path("/passthrough", fdt, pfdt);
	if (r < 0 && r != -FDT_ERR_NOTFOUND) {
		LOG_ERR("Can't copy the node \"/passthrough\"");
		return r;
	}

	r = copy_node_by_path("/aliases", fdt, pfdt);
	if (r < 0 && r != -FDT_ERR_NOTFOUND) {
		LOG_ERR("Can't copy the node \"/aliases\"");
		return r;
	}

	return 0;
}

static int copy_dt_passthrough(void *fdt, void *pfdt, char **dt_passthrough,
				uint32_t nr_dt_passthrough)
{
	int i;

	for (i = 0; i < nr_dt_passthrough; i++) {
		int r;

		r = copy_node_by_path(dt_passthrough[i], fdt, pfdt);
		if (r < 0 && r != -FDT_ERR_NOTFOUND) {
			LOG_ERR("Can't copy the node \"%s\"",
					dt_passthrough[i]);
			return r;
		}
	}

	return 0;
}

static inline int fdt_to_errno(int rc)
{
	LOG_ERR("DT create nodes failed: %d = %s", rc, fdt_strerror(rc));
	return (rc == -FDT_ERR_NOSPACE) ? -ENOMEM : -EINVAL;
}

int gen_domain_fdt(struct xen_domain_cfg *domcfg, void **fdtaddr,
		  size_t *fdtsize, int xen_major, int xen_minor,
		  void *pfdt, size_t pfdt_size, int domid)
{
	int rc = 0;
	int fdt_size = CONFIG_PARTIAL_DEVICE_TREE_SIZE;
	void *fdt;

	if (pfdt)
		if (check_fdt(pfdt, pfdt_size)) {
			LOG_ERR("Partial device-tree check was failed");
			return -EINVAL;
		}

	fdt = k_aligned_alloc(XEN_PAGE_SIZE, fdt_size);
	if (!fdt) {
		LOG_ERR("Unable to allocate device-tree mem");
		return -ENOMEM;
	}

	rc = fdt_create(fdt, fdt_size);
	if (rc < 0) {
		goto err;
	}

	rc = fdt_finish_reservemap(fdt);
	if (rc < 0) {
		goto err;
	}

	rc = fdt_begin_node(fdt, "");
	if (rc < 0) {
		goto err;
	}

	rc = create_root(xen_major, xen_minor, fdt, domcfg);
	if (rc < 0) {
		goto err;
	}

	rc = create_chosen(fdt, domcfg->cmdline);
	if (rc < 0) {
		goto err;
	}

	rc = create_cpus(fdt, domcfg->max_vcpus);
	if (rc < 0) {
		goto err;
	}

	rc = create_psci(fdt);
	if (rc < 0) {
		goto err;
	}

	rc = create_memory(fdt, domcfg->mem_kb * 1024);
	if (rc < 0) {
		goto err;
	}

	switch (domcfg->gic_version) {
	case XEN_DOMCTL_CONFIG_GIC_V2:
		rc = create_gicv2(fdt);
		if (rc < 0) {
			goto err;
		}

		break;
	case XEN_DOMCTL_CONFIG_GIC_V3:
		rc = create_gicv3(fdt);
		if (rc < 0) {
			goto err;
		}

		break;
	default:
		LOG_ERR("Error: Unknown GIC version");
		rc = FDT_ERR_BADVALUE;
		goto err;
	}

	/* We don't need to set timer frequency to be set right now*/
	rc = create_timer(fdt, 0);
	if (rc < 0) {
		goto err;
	}

	rc = create_hypervisor(fdt, xen_major, xen_minor, domcfg, domid);
	if (rc < 0) {
		goto err;
	}

	if (domcfg->tee_type == XEN_DOMCTL_CONFIG_TEE_OPTEE) {
		rc = create_optee(fdt);
		if (rc < 0) {
			goto err;
		}
	}

	if (pfdt) {
		rc = copy_pfdt(fdt, pfdt);
		if (rc < 0) {
			goto err;
		}

		if (domcfg->nr_dt_passthrough > 0
			&& domcfg->dt_passthrough) {
			rc = copy_dt_passthrough(fdt, pfdt,
					  domcfg->dt_passthrough,
					  domcfg->nr_dt_passthrough);
			if (rc < 0) {
				goto err;
			}
		}
	}

	rc = fdt_end_node(fdt);
	if (rc < 0) {
		goto err;
	}

	rc = fdt_finish(fdt);
	if (rc < 0) {
		goto err;
	}

	*fdtaddr = fdt;
	*fdtsize = fdt_size;

	return 0;
 err:
	k_free(fdt);

	return fdt_to_errno(rc);
}

void free_domain_fdt(void *fdt)
{
	k_free(fdt);
}
#else /* CONFIG_XEN_LIBFDT */
int gen_domain_fdt(struct xen_domain_cfg *domcfg, void **fdtaddr,
		size_t *fdtsize, int xen_major, int xen_minor,
		void *pfdt, size_t pfdt_size, int domid)
{
	LOG_WRN("Domain device tree generation is not supported");
	*fdtaddr = pfdt;
	*fdtsize = pfdt_size;
	return 0;
}

void free_domain_fdt(void *fdt) {}
#endif /* CONFIG_XEN_LIBFDT */
