/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef XENLIB_XEN_DOMAIN_H
#define XENLIB_XEN_DOMAIN_H

#include <stdint.h>
#include <sys/types.h>

/*
 * struct xen_arch_domainconfig's ABI is covered by
 * XEN_DOMCTL_INTERFACE_VERSION.
 */
#define XEN_DOMCTL_CONFIG_GIC_NATIVE   0
#define XEN_DOMCTL_CONFIG_GIC_V2       1
#define XEN_DOMCTL_CONFIG_GIC_V3       2

#define XEN_DOMCTL_CONFIG_TEE_NONE     0
#define XEN_DOMCTL_CONFIG_TEE_OPTEE    1

/* Is this an HVM guest (as opposed to a PV guest)? */
#define _XEN_DOMCTL_CDF_hvm           0
#define XEN_DOMCTL_CDF_hvm            (1U << _XEN_DOMCTL_CDF_hvm)

/* Use hardware-assisted paging if available? */
#define _XEN_DOMCTL_CDF_hap           1
#define XEN_DOMCTL_CDF_hap            (1U << _XEN_DOMCTL_CDF_hap)

struct xen_domain_iomem {
	/* where to map, if 0 - map to same place as mfn */
	uint64_t first_gfn;
	/* what to map */
	uint64_t first_mfn;
	/* how much frames to map */
	uint64_t nr_mfns;
};

/**
 * Function cb, that should load bufsize domain image bytes to given buffer
 * @param buf buffer, where bytes should be loaded
 * @param bufsize number of image bytes, that should be loaded
 * @param read_offset number of bytes, that should be skipped from image start
 * @param image_info private data, passed to callback
 * @return 0 on success, negative errno on error
 */
typedef int (*load_image_bytes_t)(uint8_t *buf, size_t bufsize,
				uint64_t read_offset, void *image_info);

/**
 * Function cb, that should return image size in bytes
 * @param image_info private data, that can be passed to cb
 * @param size output parameter, uint64_t pointer to result
 * @return 0 on success, negative errno on error
 */
typedef ssize_t (*get_image_size_t)(void *image_info, uint64_t *size);

struct xen_domain_cfg {
	uint64_t mem_kb;

	uint32_t flags;
	uint32_t max_vcpus;
	uint32_t max_evtchns;
	int32_t gnt_frames;
	int32_t max_maptrack_frames;

	/* ARM arch related */
	uint8_t gic_version;
	uint16_t tee_type;

	/* For peripheral sharing*/
	struct xen_domain_iomem *iomems;
	uint32_t nr_iomems;

	uint32_t *irqs;
	uint32_t nr_irqs;

	char **dtdevs;
	uint32_t nr_dtdevs;

	char **dt_passthrough;
	uint32_t nr_dt_passthrough;

	char *cmdline;

	const char *dtb_start, *dtb_end;

	load_image_bytes_t load_image_bytes;
	get_image_size_t get_image_size;

	void *image_info;
};

struct xen_domain_console {
};

struct xen_domain {
};

struct xen_domain *domid_to_domain(uint32_t domid);

#endif /* XENLIB_XEN_DOMAIN_H */
