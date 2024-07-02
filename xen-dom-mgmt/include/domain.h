/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef XENLIB_XEN_DOMAIN_H
#define XENLIB_XEN_DOMAIN_H

#include <sys/types.h>
#include <zephyr/xen/events.h>
#include <zephyr/xen/generic.h>
#include <xenstore_srv.h>

#define NR_MAGIC_PAGES 4
#define CONSOLE_PFN_OFFSET 0
#define XENSTORE_PFN_OFFSET 1
#define MEMACCESS_PFN_OFFSET 2
#define VUART_PFN_OFFSET 3
#define DOM0_NAME "Domain-0"
#define CONTAINER_NAME_SIZE 64
#define INIT_XENSTORE_BUFF_SIZE 80

#ifdef __cplusplus
extern "C" {
#endif

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

/**
 * @typedef image_dt_read_cb_t
 * @brief Partial device-tree (PDT) binary read callback
 *
 * Function callback, that should load @ref bufsize domain's PDT image binary to given buffer.
 * The xenlib will attempt to load PDT if @ref dtb_start is not provided.
 *
 * @param buf buffer, where bytes should be loaded
 * @param bufsize number of bytes, that should be loaded
 * @param read_offset number of bytes, that should be skipped from image start
 * @param image_info private data, passed to callback
 * @return 0 on success, negative errno on error
 */
typedef int (*image_dt_read_cb_t)(uint8_t *buf, size_t bufsize, uint64_t read_offset,
				  void *image_info);

/**
 * @typedef image_dt_get_size_cb_t
 * @brief Partial device-tree (PDT) binary get size callback
 *
 * Function callback, that should return domain's PDT image size in bytes.
 * The xenlib will attempt to load PDT if @ref dtb_start is not provided.
 *
 * @param image_info private data, that can be passed to callback
 * @param size output parameter, uint64_t pointer to result
 * @return 0 on success, negative errno on error
 */
typedef int (*image_dt_get_size_cb_t)(void *image_info, size_t *size);

struct pv_net_configuration {
	bool configured;
	int backend_domain_id;
	char script[INIT_XENSTORE_BUFF_SIZE];
	char mac[INIT_XENSTORE_BUFF_SIZE];
	char bridge[INIT_XENSTORE_BUFF_SIZE];
	char type[INIT_XENSTORE_BUFF_SIZE];
	char ip[INIT_XENSTORE_BUFF_SIZE];
};

struct pv_block_configuration {
	bool configured;
	int backend_domain_id;
	char backendtype[INIT_XENSTORE_BUFF_SIZE];
	char format[INIT_XENSTORE_BUFF_SIZE];
	char script[INIT_XENSTORE_BUFF_SIZE];
	char target[INIT_XENSTORE_BUFF_SIZE];
	char vdev[INIT_XENSTORE_BUFF_SIZE];
	char access[INIT_XENSTORE_BUFF_SIZE];
};

#define MAX_PV_NET_DEVICES 3
#define MAX_PV_BLOCK_DEVICES 3

struct backend_configuration {
	struct pv_net_configuration vifs[MAX_PV_NET_DEVICES];
	struct pv_block_configuration disks[MAX_PV_BLOCK_DEVICES];
};

struct backend_state {
	bool functional;
	int backend_domain_id;
};

struct backends_state {
	struct backend_state vifs[MAX_PV_NET_DEVICES];
	struct backend_state disks[MAX_PV_BLOCK_DEVICES];
};

struct xen_domain_cfg {
	char name[CONTAINER_NAME_SIZE];
	const char **machine_dt_compat;
	uint32_t nr_machine_dt_compat;
	uint64_t mem_kb;

	uint32_t flags;
	uint32_t max_vcpus;
	uint32_t max_evtchns;
	int32_t gnt_frames;
	int32_t max_maptrack_frames;
	uint32_t ssidref; /**< XSM security labels id */

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
#if defined(CONFIG_XEN_DOMCFG_READ_PDT)
	image_dt_read_cb_t image_dt_read;
	image_dt_get_size_cb_t image_dt_get_size;
#endif /* CONFIG_XEN_DOMCFG_READ_PDT */

	load_image_bytes_t load_image_bytes;
	get_image_size_t get_image_size;

	void *image_info;

	struct backend_configuration back_cfg;

	bool f_paused:1; /**< Domain should remain paused after creation */
};

struct xen_domain_console {
	struct xencons_interface *intf;
	struct k_mutex lock;
	struct k_thread ext_thrd;
	struct k_thread int_thrd;
	struct k_sem ext_sem;
	struct k_sem int_sem;
	k_tid_t ext_tid;
	atomic_t stop_thrd;
	evtchn_port_t evtchn;
	evtchn_port_t local_evtchn;
	int stack_idx;
	bool first_attach;

	/* Local console ring buffer. This ring buffer differs from
	 * standard one because it supports overruns. Number of lost
	 * characters will be stored in `lost_chars`.
	 */
	char *int_buf;
	size_t int_prod;
	size_t int_cons;
	size_t lost_chars;
};

struct xen_domain {
	uint32_t domid;
	char name[CONTAINER_NAME_SIZE];
	struct xenstore xenstore;
	int num_vcpus;
	int address_size;
	uint64_t max_mem_kb;
	sys_dnode_t node;

	/* TODO: domains can have more than one console */
	struct xen_domain_console console;
	struct backends_state back_state;

	bool f_dom0less:1; /**< Indicates that domain was created by Xen itself */
};

struct xen_domain *domid_to_domain(uint32_t domid);

#ifdef __cplusplus
}
#endif

#endif /* XENLIB_XEN_DOMAIN_H */
