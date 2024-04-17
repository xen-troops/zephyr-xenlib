// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2023 EPAM Systems
 */
#include <domain.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <zephyr/data/json.h>
#include <zephyr/logging/log.h>
#include <zephyr/kernel.h>
#include <zephyr/spinlock.h>
#include <zephyr/sys/slist.h>

#if !defined(CONFIG_BOARD_NATIVE_POSIX)
#include <zephyr/xen/public/domctl.h>
#endif

#include <storage.h>
#include <xen_dom_mgmt.h>
#include <xl_parser.h>
#include "xrun.h"

LOG_MODULE_REGISTER(xrun);

#define UNIKERNEL_ID_START 12
#define VCPUS_MAX_COUNT 24

#define CONFIG_JSON_NAME "config.json"

static K_MUTEX_DEFINE(container_lock);

static sys_slist_t container_list = SYS_SLIST_STATIC_INIT(&container_list);
static uint32_t next_domid = UNIKERNEL_ID_START;

#define XRUN_JSON_PARAMETERS_MAX 24

struct hypervisor_spec {
	const char *path;
	const char *parameters[XRUN_JSON_PARAMETERS_MAX];
	size_t params_len;
};

struct kernel_spec {
	const char *path;
	const char *parameters[XRUN_JSON_PARAMETERS_MAX];
	size_t params_len;
};

struct iomem_spec {
	const uint64_t firstGFN;
	const uint64_t firstMFN;
	const uint64_t nrMFNs;
};

struct hwconfig_spec {
	const char *deviceTree;
	const uint32_t vcpus;
	const uint64_t memKB;
	const char *dtdevs[CONFIG_XRUN_DTDEVS_MAX];
	const struct iomem_spec iomems[CONFIG_XRUN_IOMEMS_MAX];
	const uint32_t irqs[CONFIG_XRUN_IRQS_MAX];
	size_t iomems_len;
	size_t dtdevs_len;
	size_t irqs_len;
};

struct vm_spec {
	struct hypervisor_spec hypervisor;
	struct kernel_spec kernel;
	struct hwconfig_spec hwConfig;
};

struct domain_spec {
	const char *ociVersion;
	struct vm_spec vm;
};

static K_MUTEX_DEFINE(container_run_lock);
static char *gdtdevs[CONFIG_XRUN_DTDEVS_MAX];
static struct xen_domain_iomem giomems[CONFIG_XRUN_IOMEMS_MAX];
static uint32_t girqs[CONFIG_XRUN_IRQS_MAX];

struct container {
	sys_snode_t node;

	char container_id[CONTAINER_NAME_SIZE];
	const char *bundle;

	uint8_t devicetree[CONFIG_PARTIAL_DEVICE_TREE_SIZE] __aligned(8);

	uint64_t domid;
	char kernel_image[CONFIG_XRUN_MAX_PATH_SIZE];
	char dt_image[CONFIG_XRUN_MAX_PATH_SIZE];
	bool has_dt_image;
	enum container_status status;
	struct k_mutex lock;
	int refcount;
};

static const struct json_obj_descr hypervisor_spec_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct hypervisor_spec, path, JSON_TOK_STRING),
	JSON_OBJ_DESCR_ARRAY(struct hypervisor_spec, parameters,
			     XRUN_JSON_PARAMETERS_MAX, params_len,
			     JSON_TOK_STRING),
};

static const struct json_obj_descr kernel_spec_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct kernel_spec, path, JSON_TOK_STRING),
	JSON_OBJ_DESCR_ARRAY(struct kernel_spec, parameters,
			     XRUN_JSON_PARAMETERS_MAX, params_len,
			     JSON_TOK_STRING),
};

static const struct json_obj_descr iomem_spec_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct iomem_spec, firstGFN, JSON_TOK_NUMBER),
	JSON_OBJ_DESCR_PRIM(struct iomem_spec, firstMFN, JSON_TOK_NUMBER),
	JSON_OBJ_DESCR_PRIM(struct iomem_spec, nrMFNs, JSON_TOK_NUMBER),
};

static const struct json_obj_descr hwconfig_spec_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct hwconfig_spec, deviceTree, JSON_TOK_STRING),
	JSON_OBJ_DESCR_PRIM(struct hwconfig_spec, vcpus, JSON_TOK_NUMBER),
	JSON_OBJ_DESCR_PRIM(struct hwconfig_spec, memKB, JSON_TOK_NUMBER),
	JSON_OBJ_DESCR_ARRAY(struct hwconfig_spec, dtdevs, CONFIG_XRUN_DTDEVS_MAX,
			     dtdevs_len, JSON_TOK_STRING),
	JSON_OBJ_DESCR_OBJ_ARRAY(struct hwconfig_spec, iomems,
				 CONFIG_XRUN_IOMEMS_MAX, iomems_len,
				 iomem_spec_descr,
				 ARRAY_SIZE(iomem_spec_descr)),
	JSON_OBJ_DESCR_ARRAY(struct hwconfig_spec, irqs, CONFIG_XRUN_IRQS_MAX,
			     irqs_len, JSON_TOK_NUMBER),
};

static const struct json_obj_descr vm_spec_descr[] = {
	JSON_OBJ_DESCR_OBJECT(struct vm_spec,
			      hypervisor, hypervisor_spec_descr),
	JSON_OBJ_DESCR_OBJECT(struct vm_spec, kernel, kernel_spec_descr),
	JSON_OBJ_DESCR_OBJECT(struct vm_spec, hwConfig, hwconfig_spec_descr),
};

static const struct json_obj_descr domain_spec_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct domain_spec, ociVersion, JSON_TOK_STRING),
	JSON_OBJ_DESCR_OBJECT(struct domain_spec, vm, vm_spec_descr),
};

int parse_config_json(char *json, size_t json_size, struct domain_spec *domain)
{
	int expected_return_code = (1 << ARRAY_SIZE(domain_spec_descr)) - 1;
	int ret = json_obj_parse(json,
				 json_size, domain_spec_descr,
				 ARRAY_SIZE(domain_spec_descr), domain);

	if (ret < 0) {
		LOG_ERR("JSON Parse Error: %d", ret);
		return ret;
	} else if (ret != expected_return_code) {
		LOG_ERR("Not all values decoded; Expected %d but got %d",
			expected_return_code, ret);
		return -ret;
	}

	return ret;
}

static struct container *get_container_locked(const char *container_id)
{
	struct container *container = NULL;
	SYS_SLIST_FOR_EACH_CONTAINER(&container_list, container, node) {
		if (strncmp(container->container_id, container_id,
			    CONTAINER_NAME_SIZE) == 0) {
			break;
		}
	}
	if (container) {
		container->refcount++;
	}

	return container;
}
static struct container *get_container(const char *container_id)
{
	struct container *container = NULL;

	k_mutex_lock(&container_lock, K_FOREVER);

	container = get_container_locked(container_id);

	k_mutex_unlock(&container_lock);
	return container;
}

static void put_container(struct container *container)
{
	int ret;

	if (!container) {
		return;
	}
	k_mutex_lock(&container_lock, K_FOREVER);

	container->refcount--;
	if (container->refcount == 0) {
		ret = domain_destroy(container->domid);
		if (ret) {
			LOG_ERR("Failed to destroy domain %llu", container->domid);
		}

		sys_slist_find_and_remove(&container_list, &container->node);
		k_free(container);
	}

	k_mutex_unlock(&container_lock);
}

static struct container *register_container_id(const char *container_id)
{
	struct container *container;

	k_mutex_lock(&container_lock, K_FOREVER);
	container = get_container_locked(container_id);
	if (container) {
		k_mutex_unlock(&container_lock);
		put_container(container);
		LOG_ERR("Container %s already exists", container_id);
		return NULL;
	}

	container = (struct container *)k_malloc(sizeof(*container));
	if (!container) {
		k_mutex_unlock(&container_lock);
		return NULL;
	}

	strncpy(container->container_id, container_id, CONTAINER_NAME_SIZE);
	container->domid = next_domid++;
	k_mutex_init(&container->lock);

	sys_slist_append(&container_list, &container->node);
	container->refcount = 1;
	k_mutex_unlock(&container_lock);

	return container;
}

static int load_image_bytes(uint8_t *buf, size_t bufsize,
			    uint64_t image_load_offset, void *image_info)
{
	ssize_t res;
	struct container *container;

	if (!image_info || !buf) {
		return -EINVAL;
	}

	container = (struct container *)image_info;

	res = xrun_read_file(container->kernel_image, buf,
			     bufsize, image_load_offset);

	return (res > 0) ? 0 : res;
}

static ssize_t get_image_size(void *image_info, uint64_t *size)
{
	struct container *containter;
	ssize_t image_size;

	if (!image_info || !size) {
		return -EINVAL;
	}

	containter = (struct container *)image_info;

	image_size = xrun_get_file_size(containter->kernel_image);
	if (image_size > 0) {
		*size = image_size;
	}

	return (size == 0) ? -EINVAL : 0;
}

static int fill_domcfg(struct xen_domain_cfg *domcfg, struct domain_spec *spec,
		       struct container *container)
{
	int i;

	if (!domcfg || !spec) {
		return -EINVAL;
	}

	snprintf(domcfg->name, CONTAINER_NAME_SIZE, "%s", container->container_id);
	domcfg->mem_kb = (spec->vm.hwConfig.memKB) ?
		spec->vm.hwConfig.memKB : 4096;
	domcfg->flags = (XEN_DOMCTL_CDF_hvm | XEN_DOMCTL_CDF_hap);
	domcfg->max_evtchns = 10;
	if (spec->vm.hwConfig.vcpus < VCPUS_MAX_COUNT) {
		domcfg->max_vcpus = (spec->vm.hwConfig.vcpus) ?
			spec->vm.hwConfig.vcpus : 1;
	} else {
		domcfg->max_vcpus = 1;
	}

	domcfg->gnt_frames = 32;
	domcfg->max_maptrack_frames = 1;

	domcfg->nr_iomems = spec->vm.hwConfig.iomems_len;

	/*
	 * NOTE: We expect iomems, dtdevs and irqs arrays to be allocated
	 * by caller. We don't need those buffers after domain is created so
	 * I expect them to be allocated on the upper layer.
	 */

	if (domcfg->nr_iomems) {
		if (domcfg->nr_iomems > CONFIG_XRUN_IRQS_MAX) {
			return -EINVAL;
		}

		for (i = 0; i < domcfg->nr_iomems; i++) {
			domcfg->iomems[i].first_gfn =
				spec->vm.hwConfig.iomems[i].firstGFN;
			domcfg->iomems[i].first_mfn =
				spec->vm.hwConfig.iomems[i].firstMFN;
			domcfg->iomems[i].nr_mfns =
				spec->vm.hwConfig.iomems[i].nrMFNs;
		}
	}

	domcfg->nr_irqs = spec->vm.hwConfig.irqs_len;

	if (domcfg->nr_irqs) {
		if (domcfg->nr_irqs > CONFIG_XRUN_IRQS_MAX) {
			return -EINVAL;
		}

		for (i = 0; i < domcfg->nr_irqs; i++) {
			domcfg->irqs[i] =
				spec->vm.hwConfig.irqs[i];
		}
	}

	domcfg->nr_dtdevs = spec->vm.hwConfig.dtdevs_len;

	if (domcfg->nr_dtdevs) {
		if (domcfg->nr_dtdevs > CONFIG_XRUN_DTDEVS_MAX) {
			return -EINVAL;
		}

		/*
		 * dtdevs strings should be used to create domain before spec
		 * is destroyed.
		 */
		for (i = 0; i < domcfg->nr_dtdevs; i++) {
			domcfg->dtdevs[i] = (char *)spec->vm.hwConfig.dtdevs[i];
		}
	}

	/*
	 * Current implementation doesn't support GIC_NATIVE
	 * parameter. We use the same gic version as is on the system.
	 */
#if defined(CONFIG_GIC_V3)
	domcfg->gic_version = XEN_DOMCTL_CONFIG_GIC_V3;
#else
	domcfg->gic_version = XEN_DOMCTL_CONFIG_GIC_V2;
#endif
	domcfg->tee_type = XEN_DOMCTL_CONFIG_TEE_NONE;

	/* OCI spec do not support dt_passthrough */
	domcfg->nr_dt_passthrough = 0;

	domcfg->get_image_size = get_image_size;
	domcfg->load_image_bytes = load_image_bytes;
	domcfg->image_info = container;

	if (container->has_dt_image) {
		size_t res =
			xrun_read_file(container->dt_image,
				       container->devicetree,
				       CONFIG_PARTIAL_DEVICE_TREE_SIZE, 0);
		if (res < 0) {
			LOG_ERR("Unable to read dtb rc: %ld", res);
			return res;
		}
		domcfg->dtb_start = container->devicetree;
		domcfg->dtb_end = container->devicetree + res;
	} else {
		domcfg->dtb_start = NULL;
		domcfg->dtb_end = NULL;
	}

	/* Parse and fill backend configuration */
	memset(&domcfg->back_cfg, 0, sizeof(domcfg->back_cfg));

	for (i = 0; i < spec->vm.kernel.params_len; i++) {
		parse_one_record_and_fill_cfg(spec->vm.kernel.parameters[i], &domcfg->back_cfg);
	}

	return 0;
}

static int generate_cmdline(struct domain_spec *spec, char **cmdline)
{
	int i, pos = 0;
	int len = 0, str_len;

	if (!spec) {
		LOG_ERR("Can't generate cmdline, invalid parameters");
		return -EINVAL;
	}

	if (spec->vm.kernel.params_len == 0) {
		/*
		 * If cmd parameter weren't provided - then we
		 * don't allocate any memory for cmdline and return
		 * NULL. This is safe because /chosen node will not
		 * be created if cmdline is NULL. k_free also handles
		 * NULL
		 */
		*cmdline = NULL;
		return 0;
	}

	for (i = 0; i < spec->vm.kernel.params_len; i++) {
		str_len = strlen(spec->vm.kernel.parameters[i]);
		if (!str_len) {
			LOG_ERR("Empty parameter from json");
			return -EINVAL;
		}

		len += str_len;

		if (i == spec->vm.kernel.params_len - 1) {
			len++;
		}
	}

	*cmdline = k_malloc(len + 1);
	if (!*cmdline) {
		LOG_ERR("Unable to allocate cmdline");
		return -ENOMEM;
	}

	for (i = 0; i < spec->vm.kernel.params_len; i++) {
		if (i == spec->vm.kernel.params_len - 1) {
			pos += snprintf(*cmdline + pos, len - pos + 1, "%s",
					spec->vm.kernel.parameters[i]);
		} else {
			pos += snprintf(*cmdline + pos, len - pos + 1, "%s ",
					spec->vm.kernel.parameters[i]);
		}
	}

	return 0;
}

static ssize_t get_fpath_size(const char *path, const char *name)
{
	size_t target_size = 0;
	size_t path_len, name_len;

	if (!path || !name) {
		LOG_ERR("Invalid input parameters");
		return -EINVAL;
	}

	path_len = strlen(path);
	name_len = strlen(name);

	if (path_len == 0 || name_len == 0) {
		LOG_ERR("Wrong path or name was provided");
		return -EINVAL;
	}

	target_size = path_len + name_len + 2;
	if (target_size >= CONFIG_XRUN_MAX_PATH_SIZE) {
		LOG_ERR("File path is too long");
		return -EINVAL;
	}

	return target_size;
}

int xrun_run(const char *bundle, int console_socket, const char *container_id)
{
	int ret = 0;
	ssize_t bytes_read;
	char *config;
	char *fpath;
	ssize_t fpath_len;
	struct domain_spec spec = {0};
	struct container *container;
	struct xen_domain_cfg domcfg = {0};

	/* Don't allow empty (first char is \0) or null container_id */
	if (!container_id || !*container_id) {
		return -EINVAL;
	}

	/* Don't allow empty or null bundle */
	if (!bundle || !*bundle) {
		return -EINVAL;
	}

	container = register_container_id(container_id);
	if (!container) {
		ret = -ENOMEM;
		goto err_unlock;
	}

	config = k_malloc(CONFIG_XRUN_JSON_SIZE_MAX);
	if (!config) {
		ret = -ENOMEM;
		goto err;
	}

	fpath_len = get_fpath_size(bundle, CONFIG_JSON_NAME);
	if (fpath_len < 0) {
		ret = fpath_len;
		goto err_config;
	}

	fpath = k_malloc(fpath_len);
	if (!fpath) {
		LOG_ERR("Unable to allocate fpath memory");
		ret = -ENOMEM;
		goto err_config;
	}

	ret = snprintf(fpath, fpath_len, "%s/%s", bundle, CONFIG_JSON_NAME);
	if (ret <= 0) {
		LOG_ERR("Unable to form file path: %d", ret);
		k_free(fpath);
		goto err_config;
	}

	bytes_read = xrun_read_file(fpath, config,
				    CONFIG_XRUN_JSON_SIZE_MAX, 0);
	if (bytes_read < 0) {
		LOG_ERR("Can't read config.json ret = %ld", bytes_read);
		ret = bytes_read;
		k_free(fpath);
		goto err_config;
	}

	k_free(fpath);

	ret = parse_config_json(config, bytes_read, &spec);
	if (ret < 0) {
		goto err_config;
	}

	ret = snprintf(container->kernel_image,
		       CONFIG_XRUN_MAX_PATH_SIZE,
		       "%s", spec.vm.kernel.path);
	if (ret < strlen(spec.vm.kernel.path)) {
		LOG_ERR("Unable to get kernel path, rc = %d", ret);
		goto err_config;
	}

	container->has_dt_image = spec.vm.hwConfig.deviceTree &&
		strlen(spec.vm.hwConfig.deviceTree) > 0;

	if (container->has_dt_image) {
		ret = snprintf(container->dt_image,
			       CONFIG_XRUN_MAX_PATH_SIZE,
			       "%s", spec.vm.hwConfig.deviceTree);
		if (ret < strlen(spec.vm.hwConfig.deviceTree)) {
			LOG_ERR("Unable to get device-tree path, rc = %d", ret);
			goto err_config;
		}
	}

	ret = generate_cmdline(&spec, &domcfg.cmdline);
	if (ret < 0) {
		goto err_config;
	}

	container->bundle = bundle;
	container->status = RUNNING;

	if (spec.vm.hwConfig.iomems_len) {
		domcfg.iomems = giomems;
	}

	if (spec.vm.hwConfig.dtdevs_len) {
		domcfg.dtdevs = gdtdevs;
	}

	if (spec.vm.hwConfig.irqs_len) {
		domcfg.irqs = girqs;
	}

	LOG_DBG("domid = %lld", container->domid);
	k_mutex_lock(&container_run_lock, K_FOREVER);

	ret = fill_domcfg(&domcfg, &spec, container);
	if (ret) {
		k_mutex_unlock(&container_run_lock);
		goto err_config;
	}

	ret = domain_create(&domcfg, container->domid);
	if (ret < 0) {
		k_mutex_unlock(&container_run_lock);
		goto err_config;
	}

	ret = domain_post_create(&domcfg, container->domid);

	k_free(config);
	k_free(domcfg.cmdline);
	k_mutex_unlock(&container_run_lock);

	return ret;
 err_config:
	k_free(config);
 err:
	k_free(domcfg.cmdline);
	put_container(container);
 err_unlock:
	k_mutex_unlock(&container_run_lock);
	return ret;
}

int xrun_pause(const char *container_id)
{
	int ret = 0;
	struct container *container = get_container(container_id);

	if (!container) {
		return -EINVAL;
	}
	k_mutex_lock(&container->lock, K_FOREVER);

	ret = domain_pause(container->domid);
	if (ret) {
		goto out;
	}

	container->status = PAUSED;
out:
	k_mutex_unlock(&container->lock);
	put_container(container);
	return ret;
}

int xrun_resume(const char *container_id)
{
	int ret = 0;
	struct container *container = get_container(container_id);

	if (!container) {
		return -EINVAL;
	}
	k_mutex_lock(&container->lock, K_FOREVER);

	ret = domain_unpause(container->domid);
	if (ret) {
		goto out;
	}

	container->status = RUNNING;
out:
	k_mutex_unlock(&container->lock);
	put_container(container);
	return ret;
}

int xrun_kill(const char *container_id)
{
	int ret = 0;
	struct container *container = get_container(container_id);

	if (!container) {
		return -EINVAL;
	}

	/* Put container twice to drop the last reference */
	put_container(container);
	put_container(container);
	return ret;
}

int xrun_state(const char *container_id, enum container_status *state)
{
	struct container *container = get_container(container_id);

	if (!container) {
		return -EINVAL;
	}

	*state = container->status;
	put_container(container);
	return 0;
}
