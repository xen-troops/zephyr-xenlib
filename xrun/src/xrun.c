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
#include <zephyr/spinlock.h>
#include <zephyr/sys/slist.h>
#include <zephyr/xen/public/domctl.h>

#include <storage.h>
#include <xen_dom_mgmt.h>
#include "xrun.h"

#define MAX_STR_SIZE 64

LOG_MODULE_REGISTER(xrun);

#define CONTAINER_NAME_SIZE 64
#define UNIKERNEL_ID_START 12

#define CONFIG_JSON_NAME "config.json"

K_MUTEX_DEFINE(container_lock);
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

struct hwconfig_spec {
	const char *devicetree;
};

struct vm_spec {
	struct hypervisor_spec hypervisor;
	struct kernel_spec kernel;
	struct hwconfig_spec hwconfig;
};

struct domain_spec {
	const char *ociVersion;
	struct vm_spec vm;
};

struct container {
	sys_snode_t node;

	char container_id[CONTAINER_NAME_SIZE];
	const char *bundle;

	uint8_t devicetree[CONFIG_PARTIAL_DEVICE_TREE_SIZE];
	char *cmdline;

	uint64_t domid;
	char kernel_image[MAX_STR_SIZE];
	char dt_image[MAX_STR_SIZE];
	bool has_dt_image;
	/* struct domain_spec spec; */
	struct xen_domain_cfg domcfg;
	enum container_status status;
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

static const struct json_obj_descr hwconfig_spec_descr[] = {
	JSON_OBJ_DESCR_PRIM(struct hwconfig_spec, devicetree, JSON_TOK_STRING),
};

static const struct json_obj_descr vm_spec_descr[] = {
	JSON_OBJ_DESCR_OBJECT(struct vm_spec,
			      hypervisor, hypervisor_spec_descr),
	JSON_OBJ_DESCR_OBJECT(struct vm_spec, kernel, kernel_spec_descr),
	JSON_OBJ_DESCR_OBJECT(struct vm_spec, hwconfig, hwconfig_spec_descr),

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

static struct container *get_container(const char *container_id)
{
	struct container *container = NULL;

	k_mutex_lock(&container_lock, K_FOREVER);

	SYS_SLIST_FOR_EACH_CONTAINER(&container_list, container, node) {
		if (strncmp(container->container_id, container_id,
			    CONTAINER_NAME_SIZE) == 0) {
			break;
		}
	}

	k_mutex_unlock(&container_lock);
	return container;
}

static struct container *register_container_id(const char *container_id)
{
	struct container *container;

	/*
	 * TODO: There is a problem with all calls to
	 * get_container function that on multithread
	 * systems container may be freed right after
	 * return from the function. This may lead to
	 * unexpected failures which are hard to catch.
	 *
	 * This should be applied to all get_container
	 * calls.
	 *
	 * There are two ways to handle this situation:
	 * - Hold the global lock the whole time you are
	 * holding pointer to a container.
	 * - Add reference counting (like linux kref) to
	 * ensure that this object does not disappear under
	 * your feet.
	 */
	container = get_container(container_id);
	if (container) {
		LOG_ERR("Container %s already exists", container_id);
		return NULL;
	}

	container = (struct container *)k_malloc(sizeof(*container));
	if (!container) {
		return NULL;
	}

	strncpy(container->container_id, container_id, CONTAINER_NAME_SIZE);
	container->domid = next_domid++;
	container->cmdline = NULL;

	k_mutex_lock(&container_lock, K_FOREVER);
	sys_slist_append(&container_list, &container->node);
	k_mutex_unlock(&container_lock);

	return container;
}

static int unregister_container_id(const char *container_id)
{
	struct container *container = get_container(container_id);

	if (!container) {
		return -ENOENT;
	}

	k_free(container->cmdline);
	k_mutex_lock(&container_lock, K_FOREVER);
	sys_slist_find_and_remove(&container_list, &container->node);
	k_mutex_unlock(&container_lock);
	k_free(container);
	return 0;
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

static int fill_domcfg(struct container *container)
{
	struct xen_domain_cfg *domcfg;

	if (!container) {
		return -EINVAL;
	}
	domcfg = &container->domcfg;

	/*
	 * TODO: Memory and cpu configuration should be read
	 * from json spec. Hardcoding those parameters because
	 * there is no clear view about JSON format
	 */
	domcfg->mem_kb = 4096;
	domcfg->flags = (XEN_DOMCTL_CDF_hvm | XEN_DOMCTL_CDF_hap);
	domcfg->max_evtchns = 10;
	domcfg->max_vcpus = 1;
	domcfg->gnt_frames = 32;
	domcfg->max_maptrack_frames = 1;

	domcfg->nr_iomems = 0;

	/* irqs = domd_irqs, */
	domcfg->nr_irqs = 0;
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

	/* domcfg->dtdevs = domd_dtdevs, */
	domcfg->nr_dtdevs = 0;

	domcfg->nr_dt_passthrough = 0;

	domcfg->cmdline = container->cmdline;

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
	struct domain_spec spec;
	struct container *container;

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
		return -ENOMEM;
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
		       MAX_STR_SIZE,
		       "%s", spec.vm.kernel.path);
	if (ret < strlen(spec.vm.kernel.path)) {
		LOG_ERR("Unable to get kernel path, rc = %d", ret);
		goto err_config;
	}

	container->has_dt_image = strlen(spec.vm.hwconfig.devicetree) > 0;

	if (container->has_dt_image) {
		ret = snprintf(container->dt_image,
			       MAX_STR_SIZE,
			       "%s", spec.vm.hwconfig.devicetree);
		if (ret < strlen(spec.vm.hwconfig.devicetree)) {
			LOG_ERR("Unable to get device-tree path, rc = %d", ret);
			goto err_config;
		}
	}

	ret = generate_cmdline(&spec, &container->cmdline);
	if (ret < 0) {
		goto err_config;
	}

	k_free(config);

	container->bundle = bundle;
	container->status = RUNNING;
	LOG_DBG("domid = %lld", container->domid);

	ret = fill_domcfg(container);
	if (ret) {
		goto err;
	}

	ret = domain_create(&container->domcfg, container->domid);
	if (ret) {
		goto err;
	}

	ret = domain_unpause(container->domid);
	return ret;
 err_config:
	k_free(config);
 err:
	unregister_container_id(container_id);
	return ret;
}

int xrun_pause(const char *container_id)
{
	int ret = 0;
	struct container *container = get_container(container_id);

	if (!container) {
		return -EINVAL;
	}

	ret = domain_pause(container->domid);
	if (ret) {
		return ret;
	}

	container->status = PAUSED;
	return 0;
}

int xrun_resume(const char *container_id)
{
	int ret = 0;
	struct container *container = get_container(container_id);

	if (!container) {
		return -EINVAL;
	}

	ret = domain_unpause(container->domid);
	if (ret) {
		return ret;
	}

	container->status = RUNNING;
	return 0;
}

int xrun_kill(const char *container_id)
{
	int ret = 0;
	struct container *container = get_container(container_id);

	if (!container) {
		return -EINVAL;
	}

	ret = domain_destroy(container->domid);
	if (ret) {
		return ret;
	}

	return unregister_container_id(container_id);
}

int xrun_state(const char *container_id, enum container_status *state)
{
	struct container *container = get_container(container_id);

	if (!container) {
		return -EINVAL;
	}

	*state = container->status;
	return 0;
}
