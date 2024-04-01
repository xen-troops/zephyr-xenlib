// SPDX-License-Identifier: Apache-2.0
/*
 * Copyright (c) 2024 EPAM Systems
 *
 * Xenstore util functions.
 */

#include <stdint.h>
#include <string.h>
#include <stdio.h>

#include <zephyr/init.h>
#include <zephyr/logging/log.h>

#include <mem-mgmt.h>
#include <domain.h>
#include <xen/public/io/xs_wire.h>
#include <xss.h>
#include <xen-dom-xs.h>
#include <xenstore_srv.h>

LOG_MODULE_REGISTER(xen_dom_xs);

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

#define INIT_XENSTORE_BUFF_SIZE 80
#define INIT_XENSTORE_UUID_BUF_SIZE 40

#define DOM0_XENSTORE_PRIORITY 45
BUILD_ASSERT(DOM0_XENSTORE_PRIORITY > CONFIG_KERNEL_INIT_PRIORITY_DEFAULT);

void xs_deinitialize_domain_xenstore(uint32_t domid)
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

int xs_add_pvblock_xenstore(const struct pv_block_configuration *cfg, int domid)
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

int xs_remove_xenstore_backends(int domid)
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

int xs_add_pvnet_xenstore(const struct pv_net_configuration *cfg, int domid, int instance_id)
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

	/* TODO: generate MAC if not present */
	if (cfg->mac[0] == '\0') {
		LOG_ERR("There isn't valid MAC for network interface! domid %u backendid %u ",
			domid, backendid);
		return -EINVAL;
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

int xs_initialize_xenstore(uint32_t domid, const struct xen_domain *domain)
{
	char lbuffer[INIT_XENSTORE_BUFF_SIZE] = { 0 };
	char rbuffer[INIT_XENSTORE_BUFF_SIZE] = { 0 };
	char uuid[INIT_XENSTORE_UUID_BUF_SIZE];
	int i, rc;
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

	for (i = 0; i < domain->num_vcpus; ++i) {
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
	xs_deinitialize_domain_xenstore(domid);
	LOG_ERR("Failed to initialize xenstore for domid#%u (rc=%d)", domid, rc);
	return rc;
}

static int initialize_dom0_xenstore(__attribute__ ((unused)) const struct device *dev)
{
	int ret = 0;
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
	dom0 = k_malloc(sizeof(struct xen_domain));
	memset(dom0, 0, sizeof(*dom0));
	if (!dom0) {
		ret = -ENOMEM;
		LOG_ERR("Can't allocate memory for dom0 domain struct");
		goto out;
	}
	snprintf(dom0->name, CONTAINER_NAME_SIZE, "%s", DOM0_NAME);
#ifdef CONFIG_XSTAT
	dom0->num_vcpus = dom0stat->num_vcpus;
	dom0->max_mem_kb = dom0stat->cur_mem / 1024;
#else
	dom0->num_vcpus = 0;
	dom0->max_mem_kb = 0;
#endif
	xss_write("/tool/xenstored", "");
	ret = xs_initialize_xenstore(0, dom0);
out:
#ifdef CONFIG_XSTAT
	k_free(dom0stat);
#endif
	k_free(dom0);
	return ret;
}

SYS_INIT(initialize_dom0_xenstore, APPLICATION, DOM0_XENSTORE_PRIORITY);
