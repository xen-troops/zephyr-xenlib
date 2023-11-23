/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef XL_PARSER_H
#define XL_PARSER_H

#include <domain.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Function that takes one xl-like(see https://xenbits.xen.org/docs/unstable/man/xl.cfg.5.html Devices chapter)
 * and fill appropriate unconfigured parts inside cfg.
 * Note: currently supported configuration types are:
 *       disk https://xenbits.xen.org/docs/unstable/man/xl-disk-configuration.5.html
 *       vif  https://xenbits.xen.org/docs/unstable/man/xl-network-configuration.5.html
 * Examples:
 *  disk=['backend=1, vdev=xvda, access=rw, target=/dev/mmcblk0p3']
 *  vif =['backend=1,bridge=xenbr0,mac=08:00:27:ff:cb:ce,ip=172.44.0.2 255.255.255.0 172.44.0.1']
 *
 * Note: all internal configurations should obey key=value scheme.
 *
 * Restriction on disk type: only Xen virtual disk (aka xvd without partitions and in
 * lowercase) supported.
 * see : https://xenbits.xen.org/docs/unstable/man/xen-vbd-interface.7.html
 *
 * @param str xl like backend configuration string
 * @param cfg pointer to global backends configuration structure
 * @return 0 on success, negative errno on error
 */
int parse_one_record_and_fill_cfg(const char *str, struct backend_configuration *cfg);

#ifdef __cplusplus
}
#endif

#endif /* XL_PARSER_H */
