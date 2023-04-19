/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef XENLIB_XENSTORE_SRV_H
#define XENLIB_XENSTORE_SRV_H

int start_domain_stored(struct xen_domain *domain);
int stop_domain_stored(struct xen_domain *domain);

#endif
