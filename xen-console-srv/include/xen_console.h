/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2023 EPAM Systems
 */

#ifndef XENLIB_XEN_CONSOLE_H
#define XENLIB_XEN_CONSOLE_H

/*
 * Initialize domain console by setting HVM param for domain
 * and event channel binding in dom0.
 *
 * @param domain - domain, where console should be initialized
 *
 * @return - zero on success, negative errno on failure
 */
int xen_init_domain_console(struct xen_domain *domain);

/*
 * Start console thread in dom0, that reads domain output.
 *
 * @param domain - domain, where console thread will be started
 *
 * @return - zero on success, negative errno on failure
 */
int xen_start_domain_console(struct xen_domain *domain);

/*
 * Stop console thread in dom0, that reads domain output.
 *
 * @param domain - domain, where console thread will be stopped
 *
 * @return - zero on success, negative errno on failure
 */
int xen_stop_domain_console(struct xen_domain *domain);

#endif /* XENLIB_XEN_CONSOLE_H */
