/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2023 EPAM Systems
 */

#ifndef XENLIB_XEN_CONSOLE_H
#define XENLIB_XEN_CONSOLE_H

#include <zephyr/shell/shell.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * Start console thread in dom0, that reads domain output.
 *
 * @param domain - domain, where console thread will be started
 *
 * @return - zero on success, negative errno on failure
 */
int xen_start_domain_console(struct xen_domain *domain);

/**
 * Stop console thread in dom0, that reads domain output.
 *
 * @param domain - domain, where console thread will be stopped
 *
 * @return - zero on success, negative errno on failure
 */
int xen_stop_domain_console(struct xen_domain *domain);

/**
 * Attach Zephyr shell to console in given domain
 *
 * @param shell - Zephyr shell instance attach to
 *
 * @param domain - domain, which console should be attached
 *
 * @return - zero on success, negative errno on failure
 */
int xen_attach_domain_console(const struct shell *shell,
			      struct xen_domain *domain);

/**
 * Sets the console feed cb object.
 *
 * @param domain - domain, where console feed cb will be set
 *
 * @param cb - callback function to be called on console feed
 *
 * @param cb_data - data to be passed to the callback function
 *
 * @return - zero on success, negative errno on failure
 */
int set_console_feed_cb(struct xen_domain *domain, on_console_feed_cb_t cb, void *cb_data);

#ifdef __cplusplus
}
#endif

#endif /* XENLIB_XEN_CONSOLE_H */
