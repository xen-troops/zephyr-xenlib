/*
 * Copyright (c) 2023 EPAM Systems
 *
 * SPDX-License-Identifier: Apache-2.0
 */

#ifndef XENLIB_XEN_DOM_MGMT_H
#define XENLIB_XEN_DOM_MGMT_H

/* TODO: remove this include (see below) */
#include <zephyr/shell/shell.h>

/* TODO: Rework interface. dom_mgmt lib should not export shell functions */
int domu_create(const struct shell *shell, size_t argc, char **argv);
int domu_destroy(const struct shell *shell, size_t argc, char **argv);
int domu_pause(const struct shell *shell, size_t argc, char **argv);
int domu_unpause(const struct shell *shell, size_t argc, char **argv);

#endif
