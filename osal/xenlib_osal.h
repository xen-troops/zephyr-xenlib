/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026 EPAM Systems
 *
 * Xenlib Operating System Abstraction Layer (OSAL) interface
 *
 * The target platform must provide an implementation of this interface
 * to integrate the xenlib module.
 * This is the top-level interface header included by xenlib submodules.
 */
#ifndef XENLIB_OSAL_H
#define XENLIB_OSAL_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Platform-provided types and macros required by the xenlib OSAL.
 */
#include <xenlib_osal_platform.h>

/* Verify that the platform provides the required macro definitions */
#ifndef XENLIB_OSAL_INIT
#error "OSAL does not provide the module entry-point definition macro: " \
	   "XENLIB_OSAL_INIT"
#endif

/* Subsystem OSAL APIs */
#include <xenlib_osal_assert.h>
#include <xenlib_osal_atomic.h>
#include <xenlib_osal_barrier.h>
#include <xenlib_osal_list.h>
#include <xenlib_osal_log.h>
#include <xenlib_osal_memory.h>
#include <xenlib_osal_mutex.h>
#include <xenlib_osal_semaphore.h>
#include <xenlib_osal_shell.h>
#include <xenlib_osal_thread.h>
#include <xenlib_osal_timepoint.h>

#ifdef __cplusplus
}
#endif

#endif /* XENLIB_OSAL_H */
