/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026 EPAM Systems
 *
 * Xenlib Operating System Abstraction Layer (OSAL) mutex interface
 *
 */
#ifndef XENLIB_OSAL_MUTEX_H
#define XENLIB_OSAL_MUTEX_H

/*
 * Platform-provided types and macros required by the xenlib OSAL.
 */
#include <xenlib_osal_platform.h>

/* Verify that the platform provides the required macro definitions */
#ifndef XENLIB_OSAL_MUTEX_DEFINE
#error "OSAL does not provide the required static mutex definition macro: " \
       "XENLIB_OSAL_MUTEX_DEFINE"
#endif

/**
 * @brief Initialize mutex
 *
 * @param mutex mutex to initialize
 *
 * @return 0 on success, none-zero error code otherwise
 */
extern int xenlib_osal_mutex_init(xenlib_osal_mutex_t *mutex);

/**
 * @brief Lock mutex
 *
 * @param mutex mutex to lock
 * @param timeout timeout period for mutex locking or timeout values
 * XENLIB_OSAL_NO_WAIT/XENLIB_OSAL_WAIT_FOREVER
 *
 * @return 0 on success, non-zero error code otherwise
 */
extern int xenlib_osal_mutex_lock(xenlib_osal_mutex_t *mutex,
								  xenlib_osal_timeout_t timeout);

/**
 * @brief Unlock mutex
 *
 * @param mutex mutex to unlock that was previously locked
 *
 * @return 0 on success, non-zero error code otherwise
 */
extern int xenlib_osal_mutex_unlock(xenlib_osal_mutex_t *mutex);

#endif /* XENLIB_OSAL_MUTEX_H */
