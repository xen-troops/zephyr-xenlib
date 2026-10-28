/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026 EPAM Systems
 *
 * Xenlib Operating System Abstraction Layer (OSAL) semaphore interface
 *
 */
#ifndef XENLIB_OSAL_SEMAPHORE_H
#define XENLIB_OSAL_SEMAPHORE_H

/*
 * Platform-provided types and macros required by the xenlib OSAL.
 */
#include <xenlib_osal_platform.h>

/**
 * @brief Initialize semaphore
 *
 * @param sem semaphore to initialize
 * @param init_count initial semaphore count
 * @param max_count maximum permitted semaphore count
 *
 * @return 0 on success, none-zero error code otherwise
 */
extern int xenlib_osal_semaphore_init(xenlib_osal_semaphore_t *sem,
									  int init_count,
									  int max_count);

/**
 * @brief Wait to acquire a semaphore
 *
 * @param sem semaphore to take
 * @param timeout waiting period to take the semaphore or timeout values
 * XENLIB_OSAL_NO_WAIT/XENLIB_OSAL_WAIT_FOREVER
 *
 * @return 0 on success, none-zero error code otherwise
 */
extern int xenlib_osal_semaphore_wait(xenlib_osal_semaphore_t *sem,
									  xenlib_osal_timeout_t timeout);

/**
 * @brief Release a semaphore
 *
 * @param sem semaphore to release
 *
 * @return 0 on success, none-zero error code otherwise
 */
extern int xenlib_osal_semaphore_signal(xenlib_osal_semaphore_t *sem);

#endif /* XENLIB_OSAL_SEMAPHORE_H */
