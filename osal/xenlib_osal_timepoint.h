/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026 EPAM Systems
 *
 * Xenlib Operating System Abstraction Layer (OSAL) timepoint interface
 *
 */
#ifndef XENLIB_OSAL_TIMEPOINT_H
#define XENLIB_OSAL_TIMEPOINT_H

/*
 * Platform-provided types and macros required by the xenlib OSAL.
 */
#include <xenlib_osal_platform.h>

/* Verify that the platform provides the required macro definitions */
#ifndef XENLIB_OSAL_WAIT_FOREVER
#error "OSAL does not provide the required timeout macro: " \
	   "XENLIB_OSAL_WAIT_FOREVER"
#endif
#ifndef XENLIB_OSAL_NO_WAIT
#error "OSAL does not provide the required timeout macro: " \
	   "XENLIB_OSAL_NO_WAIT"
#endif

/**
 * @brief Get remaining time to reach the target timepoint
 *
 * @param tp target timepoint
 * 
 * @return timeout interval between current time and target timepoint.
 * returns XENLIB_OSAL_NO_WAIT if the timepoint has expired
 * returns XENLIB_OSAL_WAIT_FOREVER, if the timepoint was created with the
 * same timeout value
 */
extern xenlib_osal_timeout_t xenlib_osal_timepoint_timeout(
												xenlib_osal_timepoint_t tp);

/**
 * @brief Check if the timepoint has expired
 *
 * @param tp target timepoint
 * 
 * @return true if the timepoint has expired, false otherwise
 */
extern bool xenlib_osal_timepoint_expired(xenlib_osal_timepoint_t tp);

/**
 * @brief Calculate a timepoint value with expiration corresponding to
 * specified timeout relative to current timepoint (now())
 *
 * @param timeout timeout
 * 
 * @return timepoint value relative to current specified timeout
 */
extern xenlib_osal_timepoint_t xenlib_osal_timepoint_calc(
												xenlib_osal_timeout_t timeout);

#endif /* XENLIB_OSAL_TIMEPOINT_H */
