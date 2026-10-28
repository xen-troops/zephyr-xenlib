/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026 EPAM Systems
 *
 * Xenlib Operating System Abstraction Layer (OSAL) logging interface
 *
 */
#ifndef XENLIB_OSAL_LOG_H
#define XENLIB_OSAL_LOG_H

/*
 * Platform-provided types and macros required by the xenlib OSAL.
 */
#include <xenlib_osal_platform.h>


/* Verify that the platform provides the required macro definitions */
#ifndef XENLIB_OSAL_LOG_ERR
#error "OSAL does not provide the required log interface: XENLIB_OSAL_LOG_ERR"
#endif
#ifndef XENLIB_OSAL_LOG_WRN
#error "OSAL does not provide the required log interface: XENLIB_OSAL_LOG_WRN"
#endif
#ifndef XENLIB_OSAL_LOG_INF
#error "OSAL does not provide the required log interface: XENLIB_OSAL_LOG_INF"
#endif
#ifndef XENLIB_OSAL_LOG_DBG
#error "OSAL does not provide the required log interface: XENLIB_OSAL_LOG_DBG"
#endif

#endif /* XENLIB_OSAL_LOG_H */
