/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026 EPAM Systems
 *
 * Xenlib Operating System Abstraction Layer (OSAL) assert interface
 *
 */
#ifndef XENLIB_OSAL_ASSERT_H
#define XENLIB_OSAL_ASSERT_H

/*
 * Platform-provided types and macros required by the xenlib OSAL.
 */
#include <xenlib_osal_platform.h>


/* Verify that the platform provides the required macro definitions */
#ifndef XENLIB_OSAL_ASSERT
#error "OSAL does not provide the required assert interface: XENLIB_OSAL_ASSERT"
#endif
#ifndef XENLIB_OSAL_ASSERT_NO_MSG
#error "OSAL does not provide the required assert interface: " \
	   "XENLIB_OSAL_ASSERT_NO_MSG"
#endif
#ifndef XENLIB_OSAL_BUILD_ASSERT
#error "OSAL does not provide the required assert interface: " \
	   "XENLIB_OSAL_BUILD_ASSERT"
#endif

#endif /* XENLIB_OSAL_ASSERT_H */
