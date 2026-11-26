/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026 EPAM Systems
 *
 * Xenlib Operating System Abstraction Layer (OSAL) compiler interface
 */
#ifndef XENLIB_OSAL_COMPILER_H
#define XENLIB_OSAL_COMPILER_H

/*
 * Platform-provided types and macros required by the xenlib OSAL.
 */
#include <xenlib_osal_platform.h>

/*
 * Keep OSAL implementations predating this optional attribute
 * source-compatible.
 */
#ifndef XENLIB_OSAL_MAYBE_UNUSED
#define XENLIB_OSAL_MAYBE_UNUSED
#endif

#endif /* XENLIB_OSAL_COMPILER_H */
