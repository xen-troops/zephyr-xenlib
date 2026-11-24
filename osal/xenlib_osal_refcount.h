/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026 EPAM Systems
 *
 * Xenlib Operating System Abstraction Layer reference counter interface
 */

#ifndef XENLIB_OSAL_REFCOUNT_H
#define XENLIB_OSAL_REFCOUNT_H

#include <xenlib_osal_platform.h>

/** Initialize a saturating reference counter to one. */
extern void xenlib_osal_refcount_init(xenlib_osal_refcount_t *ref);

/** Increment a reference counter that is already non-zero. */
extern void xenlib_osal_refcount_get(xenlib_osal_refcount_t *ref);

/**
 * Decrement a reference counter.
 *
 * @return true if the counter reached zero, false otherwise.
 */
extern bool xenlib_osal_refcount_put(xenlib_osal_refcount_t *ref);

#endif /* XENLIB_OSAL_REFCOUNT_H */
