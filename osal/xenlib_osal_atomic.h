/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026 EPAM Systems
 *
 * Xenlib Operating System Abstraction Layer (OSAL) atomic variables interface
 *
 */
#ifndef XENLIB_OSAL_ATOMIC_H
#define XENLIB_OSAL_ATOMIC_H

/*
 * Platform-provided types and macros required by the xenlib OSAL.
 */
#include <xenlib_osal_platform.h>

/**
 * @brief Set a bit in an atomic variable.
 *
 * @param target Address of atomic variable.
 * @param bit Bit number (starting from 0).
 */
extern void xenlib_osal_atomic_set_bit(xenlib_osal_atomic_t *target,
											unsigned int bit);

/**
 * @brief Clear a bit in an atomic variable.
 *
 * @param target Address of atomic variable or array.
 * @param bit Bit number (starting from 0).
 */
extern void xenlib_osal_atomic_clear_bit(xenlib_osal_atomic_t *target,
											unsigned int bit);

/**
 * @brief Atomically set variable.
 *
 * @param target Address of atomic variable.
 * @param value Value to write to @a target.
 *
 * @return Previous value of @a target.
 */
extern xenlib_osal_atomic_val_t xenlib_osal_atomic_set(
											xenlib_osal_atomic_t *target,
											xenlib_osal_atomic_val_t value);

/**
 * @brief Atomically clear variable.
 *
 * @param target Address of atomic variable.
 *
 * @return Previous value of @a target.
 */
extern xenlib_osal_atomic_val_t xenlib_osal_atomic_clear(
											xenlib_osal_atomic_t *target);

/**
 * @brief Atomically clear a bit and test it.
 *
 * @param target Address of atomic variable.
 * @param bit Bit number (starting from 0).
 *
 * @return false if the bit was already cleared, true if it wasn't.
 */
extern bool xenlib_osal_atomic_test_and_clear_bit(
											xenlib_osal_atomic_t *target,
											unsigned int bit);

/**
 * @brief Get atomic variable value.
 *
 * @param target Address of atomic variable.
 *
 * @return Value of @a target.
 */
extern xenlib_osal_atomic_val_t xenlib_osal_atomic_get(
											const xenlib_osal_atomic_t *target);

#endif /* XENLIB_OSAL_ATOMIC_H */
