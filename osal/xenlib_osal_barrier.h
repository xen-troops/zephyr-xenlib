/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026 EPAM Systems
 *
 * Xenlib Operating System Abstraction Layer (OSAL) barrier interface
 *
 */
#ifndef XENLIB_OSAL_BARRIER_H
#define XENLIB_OSAL_BARRIER_H

/**
 * @brief Full data memory barrier
 *
 * Preventing reordering of memory accesses across the barrier.
 */
extern void xenlib_osal_dmem_fence_full(void);

/**
* @brief Perform a full data synchronization barrier.
*
* Ensures that prior explicit memory accesses and relevant memory
* operations have completed to the required architectural point before
* execution proceeds beyond the barrier.
*/
extern void xenlib_osal_dsync_fence_full(void);

#endif /* XENLIB_OSAL_BARRIER_H */
