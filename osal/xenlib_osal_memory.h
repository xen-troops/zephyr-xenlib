/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026 EPAM Systems
 *
 * Xenlib Operating System Abstraction Layer (OSAL) memory interface
 *
 */
#ifndef XENLIB_OSAL_MEMORY_H
#define XENLIB_OSAL_MEMORY_H

/*
 * Platform-provided types and macros required by the xenlib OSAL.
 */
#include <xenlib_osal_platform.h>

/**
 * @brief Allocate memory block
 *
 * @param msize memory block size in bytes
 *
 * @return allocated memory block pointer if the allocation is successful,
 * NULL pointer otherwise
 */
extern void *xenlib_osal_memalloc(size_t msize);

/**
 * @brief Allocate memory block with a specified alignment
 *
 * @param align alignment of memory requested in bytes.
 * @param msize memory block size in bytes
 *
 * @return allocated memory block pointer if the allocation is successful,
 * NULL pointer otherwise
 */
extern void *xenlib_osal_memalloc_aligned(size_t align, size_t msize);

/**
 * @brief Free memory block
 *
 * @param mblock memory block to de-allocate
 */
extern void xenlib_osal_memfree(void *mblock);

/**
 * @brief Flush and invalidate data cache range
 *
 * @param addr starting address of the memory range
 * @param size size of the memory range in bytes
 *
 * @return 0 on success, non-zero error code otherwise
 */
extern int xenlib_osal_dcache_flush_and_invd_range(void *addr, size_t size);

/**
 * @brief Converts a 32-bit integer from big-endian byte order to the CPU's
 * native byte order.
 *
 * @param value value to convert
 *
 * @return converted input value
 */
extern uint32_t xenlib_osal_be32_to_cpu(uint32_t value);

#endif /* XENLIB_OSAL_MEMORY_H */
