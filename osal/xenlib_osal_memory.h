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

#if !defined(XENLIB_OSAL_MEM_CACHE_NC) || \
	!defined(XENLIB_OSAL_MEM_CACHE_WB) || \
	!defined(XENLIB_OSAL_MEM_PERM_RO) || \
	!defined(XENLIB_OSAL_MEM_PERM_RW)
#error "OSAL does not provide the required physical memory mapping attributes"
#endif

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
 * @brief Map a physical memory range into the caller's address space.
 *
 * @param[out] vaddr Address that receives the mapped virtual address.
 * @param paddr Physical address of the range to map.
 * @param size Size of the range in bytes.
 * @param flags Bitwise OR of one cache attribute
 * (XENLIB_OSAL_MEM_CACHE_NC or XENLIB_OSAL_MEM_CACHE_WB) and one access
 * attribute (XENLIB_OSAL_MEM_PERM_RO or XENLIB_OSAL_MEM_PERM_RW).
 *
 * @return 0 on success, non-zero error code otherwise
 */
extern int xenlib_osal_map_phys_memory(void **vaddr, uintptr_t paddr,
				      size_t size, uint32_t flags);

/**
 * @brief Remove a mapping created by xenlib_osal_map_phys_memory().
 *
 * @param vaddr Mapped virtual address.
 * @param size Size of the mapped range in bytes.
 */
extern void xenlib_osal_unmap_phys_memory(void *vaddr, size_t size);

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
