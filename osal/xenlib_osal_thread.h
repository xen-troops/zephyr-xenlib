/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026 EPAM Systems
 *
 * Xenlib Operating System Abstraction Layer (OSAL) thread interface
 *
 */
#ifndef XENLIB_OSAL_THREAD_H
#define XENLIB_OSAL_THREAD_H

/*
 * Platform-provided types and macros required by the xenlib OSAL.
 */
#include <xenlib_osal_platform.h>

/* Verify that the platform provides the required macro definitions */
#ifndef XENLIB_OSAL_THREAD_STACK_DEFINE
#error "OSAL does not provide the required thread stack definition macro: " \
	   "XENLIB_OSAL_THREAD_STACK_DEFINE"
#endif
#ifndef XENLIB_OSAL_THREAD_STACK_ARRAY_DEFINE
#error "OSAL does not provide the required thread stack array definition macro: " \
	   "XENLIB_OSAL_THREAD_STACK_ARRAY_DEFINE"
#endif

/**
 * @brief Create a thread and schedule it for execution
 *
 * Using other values, or sizeof(stack) may produce undefined behavior.
 *
 * @param thread uninitialized thread object that will be created
 * @param stack preallocated thread stack (via XENLIB_OSAL_THREAD_STACK_DEFINE())
 * @param stack_size stack size in bytes
 * @param entry thread entry function
 * @param arg1 1st entry point parameter
 * @param arg2 2nd entry point parameter
 * @param arg3 3rd entry point parameter
 * @param priority thread priority
 * @param options thread options
 * @param delay scheduling delay, or XENLIB_OSAL_NO_WAIT (for no delay)
 * 
 * @return ID of new thread.
 */
extern xenlib_osal_tid_t xenlib_osal_thread_create(
											xenlib_osal_thread_t *thread,
											xenlib_osal_thread_stack_t *stack,
											size_t stack_size,
											xenlib_osal_thread_entry_t entry,
											void *arg1,
											void *arg2,
											void *arg3,
											int priority,
											int options,
											xenlib_osal_timeout_t delay);

/**
 * @brief Set thread name that will be used when tracing and debugging
 *
 * Using other values, or sizeof(stack) may produce undefined behavior.
 *
 * @param thread thread ID whose name shall be set (NULL for current thread)
 * @param name thread name to set
 * 
 * @return 0 on success, non-zero error code otherwise
 */
extern int xenlib_osal_thread_name_set(xenlib_osal_tid_t thread,
									   const char *name);

/**
 * @brief Sleep until the target thread exit
 *
 * Using other values, or sizeof(stack) may produce undefined behavior.
 *
 * @param thread target thread
 * @param timeout wait timeout for thread exit or timeout constant
 * XENLIB_OSAL_WAIT_FOREVER
 * 
 * @return 0 on success, non-zero error code otherwise
 */
extern int xenlib_osal_thread_join(xenlib_osal_thread_t *thread,
								   xenlib_osal_timeout_t timeout);

#endif /* XENLIB_OSAL_THREAD_H */
