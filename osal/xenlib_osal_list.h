/* SPDX-License-Identifier: Apache-2.0 */
/*
 * Copyright (c) 2026 EPAM Systems
 *
 * Xenlib Operating System Abstraction Layer (OSAL) list interface
 *
 * Provides single-linked (slist) and double-linked (dlist) list operations,
 * including static and runtime initialization, list iteration, and node
 * insertion and removal.
 */
#ifndef XENLIB_OSAL_LIST_H
#define XENLIB_OSAL_LIST_H

/*
 * Platform-provided types and macros required by the xenlib OSAL.
 */
#include <xenlib_osal_platform.h>


/* Verify that the platform provides the required macro definitions */
#ifndef XENLIB_OSAL_DLIST_STATIC_INIT
#error "OSAL does not provide the required double-linked list interface: " \
	   "XENLIB_OSAL_DLIST_STATIC_INIT"
#endif
#ifndef XENLIB_OSAL_DLIST_FOR_EACH_CONTAINER
#error "OSAL does not provide the required double-linked list interface: " \
	   "XENLIB_OSAL_DLIST_FOR_EACH_CONTAINER"
#endif
#ifndef XENLIB_OSAL_DLIST_FOR_EACH_CONTAINER_SAFE
#error "OSAL does not provide the required double-linked list interface: " \
	   "XENLIB_OSAL_DLIST_FOR_EACH_CONTAINER_SAFE"
#endif
#ifndef XENLIB_OSAL_DLIST_PEEK_HEAD_CONTAINER
#error "OSAL does not provide the required double-linked list interface: " \
	   "XENLIB_OSAL_DLIST_PEEK_HEAD_CONTAINER"
#endif
#ifndef XENLIB_OSAL_SLIST_STATIC_INIT
#error "OSAL does not provide the required single-linked list interface: " \
	   "XENLIB_OSAL_SLIST_STATIC_INIT"
#endif
#ifndef XENLIB_OSAL_SLIST_FOR_EACH_CONTAINER
#error "OSAL does not provide the required single-linked list interface: " \
	   "XENLIB_OSAL_SLIST_FOR_EACH_CONTAINER"
#endif
#ifndef XENLIB_OSAL_SLIST_FOR_EACH_CONTAINER_SAFE
#error "OSAL does not provide the required single-linked list interface: " \
	   "XENLIB_OSAL_SLIST_FOR_EACH_CONTAINER_SAFE"
#endif
#ifndef XENLIB_OSAL_SLIST_PEEK_HEAD_CONTAINER
#error "OSAL does not provide the required single-linked list interface: " \
	   "XENLIB_OSAL_SLIST_PEEK_HEAD_CONTAINER"
#endif

/**
 * @brief initialize dlist
 *
 * @param list the doubly-linked list
 */
extern void xenlib_osal_dlist_init(xenlib_osal_dlist_t *list);

/**
 * @brief initialize dlist node
 *
 * @param node the doubly-linked list node
 */
extern void xenlib_osal_dnode_init(xenlib_osal_dnode_t *node);

/**
 * @brief Append node to dlist
 *
 * @param list the target doubly-linked list
 * @param node the list node to append
 */
extern void xenlib_osal_dlist_append(xenlib_osal_dlist_t *list,
									 xenlib_osal_dnode_t *node);

/**
 * @brief Check if dlist is empty
 *
 * @param list the target doubly-linked list
 *
 * @return true if empty, false otherwise
 */
extern bool xenlib_osal_dlist_is_empty(const xenlib_osal_dlist_t *list);

/**
 * @brief Remove dlist node
 *
 * The node must be present in the list
 *
 * @param node dlist node to remove
 */
extern void xenlib_osal_dlist_remove(xenlib_osal_dnode_t *node);

/**
 * @brief initialize slist
 *
 * @param node the single-linked list to initialize
 */
extern void xenlib_osal_slist_init(xenlib_osal_slist_t *list);

/**
 * @brief Append node to slist
 *
 * @param list the target single-linked list
 * @param node the list node to append
 */
extern void xenlib_osal_slist_append(xenlib_osal_slist_t *list,
									 xenlib_osal_snode_t *node);

/**
 * @brief Check if slist is empty
 *
 * @param list the target single-linked list
 *
 * @return true if empty, false otherwise
 */
extern bool xenlib_osal_slist_is_empty(const xenlib_osal_slist_t *list);

/**
 * @brief Remove slist node
 *
 * @param list list to which the node belongs
 * @param prev_node previous node
 * (can be NULL, which means the node is the list's head)
 * @param node slist node to remove
 */
extern void xenlib_osal_slist_remove(xenlib_osal_slist_t *list,
									 xenlib_osal_snode_t *prev,
						 			 xenlib_osal_snode_t *node);

#endif /* XENLIB_OSAL_LIST_H */
