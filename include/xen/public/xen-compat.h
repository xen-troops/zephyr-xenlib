/* SPDX-License-Identifier: MIT */
/******************************************************************************
 * xen-compat.h
 *
 * Guest OS interface to Xen.  Compatibility layer.
 *
 * Copyright (c) 2006, Christian Limpach
 */

#ifndef __XEN_PUBLIC_XEN_COMPAT_H__
#define __XEN_PUBLIC_XEN_COMPAT_H__

#define __XEN_LATEST_INTERFACE_VERSION__ 0x00040e00

#if defined(__XEN__) || defined(__XEN_TOOLS__)
/* Xen is built with matching headers and implements the latest interface. */
#define __XEN_INTERFACE_VERSION__ __XEN_LATEST_INTERFACE_VERSION__
#elif defined(CONFIG_XEN_INTERFACE_VERSION)
/* modification for zephyr: Define __XEN_TOOLS__ for supporting DOM0 */
#define __XEN_TOOLS__

/* modification for zephyr: If a version is specified explicitly, it will be used. */
#define __XEN_INTERFACE_VERSION__ CONFIG_XEN_INTERFACE_VERSION

/* modification for zephyr: Add common definitions. */
#if !defined(_ASMLANGUAGE)
#include <stdbool.h>
#include <stdint.h>
#endif
#elif !defined(__XEN_INTERFACE_VERSION__)
/* Guests which do not specify a version get the legacy interface. */
#define __XEN_INTERFACE_VERSION__ 0x00000000
#endif

#if __XEN_INTERFACE_VERSION__ > __XEN_LATEST_INTERFACE_VERSION__
#error "These header files do not support the requested interface version."
#endif

#define COMPAT_FLEX_ARRAY_DIM XEN_FLEX_ARRAY_DIM

#endif /* __XEN_PUBLIC_XEN_COMPAT_H__ */
