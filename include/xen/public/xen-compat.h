/* SPDX-License-Identifier: MIT */
/******************************************************************************
 * xen-compat.h
 *
 * Guest OS interface to Xen.  Compatibility layer.
 *
 * Copyright (c) 2006, Christian Limpach
 * Copyright (c) 2026, TOKITA Hiroshi
 */

#ifndef __XEN_PUBLIC_XEN_COMPAT_H__
#define __XEN_PUBLIC_XEN_COMPAT_H__

#define __XEN_LATEST_INTERFACE_VERSION__ 0x00041300

#ifdef CONFIG_XEN_DOM0
#define __XEN_TOOLS__
/* Xen is built with matching headers and implements the latest interface. */
#define __XEN_INTERFACE_VERSION__ CONFIG_XEN_INTERFACE_VERSION
#elif !defined(__XEN_INTERFACE_VERSION__)
/* Guests which do not specify a version get the legacy interface. */
#define __XEN_INTERFACE_VERSION__ 0x00000000
#endif

#if __XEN_INTERFACE_VERSION__ > __XEN_LATEST_INTERFACE_VERSION__
#error "These header files do not support the requested interface version."
#endif

#define COMPAT_FLEX_ARRAY_DIM XEN_FLEX_ARRAY_DIM

#if defined(CONFIG_XEN)
#if !defined(_ASMLANGUAGE)
/* modification for zephyr: Add common definitions. */
#include <stdbool.h>
#include <stdint.h>
#endif
#endif

#endif /* __XEN_PUBLIC_XEN_COMPAT_H__ */
