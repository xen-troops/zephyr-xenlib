# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2023 EPAM Systems
# Author: Volodymyr Babchuk <volodymyr_babchuk@epam.com>

add_subdirectory_ifdef(CONFIG_XEN_STORE_SRV xenstore-srv)
add_subdirectory_ifdef(CONFIG_XEN_DOMAIN_MANAGEMENT xen-dom-mgmt)
add_subdirectory_ifdef(CONFIG_XEN_SHELL xen-shell-cmd)
add_subdirectory_ifdef(CONFIG_XEN_CONSOLE_SRV xen-console-srv)
add_subdirectory_ifdef(CONFIG_XEN_VCH vch)
add_subdirectory_ifdef(CONFIG_XEN_LIBFDT libfdt)
add_subdirectory_ifdef(CONFIG_XSTAT xstat)
