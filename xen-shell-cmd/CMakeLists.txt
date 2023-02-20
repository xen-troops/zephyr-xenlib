# SPDX-License-Identifier: Apache-2.0

add_library(XEN_SHELL INTERFACE)

zephyr_library()
zephyr_library_sources(src/xen_cmds.c)
zephyr_library_sources_ifdef(CONFIG_XRUN_SHELL_CMDS src/xrun_cmds.c)
zephyr_library_link_libraries(XEN_SHELL)
