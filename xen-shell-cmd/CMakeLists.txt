# SPDX-License-Identifier: Apache-2.0

add_library(XEN_SHELL INTERFACE)

target_include_directories(XEN_SHELL INTERFACE include)

zephyr_library()
zephyr_library_sources(src/xen_shell.c src/xen_cmds.c)
zephyr_library_link_libraries(XEN_SHELL)
zephyr_include_directories(include)
