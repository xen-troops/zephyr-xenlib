# SPDX-License-Identifier: Apache-2.0

add_library(XEN_CONSOLE_SRV INTERFACE)

target_include_directories(XEN_CONSOLE_SRV INTERFACE include)

zephyr_library()
zephyr_library_sources(src/xen_console.c)
zephyr_library_link_libraries(XEN_CONSOLE_SRV)
zephyr_include_directories(include)
