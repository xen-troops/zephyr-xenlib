# SPDX-License-Identifier: Apache-2.0

add_library(XEN_LIBFDT INTERFACE)

target_include_directories(XEN_LIBFDT INTERFACE .)

zephyr_library()
zephyr_library_sources(fdt.c fdt_addresses.c fdt_check.c fdt_empty_tree.c fdt_overlay.c fdt_ro.c fdt_rw.c
  fdt_strerror.c fdt_sw.c fdt_wip.c)
zephyr_library_link_libraries(XEN_LIBFDT)
zephyr_include_directories(.)
