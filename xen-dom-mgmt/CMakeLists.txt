# SPDX-License-Identifier: Apache-2.0

add_library(XENDOM_MGMT INTERFACE)

target_include_directories(XENDOM_MGMT INTERFACE include)

zephyr_library()
zephyr_library_sources(src/xen-dom-mgmt.c src/xen-dom-fdt.c src/mem-mgmt.c src/xl_parser.c)
zephyr_library_sources(src/xen-dom-xs.c)
if(CONFIG_XEN_DOMCFG_SECTION)
    zephyr_linker_sources(DATA_SECTIONS linker.ld)
endif()
zephyr_library_link_libraries(XENDOM_MGMT)
zephyr_include_directories(include)
