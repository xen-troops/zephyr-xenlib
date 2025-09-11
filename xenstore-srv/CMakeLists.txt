# SPDX-License-Identifier: Apache-2.0

add_library(XENSTORE_SRV INTERFACE)

target_include_directories(XENSTORE_SRV INTERFACE include)

zephyr_library()
zephyr_library_sources(src/xenstore_srv.c)
zephyr_library_link_libraries(XENSTORE_SRV XEN_STORE_COMMON)
zephyr_include_directories(include)
