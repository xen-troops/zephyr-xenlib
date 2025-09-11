# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2025 TOKITA Hiroshi

add_library(XENSTORE_CLI INTERFACE)

target_include_directories(XENSTORE_CLI INTERFACE include)

zephyr_library()
zephyr_library_sources(src/xenstore_cli.c)
zephyr_library_link_libraries(XENSTORE_CLI XEN_STORE_COMMON)
zephyr_include_directories(include)
