# SPDX-License-Identifier: Apache-2.0

add_library(XSTAT INTERFACE)

target_include_directories(XSTAT INTERFACE include)

zephyr_library()
zephyr_library_sources(src/xstat.c)
zephyr_library_link_libraries(XSTAT)
zephyr_include_directories(include)
