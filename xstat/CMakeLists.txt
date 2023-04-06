# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2023 EPAM Systems
# Author: Dmytro Semenets <dmytro_semenets@epam.com>

add_library(XSTAT INTERFACE)

target_include_directories(XSTAT INTERFACE include)

zephyr_library()
zephyr_library_sources(src/xstat.c)
zephyr_library_link_libraries(XSTAT)
zephyr_include_directories(include)
