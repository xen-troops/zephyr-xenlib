# Copyright (c) 2023 EPAM Systems
#
# SPDX-License-Identifier: Apache-2.0
#

add_library(VCH INTERFACE)
target_include_directories(VCH INTERFACE include)

zephyr_library()
zephyr_library_sources(src/vch.c)
zephyr_library_link_libraries(VCH)
zephyr_include_directories(include)
