# SPDX-License-Identifier: Apache-2.0
#
# Copyright (c) 2023 EPAM Systems
#

add_library(XRUN INTERFACE)

target_include_directories(XRUN INTERFACE include)

zephyr_library()
zephyr_library_sources(src/storage.c)
zephyr_library_link_libraries(XRUN)
zephyr_include_directories(include)
zephyr_library_include_directories_ifdef(
  CONFIG_FILE_SYSTEM_LITTLEFS
  ${ZEPHYR_LITTLEFS_MODULE_DIR}
  )
