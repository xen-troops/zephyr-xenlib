# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(test_xrun)

target_include_directories(app PRIVATE ${APPLICATION_SOURCE_DIR}/../../xrun/include/
${APPLICATION_SOURCE_DIR}/include)

FILE(GLOB app_sources src/main.c src/mock-storage.c src/mock-xen-dom-mgmt.c)
target_sources(app PRIVATE ${app_sources} ../../xrun/src/xrun.c)
zephyr_include_directories(include)
