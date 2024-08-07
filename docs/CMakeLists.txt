# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2023 EPAM Systems

cmake_minimum_required (VERSION 3.8)
project ("xenlibdocs")

find_package(Doxygen REQUIRED)

set(CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}" ${CMAKE_MODULE_PATH})

# Find all the public headers
set(XENLIB_PUBLIC_HEADER_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../)
file(GLOB_RECURSE XENLIB_PUBLIC_HEADERS ${XENLIB_PUBLIC_HEADER_DIR}/*.h)

#This will be the main output of our command
set(DOXYGEN_INPUT_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../)
set(DOXYGEN_OUTPUT_DIR ${CMAKE_CURRENT_BINARY_DIR}/doxygen)
set(DOXYGEN_INDEX_FILE ${DOXYGEN_OUTPUT_DIR}/html/index.html)
set(DOXYFILE_IN ${CMAKE_CURRENT_SOURCE_DIR}/Doxyfile.in)
set(DOXYFILE_OUT ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile)

#Replace variables inside @@ with the current values
configure_file(${DOXYFILE_IN} ${DOXYFILE_OUT} @ONLY)


file(MAKE_DIRECTORY ${DOXYGEN_OUTPUT_DIR}) #Doxygen won't create this for us
add_custom_command(OUTPUT ${DOXYGEN_INDEX_FILE}
                   DEPENDS ${XENLIB_PUBLIC_HEADERS}
                   COMMAND ${DOXYGEN_EXECUTABLE} ${DOXYFILE_OUT}
                   MAIN_DEPENDENCY ${DOXYFILE_OUT} ${DOXYFILE_IN}
                   COMMENT "Generating docs")

add_custom_target(Doxygen ALL DEPENDS ${DOXYGEN_INDEX_FILE})


find_package(Sphinx REQUIRED)

set(SPHINX_SOURCE ${CMAKE_CURRENT_SOURCE_DIR})
set(SPHINX_BUILD ${CMAKE_CURRENT_BINARY_DIR}/sphinx)
set(SPHINX_INDEX_FILE ${SPHINX_BUILD}/index.html)

file(MAKE_DIRECTORY ${SPHINX_BUILD})
add_custom_target(Sphinx ALL
                  COMMAND
                   ${SPHINX_EXECUTABLE} -b html
                   # Tell Breathe where to find the Doxygen output
                   -Dbreathe_projects.xenlib_docs=${DOXYGEN_OUTPUT_DIR}/xml
                   ${SPHINX_SOURCE} ${SPHINX_BUILD}
                  WORKING_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}
                  DEPENDS
                   # Other docs files you want to track should go here (or in some variable)
                  ${CMAKE_CURRENT_SOURCE_DIR}/index.rst
                  ${DOXYGEN_INDEX_FILE}
                  ${SPHINX_SOURCE}/conf.py
                  COMMENT "Generating documentation with Sphinx")

add_dependencies(Sphinx Doxygen)
