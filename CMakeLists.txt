# (c) Copyright 2016 Hewlett Packard Enterprise Development LP
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

cmake_minimum_required (VERSION 2.8)

set (CLASSIFIERD ops-classifierd)
project (${CLASSIFIERD})
# top level src and include dir
set (OPS_CLS_SOURCE_DIR ${CMAKE_SOURCE_DIR}/src)
set (OPS_CLS_INCLUDE_DIR ${CMAKE_SOURCE_DIR}/include)
# dirs under top level src, src/common and src/include dir
set (CLS_COMMON_DIR ${OPS_CLS_SOURCE_DIR}/common)
set (CLS_INCLUDE_DIR ${OPS_CLS_SOURCE_DIR}/include)
# ACL source dir under top level src
set (CLS_ACL_DIR ${OPS_CLS_SOURCE_DIR}/acl)

MESSAGE("PROJECT_SRC_DIR=${PROJECT_SOURCE_DIR}")
MESSAGE("OPS_CLS_SOURCE_DIR=${OPS_CLS_SOURCE_DIR}")
MESSAGE("OPS_CLS_INCLUDE_DIR=${OPS_CLS_INCLUDE_DIR}")
MESSAGE("CLS_COMMON_DIR=${CLS_COMMON_DIR}")
MESSAGE("CLS_INCLUDE_DIR=${CLS_INCLUDE_DIR}")
MESSAGE("CLS_ACL_DIR=${CLS_ACL_DIR}")

# Define compile flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -Werror")

# Rules to locate needed libraries
include(FindPkgConfig)
pkg_check_modules(OVSCOMMON REQUIRED libovscommon)
pkg_check_modules(OVSDB REQUIRED libovsdb)

include_directories (${PROJECT_BINARY_DIR} ${PROJECT_SOURCE_DIR}/${INCL_DIR}
                     ${OVSCOMMON_INCLUDE_DIRS} ${OPS_CLS_INCLUDE_DIR}
                     ${CLS_INCLUDE_DIR} )

# Sources to build ops-classifierd
set (SOURCES ${OPS_CLS_SOURCE_DIR}/ops-classifierd.c)

set (HEADERS ${OPS_CLS_INCLUDE_DIR}/ops-cls-asic-plugin.h)

# Rules to build ops-classifierd
add_executable (${CLASSIFIERD} ${SOURCES})

target_link_libraries (${CLASSIFIERD}
                       ${OVSCOMMON_LIBRARIES} ${OVSDB_LIBRARIES}
                       -lpthread -lrt audit)

# Rules to install ops-classifierd binary in rootfs
install(TARGETS ${CLASSIFIERD}
        RUNTIME DESTINATION bin)

install (FILES ${HEADERS} DESTINATION include)

# Build sub-features
add_subdirectory(src)
