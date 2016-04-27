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

set (ACL acl_plugin)
set (INCLUDE_DIR include)
project (${ACL})

MESSAGE("got to switchd-plugin")
MESSAGE("PROJECT_BINARY_DIR = ${PROJECT_BINARY_DIR}")
MESSAGE("PROJECT_SOURCE_DIR = ${PROJECT_SOURCE_DIR}")
MESSAGE("INCL_DIR = ${INCL_DIR}")
MESSAGE("CMAKE_SOURCE_DIR = ${CMAKE_SOURCE_DIR}")

# Define compile flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -Werror")

# Rules to locate needed libraries
include(FindPkgConfig)
pkg_check_modules(OVSCOMMON REQUIRED libovscommon)

include_directories(
   ${PROJECT_BINARY_DIR}
   ${PROJECT_SOURCE_DIR}
   ${OPS_CLS_INCLUDE_DIR}
   ${ACL_INCLUDE_DIR}
   ${CLS_INCLUDE_DIR}
   ${OVSCOMMON_INCLUDE_DIRS}
   ${INCLUDE_DIR}
)

# Sources to build acl
file(GLOB SOURCES "${PROJECT_SOURCE_DIR}/*.c" "${ACL_UTIL_DIR}/*.c" "${CLS_COMMON_DIR}/*.c")
add_library(${ACL} SHARED ${SOURCES})
install(TARGETS ${ACL} LIBRARY DESTINATION lib/openvswitch/plugins)

MESSAGE("done with switchd-plugin")
