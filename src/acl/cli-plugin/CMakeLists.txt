# (C) Copyright 2016 Hewlett Packard Enterprise Development LP
#
#  Licensed under the Apache License, Version 2.0 (the "License"); you may
#  not use this file except in compliance with the License. You may obtain
#  a copy of the License at
#
#       http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#  License for the specific language governing permissions and limitations
#  under the License.

cmake_minimum_required (VERSION 2.8)

project ("acl_cli")

set (CMAKE_INCL_DIR ${CMAKE_SOURCE_DIR}/include)
set (LIBACLCLI acl_cli)

# This option is passed by build system.
OPTION( CPU_LITTLE_ENDIAN "Specifies CPU architecture is Little-Endian" OFF )

# Define compile flags
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -std=gnu99 -Wall -Werror")


add_definitions(-DHAVE_CONFIG_H -DHAVE_SOCKLEN_T)

# Rules to locate needed libraries
include(FindPkgConfig)
pkg_check_modules(OVSCOMMON REQUIRED libovscommon)
pkg_check_modules(OVSDB REQUIRED libovsdb)
pkg_check_modules(OPSCLI REQUIRED ops-cli)

include_directories (${CMAKE_INCL_DIR}
                     ${PROJECT_SOURCE_DIR}
                     ${OVSCOMMON_INCLUDE_DIRS}
                     ${OPSCLI_INCLUDE_DIRS}
                     ${OPS_CLS_INCLUDE_DIR}
                     ${CLS_INCLUDE_DIR}
                     ${ACL_INCLUDE_DIR}
                    )

# CLI library source files
set (SOURCES_CLI
                 ${ACL_UTIL_DIR}/acl_parse.c
                 ${ACL_UTIL_DIR}/acl_db_util.c
                 ${PROJECT_SOURCE_DIR}/access_list_vty.c
                 ${PROJECT_SOURCE_DIR}/access_list_vty_ovsdb.c
                 ${PROJECT_SOURCE_DIR}/access_list_vty_ovsdb_util.c
                 ${PROJECT_SOURCE_DIR}/access_list_vty_util.c
                 ${PROJECT_SOURCE_DIR}/vtysh_ovsdb_access_list_context.c
    )

add_library (${LIBACLCLI} SHARED ${SOURCES_CLI})

target_link_libraries(${LIBACLCLI} audit)

# Installation
install(TARGETS ${LIBACLCLI}
        LIBRARY DESTINATION lib/cli/plugins
       )
