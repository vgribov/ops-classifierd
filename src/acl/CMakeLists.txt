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

PROJECT(acl)

MESSAGE("got to acl")
# acl/include directory
set(ACL_INCLUDE_DIR "${PROJECT_SOURCE_DIR}/include")

# acl/util directory
set(ACL_UTIL_DIR "${PROJECT_SOURCE_DIR}/util")

MESSAGE("PROJECT_SOURCE_DIR=${PROJECT_SOURCE_DIR}")
MESSAGE("ACL_INCLUDE_DIR=${ACL_INCLUDE_DIR}")
MESSAGE("ACL_UTIL_DIR=${ACL_UTIL_DIR}")
