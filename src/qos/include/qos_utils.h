/****************************************************************************
 * (c) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 *
 ***************************************************************************/

#ifndef _QOS_UTILS_H_
#define _QOS_UTILS_H_


#define QOS_FACTORY_DEFAULT_NAME "factory-default"
#define QOS_DEFAULT_NAME "default"

#define QOS_TRUST_KEY "qos_trust"
#define QOS_TRUST_NONE_STRING "none"
#define QOS_TRUST_DEFAULT QOS_TRUST_NONE_STRING

#define QOS_COS_OVERRIDE_KEY "cos_override"
#define QOS_DSCP_OVERRIDE_KEY "dscp_override"

#define QOS_LOCAL_PRIORITY_DEFAULT 0
#define QOS_COLOR_DEFAULT "green"
#define QOS_DESCRIPTION_DEFAULT ""

#define QOS_MAX_LOCAL_PRIORITY 7
#define QOS_LOCAL_PRIORITY_COUNT (QOS_MAX_LOCAL_PRIORITY + 1)

#define QOS_CLI_MAX_STRING_LENGTH 64
#define QOS_CLI_STRING_BUFFER_SIZE (QOS_CLI_MAX_STRING_LENGTH + 3)

#define QOS_CLI_AUDIT_BUFFER_SIZE 160

#define QOS_COS_MAP_ENTRY_COUNT 8

#define QOS_DSCP_MAP_ENTRY_COUNT 64

#define QOS_DEFAULT_CODE_POINT_KEY "default_code_point"
#define QOS_DEFAULT_LOCAL_PRIORITY_KEY "default_local_priority"
#define QOS_DEFAULT_PRIORITY_CODE_POINT_KEY "default_priority_code_point"
#define QOS_DEFAULT_COLOR_KEY "default_color"
#define QOS_DEFAULT_DESCRIPTION_KEY "default_description"

#endif /* _QOS_UTILS_H_ */
