/*
 * Copyright (C) 2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __OPS_CLS_ACL_PARSE_H__
#define __OPS_CLS_ACL_PARSE_H__ 1

#include <stdlib.h>
#include <ctype.h>
#include "ops-cls-asic-plugin.h"

#define ACL_PROTOCOL_ICMP    1
#define ACL_PROTOCOL_IGMP    2
#define ACL_PROTOCOL_TCP     6
#define ACL_PROTOCOL_UDP     17
#define ACL_PROTOCOL_GRE     47
#define ACL_PROTOCOL_ESP     50
#define ACL_PROTOCOL_AH      51
#define ACL_PROTOCOL_ICMPV6  58
#define ACL_PROTOCOL_PIM     103
#define ACL_PROTOCOL_SCTP    132
#define ACL_PROTOCOL_INVALID 255

/* Log timer constants */
#define ACL_LOG_TIMER_STR "acl_log_timer"
#define ACL_LOG_TIMER_MIN "30"
#define ACL_LOG_TIMER_MAX "300"
#define ACL_LOG_TIMER_DEFAULT ACL_LOG_TIMER_MAX

/**
 * Determine if a string is numeric or not
 *
 * @param  in_str  String to test for numeric contents
 *
 * @return         true if string is numeric, false otherwise
 */
bool acl_parse_str_is_numeric(const char *in_str);

/**
 * Get numeric IP protocol number from an all-lowercase string
 *
 * @param  in_proto String as provided by user interface (e.g. CLI)
 *
 * @return          Numeric protocol number or 255 on error
 */
uint8_t acl_parse_protocol_get_number_from_name(const char *in_proto);

/**
 * Get all-lowercase string token for a given IP protocol number
 *
 * @param  proto_number Numeric IP protocol number
 *
 * @return              String protocol name (may be numeric if no name)
 */
const char *acl_parse_protocol_get_name_from_number(uint8_t proto_number);

/**
 * Translate a user-input string into a database-format string
 *
 * @param[in]  user_str       User string formatted "any", "A.B.C.D",
 *                            "A.B.C.D/M", "A.B.C.D/W.X.Y.Z".
 * @param[out] normalized_str Database string formatted "A.B.C.D/W.X.Y.Z".
 *                            Must be allocated with length INET_ADDRSTRLEN*2.
 *
 * @return                    true on success, false on failure
 */
bool acl_ipv4_address_user_to_normalized(const char *user_str, char *normalized_str);

/**
 * Translate a database-format string into a user-input string
 *
 * @param[in]  normalized_str Database string formatted "A.B.C.D/W.X.Y.Z".
 * @param[out] user_str       User string formatted "any", "A.B.C.D",
 *                            "A.B.C.D/M", "A.B.C.D/W.X.Y.Z".
 *                            Must be allocated with length INET_ADDRSTRLEN*2.
 *
 * @return                    true on success, false on failure
 */
bool acl_ipv4_address_normalized_to_user(const char *normalized_str, char *user_str);

#endif  /* __OPS_CLS_ACL_PARSE_H__ */
