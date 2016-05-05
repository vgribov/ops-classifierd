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
#include <vswitch-idl.h>
#include "ops-cls-asic-plugin.h"

#define ACL_PROTOCOL_INVALID -1 /**< negative value to indicate error  */
#define ACL_PROTOCOL_MIN      0 /**< lowest possible packet data value */
#define ACL_PROTOCOL_MAX    256 /**< highest possible packet data valu */
#define ACL_PROTOCOL_ANY (ACL_PROTOCOL_MAX + 1) /**< positive but beyond max */

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
 * @retval          Numeric protocol number on success
 * @retval          ACL_PROTOCOL_INVALID on error
 * @retval          ACL_PROTOCOL_ANY if in_proto is NULL or "any"
 */
int acl_parse_protocol_get_number_from_name(const char *in_proto);


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
 *                            "" if given special values "any" or NULL.
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
 *                            "any" if given special values NULL or "".
 *                            Must be allocated with length INET_ADDRSTRLEN*2.
 *
 * @return                    true on success, false on failure
 */
bool acl_ipv4_address_normalized_to_user(const char *normalized_str, char *user_str);

/**
 * Add IP address config information to an ACE dynamic string
 *
 * @param dstring      Pointer to initialized dynamic string
 * @param address_str  Pointer to IP address string
 */
void acl_entry_ip_address_config_to_ds(struct ds *dstring, char *address_str);

/**
 * Add L4 port config information to an ACE dynamic string
 *
 * @param dstring  Pointer to initialized dynamic string
 * @param min      First port number
 * @param max      Last port number
 * @param reverse  Whether range is reversed
 */
void acl_entry_l4_port_config_to_ds(struct ds *dstring,
                               int64_t min, int64_t max, bool reverse);

/**
 * Creates a string with an ACL Entry config as if it were entered into the CLI
 *
 * @param sequence_num  ACL Entry Sequence number
 * @param ace_row       Pointer to ACL_Entry row
 *
 * @return              ACL Entry string, caller-freed, not newline-terminated
 */
char *acl_entry_config_to_string(const int64_t sequence_num,
                           const struct ovsrec_acl_entry *ace_row);

/**
 * Look up an ACE by key (sequence number) in ACE statistics
 *
 * @param  port_row        Port row pointer
 * @param  sequence_number ACE sequence number
 *
 * @return                 Hit count for ACE, 0 on failure
 *
 * @todo This could/should be generated as part of IDL.
 */
const int64_t ovsrec_port_aclv4_in_statistics_getvalue(
                                            const struct ovsrec_port *port_row,
                                            const int64_t key);
#endif  /* __OPS_CLS_ACL_PARSE_H__ */
