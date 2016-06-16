/*
 * Copyright (C) 2015, 2016 Hewlett Packard Enterprise Development LP
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/************************************************************************//**
 * @defgroup ops-access-list Access Control List (ACL)
 * Access Control List (ACL) CLI commands and associated code.
 * See ops/doc/access_list_cli.md for command syntax/documentation.
 ***************************************************************************/

/************************************************************************//**
 * @ingroup ops-access-list
 *
 * @file
 * Definition of Access Control List (ACL) CLI command definitions.
 ***************************************************************************/

#ifndef _ACCESS_LIST_VTY_H
#define _ACCESS_LIST_VTY_H

/* Misc constants */
#define MAX_ACL_NAME_LENGTH 65 /**< 64 character name + NULL-terminator */
#define IP_VER_STR_LEN 5       /**< "ipv{4|6}" + NULL-terminator */
#define ACL_TRUE_STR "true"
#define ACL_LOG_TIMER_NAME_STR "ACL log timer length (frequency)"
#define ACL_LOG_TIMER_DEFAULT_STR "default"

/* Constants related to ACE sequence numbers */
#define ACE_SEQ_MAX 4294967295 /**< Maximum sequence number allowed for an ACE */
#define ACE_SEQ_MAX_STR_LEN 11 /**< ACE_SEQ_MAX in a string + NULL-terminator */
#define ACE_SEQ_AUTO_INCR   10 /**< Amount to increment new ACEs automatically by */

/* https://gcc.gnu.org/onlinedocs/cpp/Stringification.html#Stringification */
#define ACL_NUM_TO_STR_HELPER(x) #x                /**< Preprocessor helper macro */
#define ACL_NUM_TO_STR(x) ACL_NUM_TO_STR_HELPER(x) /**< Preprocessor stringify macro */

/* Common help strings */
#define ACL_STR "Access control list (ACL)\n"
#define ACL_NAME_STR "ACL name\n"
#define ACL_CLI_CMD_STR "Format output as CLI commands\n"
#define ACL_CFG_STR "Display user-specified configuration\n"
#define ACL_HITCOUNTS_STR "Hit counts (statistics)\n"
#define ACL_IN_STR "Inbound (ingress) traffic\n"
#define ACL_OUT_STR "Outbound (egress) traffic\n"
#define ACL_IP_STR "Internet Protocol v4 (IPv4)\n"
#define ACL_INTERFACE_STR "Specify interface\n"
#define ACL_INTERFACE_NAME_STR "Interface Name\n"
#define ACL_INTERFACE_ID_STR "Identifier (Interface Name or VLAN ID)\n"
#define ACL_VLAN_STR "Specify VLAN\n"
#define ACL_VLAN_ID_STR "VLAN ID\n"
#define ACL_ALL_STR "All access-lists\n"
#define ACL_RESET_STR "Reset configuration\n"
#define ACL_APPLIED_STR "Applied configuration record\n"

/* Command strings (cmdstr) and Help strings (helpstr) used in vtysh DEFUNs */
#define ACE_SEQ_CMDSTR "<1-" ACL_NUM_TO_STR(ACE_SEQ_MAX) "> "
#define ACE_SEQ_HELPSTR "Access control entry (ACE) sequence number\n"
#define ACE_ACTION_CMDSTR "(deny | permit) "
#define ACE_ACTION_HELPSTR "Deny packets matching this ACE\n" \
                           "Permit packets matching this ACE\n"
#define ACE_ALL_PROTOCOLS_CMDSTR "(any | ah | gre | esp | icmp | igmp |  pim | sctp | tcp | udp | <0-255>) "
#define ACE_ALL_PROTOCOLS_HELPSTR "Any internet protocol number\n" \
                                  "Authenticated header\n" \
                                  "Generic routing encapsulation\n" \
                                  "Encapsulation security payload\n" \
                                  "Internet control message protocol\n" \
                                  "Internet group management protocol\n" \
                                  "Protocol independent multicast\n" \
                                  "Stream control transport protocol\n" \
                                  "Transport control protocol\n" \
                                  "User datagram protocol\n" \
                                  "Specify numeric protocol value\n"
#define ACE_PORT_PROTOCOLS_CMDSTR  "(sctp | tcp | udp) "
#define ACE_PORT_PROTOCOLS_HELPSTR "Stream control transport protocol\n" \
                                   "Transport control protocol\n" \
                                   "User datagram protocol\n"
#define ACE_IP_ADDRESS_CMDSTR "(any | A.B.C.D | A.B.C.D/M | A.B.C.D/W.X.Y.Z) "
#define ACE_SRC_IP_ADDRESS_HELPSTR "Any source IP address\n" \
                                   "Specify source IP host address\n" \
                                   "Specify source IP network address with prefix length\n" \
                                   "Specify source IP network address with network mask\n"
#define ACE_DST_IP_ADDRESS_HELPSTR "Any destination IP address\n" \
                                   "Specify destination IP host address\n" \
                                   "Specify destination IP network address with prefix length\n" \
                                   "Specify destination IP network address with network mask\n"
#define ACE_PORT_OPER_CMDSTR "(eq | gt | lt | neq) <0-65535> "
#define ACE_SRC_PORT_OPER_HELPSTR "Layer 4 source port equal to\n" \
                                  "Layer 4 source port greater than\n" \
                                  "Layer 4 source port less than\n" \
                                  "Layer 4 source port not equal to\n" \
                                  "Layer 4 source port\n"
#define ACE_DST_PORT_OPER_HELPSTR "Layer 4 destination port equal to\n" \
                                  "Layer 4 destination port greater than\n" \
                                  "Layer 4 destination port less than\n" \
                                  "Layer 4 destination port not equal to\n" \
                                  "Layer 4 destination port\n"
#define ACE_PORT_RANGE_CMDSTR "(range) <0-65535> <0-65535> "
#define ACE_SRC_PORT_RANGE_HELPSTR "Layer 4 source port range\n" \
                                   "Layer 4 source minimum port\n" \
                                   "Layer 4 source maximum port\n"
#define ACE_DST_PORT_RANGE_HELPSTR "Layer 4 destination port range\n" \
                                   "Layer 4 destination minimum port\n" \
                                   "Layer 4 destination maximum port\n"
#define ACE_ADDITIONAL_OPTIONS_CMDSTR "{ log | count }"
#define ACE_ADDITIONAL_OPTIONS_HELPSTR "Log packets matching this entry (will also enable 'count')\n" \
                                       "Count packets matching this entry\n"
#define ACE_COMMENT_CMDSTR "(comment) "
#define ACE_COMMENT_HELPSTR "Set a text comment for a new or existing ACE\n"
#define ACE_COMMENT_TEXT_CMDSTR ".TEXT"
#define ACE_COMMENT_TEXT_HELPSTR "Comment text\n"
#define ACE_ETC_CMDSTR "...."
#define ACE_ETC_HELPSTR "(ignored)\n"

#endif /* _ACCESS_LIST_VTY_H */
