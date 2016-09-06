/*
 * CoPP CLI Implementation
 *
 * (C) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 *   Licensed under the Apache License, Version 2.0 (the "License"); you may
 *   not use this file except in compliance with the License. You may obtain
 *   a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *   License for the specific language governing permissions and limitations
 *   under the License.
 */

#include "copp-temp-keys.h"

#define COPP_STR        "Show COPP information\n"
#define STATISTICS_STR  "Show COPP statistics information\n"
#define COPP_SHOW_CMD   "show copp statistics (bgp|ospfv2-unicast|ospfv2-multicast|" \
                        "lldp|lacp|arp-unicast|arp-broadcast|icmpv4-unicast|" \
                        "icmpv4-multidest|icmpv6-unicast|icmpv6-multicast|" \
                        "ipv4-options|ipv6-options|dhcpv4|dhcpv6|acl-logging|sflow|" \
                        "stp|bfd|unknown-ip|unclassified)"

#define COPP_MAX_STRING "18446744073709551615"
#define COPP_ZERO_STRING          "0"
#define COPP_DEFAULT_STATS_STRING COPP_MAX_STRING "," \
                                  COPP_MAX_STRING "," \
                                  COPP_MAX_STRING "," \
                                  COPP_MAX_STRING "," \
                                  COPP_MAX_STRING "," \
                                  COPP_MAX_STRING "," \
                                  COPP_MAX_STRING

#define COPP_STATS_PROTOCOL_MAX_LENGTH     12

#define COPP_VALIDATE_BUFFER(buf)          \
    if(buf == NULL) {                      \
        buf = COPP_DEFAULT_STATS_STRING;   \
    }
