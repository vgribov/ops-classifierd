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

#include "acl_parse.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(acl_parse);

/** Static map of protocols whose string names are supported */
static const char * const protocol_names[] = {
       "0", "icmp", "igmp",    "3",    "4",    "5",  "tcp",    "7",
       "8",    "9",   "10",   "11",   "12",   "13",   "14",   "15",
      "16",  "udp",   "18",   "19",   "20",   "21",   "22",   "23",
      "24",   "25",   "26",   "27",   "28",   "29",   "30",   "31",
      "32",   "33",   "34",   "35",   "36",   "37",   "38",   "39",
      "40",   "41",   "42",   "43",   "44",   "45",   "46",  "gre",
      "48",   "49",  "esp",   "ah",   "52",   "53",   "54",   "55",
      "56",   "57",   "58",   "59",   "60",   "61",   "62",   "63",
      "64",   "65",   "66",   "67",   "68",   "69",   "70",   "71",
      "72",   "73",   "74",   "75",   "76",   "77",   "78",   "79",
      "80",   "81",   "82",   "83",   "84",   "85",   "86",   "87",
      "88",   "89",   "90",   "91",   "92",   "93",   "94",   "95",
      "96",   "97",   "98",   "99",  "100",  "101",  "102",  "pim",
     "104",  "105",  "106",  "107",  "108",  "109",  "110",  "111",
     "112",  "113",  "114",  "115",  "116",  "117",  "118",  "119",
     "120",  "121",  "122",  "123",  "124",  "125",  "126",  "127",
     "128",  "129",  "130",  "131", "sctp",  "133",  "134",  "135",
     "136",  "137",  "138",  "139",  "140",  "141",  "142",  "143",
     "144",  "145",  "146",  "147",  "148",  "149",  "150",  "151",
     "152",  "153",  "154",  "155",  "156",  "157",  "158",  "159",
     "160",  "161",  "162",  "163",  "164",  "165",  "166",  "167",
     "168",  "169",  "170",  "171",  "172",  "173",  "174",  "175",
     "176",  "177",  "178",  "179",  "180",  "181",  "182",  "183",
     "184",  "185",  "186",  "187",  "188",  "189",  "190",  "191",
     "192",  "193",  "194",  "195",  "196",  "197",  "198",  "199",
     "200",  "201",  "202",  "203",  "204",  "205",  "206",  "207",
     "208",  "209",  "210",  "211",  "212",  "213",  "214",  "215",
     "216",  "217",  "218",  "219",  "220",  "221",  "222",  "223",
     "224",  "225",  "226",  "227",  "228",  "229",  "230",  "231",
     "232",  "233",  "234",  "235",  "236",  "237",  "238",  "239",
     "240",  "241",  "242",  "243",  "244",  "245",  "246",  "247",
     "248",  "249",  "250",  "251",  "252",  "253",  "254",  "255"
};

const char *
acl_parse_protocol_get_name_from_number(uint8_t proto_number)
{
    return protocol_names[proto_number];
}

bool
acl_parse_str_is_numeric(const char *in_str)
{
    /* Null check. May not be necessary here */
    if (!*in_str) {
        return false;
    }

    /* Check if every character in the string is a digit */
    while (*in_str) {
        if (!isdigit(*in_str)) {
            return false;
        }
        ++in_str;
    }

    return true;
}

int
acl_parse_protocol_get_number_from_name(const char *in_proto)
{
    int i;

    /* Interpret NULL, "any", or "" to mean any protocol */
    if (!in_proto || !strcmp(in_proto, "any") || !strcmp(in_proto, "")) {
        return ACL_PROTOCOL_ANY;
    }

    /* Translate numeric protocols */
    if (acl_parse_str_is_numeric(in_proto)) {
        return strtol(in_proto, NULL, 0);
    }

    /* Otherwise, look up named protocol */
    for (i = ACL_PROTOCOL_MIN; i <= ACL_PROTOCOL_MAX; i++) {
        if (!strcmp(in_proto, protocol_names[i])) {
            return i;
        }
    }

    return ACL_PROTOCOL_INVALID;
}

static in_addr_t
ipv4_mask_create(uint8_t prefix_len)
{
    /* bit twiddling ideas from:
     * http://stackoverflow.com/questions/20263860/ipv4-prefix-length-to-netmask
     *
     *          1 << (32 - prefix_len)
     * 32 -> 0b00000000 00000000 00000000 00000001
     * 24 -> 0b00000000 00000000 00000001 00000000
     *  1 -> 0b10000000 00000000 00000000 00000000
     *
     *          (1 << (32 - prefix_len)) - 1
     * 32 -> 0b00000000 00000000 00000000 00000000
     * 24 -> 0b00000000 00000000 00000000 11111111
     *  1 -> 0b01111111 11111111 11111111 11111111
     *
     *        ~((1 << (32 - prefix_len)) - 1)
     * 32 -> 0b11111111 11111111 11111111 11111111
     * 24 -> 0b11111111 11111111 11111111 00000000
     *  1 -> 0b10000000 00000000 00000000 00000000
     */
    return prefix_len ? htonl(~((0x1u << (32 - prefix_len)) - 1)) : 0;
}

bool
acl_ipv4_address_user_to_normalized(const char *user_str, char *normalized_str)
{
    char *slash_ptr;
    char *mask_substr = NULL;
    struct in_addr v4_mask;
    uint8_t prefix_len;

    /* Special cases of NULL or "any" can return early */
    if (!user_str || !strcmp(user_str, "any")) {
        normalized_str[0] = '\0';
        return true;
    }

    /* Find the slash character (if any) in input */
    slash_ptr = strchr(user_str, '/');
    /* If no mask is given, set host mask (/32) */
    if (!slash_ptr) {
        strncpy(normalized_str, user_str, INET_ADDRSTRLEN*2);
        strcat(normalized_str, "/255.255.255.255");
        return true;
    }

    mask_substr = &slash_ptr[1];

    /* Check if mask is in prefix-length notation */
    if (acl_parse_str_is_numeric(mask_substr)) {
        prefix_len = strtoul(mask_substr, NULL, 0);
        if (prefix_len > 32) {
            VLOG_ERR("Invalid IPv4 prefix length %d", prefix_len);
            return false;
        }
        /* Calculate the mask using the prefix length */
        v4_mask.s_addr = ipv4_mask_create(prefix_len);
        /* Copy the address as-is */
        strncpy(normalized_str, user_str, slash_ptr - user_str);
        /* Add '/' after address */
        normalized_str[slash_ptr - user_str] = '/';
        /* Convert calculated mask back into string format */
        if (!inet_ntop(AF_INET, &v4_mask, &normalized_str[slash_ptr - user_str + 1], INET_ADDRSTRLEN)) {
            VLOG_ERR("Invalid IPv4 mask value %s", mask_substr);
            return false;
        }
        return true;
    }

    /* For dotted-decimal mask, just copy the whole string as-is */
    strncpy(normalized_str, user_str, INET_ADDRSTRLEN*2);
    return true;
}

bool
acl_ipv4_address_normalized_to_user(const char *normalized_str, char *user_str)
{
    char *slash_ptr;
    char *mask_substr = NULL;

    /* Special case of "any" or empty string can return early */
    if (!normalized_str || !strcmp(normalized_str, "")) {
        strncpy(user_str, "any", MIN(strlen("any")+1, INET_ADDRSTRLEN*2));
        return true;
    }

    /* Find the slash character (if any) in input */
    slash_ptr = strchr(normalized_str, '/');
    if (!slash_ptr) {
        VLOG_ERR("Invalid IPv4 address string %s: expectd 'A.B.C.D/W.X.Y.Z'", normalized_str);
        return false;
    }

    mask_substr = &slash_ptr[1];

    /* If we have a host mask (/32), copy out the address and NULL-terminate */
    if (!strcmp(mask_substr, "255.255.255.255")) {
        strncpy(user_str, normalized_str, slash_ptr - normalized_str);
        user_str[slash_ptr - normalized_str] = '\0';
        return true;
    }

    /** @todo check for ability to show in prefix-length notation (e.g. /24) */

    /* Otherwise just copy the whole string as-is */
    strncpy(user_str, normalized_str, INET_ADDRSTRLEN*2);
    return true;
}

void
acl_entry_ip_address_config_to_ds(struct ds *dstring, char *address_str)
{
    char user_str[INET_ADDRSTRLEN*2];
    if(acl_ipv4_address_normalized_to_user(address_str, user_str))
    {
        ds_put_format(dstring, "%s ", user_str);
    }
}

void
acl_entry_l4_port_config_to_ds(struct ds *dstring,
                               int64_t min, int64_t max, bool reverse)
{
    if (min == max) {
        if (reverse) {
            ds_put_format(dstring, "%s %" PRId64 " ", "neq", min);
        } else {
            ds_put_format(dstring, "%s %" PRId64 " ", "eq", min);
        }
    } else if (min == 0 && max < 65535) {
        ds_put_format(dstring, "%s %" PRId64 " ", "lt", max + 1);
    } else if (min > 0 && max == 65535) {
        ds_put_format(dstring, "%s %" PRId64 " ", "gt", min - 1);
    } else {
        ds_put_format(dstring, "%s %" PRId64 " %" PRId64 " ", "range", min, max);
    }
}

char *
acl_entry_config_to_string(const int64_t sequence_num,
                           const struct ovsrec_acl_entry *ace_row)
{
    struct ds dstring;
    ds_init(&dstring);

    ds_put_format(&dstring, "%" PRId64 " ", sequence_num);
    ds_put_format(&dstring, "%s ", ace_row->action);
    if (ace_row->n_protocol > 0) {
        ds_put_format(&dstring, "%s ", acl_parse_protocol_get_name_from_number(ace_row->protocol[0]));
    } else {
        ds_put_format(&dstring, "%s ", "any");
    }
    acl_entry_ip_address_config_to_ds(&dstring, ace_row->src_ip);
    if (ace_row->n_src_l4_port_min && ace_row->n_src_l4_port_max) {
        acl_entry_l4_port_config_to_ds(&dstring,
                                       ace_row->src_l4_port_min[0],
                                       ace_row->src_l4_port_max[0],
                                       ace_row->n_src_l4_port_range_reverse);
    }
    acl_entry_ip_address_config_to_ds(&dstring, ace_row->dst_ip);
    if (ace_row->n_dst_l4_port_min && ace_row->n_dst_l4_port_max) {
        acl_entry_l4_port_config_to_ds(&dstring,
                                       ace_row->dst_l4_port_min[0],
                                       ace_row->dst_l4_port_max[0],
                                       ace_row->n_dst_l4_port_range_reverse);
    }
    if (ace_row->log) {
        ds_put_format(&dstring, "log ");
    /* Log implies count, only print count if not logging */
    } else if (ace_row->count) {
        ds_put_format(&dstring, "count ");
    }
    return ds_steal_cstr(&dstring);
}

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
const int64_t
ovsrec_port_aclv4_in_statistics_getvalue(const struct ovsrec_port *port_row,
                                         const int64_t key)
{
    int i;
    for (i = 0; i < port_row->n_aclv4_in_statistics; i ++) {
        if (port_row->key_aclv4_in_statistics[i] == key) {
            return port_row->value_aclv4_in_statistics[i];
        }
    }
    return 0;
}
