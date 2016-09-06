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
 *   #include "vswitch-idl.h"
 */

#include "copp_vty.h"
#include <sys/wait.h>
#include <arpa/inet.h>
#include <ctype.h>
#include "memory.h"
#include "vtysh/vtysh.h"
#include "vtysh/vtysh_user.h"
#include "ovsdb-idl.h"
#include "vtysh/command.h"
#include "smap.h"
#include "openvswitch/vlog.h"
#include "openswitch-idl.h"
#include "ovsdb-data.h"
#include "vswitch-idl.h"
#include "vtysh/vtysh_ovsdb_config.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/utils/ovsdb_vtysh_utils.h"

VLOG_DEFINE_THIS_MODULE(vtysh_copp_cli);

/* Global variables */
extern struct ovsdb_idl *idl;

/* This function prints the different tokens */
static void token_print(int i, char * token)
{

    /* print blanks for the UNSUPPORTED/INVALID indicator */
    if (!strncmp(token, COPP_MAX_STRING, 20)) {
        token = " ";
    }

    switch (i) {
        case 1:
            vty_out(vty, "\t  %s    %18s\n", "rate (pps):", token);
            break;
        case 2:
            vty_out(vty, "\t  %s    %11s\n", "burst size (pkts):", token);
            break;
        case 3:
            vty_out(vty, "\t  %s    %14s\n\n", "local priority:", token);
            break;
        case 4:
            vty_out(vty, "\t  %s    %14s\t", "packets passed:", token);
            break;
        case 5:
            vty_out(vty, "   %s    %13s\n", "bytes passed:", token);
            break;
        case 6:
            vty_out(vty, "\t  %s    %13s\t", "packets dropped:", token);
            break;
        case 7:
            vty_out(vty, "   %s    %12s\n\n\n", "bytes dropped:", token);
            break;
        default:
            printf("ERROR");
            break;
    }
}

/* This function expects a string of 7 comma separated values
 * Eg: 100,200,300,400,500,600,700
 * The function tokenizes all the 7 values and prints them out
 * in the cli output.
 * This is a temporary placeholder and the tokenized keys will not be present
 * in long run when CoPP table is defined.
 */
static void temp_copp_stats_tokenize(const char *buf)
{
    char *pch = NULL;
    char *str = NULL;
    int i = 1;

    str = strdup(buf);
    pch = strtok(str, ",");
    while (pch != NULL)
    {
        token_print(i, pch);
        pch = strtok(NULL, ",");
        i++;
    }
}

/* Implementation of the function which retrieves copp stats from OVSDB */
static void
vtysh_ovsdb_show_copp_protocol_statistics(int argc, const char *argv[])
{
    const struct ovsrec_system *ovs_system = NULL;
    const char *buf = NULL;

    /* Get access to the System Table */
    ovs_system = ovsrec_system_first(idl);
    if (NULL == ovs_system) {
        vty_out(vty, "Could not access the System Table\n");
        return;
    }

    if (strncmp(argv[0], "bgp", COPP_STATS_PROTOCOL_MAX_LENGTH) == 0) {
        buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_BGP]);
        COPP_VALIDATE_BUFFER(buf);
        vty_out(vty, "\tControl Plane Packet: BGP packets\n\n");
        temp_copp_stats_tokenize(buf);

    } else if (strncmp(argv[0], "lldp", COPP_STATS_PROTOCOL_MAX_LENGTH) == 0) {
        buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_LLDP]);
        COPP_VALIDATE_BUFFER(buf);
        vty_out(vty, "\tControl Plane Packet: LLDP packets\n\n");
        temp_copp_stats_tokenize(buf);

    } else if (strncmp(argv[0], "lacp", COPP_STATS_PROTOCOL_MAX_LENGTH) == 0) {
        buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_LACP]);
        COPP_VALIDATE_BUFFER(buf);
        vty_out(vty, "\tControl Plane Packet: LACP packets\n\n");
        temp_copp_stats_tokenize(buf);

    } else if (strncmp(argv[0], "ospfv2-unicast", COPP_STATS_PROTOCOL_MAX_LENGTH) == 0) {
        buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_OSPFv2_UNICAST]);
        COPP_VALIDATE_BUFFER(buf);
        vty_out(vty, "\tControl Plane Packet: OSPFV2 unicast packets\n\n");
        temp_copp_stats_tokenize(buf);

    } else if (strncmp(argv[0], "ospfv2-multicast", COPP_STATS_PROTOCOL_MAX_LENGTH) == 0) {
        buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_OSPFv2_MULTICAST]);
        COPP_VALIDATE_BUFFER(buf);
        vty_out(vty, "\tControl Plane Packet: OSPFV2 multicast packets\n\n");
        temp_copp_stats_tokenize(buf);

    } else if (strncmp(argv[0], "arp-broadcast", COPP_STATS_PROTOCOL_MAX_LENGTH) == 0) {
        buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_ARP_BROADCAST]);
        COPP_VALIDATE_BUFFER(buf);
        vty_out(vty, "\tControl Plane Packet: ARP BROADCAST packets\n\n");
        temp_copp_stats_tokenize(buf);

    } else if (strncmp(argv[0], "arp-unicast", COPP_STATS_PROTOCOL_MAX_LENGTH) == 0) {
        buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_ARP_MY_UNICAST]);
        COPP_VALIDATE_BUFFER(buf);
        vty_out(vty, "\tControl Plane Packet: ARP UNICAST packets\n\n");
        temp_copp_stats_tokenize(buf);

    } else if (strncmp(argv[0], "dhcpv4", COPP_STATS_PROTOCOL_MAX_LENGTH) == 0) {
        buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_DHCPv4]);
        COPP_VALIDATE_BUFFER(buf);
        vty_out(vty, "\tControl Plane Packet: DHCPv4 packets\n\n");
        temp_copp_stats_tokenize(buf);

    } else if (strncmp(argv[0], "dhcpv6", COPP_STATS_PROTOCOL_MAX_LENGTH) == 0) {
        buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_DHCPv6]);
        COPP_VALIDATE_BUFFER(buf);
        vty_out(vty, "\tControl Plane Packet: DHCPv6 packets\n\n");
        temp_copp_stats_tokenize(buf);

    } else if (strncmp(argv[0], "icmpv4-unicast", COPP_STATS_PROTOCOL_MAX_LENGTH) == 0) {
        buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_ICMPv4_UNICAST]);
        COPP_VALIDATE_BUFFER(buf);
        vty_out(vty, "\tControl Plane Packet: ICMPv4 UNICAST packets\n\n");
        temp_copp_stats_tokenize(buf);

    } else if (strncmp(argv[0], "icmpv4-multidest", COPP_STATS_PROTOCOL_MAX_LENGTH) == 0) {
        buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_ICMPv4_MULTIDEST]);
        COPP_VALIDATE_BUFFER(buf);
        vty_out(vty, "\tControl Plane Packet: ICMPv4 MULTIDEST packets\n\n");
        temp_copp_stats_tokenize(buf);

    } else if (strncmp(argv[0], "icmpv6-unicast", COPP_STATS_PROTOCOL_MAX_LENGTH) == 0) {
        buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_ICMPv6_UNICAST]);
        COPP_VALIDATE_BUFFER(buf);
        vty_out(vty, "\tControl Plane Packet: ICMPv6 UNICAST packets\n\n");
        temp_copp_stats_tokenize(buf);

    } else if (strncmp(argv[0], "icmpv6-multicast", COPP_STATS_PROTOCOL_MAX_LENGTH) == 0) {
        buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_ICMPv6_MULTICAST]);
        COPP_VALIDATE_BUFFER(buf);
        vty_out(vty, "\tControl Plane Packet: ICMPv6 MULTICAST packets\n\n");
        temp_copp_stats_tokenize(buf);

    } else if (strncmp(argv[0], "unknown-ip", COPP_STATS_PROTOCOL_MAX_LENGTH) == 0) {
        buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_UNKNOWN_IP_UNICAST]);
        COPP_VALIDATE_BUFFER(buf);
        vty_out(vty, "\tControl Plane Packet: UNKNOWN IP UNICAST packets\n\n");
        temp_copp_stats_tokenize(buf);

    } else if (strncmp(argv[0], "unclassified", COPP_STATS_PROTOCOL_MAX_LENGTH) == 0) {
        buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_DEFAULT_UNKNOWN]);
        COPP_VALIDATE_BUFFER(buf);
        vty_out(vty, "\tControl Plane Packet: UNCLASSIFIED packets\n\n");
        temp_copp_stats_tokenize(buf);

    } else if (strncmp(argv[0], "sflow", COPP_STATS_PROTOCOL_MAX_LENGTH) == 0) {
        buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_sFLOW_SAMPLES]);
        COPP_VALIDATE_BUFFER(buf);
        vty_out(vty, "\tControl Plane Packet: sFLOW SAMPLES packets\n\n");
        temp_copp_stats_tokenize(buf);

    } else if (strncmp(argv[0], "stp", COPP_STATS_PROTOCOL_MAX_LENGTH) == 0) {
        buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_STP_BPDU]);
        COPP_VALIDATE_BUFFER(buf);
        vty_out(vty, "\tControl Plane Packet: STP packets\n\n");
        temp_copp_stats_tokenize(buf);

    } else if (strncmp(argv[0], "bfd", COPP_STATS_PROTOCOL_MAX_LENGTH) == 0) {
        buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_BFD]);
        COPP_VALIDATE_BUFFER(buf);
        vty_out(vty, "\tControl Plane Packet: BFD packets\n\n");
        temp_copp_stats_tokenize(buf);

    } else if (strncmp(argv[0], "ipv4-options", COPP_STATS_PROTOCOL_MAX_LENGTH) == 0) {
        buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_IPv4_OPTIONS]);
        COPP_VALIDATE_BUFFER(buf);
        vty_out(vty, "\tControl Plane Packet: ipv4-options packets\n\n");
        temp_copp_stats_tokenize(buf);

    } else if (strncmp(argv[0], "ipv6-options", COPP_STATS_PROTOCOL_MAX_LENGTH) == 0) {
        buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_IPv6_OPTIONS]);
        COPP_VALIDATE_BUFFER(buf);
        vty_out(vty, "\tControl Plane Packet: ipv6-options packets\n\n");
        temp_copp_stats_tokenize(buf);

    } else if (strncmp(argv[0], "acl-logging", COPP_STATS_PROTOCOL_MAX_LENGTH) == 0) {
        buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_ACL_LOGGING]);
        COPP_VALIDATE_BUFFER(buf);
        vty_out(vty, "\tControl Plane Packet: ACL LOGGING packets\n\n");
        temp_copp_stats_tokenize(buf);

    } else {
        vty_out(vty, "Could not find protocol: %s\n", argv[0]);
    }
}

/* Implementation of the function which retrieves copp stats from OVSDB */
static void
vtysh_ovsdb_show_copp_generic_statistics()
{
    const struct ovsrec_system *ovs_system = NULL;
    const char *buf = NULL;

    /* Get access to the System Table */
    ovs_system = ovsrec_system_first(idl);
    if (NULL == ovs_system) {
        vty_out(vty, "Could not access the System Table\n");
        return;
    }

    /* Obtain and print the total stats first */
    vty_out(vty, "\tControl Plane Packets Total Statistics\n\n");

    buf = smap_get(&ovs_system->copp_statistics,
                   SYSTEM_COPP_STATISTICS_MAP_TOTAL_PKTS_PASSED);
    vty_out(vty, "\t  %s  %13s    ", "total packets passed:", ((buf) ? buf : COPP_ZERO_STRING));

    buf = smap_get(&ovs_system->copp_statistics,
                   SYSTEM_COPP_STATISTICS_MAP_TOTAL_BYTES_PASSED);
    vty_out(vty, "%s    %13s\n", "total bytes passed:", ((buf) ? buf : COPP_ZERO_STRING));

    buf = smap_get(&ovs_system->copp_statistics,
                   SYSTEM_COPP_STATISTICS_MAP_TOTAL_PKTS_DROPPED);
    vty_out(vty, "\t  %s  %12s    ", "total packets dropped:", ((buf) ? buf : COPP_ZERO_STRING));

    buf = smap_get(&ovs_system->copp_statistics,
                   SYSTEM_COPP_STATISTICS_MAP_TOTAL_BYTES_DROPPED);
    vty_out(vty, "%s    %12s\n\n\n", "total bytes dropped:", ((buf) ? buf : COPP_ZERO_STRING));

    /* Obtain the protocol stats one by one and print them.. */
    buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_BGP]);
    COPP_VALIDATE_BUFFER(buf);
    vty_out(vty, "\tControl Plane Packet: BGP packets\n\n");
    temp_copp_stats_tokenize(buf);

    buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_LLDP]);
    COPP_VALIDATE_BUFFER(buf);
    vty_out(vty, "\tControl Plane Packet: LLDP packets\n\n");
    temp_copp_stats_tokenize(buf);

    buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_LACP]);
    COPP_VALIDATE_BUFFER(buf);
    vty_out(vty, "\tControl Plane Packet: LACP packets\n\n");
    temp_copp_stats_tokenize(buf);

    buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_OSPFv2_UNICAST]);
    COPP_VALIDATE_BUFFER(buf);
    vty_out(vty, "\tControl Plane Packet: OSPFV2 unicast packets\n\n");
    temp_copp_stats_tokenize(buf);

    buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_OSPFv2_MULTICAST]);
    COPP_VALIDATE_BUFFER(buf);
    vty_out(vty, "\tControl Plane Packet: OSPFV2 multicast packets\n\n");
    temp_copp_stats_tokenize(buf);

    buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_ARP_BROADCAST]);
    COPP_VALIDATE_BUFFER(buf);
    vty_out(vty, "\tControl Plane Packet: ARP BROADCAST packets\n\n");
    temp_copp_stats_tokenize(buf);

    buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_ARP_MY_UNICAST]);
    COPP_VALIDATE_BUFFER(buf);
    vty_out(vty, "\tControl Plane Packet: ARP UNICAST packets\n\n");
    temp_copp_stats_tokenize(buf);

    buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_DHCPv4]);
    COPP_VALIDATE_BUFFER(buf);
    vty_out(vty, "\tControl Plane Packet: DHCPv4 packets\n\n");
    temp_copp_stats_tokenize(buf);

    buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_DHCPv6]);
    COPP_VALIDATE_BUFFER(buf);
    vty_out(vty, "\tControl Plane Packet: DHCPv6 packets\n\n");
    temp_copp_stats_tokenize(buf);

    buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_ICMPv4_UNICAST]);
    COPP_VALIDATE_BUFFER(buf);
    vty_out(vty, "\tControl Plane Packet: ICMPv4 UNICAST packets\n\n");
    temp_copp_stats_tokenize(buf);

    buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_ICMPv4_MULTIDEST]);
    COPP_VALIDATE_BUFFER(buf);
    vty_out(vty, "\tControl Plane Packet: ICMPv4 MULTIDEST packets\n\n");
    temp_copp_stats_tokenize(buf);

    buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_ICMPv6_UNICAST]);
    COPP_VALIDATE_BUFFER(buf);
    vty_out(vty, "\tControl Plane Packet: ICMPv6 UNICAST packets\n\n");
    temp_copp_stats_tokenize(buf);

    buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_ICMPv6_MULTICAST]);
    COPP_VALIDATE_BUFFER(buf);
    vty_out(vty, "\tControl Plane Packet: ICMPv6 MULTICAST packets\n\n");
    temp_copp_stats_tokenize(buf);

    buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_UNKNOWN_IP_UNICAST]);
    COPP_VALIDATE_BUFFER(buf);
    vty_out(vty, "\tControl Plane Packet: UNKNOWN IP UNICAST packets\n\n");
    temp_copp_stats_tokenize(buf);

    buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_DEFAULT_UNKNOWN]);
    COPP_VALIDATE_BUFFER(buf);
    vty_out(vty, "\tControl Plane Packet: UNCLASSIFIED packets\n\n");
    temp_copp_stats_tokenize(buf);

    buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_sFLOW_SAMPLES]);
    COPP_VALIDATE_BUFFER(buf);
    vty_out(vty, "\tControl Plane Packet: sFLOW SAMPLES packets\n\n");
    temp_copp_stats_tokenize(buf);

    buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_STP_BPDU]);
    COPP_VALIDATE_BUFFER(buf);
    vty_out(vty, "\tControl Plane Packet: STP packets\n\n");
    temp_copp_stats_tokenize(buf);

    buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_BFD]);
    COPP_VALIDATE_BUFFER(buf);
    vty_out(vty, "\tControl Plane Packet: BFD packets\n\n");
    temp_copp_stats_tokenize(buf);

    buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_IPv4_OPTIONS]);
    COPP_VALIDATE_BUFFER(buf);
    vty_out(vty, "\tControl Plane Packet: ipv4-options packets\n\n");
    temp_copp_stats_tokenize(buf);

    buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_IPv6_OPTIONS]);
    COPP_VALIDATE_BUFFER(buf);
    vty_out(vty, "\tControl Plane Packet: ipv6-options packets\n\n");
    temp_copp_stats_tokenize(buf);

    buf = smap_get(&ovs_system->copp_statistics, temp_copp_keys[COPP_ACL_LOGGING]);
    COPP_VALIDATE_BUFFER(buf);
    vty_out(vty, "\tControl Plane Packet: ACL LOGGING packets\n\n");
    temp_copp_stats_tokenize(buf);


}

/*================================================================================================*/
/* CLI Definitions */

/* SHOW CLIs */
DEFUN ( vtysh_show_copp_protocol_statistics,
        vtysh_show_copp_protocol_statistics_cmd,
        COPP_SHOW_CMD,
        SHOW_STR
        COPP_STR
        STATISTICS_STR
        "Show bgp pkts copp statistics\n"
        "Show ospfv2-unicast pkts copp statistics\n"
        "Show ospfv2-multicast pkts copp statistics\n"
        "Show lldp pkts copp statistics\n"
        "Show lacp pkts copp statistics\n"
        "Show arp-unicast pkts copp statistics\n"
        "Show arp-broadcast pkts copp statistics\n"
        "Show icmpv4-unicast pkts copp statistics\n"
        "Show icmpv4-multidest pkts copp statistics\n"
        "Show icmpv6-unicast pkts copp statistics\n"
        "Show icmpv6-multicast pkts copp statistics\n"
        "Show ipv4 options pkts copp statistics\n"
        "Show ipv6 options pkts copp statistics\n"
        "Show dhcpv4 pkts copp statistics\n"
        "Show dhcpv6 pkts copp  statistics\n"
        "Show acl-logging pkts copp statistics\n"
        "Show sflow pkts copp statistics\n"
        "Show stp pkts copp statistics\n"
        "Show bfd pkts copp statistics\n"
        "Show unknown-ip pkts copp statistics\n"
        "Show unclassified pkts copp statistics\n"
      )
{
    vtysh_ovsdb_show_copp_protocol_statistics(argc, argv);
    return CMD_SUCCESS;
}

DEFUN ( vtysh_show_copp_generic_statistics,
        vtysh_show_copp_generic_statistics_cmd,
        "show copp statistics",
        SHOW_STR
        COPP_STR
        STATISTICS_STR
      )
{
    vtysh_ovsdb_show_copp_generic_statistics();
    return CMD_SUCCESS;
}

extern struct ovsdb_idl *idl;

/*================================================================================================*/

/* Initialize ops-copp cli node.
 */
void cli_pre_init(void)
{

    /* register cli as listener to the copps stats column of System table  */
    ovsdb_idl_add_table(idl,&ovsrec_table_system);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_copp_statistics);
}

/*================================================================================================*/

/* Initialize ops-copp cli element.
 */
void cli_post_init (void)
{
    /* SHOW CMDS */
    install_element (VIEW_NODE, &vtysh_show_copp_protocol_statistics_cmd);
    install_element (ENABLE_NODE, &vtysh_show_copp_protocol_statistics_cmd);
    install_element (VIEW_NODE, &vtysh_show_copp_generic_statistics_cmd);
    install_element (ENABLE_NODE, &vtysh_show_copp_generic_statistics_cmd);

}
