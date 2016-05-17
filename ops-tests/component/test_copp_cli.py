# -*- coding: utf-8 -*-
#
# Copyright (C) 2016 Hewlett Packard Enterprise Development LP
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

"""
OpenSwitch Test for CoPP CLI
"""

TOPOLOGY = """
#
# +--------+
# |  ops1  |
# +--------+
#

# Nodes
[type=openswitch name="OpenSwitch 1"] ops1
"""

"""
Default string, burst and cpu queue values for protocols for CoPP
"""

arpbc_string = "1000,1000,4,1000,64000,1000,64000"

arpuc_string = "1000,1000,5,1000,64000,1000,64000"

lacp_string = "1000,1000,8,1000,64000,1000,64000"

lldp_string = "500,500,8,500,32000,500,32000"

stp_string = "1000,1000,9,1000,64000,1000,64000"

bgp_string = "5000,5000,9,5000,320000,5000,320000"

dhcpv4_string = "500,500,4,500,32000,500,32000"

dhcpv6_string = "500,500,4,500,32000,500,32000"

icmpv4uc_string = "1000,1000,5,100000,6400000,100000,6400000"

icmpv4bc_string = "1000,1000,4,100000,6400000,100000,6400000"

icmpv6uc_string = "1000,1000,5,100000,6400000,100000,6400000"

icmpv6mc_string = "1000,1000,4,100000,6400000,100000,6400000"

ospfv2uc_string = "5000,5000,9,5000,320000,5000,320000"

ospfv2mc_string = "5000,5000,9,5000,320000,5000,320000"

unk_string = "2500,2500,6,2500,160000,2500,160000"

unclassified_string = "5000,5000,6,5000,320000,5000,320000"

sflow_string = "20000,20000,3,20000,1280000,20000,1280000"

acl_log_string = "5,5,0,5,320,5,320"

total_pkt_pass = "123456789"

total_bytes_pass = "45678912345"

total_pkt_drop = "123456789"

total_bytes_drop = "45678912345"


def copp_setup(**kwargs):
    topology_new = kwargs.get('topology_new', None)
    assert topology_new is not None
    ops = topology_new.get('ops1')

    return ops


def test_copp_cli(topology):
    """
    Test the COPP CLI.
    """
    ops1 = copp_setup(topology_new=topology)

    # Stop switchd process so that we can avoid it from polling
    ops1("systemctl stop switchd", shell='bash')

    # Use ovsdb client now to write values to the system table
    ovsdb_transaction_cmd = """ovsdb-client transact '[ "OpenSwitch",
        {
            "op" : "update",
            "table" : "System",
            "where":[["cur_hw","==",1]],
            "row" : {
                "copp_statistics": [
                    "map",
                    [
                        [ "temp_copp_bgp", "%s" ],
                        [ "temp_copp_lldp", "%s" ],
                        [ "temp_copp_lacp", "%s" ],
                        [ "temp_copp_ospfv2_unicast", "%s" ],
                        [ "temp_copp_ospfv2_multicast", "%s" ],
                        [ "temp_copp_arp_broadcast", "%s" ],
                        [ "temp_copp_arp_my_unicast", "%s" ],
                        [ "temp_copp_dhcpv4", "%s" ],
                        [ "temp_copp_dhcpv6", "%s" ],
                        [ "temp_copp_icmpv4_unicast", "%s" ],
                        [ "temp_copp_icmpv4_multidest", "%s" ],
                        [ "temp_copp_icmpv6_unicast", "%s" ],
                        [ "temp_copp_icmpv6_multicast", "%s" ],
                        [ "temp_copp_unknown_ip_unicast", "%s" ],
                        [ "temp_copp_default_unknown", "%s" ],
                        [ "temp_copp_sflow_samples", "%s" ],
                        [ "temp_copp_acl_logging", "%s" ],
                        [ "total_packets_passed", "%s" ],
                        [ "total_bytes_passed", "%s" ],
                        [ "total_packets_dropped", "%s" ],
                        [ "total_bytes_dropped", "%s" ]
                    ]
                ]
            }
         }
]'""" % (bgp_string, lldp_string, lacp_string, ospfv2uc_string,
         ospfv2mc_string, arpbc_string, arpuc_string, dhcpv4_string,
         dhcpv6_string, icmpv4uc_string, icmpv4bc_string, icmpv6uc_string,
         icmpv6mc_string, unk_string, unclassified_string, sflow_string,
         acl_log_string, total_pkt_pass, total_bytes_pass, total_pkt_drop,
         total_bytes_drop)

    ops1(ovsdb_transaction_cmd, shell='bash')

    retstruct = ops1('show copp statistics bgp', shell='vtysh')
    for curLine in retstruct.split('\n'):
        if "Control Plane Packet: " in curLine:
            dstmac = curLine.split('Control Plane Packet: ')[1]
            if (dstmac == "BGP packets"):
                print("SUCCESS")
            else:
                print("FAILURE")
                assert(0)

        if "rate" in curLine:
            for match_rate in curLine.split():
                print(match_rate)
            rate_str = bgp_string.split(',')[0]
            if (rate_str == match_rate):
                print(" SUCCESS in rate comparison ")

        if "burst" in curLine:
            for match_burst in curLine.split():
                print(match_burst)
            burst_str = bgp_string.split(',')[1]
            if (burst_str == match_burst):
                print(" SUCCESS in burst comparison ")

        if "local_priority" in curLine:
            for match_queue in curLine.split():
                print(match_queue)
            queue_str = bgp_string.split(',')[2]
            if (queue_str == match_queue):
                print(" SUCCESS in local_priority comparison ")

        if "packets_passed" in curLine:
            for match_pkt_pass in curLine.split():
                if match_pkt_pass.isdigit():
                    print(match_pkt_pass)
                    break
            pkt_pass_str = bgp_string.split(',')[3]
            if (pkt_pass_str == match_pkt_pass):
                print(" SUCCESS in packets_passed comparison ")

        if "bytes_passed" in curLine:
            for match_bytes_pass in curLine.split():
                if match_bytes_pass.isdigit():
                    print(match_bytes_pass)
            bytes_pass_str = bgp_string.split(',')[4]
            if (bytes_pass_str == match_bytes_pass):
                print(" SUCCESS in bytes_passed comparison ")

        if "packets_dropped" in curLine:
            for match_pkt_drop in curLine.split():
                if match_pkt_drop.isdigit():
                    print(match_pkt_drop)
                    break
            pkt_drop_str = bgp_string.split(',')[5]
            if (pkt_drop_str == match_pkt_drop):
                print(" SUCCESS in packets_dropped comparison ")

        if "bytes_passed" in curLine:
            for match_bytes_drop in curLine.split():
                if match_bytes_drop.isdigit():
                    print(match_bytes_drop)
            bytes_drop_str = bgp_string.split(',')[6]
            if (bytes_drop_str == match_bytes_drop):
                print(" SUCCESS in bytes_dropped comparison ")

    retstruct = ops1('show copp statistics', shell='vtysh')
    for curLine in retstruct.split('\n'):
        if "total_packets_passed" in curLine:
            for match_pkt_pass in curLine.split():
                if match_pkt_pass.isdigit():
                    print(match_pkt_pass)
                    break
            if (match_pkt_pass == total_pkt_pass):
                print(" SUCCESS in total packets_passed comparison ")

        if "total_bytes_passed" in curLine:
            for match_bytes_pass in curLine.split():
                if match_bytes_pass.isdigit():
                    print(match_bytes_pass)
            if (match_bytes_pass == total_bytes_pass):
                print(" SUCCESS in total bytes_passed comparison ")
