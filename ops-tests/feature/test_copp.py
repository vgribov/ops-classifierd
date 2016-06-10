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
OpenSwitch Test for copp stats.
"""
from time import sleep
from pytest import mark
# from pytest import set_trace

TOPOLOGY = """
# +-------+
# |       |  1  +---V----+
# |  hs1  <----->  ops1  |
# |       |     +---^----+
# +-------+


# Nodes
[type=openswitch name="OpenSwitch 1"] ops1
[type=host name="Host 1"] hs1

# Links
hs1:1 -- ops1:1
"""

switch_ip = '10.0.10.10'
mask = '24'
swport = None
swport_str = '1'
# Response field names
f_pkts = 'pkts'
f_bytes = 'bytes'
f_drops = 'drops'
f_dropbytes = 'dropbytes'
f_rate = 'rate'
f_pri = 'pri'
f_burst = 'burst'


def setup_topo(topology):
    """
    Build a topology of one switch and one host. Connect the host to the
    switch. Assign an IP to the switch port and host so the host can ping
    the switch.
    """
    global swport
    global swport_str

    hs1 = topology.get('hs1')
    ops1 = topology.get('ops1')

    assert ops1 is not None
    assert hs1 is not None

    # Setup the switch ports for mirror testing

    swport = ops1.ports[swport_str]

    # Mark interfaces as enabled
    """
    assert not ops1(
        'set interface {swport} user_config:admin=up'.format(**globals()),
        shell='vsctl'
    )
    """

    # set_trace()
    # Configure interfaces
    with ops1.libs.vtysh.ConfigInterface(swport_str) as ctx:
        ctx.no_shutdown()
        ctx.ip_address(switch_ip + '/' + mask)

    # Configure host interfaces
    hs1.libs.ip.interface('1', addr='10.0.10.1/24', up=True)

    # FIXME: Use library
    ops1('show running-config')
    ops1('show interface {swport}'.format(**globals()))


# Check if the value provided is an integer
def isint(val):
    try:
        int(val)
        return True
    except ValueError:
        return False


# Returns the value if found, -1 if it appears unsupported or -2 if requested
#  field not found at all
#  Note that the unsupported response value can be changed from the default
#  by the caller.
def getstatsvalue(coppstatsresp, classtype, field, unsuppresponseval=-1):
    statslist = coppstatsresp.split("Control Plane Packet: ")
    for listentry in statslist:
        if classtype in listentry:
            listentry = ' '.join(listentry.split())
            listentrytokens = listentry.split(" ")
            i = 0
            if classtype == 'Total':
                for token in listentrytokens:
                    # print("%d - %s" % (i, token))
                    if f_pkts == field:
                        if "total" in token and "packets" in \
                                listentrytokens[i+1] and "passed:" in \
                                listentrytokens[i+2]:
                            if isint(listentrytokens[i+3]):
                                return listentrytokens[i+3]
                            else:
                                return unsuppresponseval
                    if f_bytes == field:
                        if "total" in token and "bytes" in \
                                listentrytokens[i+1] and "passed:" in \
                                listentrytokens[i+2]:
                            if isint(listentrytokens[i+3]):
                                return listentrytokens[i+3]
                            else:
                                return unsuppresponseval
                    if f_drops == field:
                        if "total" in token and "packets" in \
                                listentrytokens[i+1] and "dropped:" in \
                                listentrytokens[i+2]:
                            if isint(listentrytokens[i+3]):
                                return listentrytokens[i+3]
                            else:
                                return unsuppresponseval
                    if f_dropbytes == field:
                        if "total" in token and "bytes" in \
                                listentrytokens[i+1] and "dropped:" in \
                                listentrytokens[i+2]:
                            if i+3 < len(listentrytokens) and \
                                     isint(listentrytokens[i+3]):
                                return listentrytokens[i+3]
                            else:
                                return unsuppresponseval
                    i += 1
            else:
                for token in listentrytokens:
                    # print("%d - %s" % (i, token))
                    if f_pkts == field:
                        if "packets" in token and "passed:" in \
                                listentrytokens[i+1]:
                            if isint(listentrytokens[i+2]):
                                return listentrytokens[i+2]
                            else:
                                return unsuppresponseval
                    if f_rate == field:
                        if "rate" in token and "(pps):" in \
                                listentrytokens[i+1]:
                            if isint(listentrytokens[i+2]):
                                return listentrytokens[i+2]
                            else:
                                return unsuppresponseval
                    if f_pri == field:
                        if "local" in token and "priority:" in \
                                listentrytokens[i+1]:
                            if isint(listentrytokens[i+2]):
                                return listentrytokens[i+2]
                            else:
                                return unsuppresponseval
                    if f_burst == field:
                        if "burst" in token and "size" in \
                                listentrytokens[i+1]:
                            if isint(listentrytokens[i+3]):
                                return listentrytokens[i+3]
                            else:
                                return unsuppresponseval
                    if f_bytes == field:
                        if "bytes" in token and "passed:" in \
                                listentrytokens[i+1]:
                            if isint(listentrytokens[i+2]):
                                return listentrytokens[i+2]
                            else:
                                return unsuppresponseval
                    if f_drops == field:
                        if "packets" in token and "dropped:" in \
                                listentrytokens[i+1]:
                            if isint(listentrytokens[i+2]):
                                return listentrytokens[i+2]
                            else:
                                return unsuppresponseval
                    if f_dropbytes == field:
                        if "bytes" in token and "dropped:" in \
                                listentrytokens[i+1]:
                            if i+2 < len(listentrytokens) and \
                                    isint(listentrytokens[i+2]):
                                return listentrytokens[i+2]
                            else:
                                return unsuppresponseval
                    i += 1
    return -2


@mark.test_id(10450)
def test_copp_stats(topology):
    """
    Test that copp stats is functional with a OpenSwitch switch.
    """
    setup_topo(topology)

    hs1 = topology.get('hs1')
    ops1 = topology.get('ops1')

    # Give the openswitch container time to start up or the ports
    # won't be present in openvswitch
    print("Waiting 5 seconds for OPS HARDWARE to stabilize...")
    # set_trace()
    sleep(5)

    print("##################################################")
    print("Test COPP stats by pinging the switch")
    print("##################################################")

    # set_trace()

    # Ping the switch
    hs1.send_command('ping -i 0.5 10.0.10.10 > /dev/null &', shell='bash')

    response = ops1.send_command('show copp statistics', shell='vtysh')

    pktcount1 = getstatsvalue(response, 'ICMPv4 UNICAST', f_pkts)
    print("##################################################")
    print(" pktcount1 is %s" % pktcount1)
    print("##################################################")

    retries = 5
    while int(pktcount1) < 0 and int(retries) > 0:
        print("(%s) Packet count %s was invalid, trying again" %
              (retries, pktcount1))
        sleep(1)
        response = ops1.send_command('show copp statistics', shell='vtysh')
        pktcount1 = getstatsvalue(response, 'ICMPv4 UNICAST', f_pkts)
        retries -= 1

    if int(pktcount1) == -1:
        print("ICMPv4 UNICAST class type not supported")
        # If class not supported , pkts go to default UNCLASSIFIED queue
        print("Checking packets in UNCLASSIFIED queue")

        # Grab the other stats too for comparison later
        bytes1 = getstatsvalue(response, 'UNCLASSIFIED', bytes)

        print("Pause to give time for stats to update...")
        sleep(10)

        # Stop the ping
        hs1.send_command('pkill ping', shell='bash')

        response = ops1.send_command('show copp statistics', shell='vtysh')

        # get the total for UNCLASSIFIED
        pktcountunclassified = getstatsvalue(response, 'UNCLASSIFIED', f_pkts)
        print("New packet count is %s" % pktcountunclassified)
        bytes2 = getstatsvalue(response, 'UNCLASSIFIED', f_bytes)
        dropcount = getstatsvalue(response, 'UNCLASSIFIED', f_drops)
        dropbytes = getstatsvalue(response, 'UNCLASSIFIED', f_dropbytes)

        # Packet count should have increased
        assert int(pktcount1) < int(pktcountunclassified), \
            "Packet count didn't increase"
        assert int(bytes1) < int(bytes2), "Byte count didn't increase"
        assert int(dropcount) == 0, "Drop count should be zero"
        assert int(dropbytes) == -1, "Drop bytes should be unsupported"

        # Check the hw stats values
        rateval = getstatsvalue(response, 'UNCLASSIFIED', f_rate)
        burstval = getstatsvalue(response, 'UNCLASSIFIED', f_burst)
        prival = getstatsvalue(response, 'UNCLASSIFIED', f_pri)
        assert int(rateval) == 1000000000, "Incorrect rate value"
        assert int(burstval) == 1000000000, "Incorrect burst value"
        assert int(prival) == 0, "Incorrect priority"

        # Get the total packet and bytes count
        pktcounttotal = getstatsvalue(response, 'Total', f_pkts)
        bytestotal = getstatsvalue(response, 'Total', f_bytes)

        print("\nChecking total packets and unclassified packets")
        # Total better match the sum of all the classes
        assert int(pktcounttotal) == int(pktcountunclassified), \
            "Total packets should match unclassified packets"
        assert int(bytestotal) == int(bytes2), \
            "Total bytes should match unclassified bytes"

    else:
        print("packet count is %s" % pktcount1)

        # Grab the other stats too for comparison later
        bytes1 = getstatsvalue(response, 'ICMPv4 UNICAST', bytes)

        print("Pause to give time for stats to update...")
        sleep(10)

        # Stop the ping
        hs1.send_command('pkill ping', shell='bash')

        response = ops1.send_command('show copp statistics', shell='vtysh')

        # get the total for UNCLASSIFIED
        pktcounticmpv4u = getstatsvalue(response, 'ICMPv4 UNICAST', f_pkts)
        print("New packet count is %s" % pktcounticmpv4u)
        bytes2 = getstatsvalue(response, 'ICMPv4 UNICAST', f_bytes)
        dropcount = getstatsvalue(response, 'ICMPv4 UNICAST', f_drops)
        dropbytes = getstatsvalue(response, 'ICMPv4 UNICAST', f_dropbytes)

        # Packet count should have increased
        assert int(pktcount1) < int(pktcounticmpv4u), \
            "Packet count didn't increase"
        assert int(bytes1) < int(bytes2), "Byte count didn't increase"
        assert int(dropcount) == 0, "Drop count should be zero"
        assert int(dropbytes) == 0, "Drop bytes should be zero"

    print("##################################################")
    print("Test COPP stats by pinging another host")
    print("##################################################")

    pktcount1 = getstatsvalue(response, 'ARP BROADCAST', f_pkts)

    if pktcount1 != -1:
        # Ping some other host and check that the ICMP stats don't change
        hs1.send_command('ping -i 0.5 10.0.10.20 > /dev/null &', shell='bash')

        print("Pause to give time for stats to update...")
        sleep(10)

        # Stop the ping
        hs1.send_command('pkill ping', shell='bash')

        # retrieve updated stats
        response = ops1.send_command('show copp statistics', shell='vtysh')

        pktcountarpb = getstatsvalue(response, 'ARP BROADCAST', f_pkts)
        assert int(pktcount1) < int(pktcountarpb), "Pkt count didn't increase"

        # Check the hw stats values
        rateval = getstatsvalue(response, 'UNCLASSIFIED', f_rate)
        burstval = getstatsvalue(response, 'UNCLASSIFIED', f_burst)
        assert int(rateval) != 0, "Rate should not be zero"
        assert int(burstval) != 0, "Burst value should not be zero"

        print("##################################################")
        print("Test COPP stats verify totals are correct")
        print("##################################################")

        pktcountbgp = getstatsvalue(response, 'BGP', f_pkts, 0)
        pktcountlldp = getstatsvalue(response, 'LLDP', f_pkts, 0)
        pktcountlacp = getstatsvalue(response, 'LACP', f_pkts, 0)
        pktcountospfv2u = getstatsvalue(response, 'OSPFV2 unicast', f_pkts, 0)
        pktcountospfv2m = getstatsvalue(response, 'OSPFV2 multicast',
                                        f_pkts, 0)
        pktcountarpu = getstatsvalue(response, 'ARP UNICAST', f_pkts, 0)
        pktcountdhcpv4 = getstatsvalue(response, 'DHCPv4', f_pkts, 0)
        pktcountdhcpv6 = getstatsvalue(response, 'DHCPv6', f_pkts, 0)
        pktcounticmpv4u = getstatsvalue(response, 'ICMPv4 UNICAST', f_pkts, 0)
        pktcounticmpv4m = getstatsvalue(response, 'ICMPv4 MULTIDEST',
                                        f_pkts, 0)
        pktcounticmpv6u = getstatsvalue(response, 'ICMPv6 UNICAST', f_pkts, 0)
        pktcounticmpv6m = getstatsvalue(response, 'ICMPv6 MULTICAST',
                                        f_pkts, 0)
        pktcountunk = getstatsvalue(response, 'UNKNOWN', f_pkts, 0)
        pktcountuncl = getstatsvalue(response, 'UNCLASSIFIED', f_pkts)
        pktcountsflow = getstatsvalue(response, 'sFLOW', f_pkts, 0)
        pktcountacll = getstatsvalue(response, 'ACL LOGGING', f_pkts, 0)
        pktcountv4options = getstatsvalue(response, 'ipv4-options',
                                          f_pkts, 0)
        pktcountv6options = getstatsvalue(response, 'ipv6-options',
                                          f_pkts, 0)
        pktcountstp = getstatsvalue(response, 'STP',
                                    f_pkts, 0)

        # get the overall Totals
        pktcounttotal = getstatsvalue(response, 'Total', f_pkts)
        bytestotal = getstatsvalue(response, 'Total', f_bytes)

        sumpktcount = int(pktcountbgp) + int(pktcountlldp) + \
            int(pktcountlacp) + int(pktcountospfv2u) + \
            int(pktcountospfv2m) + int(pktcountarpb) + \
            int(pktcountarpu) + int(pktcountdhcpv4) + \
            int(pktcountdhcpv6) + int(pktcounticmpv4u) + \
            int(pktcounticmpv4m) + int(pktcounticmpv6u) + \
            int(pktcounticmpv6m) + int(pktcountunk) + \
            int(pktcountuncl) + int(pktcountsflow) + int(pktcountacll) + \
            int(pktcountv4options) + int(pktcountv6options) + int(pktcountstp)

        # Total better match the sum of all the classes
        assert int(pktcounttotal) == int(sumpktcount), \
            "Total packets should match sum"
        assert int(bytestotal), \
            "Total bytes should not be zero"
