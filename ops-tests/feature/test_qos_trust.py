#!/usr/bin/python3.4
# -*- coding: utf-8 -*-
#
# Copyright (C) 2015 Hewlett Packard Enterprise Development LP
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

# ------------------------------------------------------------
#  Imports
# ------------------------------------------------------------
# import http.client
"""
OpenSwitch Test for QoS trust.
"""
# ------------------------------------------------------------
#  Topology Definitions
# ------------------------------------------------------------

from array import array
from curses.ascii import isprint
import logging
import mmap
import sys
from time import sleep

from pytest import mark
# from pytest import set_trace


TOPOLOGY = """
# +-------+ +-------+
# |  hs1  | |  hs2  |
# +-------+ +-------+
#     |         |
# +---1---------2---+
# |       ops1      |
# +---3---------4---+
#     |         |
# +---v---+ +---v---+
# |  hs3  | |  hs4  |
# +-------+ +-------+

# Nodes
[type=host name="Host 1"] hs1
[type=host name="Host 2"] hs2
[type=host name="Host 3"] hs3
[type=host name="Host 4"] hs4
[type=openswitch name="OpenSwitch 1" target="AS5712"] ops1
# [type=host name="Host 1" image="openswitch/ubuntuscapy:latest"] hs1
# [type=host name="Host 2" image="openswitch/ubuntuscapy:latest"] hs2
# [type=host name="Host 3" image="openswitch/ubuntuscapy:latest"] hs3
# [type=host name="Host 4" image="openswitch/ubuntuscapy:latest"] hs4
# [type=openswitch name="OpenSwitch 1" image="mirror:latest"] ops1

# Links
hs1:1 -- ops1:1
hs2:1 -- ops1:2
hs3:1 -- ops1:3
hs4:1 -- ops1:4
"""

# ------------------------------------------------------------
#  Credentials
# ------------------------------------------------------------
DEFAULT_USER = 'netop'
DEFAULT_PASSWORD = 'netop'
loopback = '127.0.0.1'
mask = '24'
cookie = None
p1 = None
p2 = None
p3 = None
p4 = None

# ------------------------------------------------------------
#  Globals
# ------------------------------------------------------------
ec = 0
lp = [0] * 65
qp = []
dscpmap = []
queprof = []
cosmap = []
qos_trust = "dscp"
opstop = False
# Outbound packets per priority
qsize = [2, 4, 8, 16, 32, 64, 128, 256]
# qsize = [1, 1, 1, 1, 1, 1, 1, 1]
# Cumulative totals expected per queue
qmarkup = [0] * 8
# Code Points and Priorities (PCP):
# ipv4: cs0, cs2, cs4, and cs6
cpvalue1a = [0x0, 0x20, 0x40, 0x60]
cprange1a = [0, 16, 32, 48]
pcprangea = [7, 5, 3, 1]
# ipv6: cs1, cs3, cs5, and cs7
cpvalue1b = [0x10, 0x18, 0x28, 0x38]
cprange1b = [8, 24, 40, 56]
pcprangeb = [6, 4, 2, 0]
cpvalue1c = [0x0, 0x20, 0x40, 0x60, 0x10, 0x18, 0x28, 0x38]
cprange1c = [8, 24, 40, 56, 6, 4, 2, 0]
pcprangec = [0, 1, 2, 3, 4, 5, 6, 7]
# special test ipv4 0-31
cprange2a = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
             16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
             30, 31]
# special test ipv6 32-63
cprange2b = [32, 33, 34, 35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45,
             46, 47, 48, 49, 50, 51, 52, 53, 54, 55, 56, 57, 58, 59,
             60, 61, 62, 63]
pcpthrees = [3, 3, 3, 3]
pcpsevens = [7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
             7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7,
             7, 7]
dscpmaparray = []
cosmaparray = []
qprofarray = []
local_pri = False

logfile = 'qos_test.log'

# ------------------------------------------------------------
# Network Globals
# ------------------------------------------------------------
hs1ip = '10.0.10.3'
hs2ip = '10.0.10.4'
hs3aip = '10.0.10.5'
hs4aip = '10.0.10.6'
hs3ip = '10.0.20.2'
hs4ip = '10.0.30.2'
gw1ip = '10.0.20.1'
gw2ip = '10.0.30.1'
vlanip = '10.0.31.1'
hs1addr = hs1ip + '/24'
hs2addr = hs2ip + '/24'
hs3addr = hs3ip + '/24'
hs3aaddr = hs3aip + '/24'
hs4addr = hs4ip + '/24'
hs4aaddr = hs4aip + '/24'
gw1addr = gw1ip + '/24'
gw2addr = gw2ip + '/24'
vlanaddr = vlanip + '/24'
gw1 = "route add default gw " + gw1ip
gw2 = "route add default gw " + gw2ip
pingcmd = ""
setipv6 = "ip -6 addr add "
hs1ipv6 = '::ffff:' + hs1ip
hs2ipv6 = '::ffff:' + hs2ip
hs3ipv6 = 'fd00::2'
hs4ipv6 = 'fd01::2'
hs3aipv6 = '::ffff:' + hs3aip
hs4aipv6 = '::ffff:' + hs4aip
gw1ipv6 = 'fd00::1'
gw2ipv6 = 'fd01::1'
rteipv6 = "ip -6 route add default via "
swrte1 = '10.0.20.0/24 '
swrte2 = '10.0.30.0/24 '
swrte1ipv6 = 'fd00::/64 '
swrte2ipv6 = 'fd01::/64 '
swmacaddr = None


# ------------------------------------------------------------
#  Helper to check interface
# ------------------------------------------------------------
def wait_until_interface_up(switch, portlbl, timeout=30, polling_frequency=1):
    """
    Wait until the interface, as mapped by the given portlbl, is marked as up.

    :param switch: The switch node.
    :param str portlbl: Port label that is mapped to the interfaces.
    :param int timeout: Number of seconds to wait.
    :param int polling_frequency: Frequency of the polling.
    :return: None if interface is brought-up. If not, an assertion is raised.
    """
    for i in range(timeout):
        status = switch.libs.vtysh.show_interface(portlbl)
        if status['interface_state'] == 'up':
            break
        sleep(polling_frequency)
    else:
        assert False, (
            'Interface {}:{} never brought-up after '
            'waiting for {} seconds'.format(
                switch.identifier, portlbl, timeout
            )
        )


# ------------------------------------------------------------
# Analyze Logs
# ------------------------------------------------------------
class LogAnalyzer():
    """ Parses and summarizes logfiles """

    def __init__(self, readfile, writefile, topcount=5):
        """ Initializing """

    # Count ICMP echos
    def ping_count(self, spattern, epattern):
            with open(logfile, "r") as fo:
                m = mmap.mmap(fo.fileno(), 0, access=mmap.ACCESS_READ)
                spos = m.find(str.encode(spattern))
                epos = m.find(str.encode(epattern))
                echo_requests = 0
                echo_replies = 0
                cmatch = m[spos:epos]
                echo_requests = cmatch.count(str.encode("echo-request"))
                echo_replies = cmatch.count(str.encode("echo-reply"))
                print("PING-REQUESTS ", echo_requests)
                print("PING-REPLIES ", echo_replies)
                return echo_requests, echo_replies


# ------------------------------------------------------------
# string compare
# ------------------------------------------------------------
def stricmp(str1, str2):
    import re
    return re.match(re.escape(str1) + r'\Z', str2, re.I) is not None


# ------------------------------------------------------------
#  Parse IPV6 from ping6 output
# ------------------------------------------------------------
def parse_ipv6(p):
    explode = p.split()
    ipv6 = explode[3]
    print(ipv6)
    return ipv6


# ------------------------------------------------------------
#  Parse local priorities from dscp-map
# ------------------------------------------------------------
def parsepri(f1):
    out = []
    buff = []
    for c in f1:
        if c == '\n':
            out.append(''.join(buff))
            buff = []
        else:
            buff.append(c)
    else:
        if buff:
            out.append(''.join(buff))
    i = 2
    k = 0
    while True:
        line1 = out[i]
        fields1 = line1.strip().split()
        # skip header, get local priority values
        if i > 1:
            lp[k] = fields1[1]
            k += 1
        if k > 63:
            break
        i += 1
    return lp


# ------------------------------------------------------------
#  Parse code points from dscp-map or cos-map
# ------------------------------------------------------------
def parse_cp(f1):
    global qos_trust
    out = f1.split('\n')
    # print("====== fields ======")
    hdroffset = 2
    i = hdroffset
    cpcount = 0
    rslt = array('I')
    while True:
        fields = out[i].strip().split()
        rslt.append(int(fields[1]))
        # skip header, get code point values
        if i > 1:
            cpcount += 1
        if (qos_trust == "dscp") and cpcount > 63:
            break
        if (qos_trust == "cos") and cpcount > 7:
            break
        i += 1
    return rslt


# ------------------------------------------------------------
#  Setup Topology
# ------------------------------------------------------------
def setup_topo1(topology):
    """
    Build a topology of one switch and four hosts. Connect the hosts to the
    switch.
    """
    global p1
    global p2
    global p3
    global p4
    global vlan_result
    global hs1ipv6
    global hs2ipv6
    global hs3ipv6
    global hs4ipv6
    global opstop
    global swmacaddr

    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')
    hs3 = topology.get('hs3')
    hs4 = topology.get('hs4')
    ops1 = topology.get('ops1')
    opstop = ops1

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None
    assert hs3 is not None

    # Setup the switch ports for qos testing
    p1 = ops1.ports['1']
    p2 = ops1.ports['2']
    p3 = ops1.ports['3']
    p4 = ops1.ports['4']

    # Mark interfaces as enabled
    assert not ops1(
        'set interface {p1} user_config:admin=up'.format(**globals()),
        shell='vsctl'
    )
    assert not ops1(
        'set interface {p2} user_config:admin=up'.format(**globals()),
        shell='vsctl'
    )
    assert not ops1(
        'set interface {p3} user_config:admin=up'.format(**globals()),
        shell='vsctl'
    )
    assert not ops1(
        'set interface {p4} user_config:admin=up'.format(**globals()),
        shell='vsctl'
    )

    # Configure interfaces
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_routing()
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.no_routing()
        ctx.no_shutdown()

    # Configure vlan and switch interfaces
    with ops1.libs.vtysh.ConfigVlan('100') as ctx:
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigVlan('200') as ctx:
        ctx.no_shutdown()

    # Configure interfaces
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_lldp_transmit()
        ctx.no_lldp_receive()
        ctx.vlan_trunk_native(100)
        ctx.vlan_trunk_allowed(100)

    with ops1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.no_lldp_transmit()
        ctx.no_lldp_receive()
        ctx.vlan_trunk_native(100)
        ctx.vlan_trunk_allowed(100)

    with ops1.libs.vtysh.ConfigInterface('3') as ctx:
        ctx.no_lldp_transmit()
        ctx.no_lldp_receive()
        ctx.ip_address(gw1addr)
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterface('4') as ctx:
        ctx.no_lldp_transmit()
        ctx.no_lldp_receive()
        ctx.ip_address(gw2addr)
        ctx.no_shutdown()

    ops1('configure terminal', shell='vtysh')
    ops1('interface ' + p3, shell='vtysh')
    ops1('ipv6 address ' + gw1ipv6 + '/64', shell='vtysh')
    ops1('end', shell='vtysh')

    ops1('configure terminal', shell='vtysh')
    ops1('interface ' + p4, shell='vtysh')
    ops1('ipv6 address ' + gw2ipv6 + '/64', shell='vtysh')
    ops1('end', shell='vtysh')

    ops1('configure terminal', shell='vtysh')
    ops1('interface vlan 200', shell='vtysh')
    ops1('ip address ' + vlanaddr, shell='vtysh')
    ops1('end', shell='vtysh')

    ops1('configure terminal', shell='vtysh')
    ops1('ip route ' + swrte1 + p3, shell='vtysh')
    ops1('ip route ' + swrte2 + p4, shell='vtysh')
    ops1('ipv6 route ' + swrte1ipv6 + p3, shell='vtysh')
    ops1('ipv6 route ' + swrte2ipv6 + p4, shell='vtysh')
    ops1('end', shell='vtysh')

    # FIXME: Use library
    vlan_result = ops1('show vlan 100')
    vlan_result = ops1('show vlan 200')

    # Wait until interfaces are up
    for portlbl in [p1, p2, p3, p4]:
        wait_until_interface_up(ops1, portlbl)

    # Configure host interfaces
    hs1.libs.ip.interface('1', addr=hs1addr, up=True)
    hs2.libs.ip.interface('1', addr=hs2addr, up=True)
    hs3.libs.ip.interface('1', addr=hs3addr, up=True)
    hs4.libs.ip.interface('1', addr=hs4addr, up=True)

    # Add IPv4 default routes
    hs3.send_command(gw1, shell='bash')
    hs4.send_command(gw2, shell='bash')

    # Assign IPv6 addresses and default routes
    eth = hs1.ports['1']
    cmd = setipv6 + hs1ipv6 + '/64' + ' dev ' + eth
    hs1.send_command(cmd, shell='bash')
    cmd = setipv6 + hs2ipv6 + '/64' + ' dev ' + eth
    hs2.send_command(cmd, shell='bash')

    cmd = setipv6 + hs3ipv6 + '/64' + ' dev ' + eth
    hs3.send_command(cmd, shell='bash')
    cmd2 = rteipv6 + gw1ipv6
    hs3.send_command(cmd2, shell='bash')
    cmd = setipv6 + hs4ipv6 + '/64' + ' dev ' + eth
    hs4.send_command(cmd, shell='bash')
    cmd2 = rteipv6 + gw2ipv6
    hs4.send_command(cmd2, shell='bash')

    # disable mDNS on all hosts: service avahi-daemon stop
    hs1.send_command("service avahi-daemon stop", shell='bash')
    hs2.send_command("service avahi-daemon stop", shell='bash')
    hs3.send_command("service avahi-daemon stop", shell='bash')
    hs4.send_command("service avahi-daemon stop", shell='bash')

    # get switch MAC address for routed traffic
    retstruct = ops1('show interface {p1}'.format(**globals()))
    for curLine in retstruct.split('\n'):
        if "MAC Address: " in curLine:
            swmacaddr = curLine.split('MAC Address: ')[1]
    # FIXME: Use library
    print("Switch MAC is " + swmacaddr)

    ops1('show running-config')


def setup_topo2(topology):
    """
    Reconfigure topology to show all switched interfaces on two VLANs
    """
    global p1
    global p2
    global p3
    global p4
    global vlan_result
    global hs1ipv6
    global hs2ipv6
    global hs3ipv6
    global hs4ipv6
    global opstop
    global swmacaddr

    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')
    hs3 = topology.get('hs3')
    hs4 = topology.get('hs4')
    ops1 = topology.get('ops1')
    opstop = ops1

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None
    assert hs3 is not None
    assert hs4 is not None

    # Setup the switch ports for qos testing
    p1 = ops1.ports['1']
    p2 = ops1.ports['2']
    p3 = ops1.ports['3']
    p4 = ops1.ports['4']

    # Mark interfaces as enabled
    assert not ops1(
        'set interface {p1} user_config:admin=up'.format(**globals()),
        shell='vsctl'
    )
    assert not ops1(
        'set interface {p2} user_config:admin=up'.format(**globals()),
        shell='vsctl'
    )
    assert not ops1(
        'set interface {p3} user_config:admin=up'.format(**globals()),
        shell='vsctl'
    )
    assert not ops1(
        'set interface {p4} user_config:admin=up'.format(**globals()),
        shell='vsctl'
    )

    # Configure vlan and switch interfaces
    with ops1.libs.vtysh.ConfigVlan('200') as ctx:
        ctx.no_shutdown()

    # Reconfigure interfaces no-routing
    with ops1.libs.vtysh.ConfigInterface('3') as ctx:
        ctx.no_routing()
        ctx.no_shutdown()
        ctx.no_lldp_transmit()
        ctx.no_lldp_receive()
        ctx.vlan_trunk_native(200)
        ctx.vlan_trunk_allowed(200)

    with ops1.libs.vtysh.ConfigInterface('4') as ctx:
        ctx.no_routing()
        ctx.no_shutdown()
        ctx.no_lldp_transmit()
        ctx.no_lldp_receive()
        ctx.vlan_trunk_native(200)
        ctx.vlan_trunk_allowed(200)

    # Remove prior address configuration
    ops1('configure terminal', shell='vtysh')
    ops1('interface ' + p3, shell='vtysh')
    ops1('no ipv6 address ' + gw1ipv6 + '/64', shell='vtysh')
    ops1('end', shell='vtysh')

    ops1('configure terminal', shell='vtysh')
    ops1('interface ' + p4, shell='vtysh')
    ops1('no ipv6 address ' + gw2ipv6 + '/64', shell='vtysh')
    ops1('end', shell='vtysh')

    ops1('configure terminal', shell='vtysh')
    ops1('interface vlan 200', shell='vtysh')
    ops1('no ip address ' + vlanaddr, shell='vtysh')
    ops1('end', shell='vtysh')

    # Reconfigure IP addresses
    hs3.libs.ip.interface('1', addr=hs3aaddr, up=True)
    hs4.libs.ip.interface('1', addr=hs4aaddr, up=True)
    eth = hs3.ports['1']
    cmd = "ifconfig " + eth + " " + hs3aip
    hs3.send_command(cmd, shell='bash')
    cmd = "ifconfig " + eth + " inet6 add ::ffff:" + hs3aip
    hs3.send_command(cmd, shell='bash')
    cmd = "ifconfig " + eth + " " + hs4aip
    hs4.send_command(cmd, shell='bash')
    cmd = "ifconfig " + eth + " inet6 add ::ffff:" + hs4aip
    hs4.send_command(cmd, shell='bash')

    cmd = setipv6 + hs3aipv6 + '/64' + ' dev ' + eth
    hs3.send_command(cmd, shell='bash')
    cmd = setipv6 + hs4aipv6 + '/64' + ' dev ' + eth
    hs4.send_command(cmd, shell='bash')

    # Remove default routes
    cmd = "route del default"
    hs3.send_command(cmd, shell='bash')
    hs4.send_command(cmd, shell='bash')

    # get switch MAC address for routed traffic
    retstruct = ops1('show interface {p1}'.format(**globals()))
    for curLine in retstruct.split('\n'):
        if "MAC Address: " in curLine:
            swmacaddr = curLine.split('MAC Address: ')[1]
    # FIXME: Use library
    print("Switch MAC is " + swmacaddr)

    ops1('show running-config')

    # FIXME: Use library
    vlan_result = ops1('show vlan 100')
    vlan_result = ops1('show vlan 200')

    # set_trace()


def printable(input):
    return ''.join(char for char in input if isprint(char))


def pingandsniff(onoff, topology):

    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')
    sn1 = topology.get('sn1')
    eth = sn1.ports['1']
    print("sniffer interface " + eth)

    # delay for PCAP
    sleep(5)

    # ping with 1/2 second delay
    hs1.send_command('ping -q -i 0.5 10.0.10.3 > /dev/null &', shell='bash')
    hs2.send_command('ping -q -i 0.5 10.0.10.3 > /dev/null &', shell='bash')

    # listen on the sniffer node
    response = sn1.send_command('echo "sniff(iface=\\"' + eth + '\\", '
                                'prn=lambda x: x.summary(),'
                                'timeout=5)" | scapy 2>/dev/null',
                                shell='bash')
    # Stop the ping
    if onoff == 0:
        hs1.send_command('pkill ping', shell='bash')
        hs2.send_command('pkill ping', shell='bash')

    response = printable(response)
    responselist = response.split('Ether')

    for listentry in responselist:
        print(listentry)

    return responselist


def pingswitch(onoff, topology):

    hs1 = topology.get('hs1')
    sn1 = topology.get('sn1')
    eth = sn1.ports['1']
    print("sniffer interface " + eth)

    # delay for PCAP
    sleep(5)

    # ping switch with 1/2 second delay
    hs1.send_command('ping -i 0.5 10.0.10.3 &',
                     shell='bash')
    hs1.send_command('ping -i 0.5 10.0.10.5 &',
                     shell='bash')

    # listen on the sniffer node
    response = sn1.send_command('echo "sniff(iface=\\"' + eth + '\\", '
                                'prn=lambda x: x.summary(),'
                                'timeout=5)" | scapy 2>/dev/null',
                                shell='bash')
    # Stop the ping
    if onoff == 0:
        hs1.send_command('pkill ping', shell='bash')

    response = printable(response)
    responselist = response.split('Ether')

    for listentry in responselist:
        print(listentry)

    return responselist


# ------------------------------------------------------------
#  Parsers
# ------------------------------------------------------------
def parse_qprofile(f1):
    qp = array('I')
    out = f1.split('\n')
    i = 1
    entrycount = 0
    while True:
        fields = out[i].strip().split()
        # skip header, get local priority values
        if i > 1:
            qp.append(int(fields[1]))
            entrycount += 1
        if entrycount > 7:
            break
        i += 1
    return qp


# ------------------------------------------------------------
#  Update Queue Markup List
#     Updates qmarkup list of queue totals based on queue
#     profile and DSCP/COS Map
#     Updates global qmarkup
# ------------------------------------------------------------
def update_qmarkup_list(cp, pcp, pkts):
    global qmarkup
    global qos_trust
    global dscpmaparray
    global cosmaparray
    global qprofarray
    global local_pri

    # none (CoS Map 0), usually 1
    if local_pri is False:
        queuenum = qprofarray[cosmaparray[0]]
    else:
        queuenum = local_pri

    if qos_trust == "cos":
        # use cos-map and pcp for code-point
        cp = pcp
        queuenum = qprofarray[cosmaparray[cp]]
    else:
        if qos_trust == "dscp":
            queuenum = qprofarray[dscpmaparray[cp]]

    qmarkup[int(queuenum)] += pkts


# ------------------------------------------------------------
#
# Send QoS non-IP Layer 2 prioritized packet
#     Data Set C
#        args: topology, source direction, code points, pcp list
# ------------------------------------------------------------
def send_streamc(topology, s, d, cplist, pcplist):
    global dscpmap
    global queprof
    global swmacaddr
    sys.stderr.close()
    sys.stderr.close()
    ops1 = topology.get('ops1')
    src = s['topology']
    dst = d['topology']

    # Get destination Host 4 MAC address
    eth = dst.ports['1']

    # Get destination dst MAC address
    if s['routed']:
        dstmac = swmacaddr
    else:
        cmd = "cat /sys/class/net/" + eth + "/address"
        dstmac = dst.send_command(cmd, shell='bash')

    # start scapy on Host 3
    src.libs.scapy.start_scapy()
    etherp = src.libs.scapy.ether()
    # ip = src.libs.scapy.ip()
    dot1qp = src.libs.scapy.dot1q()

    etherp['dst'] = dstmac
    etherp['type'] = 0x8137
    eth = src.ports['1']
    ifc = "iface=" + "\'" + eth + "\'" + ",count=1"
    # ip['src'] = s['ipaddr']
    # ip['dst'] = d['ipaddr']
    # ip['proto'] = "icmp"
    # ip['ttl'] = 4

    # Send 8 packets to the Destination MAC
    ops1('show running-config')
    dot1qp['vlan'] = 100
    dot1qp['prio'] = 0
    ifc = "iface=" + "\'" + eth + "\'"
    pcp = 0
    pktsize = 1
    for n in range(0, len(cplist)):
        cp = cplist[n]
        # ip['tos'] = cp << 2
        pcp = pcplist[n]
        pktsize = qsize[pcp]
        dot1qp['prio'] = pcp
        # update qmarkup
        update_qmarkup_list(cp, pcp, pktsize)
        # send packet
        print("Send Set C >>> non-IP Packet Prio=" + str(pcp))
        result = src.libs.scapy.sendp('Eth/Dot1Q',
                                      [etherp, dot1qp], ifc)
        print(result)
    src.libs.scapy.exit_scapy()


# ------------------------------------------------------------
# Send Differentiated Services Code Point (DSCP) packets
#     Send Layer 3 ICMP packet with code points for each priority
#     Data Set B
#        args: topology, source direction, code points, pcp list
# ------------------------------------------------------------
def send_streamb(topology, s, d, cplist, pcplist):
    global dscpmap
    global queprof
    global qsize
    global swmacaddr
    sys.stderr.close()

    src = s['topology']
    dst = d['topology']
    eth = dst.ports['1']

    # Get destination dst MAC address
    if s['routed']:
        dstmac = swmacaddr
    else:
        cmd = "cat /sys/class/net/" + eth + "/address"
        dstmac = dst.send_command(cmd, shell='bash')

    # start scapy on src host
    src.libs.scapy.start_scapy()
    etherp = src.libs.scapy.ether()
    ip = src.libs.scapy.ip()
    dot1qp = src.libs.scapy.dot1q()

    etherp['dst'] = dstmac
    etherp['type'] = 0x0800
    eth = src.ports['1']
    ip['src'] = s['ipaddr']
    ip['dst'] = d['ipaddr']
    ip['proto'] = "icmp"
    ip['ttl'] = 4
    ip['version'] = 4

    print("dst mac =" + dstmac)

    # Send  vlan tagged IP packets
    dot1qp['vlan'] = 100
    dot1qp['type'] = 0x800

    for n in range(0, len(cplist)):
        # set code point (use Type of Service for DSCP)
        cp = cplist[n]
        ip['tos'] = cp << 2
        pcp = pcplist[n]
        dot1qp['prio'] = pcp
        pktsize = qsize[pcp]
        # update qmarkup
        update_qmarkup_list(cp, pcp, pktsize)
        ifc = "iface=" + "\'" + eth + "\'" + ",count="+str(pktsize)
        # send packet
        print("Send Set B >>> IP Packet code point=" + str(cp))
        # send src to dst
        result = src.libs.scapy.sendp('Eth/IP/Dot1Q',
                                      [etherp, ip, dot1qp],
                                      ifc)
        print(result)

    src.libs.scapy.exit_scapy()


# ------------------------------------------------------------
# Send Differentiated Services Code Point (DSCP) packets IPv6
#     Send Layer 3 ICMP packet with code points for each priority
#     Data Set B
#        args: topology, source direction, code point list
# ------------------------------------------------------------
def send_streamb_ipv6(topology, s, d, cplist, pcplist):
    global dscpmap
    global queprof
    global qsize
    global swmacaddr

    # Send IPv6 steam
    # start scapy on src host
    src = s['topology']
    dst = d['topology']
    eth = src.ports['1']

    # Get destination dst MAC address
    if s['routed']:
        dstmac = swmacaddr
    else:
        cmd = "cat /sys/class/net/" + eth + "/address"
        dstmac = dst.send_command(cmd, shell='bash')

    src.libs.scapy.start_scapy()
    etherp = src.libs.scapy.ether()
    ipv6 = src.libs.scapy.ipv6()
    dot1qp = src.libs.scapy.dot1q()

    eth = src.ports['1']
    etherp['dst'] = dstmac
    etherp['type'] = 0x86DD
    ipv6['src'] = s['ipv6']
    ipv6['dst'] = d['ipv6']
    ipv6['version'] = 6

    print("dst mac =" + dstmac)

    # Send IPv6 packets
    print("src IPv6 " + s['ipv6'])
    # Show Dst Host IPv6
    print("dst IPv6 " + d['ipv6'])
    dot1qp['vlan'] = 100
    dot1qp['type'] = 0x800

    for n in range(0, len(cplist)):
        # set code point (use Type of Service for DSCP)
        cp = cplist[n]
        ipv6['tc'] = cp << 2
        pcp = pcplist[n]
        dot1qp['prio'] = pcp
        pktsize = qsize[pcp]
        # update qmarkup
        update_qmarkup_list(cp, pcp, pktsize)
        ifc = "iface=" + "\'" + eth + "\'" + ",count="+str(pktsize)
        # send packet
        print("Send Set B >>> IPv6 Packet code point=" + str(cp))
        # send src to dst
        result = src.libs.scapy.sendp('Eth/IPv6/Dot1Q',
                                      [etherp, ipv6, dot1qp],
                                      ifc)
        print(result)

    src.libs.scapy.exit_scapy()


# ------------------------------------------------------------
# Send Differentiated Services Code Point (DSCP) packets
#     Send Layer 3 ICMP packet with code points for each priority
#     Data Set A
#        args: topology, source direction, code point list
# ------------------------------------------------------------
def send_streama(topology, s, d, cplist, pcplist):
    global dscpmap
    global queprof
    global qsize
    global swmacaddr
    sys.stderr.close()

    src = s['topology']
    dst = d['topology']

    # Start non-scapy sniffer for veriification
    eth = dst.ports['1']
    # dst.send_command("tcpdump -i " + eth + " > /tmp/out 2>/dev/null &",
    #                  shell='bash')

    # Get destination dst MAC address
    if s['routed']:
        dstmac = swmacaddr
    else:
        cmd = "cat /sys/class/net/" + eth + "/address"
        dstmac = dst.send_command(cmd, shell='bash')

    # start scapy on src host
    src.libs.scapy.start_scapy()
    etherp = src.libs.scapy.ether()
    ip = src.libs.scapy.ip()
    dot1qp = src.libs.scapy.dot1q()

    etherp['dst'] = dstmac
    etherp['type'] = 0x0800
    eth = src.ports['1']
    ip['version'] = 4
    ip['src'] = s['ipaddr']
    ip['dst'] = d['ipaddr']
    ip['proto'] = "icmp"
    ip['ttl'] = 4

    print("dst mac =" + dstmac)

    # IPv4 DSCP
    for n in range(0, len(cplist)):
        # set code point (use Type of Service for DSCP)
        cp = cplist[n]
        ip['tos'] = cp << 2
        pcp = pcplist[n]
        dot1qp['prio'] = pcp
        pktsize = qsize[pcp]
        # update qmarkup
        update_qmarkup_list(cp, pcp, pktsize)
        ifc = "iface=" + "\'" + eth + "\'" + ",count="+str(qsize[pcp])
        # send packet
        print("Send Set A >>> IP Packet code point=" + str(cp))
        # send src to dst host
        result = src.libs.scapy.sendp('Eth/IP/Dot1Q',
                                      [etherp, ip, dot1qp],
                                      ifc)
        print(result)

    # Shutdown scapy for IPv4
    src.libs.scapy.exit_scapy()

    # Stop sniffer, show verification
    # result = dst.send_command("pkill tcpdump; cat /tmp/out",
    #                           shell='bash')


# ------------------------------------------------------------
# Send Differentiated Services Code Point (DSCP) packets
#     Send Layer 3 ICMP packet with code points for each priority
#     Data Set A
#        args: topology, source direction, code point list
# ------------------------------------------------------------
def send_streama_ipv6(topology, s, d, cplist, pcplist):
    global dscpmap
    global queprof
    global qsize
    sys.stderr.close()

    src = s['topology']
    dst = d['topology']
    eth = dst.ports['1']

    # Get destination dst MAC address
    if s['routed']:
        dstmac = swmacaddr
    else:
        cmd = "cat /sys/class/net/" + eth + "/address"
        dstmac = dst.send_command(cmd, shell='bash')

    src.libs.scapy.start_scapy()
    etherp = src.libs.scapy.ether()
    ipv6 = src.libs.scapy.ipv6()
    dot1qp = src.libs.scapy.dot1q()
    eth = src.ports['1']
    etherp['type'] = 0x86DD
    etherp['dst'] = dstmac

    ipv6['src'] = s['ipv6']
    ipv6['dst'] = d['ipv6']
    ipv6['version'] = 6

    # Send  IPv6 packets
    print("src IPv6 " + s['ipv6'])
    # Show Host 4 IPv6
    print("dst IPv6 " + d['ipv6'])

    for n in range(0, len(cplist)):
        # set code point (use Traffic Class for DSCP)
        cp = cplist[n]
        ipv6['tc'] = cp << 2
        pcp = pcplist[n]
        dot1qp['prio'] = pcp
        pktsize = qsize[pcp]
        # updae qmarkup
        update_qmarkup_list(cp, pcp, pktsize)
        ifc = "iface=" + "\'" + eth + "\'" + ",count="+str(pktsize)
        # send ipv6 packet
        print("Send Set A >>> IPv6 Packet code point=" + str(cp))
        # send packet
        result = src.libs.scapy.sendp('Eth/IPv6/Dot1Q',
                                      [etherp, ipv6, dot1qp],
                                      ifc)
        print(result)

    src.libs.scapy.exit_scapy()


#
# Ping DSCP
#     send ping -Q tos for all priority ranges
#
def ping_dscp(topology):
    sys.stderr.close()
    # os.close(2)
    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs3 = topology.get('hs3')
    ops1('show running-config')
    for cs in [0x0, 0x20, 0x40, 0x60, 0x80, 0xA0, 0xC0, 0xE0]:
        pingcmd = "ping -Q " + str(cs) + " -i 0.001 " + hs2ip + \
                  " -c 10 >/dev/null"
        hs1.send_command(pingcmd, shell='bash')
        pingcmd = "ping -Q " + str(cs) + " -i 0.001 " + hs4ip + \
                  " -c 10 >/dev/null"
        hs3.send_command(pingcmd, shell='bash')
    sleep(10)


# ------------------------------------------------------------
#
# Queue Compare
#    convert 'show interface queue' results before/after to
#    arrays and compare to ensure Q0...Q7 increase
#        args: Q-list1, Q-list2, list of priority queues
#
# ------------------------------------------------------------
def qcmp(beforestr, afterstr, queuecounts):
    returnval = True
    print(":::: qcmp: ", queuecounts)
    # convert before-results to list
    before = beforestr.split('\n')

    # convert after-results to list
    after = afterstr.split('\n')

    # parse out Q0-Q7 fields and compare
    i = 0
    j = 0
    print("\n======= Compare Queue Statistics Q0-Q7 =======\n")
    while True:
        if j > 7:
            break
        beforefields = before[i].strip().split()
        afterfields = after[i].strip().split()
        i += 1
        if beforefields[0].startswith('Q'):
            expdelta = queuecounts[j]
            actualdelta = int(afterfields[2]) - int(beforefields[2])
            print(beforefields[0] + " before: " + beforefields[2]
                  + " after: " + afterfields[2] + " expected delta: " +
                  str(expdelta) + " actual delta: " + str(actualdelta))
            if (actualdelta < expdelta):
                    returnval = False
            j += 1
    return returnval


# ------------------------------------------------------------
# Queue Test (main)
# ------------------------------------------------------------
@mark.test_id(10300)
@mark.platform_incompatible(['docker'])
@mark.timeout(3600)
def test_qos_trust(topology):
    """
    Test that a vlan configuration is functional with a OpenSwitch switch.
    """

    # create a logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    logger.setLevel(logging.INFO)

    logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

    # create a file handler
    handler = logging.FileHandler(logfile)
    handler.setLevel(logging.INFO)

    # create a logging format
    formatter = logging.Formatter('%(asctime)s - %(name)s -\
%(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    # add the handlers to the logger
    logger.addHandler(handler)

    logger.info('========= Start of QoS Test =========')
    print('========= Start of QoS Test =========')

    # Setup Topology
    global p1
    global p2
    global p3
    global p4
    global vlan_result
    global qmarkup
    global dscpmap
    global queprof
    global qos_trust
    global cosmap
    global dscpmaparray
    global cosmaparray
    global qprofarray
    global local_pri

    # Setup topology 1
    setup_topo1(topology)

    # Login not currently required
    # post_login(topology)

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')
    hs3 = topology.get('hs3')
    hs4 = topology.get('hs4')
    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    # Show version
    ops1('show version', shell='vtysh')

    # Get ports
    p1 = ops1.ports['1']
    p2 = ops1.ports['2']
    eth = hs1.ports['1']
    print("HS1 interface " + eth)
    print("OPS port 1 " + p1)
    # src = "interface " + p1

    vlan_result = ops1('show vlan 100')
    vlan_result = ops1('show vlan 200')

    # Get MAC address
    eth = hs2.ports['1']
    cmd = "cat /sys/class/net/" + eth + "/address"
    h2mac = hs2.send_command(cmd, shell='bash')
    print(h2mac)

    print("##################################################")
    print("Verify that host groups can ping each other")
    print("##################################################")

    print("Verify that H1 can ping H2")
    ping = hs1.libs.ping.ping(1, hs2ip)
    assert ping['transmitted'] == ping['received'] == 1

    print("Verify that H2 can ping H1")
    ping = hs2.libs.ping.ping(1, hs1ip)
    assert ping['transmitted'] == ping['received'] == 1

    print("Verify that H3 can ping H4")
    ping = hs3.libs.ping.ping(1, hs4ip)
    assert ping['transmitted'] == ping['received'] == 1

    print("Verify that H4 can ping H3")
    ping = hs4.libs.ping.ping(1, hs3ip)
    print(ping)
    assert ping['transmitted'] == ping['received'] == 1

    q3 = ops1('show interface ' + p3 + " queues")
    q4 = ops1('show interface ' + p4 + " queues")

    print("Verify that H1 can ping H2 IPv6")
    hs1.send_command("ping6 -Q 0xE0 -I " + eth + " -c 1 " + hs2ipv6)

    print("Verify that H2 can ping H1 IPv6")
    hs2.send_command("ping6 -Q 0xE0 -I " + eth + " -c 1 " + hs1ipv6)

    print("Verify that H3 can ping H4 IPv6")
    hs3.send_command("ping6 -Q 0xE0 -I " + eth + " -c 1 " + hs4ipv6)

    print("Verify that H4 can ping H3 IPV6")
    hs3.send_command("ping6 -Q 0xE0 -I " + eth + " -c 1 " + hs3ipv6)

    # Pause for a moment to wait for extraneous traffic to die down
    print("Pausing for traffic to settle")
    sleep(10)

    print("### Queue statistics before sending ###")
    q1 = ops1('show interface ' + p1 + " queues")
    q2 = ops1('show interface ' + p2 + " queues")
    q3 = ops1('show interface ' + p3 + " queues")
    q4 = ops1('show interface ' + p4 + " queues")

    print("##################################################")
    print("###### Global Trust DSCP Pre-Test Check ######")
    print("##################################################")
    assert not ops1('configure terminal', shell='vtysh')
    assert not ops1('qos trust dscp', shell='vtysh')
    assert not ops1('end', shell='vtysh')
    ping_dscp(topology)
    q1a = ops1('show interface ' + p1 + " queues")
    q2a = ops1('show interface ' + p2 + " queues")
    q3a = ops1('show interface ' + p3 + " queues")
    q4a = ops1('show interface ' + p4 + " queues")

    # pre-test 1 packet delta expected per priority queue
    assert qcmp(q1, q1a, [10, 10, 10, 10, 10, 10, 10, 10]), \
        "FAIL -- queues did NOT increase as expected on " + p1
    print("PASS -- queues increased on " + p1)
    assert qcmp(q2, q2a, [10, 10, 10, 10, 10, 10, 10, 10]), \
        "FAIL -- queues did NOT increase as expected on " + p2
    print("PASS -- queues increased on " + p2)
    assert qcmp(q3, q3a, [10, 10, 10, 10, 10, 10, 10, 10]), \
        "FAIL -- queues did NOT increase on " + p3
    print("PASS -- queues increased on " + p3)
    assert qcmp(q4, q4a, [10, 10, 10, 10, 10, 10, 10, 10]), \
        "FAIL -- queues did NOT increase on " + p4
    print("PASS -- queues increased on " + p4)

    # ----------------------------------------
    # Essential parse of maps and profiles
    # ----------------------------------------
    qos_trust = "dscp"
    assert not ops1('configure terminal', shell='vtysh')
    assert not ops1('no qos trust dscp', shell='vtysh')
    assert not ops1('end', shell='vtysh')

    # Save default DSCP Map for subsequent tests
    dscpmap = ops1('show qos dscp-map', shell='vtysh')
    dscppri = parsepri(dscpmap)
    cosmap = ops1('show qos cos-map', shell='vtysh')

    # Lookup queue profile
    assert not ops1('configure terminal', shell='vtysh')
    queprof = ops1('do show qos queue-profile default', shell='vtysh')
    assert not ops1('end', shell='vtysh')
    print("::: queue_profile ", queprof)

    # ----------------------------------------
    #  parse the cos map, dscp map, and queue profile
    #  into arrays - REDO THIS WHENEVER THE MAPS CHANGE!
    # ----------------------------------------
    qos_trust = "dscp"
    dscpmaparray = parse_cp(dscpmap)
    qos_trust = "cos"
    cosmaparray = parse_cp(cosmap)
    qprofarray = parse_qprofile(queprof)

    print("##################################################")
    print("###### READY TO BEGIN TESTS ######")
    print("##################################################")
    # set_trace()

    # redefine host topology and addresses to pass as arguments
    hs1 = {'topology': None, 'ipaddr': hs1ip, 'ipv6': hs1ipv6, 'routed': False}
    hs2 = {'topology': None, 'ipaddr': hs2ip, 'ipv6': hs2ipv6, 'routed': False}
    hs3 = {'topology': None, 'ipaddr': hs3ip, 'ipv6': hs3ipv6, 'routed': True}
    hs4 = {'topology': None, 'ipaddr': hs4ip, 'ipv6': hs4ipv6, 'routed': True}
    hs1['topology'] = topology.get('hs1')
    hs2['topology'] = topology.get('hs2')
    hs3['topology'] = topology.get('hs3')
    hs4['topology'] = topology.get('hs4')

    print("##################################################")
    print("CASE 1 - Validate Trust None & DSCP")
    print("expect Only the egress port queue has incremented")
    print("increment priorities")
    print("##################################################")
    logger.info('===== CASE 1 - Validate Trust None & DSCP  =====')
    qos_trust = "dscp"
    print("####### Configure ports")
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.qos_trust('none')
    with ops1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.qos_trust('dscp')
    with ops1.libs.vtysh.ConfigInterface('3') as ctx:
        ctx.qos_trust('none')
    with ops1.libs.vtysh.ConfigInterface('4') as ctx:
        ctx.qos_trust('dscp')
    ops1('show running-config')
    vlan_result = ops1('show vlan 100')
    vlan_result = ops1('show vlan 200')

    # ================================================
    #  Send packets for priority 0-7
    # ================================================
    print("##########################################")
    print("####### Read and save all queue statistics")
    print("##########################################")
    q1 = ops1('show interface ' + p1 + " queues")
    q2 = ops1('show interface ' + p2 + " queues")
    q3 = ops1('show interface ' + p3 + " queues")
    q4 = ops1('show interface ' + p4 + " queues")

    print(q1, q2, q3, q4)

    print("##########################################")
    print("####### Send packet set B from H1 to H2")
    print("##########################################")
    # Initialize qmarkup before stream
    qmarkup = [0] * 8
    qos_trust = "none"
    send_streamb(topology, hs1, hs2, cprange1a, pcprangea)
    send_streamb_ipv6(topology, hs1, hs2, cprange1b, pcprangeb)
    rslt1 = qmarkup

    print("##########################################")
    print("####### Send packet set B from H2 to H1")
    print("##########################################")
    qmarkup = [0] * 8
    qos_trust = "dscp"
    send_streamb(topology, hs2, hs1, cprange1a, pcprangea)
    send_streamb_ipv6(topology, hs2, hs1, cprange1b, pcprangeb)
    rslt2 = qmarkup

    print("##########################################")
    print("####### Send packet set A from H3 to H4")
    print("##########################################")
    qmarkup = [0] * 8
    qos_trust = "none"
    send_streama(topology, hs3, hs4, cprange1a, pcprangea)
    send_streama_ipv6(topology, hs3, hs4, cprange1b, pcprangeb)
    rslt3 = qmarkup

    print("##########################################")
    print("####### Send packet set A from H4 to H3")
    print("##########################################")
    qmarkup = [0] * 8
    qos_trust = "dscp"
    send_streama(topology, hs4, hs3, cprange1a, pcprangea)
    send_streama_ipv6(topology, hs4, hs3, cprange1b, pcprangeb)
    rslt4 = qmarkup

    print("##########################################")
    print("####### Read new queue statistics H1 and H2")
    print("##########################################")
    # set_trace()

    # 10 second delay to update queue statistics
    sleep(10)

    q1a = ops1('show interface ' + p1 + " queues")
    q2a = ops1('show interface ' + p2 + " queues")

    print("##########################################")
    print("####### Read new queue statistics H3 and H4")
    print("##########################################")
    q3a = ops1('show interface ' + p3 + " queues")
    q4a = ops1('show interface ' + p4 + " queues")

    print("##########################################")
    print("####### Compare H2 before and after")
    print("expect increase on interface " + p2 + " queues")
    print("##########################################")
    # egress on H2
    print(">>>> Test 1 q2, rslt1 ", end="")
    assert qcmp(q2, q2a, rslt1), \
        "FAIL -- queues did NOT increase on " + p2
    print("PASS -- queues increased on " + p2)

    print("##########################################")
    print("####### Compare H1 before and after")
    print("on interface " + p1)
    print("##########################################")
    print(">>>> Test 1 q1, rslt2 ", end="")
    # egress on H1
    assert qcmp(q1, q1a, rslt2), \
        "FAIL -- queues did not increase as expected on " + p1
    print("PASS -- queues increased on " + p1)

    print("##########################################")
    print("####### Compare H4 before and after")
    print("expect increase on interface " + p4 + " queues")
    print("##########################################")
    print(">>>> Test 1 q4, rslt3 ", end="")
    # egress on H4
    # set_trace()
    assert qcmp(q4, q4a, rslt3), \
        "FAIL -- queues did NOT increase on " + p4
    print("PASS -- queues increased on " + p4)

    print("##########################################")
    print("####### Compare H3 before and after")
    print("##########################################")
    print(">>>> Test 1 q3, rslt4 ", end="")
    # egress on H3
    assert qcmp(q3, q3a, rslt4), \
        "FAIL -- queues did NOT increase on " + p3
    print("PASS -- queues increased on " + p3)
    logger.info('==== END CASE 1 ====')
    print('==== END CASE 1 ====')
    # set_trace()
    print("##################################################")
    print("CASE 2 - Validate changing DSCP Map")
    print("change all DSCP Map to local-priority 3")
    print("expect Only the egress port queue has incremented")
    print("set priority 3 fixed")
    print("##########################################")
    logger.info('===== CASE 2 - Validate changing DSCP Map =====')
    print("##################################################")

    # Save default DSCP Map for subsequent tests
    dscpmap = ops1('show qos dscp-map', shell='vtysh')
    dscppri = parsepri(dscpmap)
    # set_trace()
    # Lookup queue profile
    assert not ops1('configure terminal', shell='vtysh')
    queue_profile = ops1('do show qos queue-profile default', shell='vtysh')
    assert not ops1('end', shell='vtysh')
    print(queue_profile)
    # set_trace()

    # Change DSCP Map
    print("######## Create Queue Profile ########")
    assert not ops1('configure terminal', shell='vtysh')
    for cp in range(0, 64):
        assert not ops1('qos dscp-map ' + str(cp) + ' local-priority 3',
                        shell='vtysh')
    assert not ops1('end', shell='vtysh')
    dscpmap = ops1('show qos dscp-map', shell='vtysh')
    # global var qos_trust already set to "dscp" so parse_cp works correctly
    dscpmaparray = parse_cp(dscpmap)

    # ================================================
    #  Send packets for priority 3 only
    # ================================================
    print("##########################################")
    print("####### Read and save all queue statistics")
    print("##########################################")
    q1 = ops1('show interface ' + p1 + " queues")
    q2 = ops1('show interface ' + p2 + " queues")
    q3 = ops1('show interface ' + p3 + " queues")
    q4 = ops1('show interface ' + p4 + " queues")

    print(q1, q2, q3, q4)
    print("##########################################")
    print("####### Send packet set B from H2 to H1")
    print("##########################################")
    qmarkup = [0] * 8
    qos_trust = "dscp"
    send_streamb(topology, hs2, hs1, cprange1a, pcprangea)
    send_streamb_ipv6(topology, hs2, hs1, cprange1b, pcprangeb)
    rslt2 = qmarkup

    print("##########################################")
    print("####### Send packet set A from H4 to H3")
    print("##########################################")
    qmarkup = [0] * 8
    qos_trust = "dscp"
    send_streama(topology, hs4, hs3, cprange1a, pcprangea)
    send_streama_ipv6(topology, hs4, hs3, cprange1b, pcprangeb)
    rslt4 = qmarkup

    print("##########################################")
    print("####### Read new queue statistics H1 and H2")
    print("##########################################")
    # 10 second delay to update queue statistics
    sleep(10)
    q1a = ops1('show interface ' + p1 + " queues")
    q2a = ops1('show interface ' + p2 + " queues")
    q3a = ops1('show interface ' + p3 + " queues")
    q4a = ops1('show interface ' + p4 + " queues")

    print("##########################################")
    print("####### Compare H1 before and after")
    print("expect increase on interface " + p1 + " queues")
    print("##########################################")
    # Only priority 3 queue has increased
    # egress on H2
    print(">>>> Test 2 q1, rslt2 ", end="")
    # set_trace()
    assert qcmp(q1, q1a, rslt2),\
        "FAIL -- queues did NOT increase on " + p1
    print("PASS -- queues increased on " + p1)

    print("##########################################")
    print("####### Compare H3 before and after")
    print("expect increase on interface " + p3 + " queues")
    print("##########################################")
    # Only priority 3 queue has increased
    # egress on H4
    print(">>>> Test 2 q3, rslt4 ", end="")
    assert qcmp(q3, q3a, rslt4),\
        "FAIL -- queues did NOT increase on " + p3
    print("PASS -- queues increased on " + p3)

    logger.info('==== END CASE 2 ====')
    print('==== END CASE 2 ====')
    # set_trace()

    print("##################################################")
    print("CASE 3 - Validate changing DSCP Map with port override")
    print("invert DSCP Map, send 64 packets of PCP 7 ")
    print("expect Only the egress port queue has incremented")
    print("##########################################")
    logger.info('===== CASE 3 - Validate changing DSCP Map =====')
    print("##################################################")
    qos_trust = "dscp"
    # Previously saved local priorities in global variable
    # invert setting in dscppri
    assert not ops1('configure terminal', shell='vtysh')
    for i in range(0, 64):
        p0 = dscppri[63 - i]
        assert not ops1('qos dscp-map ' + str(i) + ' local-priority ' +
                        str(p0), shell='vtysh')
    assert not ops1('end', shell='vtysh')

    # Configure trust
    print("===== Configure trust ======")
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.qos_trust('none')
        ctx.qos_dscp('26')
    with ops1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.qos_trust('dscp')
    with ops1.libs.vtysh.ConfigInterface('3') as ctx:
        ctx.qos_trust('none')
        ctx.qos_dscp('26')
    with ops1.libs.vtysh.ConfigInterface('4') as ctx:
        ctx.qos_trust('dscp')

    dscpmap = ops1('show qos dscp-map', shell='vtysh')
    dscppri = parsepri(dscpmap)
    dscpmaparray = parse_cp(dscpmap)

    # Trust override
    local_pri = dscpmaparray[26]
    print("local priority = ", local_pri)

    print("######## Create Queue Profile ########")
    print("##########################################")
    print("####### Read and save all queue statistics")
    print("##########################################")
    q1 = ops1('show interface ' + p1 + " queues")
    q2 = ops1('show interface ' + p2 + " queues")
    q3 = ops1('show interface ' + p3 + " queues")
    q4 = ops1('show interface ' + p4 + " queues")

    print(q1, q2, q3, q4)
    # ================================================
    #  Send packets 64 packets with priority 7
    # ================================================
    # ================================================
    print("##########################################")
    print("####### Send packet set B' from H1 to H2")
    print("##########################################")
    qmarkup = [0] * 8
    qos_trust = "none"
    send_streamb(topology, hs1, hs2, cprange2a, pcpsevens)
    send_streamb_ipv6(topology, hs1, hs2, cprange2b, pcpsevens)
    rslt1 = qmarkup

    print("##########################################")
    print("####### Send packet set B' from H2 to H1")
    print("##########################################")
    qmarkup = [0] * 8
    qos_trust = "dscp"
    send_streamb(topology, hs2, hs1, cprange2a, pcpsevens)
    send_streamb_ipv6(topology, hs2, hs1, cprange2b, pcpsevens)
    rslt2 = qmarkup

    print("##########################################")
    print("####### Send packet set A from H3 to H4")
    print("##########################################")
    qmarkup = [0] * 8
    qos_trust = "none"
    send_streama(topology, hs3, hs4, cprange2a, pcpsevens)
    send_streama_ipv6(topology, hs3, hs4, cprange2b, pcpsevens)
    rslt3 = qmarkup

    print("##########################################")
    print("####### Send packet set A from H4 to H3")
    print("##########################################")
    qmarkup = [0] * 8
    qos_trust = "dscp"
    send_streama(topology, hs4, hs3, cprange2a, pcpsevens)
    send_streama_ipv6(topology, hs4, hs3, cprange2b, pcpsevens)
    rslt4 = qmarkup

    print("##########################################")
    print("####### Read new queue statistics H1 and H2")
    print("##########################################")
    # 10 second delay to update queue statistics
    sleep(10)
    q1a = ops1('show interface ' + p1 + " queues")
    q2a = ops1('show interface ' + p2 + " queues")

    print("##########################################")
    print("####### Read new queue statistics H3 and H4")
    print("##########################################")
    q3a = ops1('show interface ' + p3 + " queues")
    q4a = ops1('show interface ' + p4 + " queues")

    print("##########################################")
    print("####### Compare H1 before and after")
    print("expect increase on interface " + p1 + " queues")
    print("##########################################")
    print(">>>> Test 3 q2, rslt1 ", end="")
    # On port 2 only egress port queue incremented per AF31
    # set_trace()
    assert qcmp(q2, q2a, rslt1),\
        "FAIL -- queues did NOT increase on " + p2
    print("PASS -- queues increased on " + p2)

    # On port 4 only egress port queue incremented per AF31
    print(">>>> Test 3 q4, rslt3 ", end="")
    assert qcmp(q4, q4a, rslt3),\
        "FAIL -- queues did NOT increase on " + p4
    print("PASS -- queues increased on " + p4)

    # On port 1&3 each egress port queue per priorities
    print(">>>> Test 3 q1, rslt2 ", end="")
    assert qcmp(q1, q1a, rslt2),\
        "FAIL -- queues did NOT increase on " + p1
    print("PASS -- queues increased on " + p1)

    print(">>>> Test 3 q3, rslt4 ", end="")
    assert qcmp(q3, q3a, rslt4),\
        "FAIL -- queues did NOT increase on " + p3
    print("PASS -- queues increased on " + p3)

    # Disable trust overrided local priority
    local_pri = False

    # un-do dscp override
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_qos_trust()
        ctx.no_qos_dscp()
    with ops1.libs.vtysh.ConfigInterface('3') as ctx:
        ctx.no_qos_trust()
        ctx.no_qos_dscp()

    logger.info('==== END CASE 3 ====')
    print('==== END CASE 3 ====')
    print("##################################################")
    print("CASE 4 - Verify QoS Trust None & CoS")
    print("##################################################")

    # Reconfigure interfaces
    setup_topo2(topology)

    hs3 = {'topology': None, 'ipaddr': hs3aip,
           'ipv6': hs3aipv6, 'routed': False}
    hs4 = {'topology': None, 'ipaddr': hs4aip,
           'ipv6': hs4aipv6, 'routed': False}
    hs3['topology'] = topology.get('hs3')
    hs4['topology'] = topology.get('hs4')

    # set_trace()
    qos_trust = "cos"
    logger.info('===== CASE 3 - Validate Trust None CoS  =====')
    print("####### Configure ports")
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.qos_trust('none')
    with ops1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.qos_trust('cos')
    with ops1.libs.vtysh.ConfigInterface('3') as ctx:
        ctx.qos_trust('none')
    with ops1.libs.vtysh.ConfigInterface('4') as ctx:
        ctx.qos_trust('cos')

    ops1('show running-config')
    cosmap = ops1('show qos cos-map', shell='vtysh')
    cosmaparray = parse_cp(cosmap)
    vlan_result = ops1('show vlan 100')
    vlan_result = ops1('show vlan 200')

    # ================================================
    #  Read and save queue statistics
    # ================================================
    # 10 second delay to update queue statistics
    sleep(10)
    print("##########################################")
    print("####### Read and save all queue statistics")
    print("##########################################")
    q1 = ops1('show interface ' + p1 + " queues")
    q2 = ops1('show interface ' + p2 + " queues")
    q3 = ops1('show interface ' + p3 + " queues")
    q4 = ops1('show interface ' + p4 + " queues")

    print(q1, q2, q3, q4)
    print("##########################################")
    print("####### Send packet set B from H1 to H2")
    print("##########################################")
    # Initialize qmarkup before stream
    qmarkup = [0] * 8
    qos_trust = "none"
    send_streamb(topology, hs1, hs2, cprange1a, pcprangea)
    send_streamb_ipv6(topology, hs1, hs2, cprange1b, pcprangeb)
    rslt1 = qmarkup

    print("##########################################")
    print("####### Send packet set B from H2 to H1")
    print("##########################################")
    qmarkup = [0] * 8
    qos_trust = "cos"
    send_streamb(topology, hs2, hs1, cprange1a, pcprangea)
    send_streamb_ipv6(topology, hs2, hs1, cprange1b, pcprangeb)
    rslt2 = qmarkup

    print("##########################################")
    print("####### Send packet set C from H3 to H4")
    print("##########################################")
    qmarkup = [0] * 8
    qos_trust = "none"
    send_streamc(topology, hs3, hs4, cprange1c, pcprangec)
    rslt3 = qmarkup

    print("##########################################")
    print("####### Send packet set C from H4 to H3")
    print("##########################################")
    qmarkup = [0] * 8
    qos_trust = "cos"
    send_streamc(topology, hs4, hs3, cprange1c, pcprangec)
    rslt4 = qmarkup

    print("##########################################")
    print("####### Read new queue statistics ")
    print("##########################################")
    # 10 second delay to update queue statistics
    sleep(10)
    q1a = ops1('show interface ' + p1 + " queues")
    q2a = ops1('show interface ' + p2 + " queues")
    q3a = ops1('show interface ' + p3 + " queues")
    q4a = ops1('show interface ' + p4 + " queues")

    # On ports 2 & 4, only same egress port queue has incremented
    # that is specified by CoS Map PCP 0 entry & queue profile
    #
    print("##########################################")
    print("####### Compare H2 before and after")
    print("expect NO increase on interface " + p2)
    print("##########################################")
    print(">>>> Test 4 q2, rslt1 ", end="")
    assert qcmp(q2, q2a, rslt1),\
        "FAIL -- queues did NOT increase on " + p2
    print("PASS -- queues increased on " + p2)

    logger.info('==== END CASE 4 ====')
    print('==== END CASE 4 ====')
    # set_trace()

    print("##################################################")
    print("CASE 5 - Validate changing CoS Map")
    print("##################################################")
    logger.info('===== CASE 5 - Validate changing CoS Map  =====')
    ops1('show qos cos-map', shell='vtysh')
    assert not ops1('configure terminal', shell='vtysh')
    for cp in range(0, 7):
        assert not ops1('qos cos-map ' + str(cp) + ' local-priority 3',
                        shell='vtysh')
    assert not ops1('end', shell='vtysh')
    qos_trust = "cos"
    cosmap = ops1('show qos cos-map', shell='vtysh')
    cosmaparray = parse_cp(cosmap)
    vlan_result = ops1('show vlan 100')
    q1 = ops1('show interface ' + p1 + " queues")
    q2 = ops1('show interface ' + p2 + " queues")
    q3 = ops1('show interface ' + p3 + " queues")
    q4 = ops1('show interface ' + p4 + " queues")

    print("##########################################")
    print("####### Send packet set B from H2 to H1")
    print("##########################################")
    qmarkup = [0] * 8
    send_streamb(topology, hs2, hs1, cprange1a, pcpthrees)
    send_streamb_ipv6(topology, hs2, hs1, cprange1b, pcpthrees)
    rslt2 = qmarkup

    print("##########################################")
    print("####### Send packet set A from H4 to H3")
    print("##########################################")
    qmarkup = [0] * 8
    qos_trust = "cos"
    send_streama(topology, hs4, hs3, cprange1a, pcpthrees)
    send_streama_ipv6(topology, hs4, hs3, cprange1b, pcpthrees)
    rslt4 = qmarkup

    print("##########################################")
    print("####### Read new queue statistics ")
    print("##########################################")
    # 10 second delay to update queue statistics
    sleep(10)
    q1a = ops1('show interface ' + p1 + " queues")
    q2a = ops1('show interface ' + p2 + " queues")
    q3a = ops1('show interface ' + p3 + " queues")
    q4a = ops1('show interface ' + p4 + " queues")

    print("##########################################")
    print("####### Compare H1 before and after")
    print("##########################################")
    print(">>>> Test 5 q1, rslt2 ", end="")
    assert qcmp(q1, q1a, rslt2),\
        "FAIL -- queues did NOT increase on " + p1
    print("PASS -- queues increased on " + p1)

    print("##########################################")
    print("####### Compare H3 before and after")
    print("##########################################")
    print(">>>> Test 5 q3, rslt4 ", end="")
    assert qcmp(q3, q3a, rslt4),\
        "FAIL -- queues did NOT increase on " + p1
    print("PASS -- queues increased on " + p4)
    cosmap = []

    # Restore default CoS Map
    assert not ops1('configure terminal', shell='vtysh')
    assert not ops1('no qos cos-map 0', shell='vtysh')
    assert not ops1('no qos cos-map 1', shell='vtysh')
    assert not ops1('no qos cos-map 2', shell='vtysh')
    assert not ops1('no qos cos-map 3', shell='vtysh')
    assert not ops1('no qos cos-map 4', shell='vtysh')
    assert not ops1('no qos cos-map 5', shell='vtysh')
    assert not ops1('no qos cos-map 6', shell='vtysh')
    assert not ops1('no qos cos-map 7', shell='vtysh')
    assert not ops1('end', shell='vtysh')
    cosmap = ops1('show qos cos-map', shell='vtysh')
    cosmaparray = parse_cp(cosmap)
    logger.info('==== END CASE 5 ====')
