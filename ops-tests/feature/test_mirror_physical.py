#!/usr/bin/python2.7
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

"""
OpenSwitch Test for simple ping between nodes.
"""

from pytest import mark
import logging
# import http.client
import mmap
from time import sleep
from curses.ascii import isprint
# from pytest import set_trace
# from re import search


DEFAULT_USER = 'netop'
DEFAULT_PASSWORD = 'netop'
loopback = '127.0.0.1'
mask = '24'
cookie = None
p1 = None
p2 = None
p3 = None
p4 = None
ec = 0

TOPOLOGY = """
#           +-------+
#           |  sn1  |
#           +---+---+
#               |
#               |
# +-------------4-------------+
# |            ops1           |
# +---1---------2---------3---+
#     |         |         |
#     |         |         |
# +---v---+ +---v---+ +---v---+
# |  hs1  | |  hs2  | |  hs3  |
# +-------+ +-------+ +-------+

# Nodes
[type=host name="Host 1"] hs1
[type=host name="Host 2"] hs2
[type=host name="Host 3"] hs3
[type=host name="Sniffer 1" image="openswitch/ubuntuscapy:latest"] sn1
[type=openswitch name="OpenSwitch 1"] ops1


# Links
hs1:1 -- ops1:1
hs2:1 -- ops1:2
hs3:1 -- ops1:3
sn1:1 -- ops1:4
"""

logfile = 'mirror_test.log'


#
# Analyze Logs
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
                # sregexp=re.compile(spattern)
                # eregexp=re.compile(epattern)
                cmatch = m[spos:epos]
                echo_requests = cmatch.count(str.encode("echo-request"))
                echo_replies = cmatch.count(str.encode("echo-reply"))
                print("PING-REQUESTS ", echo_requests)
                print("PING-REPLIES ", echo_replies)
                return echo_requests, echo_replies


def setup_topo(topology):
    """
    Build a topology of one switch and three hosts. Connect the hosts to the
    switch. Setup a VLAN for the ports connected to the hosts and ping from
    host 1 to host 2.
    """
    global p1
    global p2
    global p3
    global p4
    global vlan_result

    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')
    hs3 = topology.get('hs3')
    ops1 = topology.get('ops1')
    sn1 = topology.get('sn1')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None
    assert hs3 is not None

    # Get the sniffer interface
    eth = sn1.ports['1']
    print("sniffer interface " + eth)

    # Setup the switch ports for mirror testing
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

    with ops1.libs.vtysh.ConfigInterface('3') as ctx:
        ctx.no_routing()
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterface('4') as ctx:
        ctx.no_shutdown()

    # Configure vlan and switch interfaces
    with ops1.libs.vtysh.ConfigVlan('100') as ctx:
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.vlan_access(100)

    with ops1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.vlan_access(100)

    with ops1.libs.vtysh.ConfigInterface('3') as ctx:
        ctx.vlan_access(100)

    # FIXME: Use library
    vlan_result = ops1('show vlan 100')

#    assert search(
#        r'100\s+(vlan|VLAN)100\s+up\s+ok\s+({p3}|{p2}),\s*({p7}|{p8})'.format(
#            **globals()
#        ),
#        vlan_result
#    )

    # Configure host interfaces
    # hs1.send_command('ip link show', shell='bash')
    hs1.libs.ip.interface('1', addr='10.0.10.1/24', up=True)
    # hs2.send_command('ip link show', shell='bash')
    hs2.libs.ip.interface('1', addr='10.0.10.2/24', up=True)
    # hs3.send_command('ip link show', shell='bash')
    hs3.libs.ip.interface('1', addr='10.0.10.3/24', up=True)
    ifg = "ifconfig " + eth + " promisc"
    sn1.send_command(ifg, shell='bash')
    # sn1.send_command('ip link show', shell='bash')
    sn1.libs.ip.interface('1', addr='10.0.10.4/24', up=True)
    # set_trace()

    # FIXME: Use library
    ops1('show running-config')


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
    hs1.send_command('ping -q -i 0.5 10.0.10.3 > /dev/null &')
    hs2.send_command('ping -q -i 0.5 10.0.10.3 > /dev/null &')

    # listen on the sniffer node
    response = sn1.send_command('echo "sniff(iface=\\"' + eth + '\\", '
                                'prn=lambda x: x.summary(),'
                                'timeout=5)" | scapy 2>/dev/null')

    # Stop the ping
    if onoff == 0:
        hs1.send_command('pkill ping', shell='bash')
        hs2.send_command('pkill ping', shell='bash')

    response = printable(response)
    responselist = response.split('Ether')

    for listentry in responselist:
        print(listentry)

    return responselist


# Mirror Test
@mark.test_id(10300)
@mark.platform_incompatible(['docker'])
def test_mirror(topology):
    """
    Test that a vlan configuration is functional with a OpenSwitch switch.
    """

    # create a logger
    logger = logging.getLogger(__name__)
    logger.setLevel(logging.INFO)
    logger.setLevel(logging.INFO)

    # create a file handler
    handler = logging.FileHandler(logfile)
    handler.setLevel(logging.INFO)

    # create a summary file
    summaryfile = './access_summary.log'
    summary = LogAnalyzer(logfile, summaryfile, 5)

    # create a logging format
    formatter = logging.Formatter('%(asctime)s - %(name)s -\
%(levelname)s - %(message)s')
    handler.setFormatter(formatter)

    # add the handlers to the logger
    logger.addHandler(handler)

    logger.info('========= Start of Mirror Test =========')

    # Setup Topology
    global p1
    global p2
    global p3
    global p4
    global vlan_result

    # Setup topology
    setup_topo(topology)
    # Login not currently required
    # post_login(topology)

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')
    hs3 = topology.get('hs3')
    sn1 = topology.get('sn1')
    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None
    assert hs3 is not None
    assert sn1 is not None

    # Get ports
    p1 = ops1.ports['1']
    p2 = ops1.ports['2']
    p3 = ops1.ports['3']
    p4 = ops1.ports['4']
    eth = sn1.ports['1']
    print("sniffer interface " + eth)
    print("OPS port 1 " + p1)
    print("OPS port 4 " + p4)

    # Give the openswitch container time to start up or the ports
    # won't be present in openvswitch
    print("Waiting 10 seconds for OPS to stabilize...")
    sleep(10)

    vlan_result = ops1('show vlan 100')

    # clear mirrors before start of tests
    ops1('configure terminal', shell='vtysh')
    ops1('no mirror session FOO', shell='vtysh')
    ops1('no mirror session Mirror1', shell='vtysh')
    ops1('end', shell='vtysh')

    print("##################################################")
    print("Verify that H1 and H2 can both ping H3")
    print("##################################################")
    ping = hs1.libs.ping.ping(1, '10.0.10.3')
    assert ping['transmitted'] == ping['received'] == 1
    ping = hs2.libs.ping.ping(1, '10.0.10.3')
    assert ping['transmitted'] == ping['received'] == 1
    # set_trace()

    # Case 1
    #  Test pings BEFORE mirror - expect no sniffer traffic
    #
    print("##################################################")
    print("CASE 1 - Verify Host Connectivity")
    print("expect")
    print("     no echo-reply")
    print("     no echo-request")
    print("##################################################")
    logger.info('========= CASE 1 - Sniffer pings BEFORE mirror  =========')
    responselist = pingandsniff(0, topology)
    passed = False
    for listentry in responselist:
        logger.info(listentry)
        if "echo-reply" in listentry:
            assert False, "reply unexpected " + listentry
        if "echo-request" in listentry:
            assert False, "request unexpected " + listentry
    logger.info('==== END CASE 1 ====')
    ereq, erply = summary.ping_count("CASE 1", "END CASE 1")
    logger.info("PING-REQUESTS " + str(ereq))
    logger.info("PING-REPLIES " + str(erply))
    if ereq > 0 or erply > 0:
        assert False, "Expect zero pings!"
    # set_trace()

    # Show interface stats after ping
    # ops1('show interface {p1}'.format(**locals()))
    # ops1('show interface {p2}'.format(**locals()))
    # ops1('show interface {p3}'.format(**locals()))
    # ops1('show interface {p4}'.format(**locals()))

    print("##################################################")
    print("CASE 2 - Verify Source Receive")
    print(" expect ONLY")
    print("     10.0.10.1 > 10.0.10.3 echo-request")
    print("##################################################")
    # ---------------------------------------
    # Case 2	Sniffer pings AFTER mirror session FOO
    # 		(Verify sniffer requests split flow)
    #
    # source interface 1 rx
    # destination interface 4 (sniffer)
    # no shutdown
    # end
    # ---------------------------------------

    logger.info('========= CASE 2 -  src I/F 1 rx, dest I/F 4  =========')
    # Create mirror FOO with port configuration
    assert not ops1('configure terminal', shell='vtysh')
    assert not ops1('mirror session FOO', shell='vtysh')
    src = "source interface " + p1 + " rx"
    assert not ops1(src, shell='vtysh')
    dst = "destination interface " + p4
    assert not ops1(dst, shell='vtysh')
    assert not ops1('no shutdown', shell='vtysh')
    assert not ops1('end', shell='vtysh')

    # Test pings AFTER mirror
    responselist = pingandsniff(0, topology)
    passed = False
    for listentry in responselist:
        logger.info(listentry)
        if "echo-reply" in listentry:
            assert False, "bad packet " + listentry
        if "echo-request" in listentry:
            if '10.0.10.1 > 10.0.10.3' not in listentry:
                assert False, "bad packet " + listentry
            else:
                passed = True
    assert passed, "didn't receive expected packet "
    ereq, erply = summary.ping_count("CASE 2", "END CASE 2")
    logger.info("PING-REQUESTS " + str(ereq))
    logger.info("PING-REPLIES " + str(erply))
    if ereq == 0:
        assert False, "Expect ping requests!"
    # set_trace()

    print("##################################################")
    print("CASE 3 - Verify Source Transmit")
    print(" expect ONLY")
    print("     10.0.10.3 > 10.0.10.1 echo-reply")
    print("##################################################")
    # ---------------------------------------
    # Case 3	mirror session FOO
    # source interface 1 tx
    # end
    # ---------------------------------------
    logger.info('========= CASE 3 - src I/F 1 tx  =========')
    assert not ops1('configure terminal', shell='vtysh')
    assert not ops1('mirror session FOO', shell='vtysh')
    src = "source interface " + p1 + " tx"
    assert not ops1(src, shell='vtysh')
    assert not ops1('end', shell='vtysh')

    # Test pings AFTER mirror
    responselist = pingandsniff(0, topology)
    passed = False
    for listentry in responselist:
        logger.info(listentry)
        if "echo-request" in listentry:
            assert False, "bad packet " + listentry
        if "echo-reply" in listentry:
            if '10.0.10.3 > 10.0.10.1' not in listentry:
                assert False, "bad packet " + listentry
            else:
                passed = True
    if passed is False:
        assert passed, "Didn't receive expected packet"

    logger.info('==== END CASE 3 ====')
    ereq, erply = summary.ping_count("CASE 3", "END CASE 3")
    logger.info("PING-REQUESTS " + str(ereq))
    logger.info("PING-REPLIES " + str(erply))
    if erply == 0:
        assert False, "Expect ping replies!"

    print("##################################################")
    print("CASE 4 - Verify Source Bi-directional")
    print(" expect BOTH")
    print("     10.0.10.3 > 10.0.10.1 echo-reply")
    print("     10.0.10.1 > 10.0.10.1 echo-request")
    print("##################################################")
    # ---------------------------------------
    # Case 4	mirror session FOO
    # source interface 1 both
    # end
    # ---------------------------------------
    logger.info('========= CASE 4 - src I/F 1 both  =========')
    assert not ops1('configure terminal', shell='vtysh')
    assert not ops1('mirror session FOO', shell='vtysh')
    src = "source interface " + p1 + " both"
    assert not ops1(src, shell='vtysh')
    assert not ops1('end', shell='vtysh')

    # Test pings AFTER mirror
    responselist = pingandsniff(0, topology)
    passed1 = False
    passed2 = False
    for listentry in responselist:
        logger.info(listentry)
        if "echo-reply" in listentry:
            if '10.0.10.3 > 10.0.10.1' not in listentry:
                assert False, "bad packet " + listentry
            else:
                passed1 = True
        if "echo-request" in listentry:
            if '10.0.10.1 > 10.0.10.3' not in listentry:
                assert False, "bad packet " + listentry
            else:
                passed2 = True
    if passed1 is False or passed2 is False:
        assert False, "Didn't receive expected packets"
    logger.info('==== END CASE 4 ====')
    ereq, erply = summary.ping_count("CASE 4", "END CASE 4")
    logger.info("PING-REQUESTS " + str(ereq))
    logger.info("PING-REPLIES " + str(erply))
    if erply == 0:
        assert False, "Expect ping requests!"
    # set_trace()

    print("##################################################")
    print("CASE 5 - Verify Two Sources")
    print(" expect BOTH")
    print("     10.0.10.1 > 10.0.10.3 echo-request")
    print("     10.0.10.2 > 10.0.10.3 echo-request")
    print("##################################################")
    # ---------------------------------------
    # Case 5	mirror session FOO
    # source interface 1 rx
    # source interface 2 rx
    # end
    # ---------------------------------------
    logger.info('========= CASE 5 - src I/F 1 rx 2 rx  =========')
    assert not ops1('configure terminal', shell='vtysh')
    assert not ops1('mirror session FOO', shell='vtysh')
    src1 = "source interface " + p1 + " rx"
    src2 = "source interface " + p2 + " rx"
    assert not ops1(src1, shell='vtysh')
    assert not ops1(src2, shell='vtysh')
    assert not ops1('end', shell='vtysh')

    # Test pings AFTER mirror
    responselist = pingandsniff(0, topology)
    passed1 = False
    passed2 = False
    for listentry in responselist:
        logger.info(listentry)
        if "echo-request" in listentry:
            if '10.0.10.1 > 10.0.10.3' not in listentry and \
                    '10.0.10.2 > 10.0.10.3' not in listentry:
                assert False, "bad packet " + listentry
            if '10.0.10.1 > 10.0.10.3' in listentry:
                passed1 = True
            if '10.0.10.2 > 10.0.10.3' in listentry:
                passed2 = True
        if "echo-reply" in listentry:
            assert False, "bad packet " + listentry
    if passed1 is False or passed2 is False:
        assert False, "Didn't receive expected packets"

    logger.info('==== END CASE 5 ====')
    ereq, erply = summary.ping_count("CASE 5", "END CASE 5")
    logger.info("PING-REQUESTS " + str(ereq))
    logger.info("PING-REPLIES " + str(erply))
    if ereq == 0:
        assert False, "Expect ping requests!"

    print("##################################################")
    print("CASE 6 - Verify Source Removal")
    print(" expect ONLY")
    print("     10.0.10.2 > 10.0.10.3 echo-request")
    print("##################################################")
    # ---------------------------------------
    # Case 6	mirror session FOO
    # no source interface 1 rx
    # end
    # ---------------------------------------
    logger.info('========= CASE 6 - no src I/F 1 rx  =========')
    assert not ops1('configure terminal', shell='vtysh')
    assert not ops1('mirror session FOO', shell='vtysh')
    src = "no source interface " + p1 + " rx"
    assert not ops1(src, shell='vtysh')
    assert not ops1('end', shell='vtysh')
    # set_trace()
    # Test pings AFTER mirror
    responselist = pingandsniff(0, topology)
    passed = False
    for listentry in responselist:
        logger.info(listentry)
        if "echo-reply" in listentry:
                assert False, "bad packet " + listentry
        if "echo-request" in listentry:
            if '10.0.10.2 > 10.0.10.3' not in listentry:
                assert False, "bad packet " + listentry
            else:
                passed = True
    assert passed, "Didn't receive expected packet"

    logger.info('==== END CASE 6 ====')
    ereq, erply = summary.ping_count("CASE 6", "END CASE 6")
    logger.info("PING-REQUESTS " + str(ereq))
    logger.info("PING-REPLIES " + str(erply))
    if ereq == 0:
        assert False, "Expect ping requests!"

    print("##################################################")
    print("CASE 7 - Verify mirror shutdown")
    print("expect")
    print("     no echo-reply")
    print("     no echo-request")
    print("##################################################")
    # ---------------------------------------
    # Case 7	Remove mirror session FOO
    #
    # no mirror session FOO
    # ---------------------------------------
    logger.info('========= CASE 7 - Remove Mirror session  =========')
    assert not ops1('configure terminal', shell='vtysh')
    assert not ops1('no mirror session FOO', shell='vtysh')
    assert not ops1('end', shell='vtysh')
    vlan_result = ops1('show vlan 100')
    # Test pings AFTER mirror
    responselist = pingandsniff(0, topology)
    passed = False
    for listentry in responselist:
        logger.info(listentry)
        if "echo-reply" in listentry:
            assert False, "reply unexpected " + listentry
        if "echo-request" in listentry:
            assert False, "request unexpected " + listentry
    logger.info('==== END CASE 7 ====')
    ereq, erply = summary.ping_count("CASE 7", "END CASE 7")
    logger.info("PING-REQUESTS " + str(ereq))
    logger.info("PING-REPLIES " + str(erply))
    if ereq > 0 or erply > 0:
        assert False, "Expect zero pings!"
