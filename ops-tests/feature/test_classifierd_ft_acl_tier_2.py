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
OpenSwitch Test for ACL operations with UDP traffic.
This file consists of the following test cases:

Test1 : acl_udp_any_any_permit
Test2 : acl_udp_any_any_deny
Test3 : acl_permit_udp_hs1_hs2
Test4 : acl_deny_udp_hs1_hs2
Test5 : acl_permit_udp_prefix_len_mask
Test6 : acl_deny_udp_prefix_len_mask
Test7 : acl_permit_udp_dotted_netmask
Test8 : acl_deny_udp_dotted_netmask
Test9 : acl_permit_udp_non_contiguous_mask
Test10: acl_deny_udp_non_contiguous_mask
Test11: acl_permit_udp_dport_eq_param
Test12: acl_deny_udp_dport_eq_param
Test13: acl_deny_udp_dport_eq_param
Test14: acl_deny_udp_dport_eq_param
Test15: acl_modify_after_sending_udp_traffic
Test16: acl_deny_udp_on_multiple_ports
Test17: acl_permit_icmp_on_multiple_ports
Test18: acl_replace_with_icmp_traffic
Test19: acl_permit_any_hs1_hs2_hitcount
Test20: test_acl_permit_any_hs1_hs2_config_persistence_ten_entries
Test21: test_acl_permit_any_hs1_hs2_config_persistence_300_entries
Test22: test_acl_permit_any_hs1_hs2_config_persistence_150x2_entries
"""

from pytest import mark
from pytest import fixture
from re import findall
from re import search
from itertools import product
from topology_lib_scapy.library import ScapyThread
from topology_lib_scapy.library import send_traffic
from topology_lib_scapy.library import sniff_traffic
from datetime import datetime


from time import sleep

TOPOLOGY = """
# +-------+                    +-------+
# |       |     +--------+     |       |G
# |  hs1  <----->  ops1  <----->  hs2  |
# |       |     +--------+     |       |
# +-------+                    +-------+

# Nodes
# [image="fs-genericx86-64:latest" \
# type=openswitch name="OpenSwitch 1"] ops1
# [type=host name="Host 1" image="openswitch/ubuntuscapy:latest"] hs1
# [type=host name="Host 2" image="openswitch/ubuntuscapy:latest"] hs2
[type=openswitch name="Switch 1"] ops1
[type=host name="Host 1" image="Ubuntu"] hs1
[type=host name="Host 2" image="Ubuntu"] hs2

# Links
hs1:1 -- ops1:1
ops1:2 -- hs2:1
"""

filter_udp = "lambda p: UDP in p and p[UDP].dport == 48621 and " \
    "p[IP].src == '1.1.1.1' and p[IP].dst == '1.1.1.2'"
filter_udp_other = "lambda p: UDP in p and p[UDP].dport == 5555 and " \
    "p[IP].src == '1.1.1.1' and p[IP].dst == '1.1.1.2'"
filter_icmp = "lambda p: ICMP in p and p[IP].src == '1.1.1.1' " \
    " and p[IP].dst == '1.1.1.2'"
filter_udp_reverse = "lambda p: UDP in p and p[UDP].dport == 48621 and " \
    "p[IP].src == '1.1.1.2' and p[IP].src == '1.1.1.1'"
filter_icmp_reverse = "lambda p: ICMP in p and p[IP].src == '1.1.1.2' and " \
    "p[IP].dst == '1.1.1.1'"
port_str = '1'
timeout = 25
count = 10
filter_str = (
                "lambda p: ICMP in p and p[IP].src == '1.1.1.1' "
                "and p[IP].dst == '1.1.1.2'"
            )


@fixture(scope='module')
def configure_acl_test(request, topology):
    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    p1 = ops1.ports['1']
    p2 = ops1.ports['2']

    # Mark interfaces as enabled
    assert not ops1(
        'set interface {p1} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )
    assert not ops1(
        'set interface {p2} user_config:admin=up'.format(**locals()),
        shell='vsctl'
    )

    # Configure interfaces
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_routing()
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.no_routing()
        ctx.no_shutdown()

    ops1('show interface {p1}'.format(**locals()))
    ops1('show interface {p2}'.format(**locals()))

    hs1.send_command('service network-manager stop', shell='bash')
    hs2.send_command('service network-manager stop', shell='bash')

    hs1.libs.ip.interface('1', addr='1.1.1.1/24', up=True)
    hs2.libs.ip.interface('1', addr='1.1.1.2/24', up=True)

    with ops1.libs.vtysh.ConfigVlan('100') as ctx:
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.vlan_access(100)

    with ops1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.vlan_access(100)

    for portlbl in ['1', '2']:
        wait_until_interface_up(ops1, portlbl)

    ping = hs2.libs.ping.ping(1, '1.1.1.1')
    print(ping)

    hs1.libs.scapy.start_scapy()
    hs2.libs.scapy.start_scapy()


def configure_permit_acl(ops1, name, seq_num, proto, src_ip,
                         src_port, dst_ip, dst_port, count_str):
    """
    Configure an ACL with one permit rule
    """

    with ops1.libs.vtysh.ConfigAccessListIpTestname(name) as ctx:
        ctx.permit(
                  '',
                  seq_num, proto, src_ip, src_port,
                  dst_ip, dst_port, count_str
                  )


def configure_deny_acl(ops1, name, seq_num, proto, src_ip,
                       src_port, dst_ip, dst_port):
    """
    Configure an ACL with one deny rule
    """

    with ops1.libs.vtysh.ConfigAccessListIpTestname(name) as ctx:
        ctx.deny('', seq_num, proto, src_ip, src_port, dst_ip, dst_port)


@mark.platform_incompatible(['docker'])
def test_acl_permit_udp_any_any(configure_acl_test, topology, step):
    """
    This test adds a "1 permit udp any any" rule on interface 1.
    It then sends 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2
    """
    global filter_udp, timeout, count, port_str

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    step('1.a Configure an ACL with 1 permit udp any any rule')
    configure_permit_acl(ops1, 'test', '1', 'udp', 'any', '', 'any', '', '')
    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+permit\s+udp\s+any\s+any'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('1.b Create UDP packets')
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.2', src='1.1.1.1'")
    udp_packet = hs1.libs.scapy.udp("dport=48621")

    list_udp = [ip_packet, udp_packet]
    proto_str = 'IP/UDP'

    txthread = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list_udp, '', count,
                '', 0)
    rxthread = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_udp, count,
                port_str, timeout)

    step('1.c Send and receive udp packets on hs1 and hs2')
    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    step('1.d Verify results')
    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert (list_result[1] == '10')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.no('1')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


@mark.platform_incompatible(['docker'])
def test_acl_deny_udp_any_any(configure_acl_test, topology, step):
    """
    This test adds a "1 deny udp any any" rule on interface 1.
    It then sends 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2
    """
    global filter_udp, timeout, count, port_str

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    step('2.a Configure an ACL with 1 deny udp any any rule')
    configure_deny_acl(ops1, 'test', '1', 'udp', 'any', '', 'any', '')
    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+deny\s+udp\s+any\s+any'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('2.b Create UDP packets')
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.2', src='1.1.1.1'")
    udp_packet = hs1.libs.scapy.udp("dport=48621")

    list_udp = [ip_packet, udp_packet]
    proto_str = 'IP/UDP'

    txthread = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list_udp, '', count,
                '', 0)
    rxthread = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_udp, count,
                port_str, timeout)

    step('2.c Send and receive UDP packets on hs1 and hs2')
    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    step('2.d Verify results')
    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert (list_result[1] == '0')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.no('1')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


@mark.platform_incompatible(['docker'])
def test_acl_permit_udp_hs1_hs2(configure_acl_test, topology, step):
    """
    This test adds a "1 permit udp 1.1.1.1 1.1.1.2" rule on interface 1.
    It then sends 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_icmp, timeout, count, port_str

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    step('3.a Configure an ACL with 1 permit udp 1.1.1.1 1.1.1.2 rule')
    configure_permit_acl(ops1, 'test', '1', 'udp', '1.1.1.1', '', '1.1.1.2',
                         '', '')
    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+permit\s+udp\s+1.1.1.1\s+1.1.1.2'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('3.b Create UDP and ICMP packets')
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.2', src='1.1.1.1'")
    udp_packet = hs1.libs.scapy.udp("dport=48621")
    icmp_packet = hs1.libs.scapy.icmp()

    list_udp = [ip_packet, udp_packet]
    list_icmp = [ip_packet, icmp_packet]
    proto_str = 'IP/UDP'
    icmp_proto_str = 'IP/ICMP'

    txthread = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list_udp, '', count,
                '', 0)
    rxthread = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_udp, count,
                port_str, timeout)

    txthread_icmp = ScapyThread(
                send_traffic,
                'hs1', topology, icmp_proto_str, list_icmp, '', count,
                '', 0)
    rxthread_icmp = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_icmp, count,
                port_str, timeout)

    step('3.c Send and receive UDP traffic on hs1 and hs2')
    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    step('3.d Verify UDP results')
    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert (list_result[1] == '10')

    step('3.e Send ICMP traffic')
    rxthread_icmp.start()
    txthread_icmp.start()

    txthread_icmp.join()
    rxthread_icmp.join()

    step('3.f Verify ICMP results')
    if rxthread_icmp.outresult():
        rest_icmp, sniffcnt_icmp = rxthread_icmp.outresult().split('<Sniffed:')
        list_result_icmp = findall(r'[0-9]+', sniffcnt_icmp)
        print(list_result_icmp)

        assert (list_result_icmp[2] == '0')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.no('1')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


@mark.platform_incompatible(['docker'])
def test_acl_deny_udp_hs1_hs2(configure_acl_test, topology, step):
    """
    This test adds a "1 deny udp 1.1.1.1 1.1.1.2" rule on interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are denied on hs2. Also, it verifies that other
    protocol traffic is received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_icmp, timeout, count, port_str

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    step('4.a Configure an ACL with 1 deny udp 1.1.1.1 1.1.1.2 rule')
    configure_deny_acl(
        ops1, 'test', '1', 'udp', '1.1.1.1', '', '1.1.1.2', '')
    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+deny\s+udp\s+1.1.1.1\s+1.1.1.2'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('4.b Create UDP and ICMP packets')
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.2', src='1.1.1.1'")
    udp_packet = hs1.libs.scapy.udp("dport=48621")
    icmp_packet = hs1.libs.scapy.icmp()

    list_udp = [ip_packet, udp_packet]
    list_icmp = [ip_packet, icmp_packet]
    proto_str = 'IP/UDP'
    icmp_proto_str = 'IP/ICMP'

    txthread = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list_udp, '', count,
                '', 0)
    rxthread = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_udp, count,
                port_str, timeout)

    txthread_icmp = ScapyThread(
                send_traffic,
                'hs1', topology, icmp_proto_str, list_icmp, '', count,
                '', 0)
    rxthread_icmp = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_icmp, count,
                port_str, timeout)

    step('4.c Send and receive UDP traffic on hs1 and hs2')
    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    step('4.d Verify UDP results')
    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert (list_result[1] == '0')

    step('4.e Send ICMP traffic')
    rxthread_icmp.start()
    txthread_icmp.start()

    txthread_icmp.join()
    rxthread_icmp.join()

    step('4.f Verify ICMP results')
    if rxthread_icmp.outresult():
        rest_icmp, sniffcnt_icmp = rxthread_icmp.outresult().split('<Sniffed:')
        list_result_icmp = findall(r'[0-9]+', sniffcnt_icmp)
        print(list_result_icmp)

        assert (list_result_icmp[2] == '0')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.no('1')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


@mark.platform_incompatible(['docker'])
def test_acl_permit_udp_prefix_len_mask(configure_acl_test, topology, step):
    """
    This test adds a "1 permit udp 1.1.1.0/31 1.1.1.0/30" rule on interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_icmp, timeout, count, port_str

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    step('5.a Configure an ACL with 1 permit udp 1.1.1.0/31 1.1.1.0/30 rule')
    configure_permit_acl(ops1, 'test', '1', 'udp', '1.1.1.0/31', '',
                         '1.1.1.0/30',
                         '', '')
    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+permit\s+udp\s+1.1.1.0/255.255.255.254\s+'
       '1.1.1.0/255.255.255.252'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('5.b Create UDP and ICMP packets')
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.2', src='1.1.1.1'")
    udp_packet = hs1.libs.scapy.udp("dport=48621")
    icmp_packet = hs1.libs.scapy.icmp()

    list_udp = [ip_packet, udp_packet]
    list_icmp = [ip_packet, icmp_packet]
    proto_str = 'IP/UDP'
    icmp_proto_str = 'IP/ICMP'

    txthread = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list_udp, '', count,
                '', 0)
    rxthread = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_udp, count,
                port_str, timeout)

    txthread_icmp = ScapyThread(
                send_traffic,
                'hs1', topology, icmp_proto_str, list_icmp, '', count,
                '', 0)
    rxthread_icmp = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_icmp, count,
                port_str, timeout)

    step('5.c Send and receive UDP traffic on hs1 and hs2')
    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    step('5.d Verify UDP results')
    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert (list_result[1] == '10')

    step('5.e Send ICMP traffic')
    rxthread_icmp.start()
    txthread_icmp.start()

    txthread_icmp.join()
    rxthread_icmp.join()

    step('5.f Verify ICMP results')
    if rxthread_icmp.outresult():
        rest_icmp, sniffcnt_icmp = rxthread_icmp.outresult().split('<Sniffed:')
        list_result_icmp = findall(r'[0-9]+', sniffcnt_icmp)
        print(list_result_icmp)

        assert (list_result_icmp[2] == '0')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.no('1')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


@mark.platform_incompatible(['docker'])
def test_acl_deny_udp_prefix_len_mask(configure_acl_test, topology, step):
    """
    This test adds a "1 permit udp 1.1.1.0/31 1.1.1.0/30" rule on interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_icmp, timeout, count, port_str

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    step('6.a Configure an ACL with 1 deny udp 1.1.1.0/31 1.1.1.0/30 rule')
    configure_deny_acl(ops1, 'test', '1', 'udp', '1.1.1.0/31', '',
                       '1.1.1.0/30',
                       '')
    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+deny\s+udp\s+1.1.1.0/255.255.255.254\s+'
       '1.1.1.0/255.255.255.252'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('6.b Create UDP and ICMP packets')
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.2', src='1.1.1.1'")
    udp_packet = hs1.libs.scapy.udp("dport=48621")
    icmp_packet = hs1.libs.scapy.icmp()

    list_udp = [ip_packet, udp_packet]
    list_icmp = [ip_packet, icmp_packet]
    proto_str = 'IP/UDP'
    icmp_proto_str = 'IP/ICMP'

    txthread = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list_udp, '', count,
                '', 0)
    rxthread = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_udp, count,
                port_str, timeout)

    txthread_icmp = ScapyThread(
                send_traffic,
                'hs1', topology, icmp_proto_str, list_icmp, '', count,
                '', 0)
    rxthread_icmp = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_icmp, count,
                port_str, timeout)

    step('6.c Send and receive UDP traffic on hs1 and hs2')
    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    step('6.d Verify UDP results')
    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert (list_result[1] == '0')

    step('6.e Send ICMP traffic')
    rxthread_icmp.start()
    txthread_icmp.start()

    txthread_icmp.join()
    rxthread_icmp.join()

    step('6.f Verify ICMP results')
    if rxthread_icmp.outresult():
        rest_icmp, sniffcnt_icmp = rxthread_icmp.outresult().split('<Sniffed:')
        list_result_icmp = findall(r'[0-9]+', sniffcnt_icmp)
        print(list_result_icmp)

        assert (list_result_icmp[2] == '0')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.no('1')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


@mark.platform_incompatible(['docker'])
def test_acl_permit_udp_dotted_netmask(configure_acl_test, topology, step):
    """
    This test adds a "1 permit udp 1.1.1.0/255.255.255.254
    1.1.1.0/255.255.255.252" rule on interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_icmp, timeout, count, port_str

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    step('7.a Configure an ACL with 1 permit udp 1.1.1.0/255.255.255.254'
         ' 1.1.1.0/255.255.255.252 rule')
    configure_permit_acl(
        ops1, 'test', '1', 'udp', 'any', '',
        '1.1.1.0/255.255.255.252', '', '')
    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+permit\s+udp\s+any\s+'
       '1.1.1.0/255.255.255.252'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('7.b Create UDP and ICMP packets')
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.2', src='1.1.1.1'")
    udp_packet = hs1.libs.scapy.udp("dport=48621")
    icmp_packet = hs1.libs.scapy.icmp()

    list_udp = [ip_packet, udp_packet]
    list_icmp = [ip_packet, icmp_packet]
    proto_str = 'IP/UDP'
    icmp_proto_str = 'IP/ICMP'

    txthread = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list_udp, '', count,
                '', 0)
    rxthread = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_udp, count,
                port_str, timeout)

    txthread_icmp = ScapyThread(
                send_traffic,
                'hs1', topology, icmp_proto_str, list_icmp, '', count,
                '', 0)
    rxthread_icmp = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_icmp, count,
                port_str, timeout)

    step('7.c Send and receive UDP traffic on hs1 and hs2')
    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    step('7.d Verify UDP results')
    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert (list_result[1] == '10')

    step('7.e Send ICMP traffic')
    rxthread_icmp.start()
    txthread_icmp.start()

    txthread_icmp.join()
    rxthread_icmp.join()

    step('7.f Verify ICMP results')
    if rxthread_icmp.outresult():
        rest_icmp, sniffcnt_icmp = rxthread_icmp.outresult().split('<Sniffed:')
        list_result_icmp = findall(r'[0-9]+', sniffcnt_icmp)
        print(list_result_icmp)

        assert (list_result_icmp[2] == '0')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.no('1')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


@mark.platform_incompatible(['docker'])
def test_acl_deny_udp_dotted_netmask(configure_acl_test, topology, step):
    """
    This test adds a "1 permit udp 1.1.1.0/255.255.255.254
    1.1.1.0/255.255.255.252" rule on interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_icmp, timeout, count, port_str

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    step('8.a Configure an ACL with 1 deny udp 1.1.1.0/255.255.255.254 '
         '1.1.1.0/255.255.255.252 rule')
    configure_deny_acl(ops1, 'test', '1', 'udp', '1.1.1.0/255.255.255.254', '',
                       '1.1.1.0/255.255.255.252',
                       '')
    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+deny\s+udp\s+1.1.1.0/255.255.255.254\s+'
       '1.1.1.0/255.255.255.252'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('8.b Create UDP and ICMP packets')
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.2', src='1.1.1.1'")
    udp_packet = hs1.libs.scapy.udp("dport=48621")
    icmp_packet = hs1.libs.scapy.icmp()

    list_udp = [ip_packet, udp_packet]
    list_icmp = [ip_packet, icmp_packet]
    proto_str = 'IP/UDP'
    icmp_proto_str = 'IP/ICMP'

    txthread = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list_udp, '', count,
                '', 0)
    rxthread = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_udp, count,
                port_str, timeout)

    txthread_icmp = ScapyThread(
                send_traffic,
                'hs1', topology, icmp_proto_str, list_icmp, '', count,
                '', 0)
    rxthread_icmp = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_icmp, count,
                port_str, timeout)

    step('8.c Send and receive udp traffic on hs1 and hs2')
    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    step('8.d Verify UDP results')
    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert (list_result[1] == '0')

    step('8.e Send ICMP traffic')
    rxthread_icmp.start()
    txthread_icmp.start()

    txthread_icmp.join()
    rxthread_icmp.join()

    step('8.f Verify ICMP results')
    if rxthread_icmp.outresult():
        rest_icmp, sniffcnt_icmp = rxthread_icmp.outresult().split('<Sniffed:')
        list_result_icmp = findall(r'[0-9]+', sniffcnt_icmp)
        print(list_result_icmp)

        assert (list_result_icmp[2] == '0')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.no('1')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


@mark.platform_incompatible(['docker'])
def test_acl_permit_udp_non_contiguous_mask(
                                      configure_acl_test, topology, step):
    """
    This test adds a "1 permit udp 1.1.1.0/255.255.255.254
    1.1.1.0/255.255.255.252" rule on interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_icmp, timeout, count, port_str

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    step('9.a Configure an ACL with 1 permit udp 1.0.1.0/255.0.255.254'
         ' any rule')
    configure_permit_acl(
        ops1, 'test', '1', 'udp', '1.0.1.0/255.0.255.254', '',
        'any', '', '')
    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+permit\s+udp\s+1.0.1.0/255.0.255.254\s+'
       'any'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('9.b Create udp packets')
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.2', src='1.1.1.1'")
    udp_packet = hs1.libs.scapy.udp("dport=48621")
    icmp_packet = hs1.libs.scapy.icmp()

    list_udp = [ip_packet, udp_packet]
    list_icmp = [ip_packet, icmp_packet]
    proto_str = 'IP/UDP'
    icmp_proto_str = 'IP/ICMP'

    txthread = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list_udp, '', count,
                '', 0)
    rxthread = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_udp, count,
                port_str, timeout)

    txthread_icmp = ScapyThread(
                send_traffic,
                'hs1', topology, icmp_proto_str, list_icmp, '', count,
                '', 0)
    rxthread_icmp = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_icmp, count,
                port_str, timeout)

    step('9.c Send and receive UDP traffic on hs1 and hs2')
    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    step('9.d Verify UDP results')
    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert (list_result[1] == '10')

    step('9.e Send ICMP traffic')
    rxthread_icmp.start()
    txthread_icmp.start()

    txthread_icmp.join()
    rxthread_icmp.join()

    step('9.f Verify ICMP results')
    if rxthread_icmp.outresult():
        rest_icmp, sniffcnt_icmp = rxthread_icmp.outresult().split('<Sniffed:')
        list_result_icmp = findall(r'[0-9]+', sniffcnt_icmp)
        print(list_result_icmp)

        assert (list_result_icmp[2] == '0')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.no('1')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


@mark.platform_incompatible(['docker'])
def test_acl_deny_udp_non_contiguous_mask(configure_acl_test, topology, step):
    """
    This test adds a "1 deny udp 1.1.1.0/255.255.255.254
    any" rule on interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_icmp, timeout, count, port_str

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    step('10.a Configure an ACL with 1 deny udp 1.0.1.0/255.255.255.254 '
         'any rule')
    configure_deny_acl(ops1, 'test', '1', 'udp', '1.0.1.0/255.0.255.0', '',
                       'any',
                       '')
    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+deny\s+udp\s+1.0.1.0/255.0.255.0\s+'
       'any'.format(**locals()), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('10.b Create UDP and ICMP packets')
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.2', src='1.1.1.1'")
    udp_packet = hs1.libs.scapy.udp("dport=48621")
    icmp_packet = hs1.libs.scapy.icmp()

    list_udp = [ip_packet, udp_packet]
    list_icmp = [ip_packet, icmp_packet]
    proto_str = 'IP/UDP'
    icmp_proto_str = 'IP/ICMP'

    txthread = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list_udp, '', count,
                '', 0)
    rxthread = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_udp, count,
                port_str, timeout)

    txthread_icmp = ScapyThread(
                send_traffic,
                'hs1', topology, icmp_proto_str, list_icmp, '', count,
                '', 0)
    rxthread_icmp = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_icmp, count,
                port_str, timeout)

    step('10.c Send and receive UDP traffic on hs1 and hs2')
    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    step('10.d Verify UDP results')
    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert (list_result[1] == '0')

    step('10.e Send ICMP traffic')
    rxthread_icmp.start()
    txthread_icmp.start()

    txthread_icmp.join()
    rxthread_icmp.join()

    step('10.f Verify ICMP results')
    if rxthread_icmp.outresult():
        rest_icmp, sniffcnt_icmp = rxthread_icmp.outresult().split('<Sniffed:')
        list_result_icmp = findall(r'[0-9]+', sniffcnt_icmp)
        print(list_result_icmp)

        assert (list_result_icmp[2] == '0')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.no('1')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


@mark.platform_incompatible(['docker'])
def test_acl_permit_udp_dport_eq_param(configure_acl_test, topology, step):
    """
    This test adds a "1 permit udp 1.1.1.1 1.1.1.2 eq 48621" rule on
    interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_udp_other, timeout, count, port_str

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    step('11.a Configure an ACL with 1 permit udp 1.1.1.1 1.1.1.2 '
         'eq 48621 rule')
    configure_permit_acl(ops1, 'test', '1', 'udp', '1.1.1.1', '',
                         '1.1.1.2',
                         'eq 48621', '')
    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+permit\s+udp\s+1.1.1.1\s+'
       '1.1.1.2 eq 48621'.format(**locals()), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('11.b Create UDP packets')
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.2', src='1.1.1.1'")
    udp_packet = hs1.libs.scapy.udp("dport=48621")
    udp_packet_other_port = hs1.libs.scapy.udp("dport=5555")

    list_udp = [ip_packet, udp_packet]
    list_udp_other = [ip_packet, udp_packet_other_port]
    proto_str = 'IP/UDP'

    txthread = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list_udp, '', count,
                '', 0)
    rxthread = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_udp, count,
                port_str, timeout)

    txthread_udp_other = ScapyThread(
                        send_traffic,
                        'hs1', topology, proto_str, list_udp_other, '', count,
                        '', 0)
    rxthread_udp_other = ScapyThread(
                        sniff_traffic,
                        'hs2', topology, '', [], filter_udp_other, count,
                        port_str, timeout)

    step('11.c Send and receive UDP traffic on hs1 and hs2')
    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    step('11.d Verify UDP results')
    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert (list_result[1] == '10')

    step('11.e Send UDP traffic to a different port')
    rxthread_udp_other.start()
    txthread_udp_other.start()

    txthread_udp_other.join()
    rxthread_udp_other.join()

    step('11.f Verify Other UDP results')
    if rxthread_udp_other.outresult():
        rest_udp_other, sniffcnt_udp_other = rxthread_udp_other.outresult(
            ).split('<Sniffed:')
        list_result_udp_other = findall(r'[0-9]+', sniffcnt_udp_other)
        print(list_result_udp_other)

        assert (list_result_udp_other[1] == '0')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.no('1')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


@mark.platform_incompatible(['docker'])
def test_acl_deny_udp_dport_eq_param(configure_acl_test, topology, step):
    """
    This test adds a "1 deny udp 1.1.1.1 1.1.1.2 eq 48621" rule on
    interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_udp_other, timeout, count, port_str

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    step('12.a Configure an ACL with 1 permit udp 1.1.1.1 1.1.1.2 eq 48621 '
         'rule')
    configure_deny_acl(ops1, 'test', '1', 'udp', '1.1.1.1', '',
                       '1.1.1.2', 'eq 48621')
    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+deny\s+udp\s+1.1.1.1\s+'
       '1.1.1.2 eq 48621'.format(**locals()), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('12.b Create UDP packets')
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.2', src='1.1.1.1'")
    udp_packet = hs1.libs.scapy.udp("dport=48621")
    udp_packet_other_port = hs1.libs.scapy.udp("dport=5555")

    list_udp = [ip_packet, udp_packet]
    list_udp_other = [ip_packet, udp_packet_other_port]
    proto_str = 'IP/UDP'

    txthread = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list_udp, '', count,
                '', 0)
    rxthread = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_udp, count,
                port_str, timeout)

    txthread_udp_other = ScapyThread(
                        send_traffic,
                        'hs1', topology, proto_str, list_udp_other, '', count,
                        '', 0)
    rxthread_udp_other = ScapyThread(
                        sniff_traffic,
                        'hs2', topology, '', [], filter_udp_other, count,
                        port_str, timeout)

    step('12.c Send and receive UDP traffic on hs1 and hs2')
    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    step('12.d Verify UDP results')
    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert (list_result[1] == '0')

    step('12.e Send UDP traffic to a different port')
    rxthread_udp_other.start()
    txthread_udp_other.start()

    txthread_udp_other.join()
    rxthread_udp_other.join()

    step('12.f Verify Other UDP results')
    if rxthread_udp_other.outresult():
        rest_udp_other, sniffcnt_udp_other = (rxthread_udp_other.outresult()
                                              .split('<Sniffed:'))
        list_result_udp_other = findall(r'[0-9]+', sniffcnt_udp_other)
        print(list_result_udp_other)

        assert (list_result_udp_other[1] == '0')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.no('1')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


@mark.platform_incompatible(['docker'])
def test_acl_permit_udp_sport_eq_param(configure_acl_test, topology, step):
    """
    This test adds a "1 permit udp 1.1.1.1 eq 5555 1.1.1.2" rule on
    interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_udp_other, timeout, count, port_str

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    step('13.a Configure an ACL with 1 permit udp 1.1.1.1 eq 5555 '
         '1.1.1.2 rule')
    configure_permit_acl(ops1, 'test', '1', 'udp', '1.1.1.1', 'eq 5555',
                         '1.1.1.2',
                         '', '')
    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+permit\s+udp\s+1.1.1.1 eq 5555\s+'
       '1.1.1.2'.format(**locals()), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('13.b Create UDP packets')
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.2', src='1.1.1.1'")
    udp_packet = hs1.libs.scapy.udp()
    udp_packet['dport'] = 48621
    udp_packet['sport'] = 5555
    udp_packet_other_port = hs1.libs.scapy.udp()
    udp_packet_other_port['dport'] = 5555
    udp_packet_other_port['sport'] = 1000

    list_udp = [ip_packet, udp_packet]
    list_udp_other = [ip_packet, udp_packet_other_port]
    proto_str = 'IP/UDP'

    txthread = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list_udp, '', count,
                '', 0)
    rxthread = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_udp, count,
                port_str, timeout)

    txthread_udp_other = ScapyThread(
                        send_traffic,
                        'hs1', topology, proto_str, list_udp_other, '', count,
                        '', 0)
    rxthread_udp_other = ScapyThread(
                        sniff_traffic,
                        'hs2', topology, '', [], filter_udp_other, count,
                        port_str, timeout)

    step('13.c Send and receive udp traffic on hs1 and hs2')
    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    step('13.d Verify UDP results')
    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert (list_result[1] == '10')

    step('13.e Send UDP traffic to a different port')
    rxthread_udp_other.start()
    txthread_udp_other.start()

    txthread_udp_other.join()
    rxthread_udp_other.join()

    step('13.f Verify Other UDP results')
    if rxthread_udp_other.outresult():
        rest_udp_other, sniffcnt_udp_other = rxthread_udp_other.outresult(
            ).split('<Sniffed:')
        list_result_udp_other = findall(r'[0-9]+', sniffcnt_udp_other)
        print(list_result_udp_other)

        assert (list_result_udp_other[1] == '0')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.no('1')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


@mark.platform_incompatible(['docker'])
def test_acl_deny_udp_sport_eq_param(configure_acl_test, topology, step):
    """
    This test adds a "1 deny udp 1.1.1.1 eq 5555 1.1.1.2" rule on
    interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_udp_other, timeout, count, port_str

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    step('14.a Configure an ACL with 1 permit udp 1.1.1.1 eq 5555 '
         ' 1.1.1.2 rule')
    configure_deny_acl(ops1, 'test', '1', 'udp', '1.1.1.1', 'eq 5555',
                       '1.1.1.2', '')
    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+deny\s+udp\s+1.1.1.1 eq 5555\s+'
       '1.1.1.2'.format(**locals()), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('14.b Create udp packets')
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.2', src='1.1.1.1'")
    udp_packet = hs1.libs.scapy.udp()
    udp_packet['dport'] = 48621
    udp_packet['sport'] = 5555
    udp_packet_other_port = hs1.libs.scapy.udp()
    udp_packet_other_port['dport'] = 5555
    udp_packet_other_port['sport'] = 1000

    list_udp = [ip_packet, udp_packet]
    list_udp_other = [ip_packet, udp_packet_other_port]
    proto_str = 'IP/UDP'

    txthread = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list_udp, '', count,
                '', 0)
    rxthread = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_udp, count,
                port_str, timeout)

    txthread_udp_other = ScapyThread(
                        send_traffic,
                        'hs1', topology, proto_str, list_udp_other, '', count,
                        '', 0)
    rxthread_udp_other = ScapyThread(
                        sniff_traffic,
                        'hs2', topology, '', [], filter_udp_other, count,
                        port_str, timeout)

    step('14.c Send and receive UDP traffic on hs1 and hs2')
    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    step('14.d Verify UDP results')
    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert (list_result[1] == '0')

    step('14.e Send UDP traffic to a different port')
    rxthread_udp_other.start()
    txthread_udp_other.start()

    txthread_udp_other.join()
    rxthread_udp_other.join()

    step('14.f Verify Other UDP results')
    if rxthread_udp_other.outresult():
        rest_udp_other, sniffcnt_udp_other = (rxthread_udp_other.outresult()
                                              .split('<Sniffed:'))
        list_result_udp_other = findall(r'[0-9]+', sniffcnt_udp_other)
        print(list_result_udp_other)

        assert (list_result_udp_other[1] == '0')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.no('1')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


@mark.platform_incompatible(['docker'])
def test_acl_modify_after_sending_udp_traffic(
                                        configure_acl_test, topology, step):
    """
    This test sends some traffic after applying an ACL to interface 1.
    It then stops traffic, modifies the ACL and verifies that traffic behavior
    complies with the applied ACL
    """
    global filter_udp, filter_icmp, count, timeout, port_str

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    step('15.a Configure an ACL with 1 permit udp 1.1.1.1 1.1.1.2 rule')
    configure_permit_acl(
                     ops1, 'test', '1', 'udp', '1.1.1.1', '',
                     '1.1.1.2', '', '')
    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+permit\s+udp\s+1.1.1.1\s+'
       '1.1.1.2'.format(**locals()), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('15.b Create UDP and ICMP packets from hs1 to hs2')
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.2', src='1.1.1.1'")
    udp_packet = hs1.libs.scapy.udp("dport=48621")
    icmp_packet = hs1.libs.scapy.icmp()

    list_udp = [ip_packet, udp_packet]
    list_icmp = [ip_packet, icmp_packet]
    proto_str = 'IP/UDP'
    icmp_proto_str = 'IP/ICMP'

    txthread = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list_udp, '', count,
                '', 0)
    rxthread = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_udp, count,
                port_str, timeout)

    txthread_icmp = ScapyThread(
                send_traffic,
                'hs1', topology, icmp_proto_str, list_icmp, '', count,
                '', 0)
    rxthread_icmp = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_icmp, count,
                port_str, timeout)

    txthread_udp_repeat = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list_udp, '', count,
                '', 0)
    rxthread_udp_repeat = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_udp, count,
                port_str, timeout)

    txthread_icmp_repeat = ScapyThread(
                send_traffic,
                'hs1', topology, icmp_proto_str, list_icmp, '', count,
                '', 0)
    rxthread_icmp_repeat = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_icmp, count,
                port_str, timeout)

    step('15.c Send UDP packets')
    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    step('15.d Verify UDP results')
    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert (list_result[1] == '10')

    step('15.e Send ICMP packets')
    rxthread_icmp.start()
    txthread_icmp.start()

    txthread_icmp.join()
    rxthread_icmp.join()

    step('15.f Verify ICMP results')
    if rxthread_icmp.outresult():
        rest, sniffcnt = rxthread_icmp.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert(list_result[2] == '0')

    step('15.g Modify ACL with 1 deny udp 1.1.1.1 1.1.1.2 rule')
    configure_deny_acl(ops1, 'test', '1', 'udp', '1.1.1.1', '',
                       '1.1.1.2', '')
    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+deny\s+udp\s+1.1.1.1\s+'
       '1.1.1.2'.format(**locals()), test1_result
    )

    step('15.h Send UDP packets')
    rxthread_udp_repeat.start()
    txthread_udp_repeat.start()

    txthread_udp_repeat.join()
    rxthread_udp_repeat.join()

    step('15.i Verify UDP results')
    if rxthread_udp_repeat.outresult():
        rest, sniffcnt = rxthread_udp_repeat.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert (list_result[1] == '0')

    step('15.j Send ICMP packets')
    rxthread_icmp_repeat.start()
    txthread_icmp_repeat.start()

    txthread_icmp_repeat.join()
    rxthread_icmp_repeat.join()

    step('15.k Verify ICMP results')
    if rxthread_icmp_repeat.outresult():
        rest, sniffcnt = rxthread_icmp_repeat.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert(list_result[2] == '0')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.no('1')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test\s+)'.format(
                                         **locals()
                                     ), test1_result
         )


@mark.platform_incompatible(['docker'])
def test_acl_deny_udp_on_multiple_ports(configure_acl_test, topology, step):
    """
    This tests applies a deny rule for UDP and permit rule for ICMP on
    interfaces 1 and 2. Then, it passes UDP traffic in both directions
    and verifies that traffic is blocked. Next, it passes ICMP traffic
    and verifies that the responses are received.
    """
    global filter_udp, filter_icmp, filter_udp_reverse, filter_icmp_reverse
    global count, timeout, port_str

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    step('16.a Configure a deny udp and permit icmp rule on ACL test')
    configure_deny_acl(ops1, 'test', '1', 'udp', '1.1.1.1', '',
                       '1.1.1.2', '')
    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+deny\s+udp\s+1.1.1.1\s+'
       '1.1.1.2'.format(**locals()), test1_result
    )

    configure_permit_acl(ops1, 'test', '2', 'icmp', 'any', '', 'any', '', '')
    test1_result = ops1('show run')

    assert search(
       ''
       r'2\s+permit\s+icmp\s+any\s+'
       'any'.format(**locals()), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('16.b Create UDP and ICMP packets')
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.2', src='1.1.1.1'")
    ip_packet_reverse = hs2.libs.scapy.ip("dst='1.1.1.1', src='1.1.1.2'")
    udp_packet = hs1.libs.scapy.udp("dport=48621")
    icmp_packet = hs1.libs.scapy.icmp()

    list_udp = [ip_packet, udp_packet]
    list_icmp = [ip_packet, icmp_packet]
    list_udp_reverse = [ip_packet_reverse, udp_packet]
    list_icmp_reverse = [ip_packet_reverse, icmp_packet]
    proto_str = 'IP/UDP'
    icmp_proto_str = 'IP/ICMP'

    txthread = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list_udp, '', count,
                '', 0)
    rxthread = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_udp, count,
                port_str, timeout)

    txthread_icmp = ScapyThread(
                send_traffic,
                'hs1', topology, icmp_proto_str, list_icmp, '', count,
                '', 0)
    rxthread_icmp = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_icmp, count,
                port_str, timeout)

    txthread_udp_reverse = ScapyThread(
                            send_traffic,
                            'hs2', topology, proto_str, list_udp, '', count,
                            '', 0)
    rxthread_udp_reverse = ScapyThread(
                            sniff_traffic,
                            'hs1', topology, '', [], filter_udp_reverse, count,
                            port_str, timeout)

    txthread_icmp_reverse = ScapyThread(
                            send_traffic,
                            'hs2', topology, icmp_proto_str, list_icmp_reverse,
                            '',
                            count, '', 0)
    rxthread_icmp_reverse = ScapyThread(
                            sniff_traffic,
                            'hs1', topology, '', [], filter_icmp_reverse,
                            count, port_str, timeout)

    step('16.c Send UDP packets from hs1 to hs2')
    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    step('16.d Verify results')
    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert(list_result[1] == '0')

    step('16.e Send UDP packets from hs2 to hs1')
    rxthread_udp_reverse.start()
    txthread_udp_reverse.start()

    txthread_udp_reverse.join()
    rxthread_udp_reverse.join()

    step('16.f Verify results')
    if rxthread_udp_reverse.outresult():
        rest, sniffcnt = rxthread_udp_reverse.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert(list_result[1] == '0')

    step('16.g Send ICMP traffic from hs1 to hs2')
    rxthread_icmp.start()
    txthread_icmp.start()

    txthread_icmp.join()
    rxthread_icmp.join()

    step('16.h Verify results')
    if rxthread_icmp.outresult():
        rest, sniffcnt = rxthread_icmp.outresult().split('<Sniffed')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert(list_result[2] == '10')

    step('16.i Send ICMP traffic from hs2 to hs1')
    rxthread_icmp_reverse.start()
    txthread_icmp_reverse.start()

    txthread_icmp_reverse.join()
    rxthread_icmp_reverse.join()

    step('16.j Verify results')
    if rxthread_icmp_reverse.outresult():
        rest, sniffcnt = rxthread_icmp_reverse.outresult().split('<Sniffed')
        list_result = findall(r'[0-9]+', sniffcnt)
        print(list_result)

        assert(list_result[2] == '10')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.no('1')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test\s+)'.format(
                                         **locals()
                                     ), test1_result
         )


@mark.platform_incompatible(['docker'])
def test_acl_permit_icmp_on_multiple_ports(configure_acl_test, topology, step):
    """
    This test sends ICMP traffic from hs1 to hs2 after applying a permit
    ACL to interface 1. After it verifies that hs2 receives 10 packets,
    it sends traffic in the reverse direction and verifies that traffic
    behavior complies with the applied permit ACL
    """

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.permit(
            '', '11', 'icmp', '1.1.1.1', '',
            '1.1.1.2', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'11\s+permit\s+icmp\s+1\.1\.1\.1'
       '\s+1\.1\.1\.2'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.permit(
            '', '12', 'icmp', '1.1.1.2', '',
            '1.1.1.1', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'12\s+permit\s+icmp\s+1\.1\.1\.2'
       '\s+1\.1\.1\.1'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.2', src='1.1.1.1'")
    icmp_packet = hs1.libs.scapy.icmp()

    list1 = [ip_packet, icmp_packet]
    proto_str = 'IP/ICMP'
    port_str = '1'
    timeout = 25
    count = 10

    txthread = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list1, '', count, '', 0)

    rxthread = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_icmp, count, port_str, timeout)

    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)

        assert (list_result[2] == '10')

    step('Create packets')
    ip_packet = hs2.libs.scapy.ip("dst='1.1.1.1', src='1.1.1.2'")
    icmp_packet = hs2.libs.scapy.icmp()

    list1 = [ip_packet, icmp_packet]
    proto_str = 'IP/ICMP'
    port_str = '1'
    timeout = 25
    count = 10

    txthread = ScapyThread(
                send_traffic,
                'hs2', topology, proto_str, list1, '', count, '', 0)

    rxthread = ScapyThread(
                sniff_traffic,
                'hs1', topology, '', [], filter_icmp_reverse, count, port_str,
                timeout)

    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)

        assert (list_result[2] == '10')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.no('12')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.no('11')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


@mark.platform_incompatible(['docker'])
def test_acl_replace_with_icmp_traffic(configure_acl_test, topology, step):
    """
    This test sends 10 ICMP packets from hs1 to hs2 with an ACL applied
    on interface 1. Verifies that the packets have been received on hs2.
    It then replaces this ACL with a deny ACL and verifies that no traffic
    is seen on hs2.
    """

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.permit(
            '', '1', 'icmp', '1.1.1.1', '', '1.1.1.2', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+permit\s+icmp\s+1\.1\.1\.1'
       '\s+1\.1\.1\.2'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step("Create ICMP packets")
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.2', src='1.1.1.1'")
    icmp_packet = hs1.libs.scapy.icmp()

    list1 = [ip_packet, icmp_packet]
    proto_str = 'IP/ICMP'
    port_str = '1'
    timeout = 25
    count = 10

    txthread = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list1, '', count, '', 0)

    rxthread = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_icmp, count, port_str, timeout)

    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)

        assert (list_result[2] == '10')

    step("Create a deny ACL")
    configure_deny_acl(
        ops1, 'test2', '1', 'icmp', '1.1.1.1', '', '1.1.1.2', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+deny\s+icmp\s+1\.1\.1\.1'
       '\s+1\.1\.1\.2'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test2')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test2\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step("Send ICMP traffic again")
    txthread_icmp = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list1, '', count, '', 0)

    rxthread_icmp = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_icmp, count, port_str, timeout)

    rxthread_icmp.start()
    txthread_icmp.start()

    txthread_icmp.join()
    rxthread_icmp.join()

    if rxthread_icmp.outresult():
        rest, sniffcnt = rxthread_icmp.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)

        assert (list_result[2] == '0')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test\s+)'.format(
                                         **locals()
                                     ), test1_result
    )

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test2')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test2\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


@mark.platform_incompatible(['docker'])
def test_acl_permit_any_hs1_hs2_hitcount(configure_acl_test, topology, step):
    """
    This test adds a "50 permit any 10.0.10.1 10.0.10.2 count" rule on
    interface 1. It then sends 10 ICMP packets from hs1 to hs2 and verifies
    that 10 ICMP packets are received on hs2 and the hitcount equals 10
    """

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.permit('', '50', 'icmp', '1.1.1.1', '', '1.1.1.2', '', 'count')

    test1_result = ops1('show run')

    assert search(
       ''
       r'50\s+permit\s+icmp\s+1\.1\.1\.1'
       '\s+1\.1\.1\.2 count'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    show_interface_re = (
        r'(?P<interface>\d+)\s+(?P<rule_applied>apply)'
    )

    interface_info, rest, *misc = test1_result.split(
                        'apply access-list ip test in'
                                    )

    interface_line = findall(r'interface\s+\d+', interface_info)[-1]
    interface_num = search('(?<=interface )\d+', interface_line).group()

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step("Create ICMP packets")
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.2', src='1.1.1.1'")
    icmp_packet = hs1.libs.scapy.icmp()

    list1 = [ip_packet, icmp_packet]
    proto_str = 'IP/ICMP'
    port_str = '1'
    timeout = 25
    count = 10

    txthread = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list1, '', count, '', 0)

    rxthread = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_icmp, count, port_str,
                timeout)

    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)

        assert (list_result[2] == '10')

    # delay added to retrieve correct hitcount
    sleep(20)

    hit_dict = ops1.libs.vtysh.show_access_list_hitcounts_ip_interface(
                             'test', interface_num)

    for rule, count in hit_dict.items():
        print(rule, count)

    assert(hit_dict['50 permit icmp 1.1.1.1 1.1.1.2 count'] == '10')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test') as ctx:
        ctx.no('50')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test')


@mark.platform_incompatible(['docker'])
def test_acl_permit_any_hs1_hs2_config_persistence_ten_entries(
                                    configure_acl_test, topology, step
                                    ):
    """
    This test adds a sequence of 10 " permit any 1.1.1.1 1.1.1.2 count"
    rules on interface 1. It then sends 10 ICMP packets from hs1 to hs2
    and verifies that configuration is persisted
    """

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    seq = 0
    ipaddr = ['1.1.1.1', '1.1.1.2', 'any', '10.0.10.3', '10.0.10.4',
              '10.0.10.7', '10.0.10.5', '10.0.10.6', '10.0.10.1', '10.0.10.2']
    protos = ['icmp', 'udp', 'tcp', 'sctp', 'igmp', 'pim', 'gre', 'ah', 'esp',
              'any']

    for (x, y) in zip(ipaddr, protos):
        seq = seq + 1
        test_multiple_aces(
                    configure_permit_acl,
                    (ops1, 'test', seq, y, x, '', 'any', '', 'count')
                    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    interface_info, rest, *misc = test1_result.split(
                        'apply access-list ip test in'
                                    )

    interface_line = findall(r'interface\s+\d+', interface_info)[-1]
    interface_num = search('(?<=interface )\d+', interface_line).group()

    create_and_verify_traffic(topology, hs1, hs2)

    # delay added to retrieve correct hitcount
    sleep(20)

    hit_dict = ops1.libs.vtysh.show_access_list_hitcounts_ip_interface(
                             'test', interface_num)

    for rule, count in hit_dict.items():
        print(rule, count)

    assert(hit_dict['1 permit icmp 1.1.1.1 any count '] == '10')

    ops1._shells['vtysh']._timeout = 1500
    ops1.libs.vtysh.copy_running_config_startup_config()

    run_res_before_boot = ops1.libs.vtysh.show_running_config()
    start_res_before_boot = ops1.libs.vtysh.show_startup_config()
    assert(run_res_before_boot == start_res_before_boot)

    sleep(60)
    print("Rebooting Switch")
    reboot_switch(ops1, shell="vtysh")
    sleep(60)

    run_res_after_boot = ops1.libs.vtysh.show_running_config()
    assert(run_res_before_boot == run_res_after_boot)

    start_res_after_boot = ops1.libs.vtysh.show_startup_config()
    assert(run_res_after_boot == start_res_after_boot)

    test2_result = ops1('show run')

    interface_info, rest, *misc = test2_result.split(
                        'apply access-list ip test in'
                                    )

    interface_line = findall(r'interface\s+\d+', interface_info)[-1]
    interface_num = search('(?<=interface )\d+', interface_line).group()

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test2_result
    )

    create_and_verify_traffic(topology, hs1, hs2)

    # delay added to retrieve correct hitcount
    sleep(20)

    hit_dict = ops1.libs.vtysh.show_access_list_hitcounts_ip_interface(
                             'test', interface_num)

    for rule, count in hit_dict.items():
        print(rule, count)

    assert(hit_dict['1 permit icmp 1.1.1.1 any count '] == '10')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test')


@mark.platform_incompatible(['docker'])
def test_acl_permit_any_hs1_hs2_config_persistence_300_entries(
                                    configure_acl_test, topology, step
                                    ):
    """
    This test adds a sequence of 300
    rules on interface 1. It then sends 10 ICMP packets from hs1 to hs2
    and verifies that configuration is persisted
    """

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    seq = 0
    ipaddr = ['1.1.1.1', '1.1.1.2', 'any', '10.0.10.3', '10.0.10.4',
              '10.0.10.1', '10.0.10.5', '10.0.10.6', '10.0.10.2', '1.1.1.3',
              '10.0.10.7', '10.0.10.8', '10.0.10.9', '1.1.1.10',
              '1.1.1.11', '1.1.1.4', '1.1.1.12', '1.1.1.5', '1.1.1.6',
              '1.1.1.7']

    protos = ['icmp', 'udp', 'tcp', 'sctp', 'igmp', 'pim', 'gre', 'ah',
              'esp', 'any', 'icmp', 'udp', 'tcp', 'sctp', 'igmp']

    for (x, y) in product(ipaddr, protos):
        seq = seq + 1
        test_multiple_aces(
                    configure_permit_acl,
                    (ops1, 'test', seq, y, x, '', 'any', '', 'count')
                    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    interface_info, rest, *misc = test1_result.split(
                        'apply access-list ip test in'
                                    )

    interface_line = findall(r'interface\s+\d+', interface_info)[-1]
    interface_num = search('(?<=interface )\d+', interface_line).group()

    create_and_verify_traffic(topology, hs1, hs2)

    # delay added to retrieve correct hitcount
    sleep(20)

    hit_dict = ops1.libs.vtysh.show_access_list_hitcounts_ip_interface(
                             'test', interface_num)

    for rule, count in hit_dict.items():
        print(rule, count)

    assert(hit_dict['1 permit icmp 1.1.1.1 any count '] == '10')

    ops1._shells['vtysh']._timeout = 1500
    ops1.libs.vtysh.copy_running_config_startup_config()
    run_res_before_boot = ops1.libs.vtysh.show_running_config()

    start_res_before_boot = ops1.libs.vtysh.show_startup_config()
    assert(run_res_before_boot == start_res_before_boot)

    sleep(60)
    print("Rebooting Switch")
    reboot_switch(ops1, shell="vtysh")
    sleep(60)

    run_res_after_boot = ops1.libs.vtysh.show_running_config()
    assert(run_res_before_boot == run_res_after_boot)

    start_res_after_boot = ops1.libs.vtysh.show_startup_config()
    assert(run_res_after_boot == start_res_after_boot)

    test2_result = ops1('show run')

    interface_info, rest, *misc = test2_result.split(
                        'apply access-list ip test in'
                                    )

    interface_line = findall(r'interface\s+\d+', interface_info)[-1]
    interface_num = search('(?<=interface )\d+', interface_line).group()

    assert search(
        r'(access-list\s+ip\s+test\s+\in)'.format(
                                          **locals()
                                        ), test2_result
    )

    create_and_verify_traffic(topology, hs1, hs2)

    # delay added to retrieve correct hitcount
    sleep(20)

    hit_dict = ops1.libs.vtysh.show_access_list_hitcounts_ip_interface(
                             'test', interface_num)

    for rule, count in hit_dict.items():
        print(rule, count)

    assert(hit_dict['1 permit icmp 1.1.1.1 any count '] == '10')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test')


@mark.platform_incompatible(['docker'])
def test_acl_permit_any_hs1_hs2_config_persistence_150x2_entries(
                                    configure_acl_test, topology, step
                                    ):
    """
    This test adds a sequence of 150 rules each on interface 1 and 2. It
    then sends 10 ICMP packets from hs1 to hs2 and verifies that
    configuration is persisted
    """

    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None
    assert hs1 is not None
    assert hs2 is not None

    seq = 0
    ipaddr1 = ['1.1.1.1', '1.1.1.2', 'any', '10.0.10.3', '10.0.10.4',
               '10.0.10.1', '10.0.10.5', '10.0.10.6', '10.0.10.2', '1.1.1.3',
               '10.0.10.7', '10.0.10.8', '10.0.10.9', '1.1.1.10',
               '1.1.1.11']

    protos1 = ['icmp', 'udp', 'tcp', 'sctp', 'igmp', 'pim', 'gre', 'ah',
               'esp', 'any']

    ipaddr2 = ['1.1.1.2', '10.0.10.5', '10.0.10.6', '10.0.10.2', '1.1.1.3',
               '10.0.10.7', '10.0.10.8', '10.0.10.9', '1.1.1.10',
               '1.1.1.11', '1.1.1.4', '1.1.1.12', '1.1.1.5', '1.1.1.6',
               '1.1.1.7']

    protos2 = ['icmp', 'udp', 'tcp', 'sctp', 'igmp', 'pim', 'gre', 'ah',
               'esp', 'any']

    for (x, y) in product(ipaddr1, protos1):
        seq = seq + 1
        test_multiple_aces(
                    configure_permit_acl,
                    (ops1, 'test1', seq, y, x, '', 'any', '', 'count')
                    )

    test1_result = ops1('show run')

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test1')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test1\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    interface_info, rest, *misc = test1_result.split(
                        'apply access-list ip test1 in'
                                    )

    interface_line = findall(r'interface\s+\d+', interface_info)[-1]
    interface_num = search('(?<=interface )\d+', interface_line).group()
    print('INTERFACE is ')
    print(interface_num)

    create_and_verify_traffic(topology, hs1, hs2)

    # delay added to retrieve correct hitcount
    sleep(20)

    hit_dict = ops1.libs.vtysh.show_access_list_hitcounts_ip_interface(
                             'test1', interface_num)

    for rule, count in hit_dict.items():
        print(rule, count)

    assert(hit_dict['1 permit icmp 1.1.1.1 any count '] == '10')

    # Apply 150 ACEs on interface 2 now
    for (x, y) in product(ipaddr2, protos2):
        seq = seq + 1
        test_multiple_aces(
                    configure_permit_acl,
                    (ops1, 'test2', seq, y, x, '', 'any', '', 'count')
                    )

    with ops1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.apply_access_list_ip_in('test2')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test2\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    interface_info, rest, *misc = test1_result.split(
                        'apply access-list ip test2 in'
                                    )

    interface_line = findall(r'interface\s+\d+', interface_info)[-1]
    interface_num = search('(?<=interface )\d+', interface_line).group()

    print('INTERFACE is ')
    print(interface_num)

    # clear hitcount on interface
    ops1.libs.vtysh.clear_access_list_hitcounts_ip_interface(
                                       'test2', interface_num)
    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.1', src='1.1.1.2'")
    icmp_packet = hs1.libs.scapy.icmp()
    filter_str = (
                    "lambda p: ICMP in p and p[IP].src == '1.1.1.2' "
                    "and p[IP].dst == '1.1.1.1'"
                )
    list1 = [ip_packet, icmp_packet]
    proto_str = 'IP/ICMP'
    port_str = '1'
    timeout = 25
    count = 10

    txthread = ScapyThread(
                send_traffic,
                'hs2', topology, proto_str, list1, '', count, '', 0)

    rxthread = ScapyThread(
                sniff_traffic,
                'hs1', topology, '', [], filter_str, count, port_str, timeout)

    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)

        assert (list_result[2] == '10')

    # delay added to retrieve correct hitcount
    sleep(20)

    hit_dict = ops1.libs.vtysh.show_access_list_hitcounts_ip_interface(
                             'test2', interface_num)

    for rule, count in hit_dict.items():
        print(rule, count)

    assert(hit_dict['151 permit icmp 1.1.1.2 any count '] == '10')

    # end Apply of ACEs on interface 2

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.session_timeout(0)
    ops1._shells['vtysh']._timeout = 1500
    ops1.libs.vtysh.copy_running_config_startup_config()
    run_res_before_boot = ops1.libs.vtysh.show_running_config()
    start_res_before_boot = ops1.libs.vtysh.show_startup_config()
    assert(run_res_before_boot == start_res_before_boot)

    sleep(60)
    print("Rebooting Switch")
    reboot_switch(ops1, shell="vtysh")
    sleep(60)

    run_res_after_boot = ops1.libs.vtysh.show_running_config()
    assert(run_res_before_boot == run_res_after_boot)

    start_res_after_boot = ops1.libs.vtysh.show_startup_config()
    assert(run_res_after_boot == start_res_after_boot)

    # run traffic with 150 ACEs on interface 1
    test2_result = ops1('show run')

    interface_info, rest, *misc = test2_result.split(
                        'apply access-list ip test1 in'
                                    )

    interface_line = findall(r'interface\s+\d+', interface_info)[-1]
    interface_num = search('(?<=interface )\d+', interface_line).group()

    assert search(
        r'(access-list\s+ip\s+test1\s+\in)'.format(
                                          **locals()
                                        ), test2_result
    )

    create_and_verify_traffic(topology, hs1, hs2)

    # delay added to retrieve correct hitcount
    sleep(20)

    hit_dict = ops1.libs.vtysh.show_access_list_hitcounts_ip_interface(
                             'test1', interface_num)

    for rule, count in hit_dict.items():
        print(rule, count)

    assert(hit_dict['1 permit icmp 1.1.1.1 any count '] == '10')

    ops1.libs.vtysh.clear_access_list_hitcounts_all()

    # run traffic with 150 ACEs on interface 2
    interface_info, rest, *misc = test2_result.split(
                        'apply access-list ip test2 in'
                                    )

    interface_line = findall(r'interface\s+\d+', interface_info)[-1]
    interface_num = search('(?<=interface )\d+', interface_line).group()

    print('INTERFACE is ')
    print(interface_num)

    # create_and_verify_traffic(topology, hs1, hs2)
    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.1', src='1.1.1.2'")
    icmp_packet = hs1.libs.scapy.icmp()
    filter_str = (
                    "lambda p: ICMP in p and p[IP].src == '1.1.1.2' "
                    "and p[IP].dst == '1.1.1.1'"
                )
    list1 = [ip_packet, icmp_packet]
    proto_str = 'IP/ICMP'
    port_str = '1'
    timeout = 25
    count = 10

    txthread = ScapyThread(
                send_traffic,
                'hs2', topology, proto_str, list1, '', count, '', 0)

    rxthread = ScapyThread(
                sniff_traffic,
                'hs1', topology, '', [], filter_str, count, port_str, timeout)

    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)

        assert (list_result[2] == '10')

    # delay added to retrieve correct hitcount
    sleep(20)

    hit_dict = ops1.libs.vtysh.show_access_list_hitcounts_ip_interface(
                             'test2', interface_num)

    for rule, count in hit_dict.items():
        print(rule, count)

    assert(hit_dict['151 permit icmp 1.1.1.2 any count '] == '10')


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


def reboot_switch(switch, shell='vtysh', silent=False, onie=False):
    """
    Reboot the switch
    :param topology_ostl.nodes.Switch switch: the switch node
    :param str shell: shell to use to perfom the reboot
    :param bool silent: suppress output if true.
    :param bool onie: reboot to the onie rescue prompt if true
    """

    if not silent:
        print('{} [{}].reboot_switch(onie=\'{}\', shell=\'{}\') ::'.format(
            datetime.now().isoformat(), switch.identifier, onie, shell
        ))

    if shell == "bash":
        _shell = switch.get_shell('bash')
        _shell.send_command(
            'reboot', matches=r'Restarting system.', timeout=300)

    elif shell == "vtysh":
        _shell = switch.get_shell('vtysh')
        _shell.send_command(
            'reboot', matches=r'\r\nDo you want to continue [y/n]?')
        _shell.send_command('y', matches=r'Restarting system.', timeout=300)

    elif shell == "onie":
        _shell = switch.get_shell('bash')
        _spawn = _shell._get_connection('0')
        _spawn.sendline('reboot')
        _spawn.expect(r'The system is going down NOW!', timeout=300)

    else:
        raise Exception(
            'Shell {} reboot command is not supported.'.format(shell)
        )

    login_switch(switch, onie=onie)


def login_switch(switch, onie=False):
    """
    Login to the switch
    :param topology_ostl.nodes.Switch switch: the switch node
    :param bool onie: login to the onie rescue prompt if true
    """

    _shell = switch.get_shell('bash')
    _spawn = _shell._get_connection('0')

    if(onie):
        expect_matches = [
            r'\*OpenSwitch.*',
            r'\*ONIE: Install OS.*',
            r'\*ONIE[^:].*',
            r'\*ONIE: Rescue.*',
            r'\r\nPlease press Enter to activate this console.',
            r'\r\nONIE:/\s+#'
        ]

        for num in range(10):
            index = _spawn.expect(expect_matches, timeout=300)
            if (index == 0 or index == 1):
                _spawn.send('v')
            elif (index == 2 or index == 3 or index == 4):
                _spawn.send('\r')
            elif index == 5:
                break
    else:
        expect_matches = [
            r'(?<!Last )login:\s*$',
            r'\r\nroot@[-\w]+:~# ',
            r'\r\n[-\w]+(\([-\w\s]+\))?#'
        ]

        _spawn.sendline('')
        for num in range(10):
            sleep(0.5)
            index = _spawn.expect(expect_matches, timeout=300)
            if index == 0:
                _spawn.sendline('root')
            elif index == 1:
                _spawn.sendline('vtysh')
            elif index == 2:
                break


@fixture
def test_multiple_aces(func, params, trace=True):
    if trace:
        print(params)
    func(*params)


def create_and_verify_traffic(
                        topology, hs1, hs2
                        ):
    global filter_str
    ip_packet = hs1.libs.scapy.ip("dst='1.1.1.2', src='1.1.1.1'")
    icmp_packet = hs1.libs.scapy.icmp()

    list1 = [ip_packet, icmp_packet]
    proto_str = 'IP/ICMP'
    port_str = '1'
    timeout = 25
    count = 10

    txthread = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list1, '', count, '', 0)

    rxthread = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_str, count, port_str, timeout)

    rxthread.start()
    txthread.start()

    txthread.join()
    rxthread.join()

    if rxthread.outresult():
        rest, sniffcnt = rxthread.outresult().split('<Sniffed:')
        list_result = findall(r'[0-9]+', sniffcnt)

        assert (list_result[2] == '10')
        assert search(
                ''
                r'ICMP\s+1\.1\.1\.1\s+\>\s+1\.1\.1\.2\s+'
                'echo-request'.format(
                                 **locals()
                               ), rxthread.outresult()
            )
