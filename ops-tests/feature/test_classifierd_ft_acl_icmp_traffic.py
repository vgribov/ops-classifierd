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
OpenSwitch Test for ACL operations with ICMP traffic.
This file consists of the following test cases:

Test1 : acl_permit_any_hs1_hs2
Test2 : acl_permit_icmp_hs1_hs2
Test3 : acl_deny_icmp_hs1_hs2
Test4 : acl_deny_any_hs1_hs2
Test5 : acl_permit_proto_1_hs1_hs2
Test6 : acl_permit_icmp_non_contiguous_mask_pos
Test7 : acl_permit_icmp_non_contiguous_mask_neg
Test8 : acl_permit_icmp_prefix_len_mask
Test9 : acl_deny_icmp_prefix_len_mask
Test10 : acl_modify_after_sending_icmp_traffic
Test11 : acl_permit_icmp_on_multiple_ports
"""

from pytest import mark
from re import search
from re import findall
from topology_lib_scapy.library import ScapyThread
from topology_lib_scapy.library import send_traffic
from topology_lib_scapy.library import sniff_traffic
from time import sleep

TOPOLOGY = """
# +-------+                    +-------+
# |       |     +--------+     |       |
# |  hs1  <----->  ops1  <----->  hs2  |
# |       |     +--------+     |       |
# +-------+                    +-------+

# Nodes
[type=openswitch name="Switch 1"] ops1
[type=host name="Host 1" image="Ubuntu"] hs1
[type=host name="Host 2" image="Ubuntu"] hs2

# Links
hs1:1 -- ops1:1
ops1:2 -- hs2:1
"""


def acl_permit_any_hs1_hs2(ops1, hs1, hs2, topology, step):
    """
    This test adds a "40 permit 10.0.10.1 10.0.10.2" rule on interface 1.
    It then sends 10 ICMP packets from hs1 to hs2 and verifies that
    10 ICMP packets are received on hs2
    """

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test1') as ctx:
        ctx.permit('', '40', 'any', '10.0.10.1', '', '10.0.10.2', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'40\s+permit\s+any\s+10\.0\.10\.1'
       '\s+10\.0\.10\.2'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test1')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test1\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='10.0.10.2', src='10.0.10.1'")
    icmp_packet = hs1.libs.scapy.icmp()

    list1 = [ip_packet, icmp_packet]
    proto_str = 'IP/ICMP'
    filter_str = 'icmp and ip src 10.0.10.1 and ip dst 10.0.10.2'
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
                r'ICMP\s+10\.0\.10\.1\s+\>\s+10\.0\.10\.2\s+'
                'echo-request'.format(
                                 **locals()
                               ), rxthread.outresult()
            )

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test1') as ctx:
        ctx.no('40')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test1')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test1\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


def acl_permit_icmp_hs1_hs2(ops1, hs1, hs2, topology, step):
    """
    This test adds a "1 permit icmp 10.0.10.1 10.0.10.2" rule on interface 1.
    It then sends 10 ICMP packets from hs1 to hs2 and verifies that
    10 ICMP packets are received on hs2.
    """
    with ops1.libs.vtysh.ConfigAccessListIpTestname('test1') as ctx:
        ctx.permit('', '1', 'icmp', '10.0.10.1', '', '10.0.10.2', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+permit\s+icmp\s+10\.0\.10\.1'
       '\s+10\.0\.10\.2'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test1')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test1\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='10.0.10.2', src='10.0.10.1'")
    icmp_packet = hs1.libs.scapy.icmp()

    list1 = [ip_packet, icmp_packet]
    proto_str = 'IP/ICMP'
    filter_str = 'icmp and ip src 10.0.10.1 and ip dst 10.0.10.2'
    port_str = '1'
    timeout = 25
    count = 10

    txthread = ScapyThread(
                send_traffic,
                'hs1', topology, proto_str, list1, '', count, '', 0)

    rxthread = ScapyThread(
                sniff_traffic,
                'hs2', topology, '', [], filter_str, 10, port_str, timeout)

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
                r'ICMP\s+10\.0\.10\.1\s+\>\s+10\.0\.10\.2\s+'
                'echo-request'.format(
                                 **locals()
                               ), rxthread.outresult()
            )

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test1') as ctx:
        ctx.no('1')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test1')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test1\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


def acl_deny_icmp_hs1_hs2(ops1, hs1, hs2, topology, step):
    """
    This test adds a "2 deny icmp 10.0.10.1 10.0.10.2" rule on interface 1.
    It then sends 10 ICMP packets from hs1 to hs2 and verifies that
    10 ICMP packets are not received on hs2.
    """
    with ops1.libs.vtysh.ConfigAccessListIpTestname('test2') as ctx:
        ctx.deny('', '2', 'icmp', '10.0.10.1', '', '10.0.10.2', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'2\s+deny\s+icmp\s+10\.0\.10\.1'
       '\s+10\.0\.10\.2'.format(
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

    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='10.0.10.2', src='10.0.10.1'")
    icmp_packet = hs1.libs.scapy.icmp()
    filter_str = 'icmp and ip src 10.0.10.1 and ip dst 10.0.10.2'

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

        assert (list_result[2] == '0')
        assert search(
                ''
                r'(?!ICMP\s+10\.0\.10\.1\s+\>\s+10\.0\.10\.2)'.format(
                                 **locals()
                               ), rxthread.outresult()
            )

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test2') as ctx:
        ctx.no('2')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test2')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test2\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


def acl_deny_any_hs1_hs2(ops1, hs1, hs2, topology, step):
    """
    This test adds a "4 deny any any any" rule on interface 1.
    It then sends 10 ICMP packets from hs1 to hs2 and verifies that
    10 ICMP packets are not received on hs2.
    """
    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.deny('', '4', 'any', 'any', '', 'any', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'4\s+deny\s+any\s+any'
       '\s+any'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test4\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='10.0.10.2', src='10.0.10.1'")
    icmp_packet = hs1.libs.scapy.icmp()

    list1 = [ip_packet, icmp_packet]
    proto_str = 'IP/ICMP'
    filter_str = 'icmp and ip src 10.0.10.1 and ip dst 10.0.10.2'
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
        assert sum(int(i) for i in list_result[:3]) == 0

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.no('4')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test4')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test4\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


def acl_permit_proto_1_hs1_hs2(ops1, hs1, hs2, topology, step):
    """
    This test adds a "6 permit 1 any any" rule on interface 1.
    It then sends 10 ICMP packets from hs1 to hs2 and verifies that
    10 ICMP packets are received on hs2.
    """
    with ops1.libs.vtysh.ConfigAccessListIpTestname('test6') as ctx:
        ctx.permit('', '6', '1', 'any', '', 'any', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'6\s+permit\s+icmp\s+any'
       '\s+any'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test6')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test6\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='10.0.10.2', src='10.0.10.1'")
    icmp_packet = hs1.libs.scapy.icmp()
    filter_str = 'icmp and ip src 10.0.10.1 and ip dst 10.0.10.2'

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

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test6') as ctx:
        ctx.no('6')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test6')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test6\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


def acl_permit_icmp_non_contiguous_mask_pos(ops1, hs1, hs2, topology, step):
    """
    This test adds a "7 permit icmp 10.0.10.0/255.0.255.252
    10.0.10.2" rule on interface 1.
    It then passes 10 ICMP packets from hs1 to hs2 and verifies that
    10 ICMP packets are received on hs2.
    """
    with ops1.libs.vtysh.ConfigAccessListIpTestname('test7') as ctx:
        ctx.permit(
            '', '7', 'icmp', '10.0.10.0/255.0.255.252', '',
            '10.0.10.2', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'7\s+permit\s+icmp\s+10\.0\.10\.0/255\.0\.255\.252'
       '\s+10\.0\.10\.2'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test7')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test7\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='10.0.10.2', src='10.0.10.1'")
    icmp_packet = hs1.libs.scapy.icmp()

    list1 = [ip_packet, icmp_packet]
    proto_str = 'IP/ICMP'
    filter_str = 'icmp and ip src 10.0.10.1 and ip dst 10.0.10.2'
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

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test7') as ctx:
        ctx.no('7')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test7')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test7\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


def acl_permit_icmp_non_contiguous_mask_neg(ops1, hs1, hs2, topology, step):
    """
    This test adds a "8 permit icmp 10.0.10.0/255.0.255.252
    10.0.10.2" rule on interface 1.
    It then sends 10 ICMP packets from hs1, which lies outside
    the permitted network, to hs2 and verifies that
    10 ICMP packets are not received on hs2.
    """
    with ops1.libs.vtysh.ConfigAccessListIpTestname('test8') as ctx:
        ctx.permit(
            '', '8', 'icmp', '10.0.10.0/255.0.255.252', '',
            '10.0.10.2', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'8\s+permit\s+icmp\s+10\.0\.10\.0/255\.0\.255\.252'
       '\s+10\.0\.10\.2'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test8')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test8\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='10.0.10.2', src='10.0.10.5'")
    icmp_packet = hs1.libs.scapy.icmp()
    filter_str = 'icmp and ip src 10.0.10.5 and ip dst 10.0.10.2'

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
        assert (list_result[2] == '0')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test8') as ctx:
        ctx.no('8')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test8')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test8\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


def acl_permit_icmp_prefix_len_mask(ops1, hs1, hs2, topology, step):
    """
    This test adds a "9 permit icmp 10.0.10.0/30 10.0.10.0/30" rule
    on interface 1. It then passes 10 ICMP packets from hs1 to hs2
    and verifies that 10 ICMP packets are received on hs2.
    """
    with ops1.libs.vtysh.ConfigAccessListIpTestname('test9') as ctx:
        ctx.permit(
            '', '9', 'icmp', '10.0.10.0/30', '',
            '10.0.10.0/30', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'9\s+permit\s+icmp\s+10\.0\.10\.0/255\.255\.255\.252'
       '\s+10\.0\.10\.0/255\.255\.255\.252'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test9')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test9\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='10.0.10.2', src='10.0.10.1'")
    icmp_packet = hs1.libs.scapy.icmp()
    filter_str = 'icmp and ip src 10.0.10.1 and ip dst 10.0.10.2'

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

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test9') as ctx:
        ctx.no('9')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test9')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test9\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


def acl_deny_icmp_prefix_len_mask(ops1, hs1, hs2, topology, step):
    """
    This test adds a "10 deny icmp 10.0.10.0/30 10.0.10.0/30" rule
    on interface 1. It then passes 10 ICMP packets from hs1 to hs2
    and verifies that 10 ICMP packets are not received on hs2.
    """
    with ops1.libs.vtysh.ConfigAccessListIpTestname('test10') as ctx:
        ctx.deny(
            '', '10', 'icmp', '10.0.10.0/30', '',
            '10.0.10.0/30', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'10\s+deny\s+icmp\s+10\.0\.10\.0/255\.255\.255\.252'
       '\s+10\.0\.10\.0/255\.255\.255\.252'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test10')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test10\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='10.0.10.2', src='10.0.10.1'")
    icmp_packet = hs1.libs.scapy.icmp()

    list1 = [ip_packet, icmp_packet]
    proto_str = 'IP/ICMP'
    filter_str = 'icmp and ip src 10.0.10.1 and ip dst 10.0.10.2'
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

        assert (list_result[2] == '0')

        assert search(
                ''
                r'(?!ICMP\s+10\.0\.10\.1\s+\>\s+10\.0\.10\.2)'.format(
                                 **locals()
                               ), rxthread.outresult()
            )

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test10') as ctx:
        ctx.no('10')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test10')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test10\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


def acl_modify_after_sending_icmp_traffic(ops1, hs1, hs2, topology, step):
    """
    This test sends ICMP traffic from hs1 to hs2 after applying a deny
    ACL to interface 1. After it verifies that hs2 does not receive anything,
    it then stops traffic, modifies the ACL and verifies that traffic behavior
    complies with the applied permit ACL
    """
    with ops1.libs.vtysh.ConfigAccessListIpTestname('test11') as ctx:
        ctx.deny(
            '', '100', 'icmp', '10.0.10.1', '',
            '10.0.10.2', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'100\s+deny\s+icmp\s+10\.0\.10\.1'
       '\s+10\.0\.10\.2'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test11')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test11\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='10.0.10.2', src='10.0.10.1'")
    icmp_packet = hs1.libs.scapy.icmp()

    list1 = [ip_packet, icmp_packet]
    proto_str = 'IP/ICMP'
    filter_str = 'icmp and ip src 10.0.10.1 and ip dst 10.0.10.2'
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

        assert (list_result[2] == '0')

        assert search(
                ''
                r'(?!ICMP\s+10\.0\.10\.1\s+\>\s+10\.0\.10\.2)'.format(
                                 **locals()
                               ), rxthread.outresult()
            )

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test11') as ctx:
        ctx.permit(
            '', '100', 'icmp', '10.0.10.1', '',
            '10.0.10.2', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'100\s+permit\s+icmp\s+10\.0\.10\.1'
       '\s+10\.0\.10\.2'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test11')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test11\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='10.0.10.2', src='10.0.10.1'")
    icmp_packet = hs1.libs.scapy.icmp()

    list1 = [ip_packet, icmp_packet]
    proto_str = 'IP/ICMP'
    filter_str = 'icmp and ip src 10.0.10.1 and ip dst 10.0.10.2'
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

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test11') as ctx:
        ctx.no('100')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test11')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test11\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


def acl_permit_icmp_on_multiple_ports(ops1, hs1, hs2, topology, step):
    """
    This test sends ICMP traffic from hs1 to hs2 after applying a permit
    ACL to interface 1. After it verifies that hs2 receives 10 packets,
    it sends traffic in the reverse direction and verifies that traffic
    behavior complies with the applied permit ACL
    """
    with ops1.libs.vtysh.ConfigAccessListIpTestname('test12') as ctx:
        ctx.permit(
            '', '11', 'icmp', '10.0.10.1', '',
            '10.0.10.2', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'11\s+permit\s+icmp\s+10\.0\.10\.1'
       '\s+10\.0\.10\.2'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_access_list_ip_in('test12')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test12\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test12') as ctx:
        ctx.permit(
            '', '12', 'icmp', '10.0.10.2', '',
            '10.0.10.1', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'12\s+permit\s+icmp\s+10\.0\.10\.2'
       '\s+10\.0\.10\.1'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.apply_access_list_ip_in('test12')

    test1_result = ops1('show run')

    assert search(
        r'(access-list\s+ip\s+test12\s+\in)'.format(
                                          **locals()
                                        ), test1_result
    )

    step('Create packets')
    ip_packet = hs1.libs.scapy.ip("dst='10.0.10.2', src='10.0.10.1'")
    icmp_packet = hs1.libs.scapy.icmp()

    list1 = [ip_packet, icmp_packet]
    proto_str = 'IP/ICMP'
    filter_str = 'icmp and ip src 10.0.10.1 and ip dst 10.0.10.2'
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

    step('Create packets')
    ip_packet = hs2.libs.scapy.ip("dst='10.0.10.1', src='10.0.10.2'")
    icmp_packet = hs2.libs.scapy.icmp()
    filter_str = 'icmp and ip src 10.0.10.2 and ip dst 10.0.10.1'

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

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test12') as ctx:
        ctx.no('12')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test12') as ctx:
        ctx.no('11')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list_ip('test12')

    test1_result = ops1('show run')

    assert search(
         r'(?!access-list\s+ip\s+test12\s+)'.format(
                                         **locals()
                                     ), test1_result
    )


@mark.test_id(10404)
@mark.platform_incompatible(['docker'])
def test_acl_icmp(topology, step):
    """
    Test traffic after applying ACEs to ports.

    Build a topology of one switch and two hosts on the same subnet.
    """
    ops1 = topology.get('ops1')
    hs1 = topology.get('hs1')
    hs2 = topology.get('hs2')

    assert ops1 is not None

    # ops1.libs.reboot.reboot_switch(shell="vtysh")

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

    hs1.libs.ip.interface('1', addr='10.0.10.1/24', up=True)
    hs2.libs.ip.interface('1', addr='10.0.10.2/24', up=True)

    with ops1.libs.vtysh.ConfigVlan('100') as ctx:
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.vlan_access(100)

    with ops1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.vlan_access(100)

    step('Wait until interfaces are up')
    for portlbl in ['1', '2']:
        wait_until_interface_up(ops1, portlbl)

    ping = hs2.libs.ping.ping(1, '10.0.10.1')
    assert ping['transmitted'] == ping['received'] == 1

    step('Start scapy on host workstations')
    hs1.libs.scapy.start_scapy()
    hs2.libs.scapy.start_scapy()

    step('################ T1 Apply ACL on one port Permit ###########')
    step('################ with proto any and A.B.C.D Host  ###############')
    acl_permit_any_hs1_hs2(ops1, hs1, hs2, topology, step)

    step('################ T2 Apply ACL on one port Permit ###########')
    step('################ with proto icmp and A.B.C.D Host  ###############')
    acl_permit_icmp_hs1_hs2(ops1, hs1, hs2, topology, step)

    step('################ T3 Apply ACL on one port Deny ###########')
    step('################ with proto any and A.B.C.D Host  ###############')
    acl_deny_icmp_hs1_hs2(ops1, hs1, hs2, topology, step)

    step('################ T4 Apply ACL on one port Deny ###########')
    step('################ with proto any and any src and dst ###############')
    acl_deny_any_hs1_hs2(ops1, hs1, hs2, topology, step)

    step('################ T5 Apply ACL on one port Deny ###########')
    step('################ with proto 1 and any src and dst ###############')
    acl_permit_proto_1_hs1_hs2(ops1, hs1, hs2, topology, step)

    step('################ T6 Apply ACL on one port Permit ###########')
    step('################ A.B.C.D/W.X.Y.Z Host  ###############')
    step('################ non-contiguous src and dst ###############')
    step('################ positive test ###############')
    acl_permit_icmp_non_contiguous_mask_pos(ops1, hs1, hs2, topology, step)

    step('################ T7 Apply ACL on one port Permit ###########')
    step('################ A.B.C.D/W.X.Y.Z Host  ###############')
    step('################ non-contiguous src and dst ###############')
    step('################ negative test ###############')
    acl_permit_icmp_non_contiguous_mask_neg(ops1, hs1, hs2, topology, step)

    step('################ T8 Apply ACL on one port Permit ###########')
    step('################ A.B.C.D/M src and dst ###############')
    acl_permit_icmp_prefix_len_mask(ops1, hs1, hs2, topology, step)

    step('################ T9 Apply ACL on one port Deny ###########')
    step('################ A.B.C.D/M src and dst ###############')
    acl_deny_icmp_prefix_len_mask(ops1, hs1, hs2, topology, step)

    step('################ T10 Apply ACL on one port Modify ###########')
    step('################ from Deny to Permit ###########')
    step('################ A.B.C.D src and dst ###############')
    acl_modify_after_sending_icmp_traffic(ops1, hs1, hs2, topology, step)

    step('################ T11 Apply ACE ###########')
    step('################ to interface 1 and 2 ###############')
    step('################ A.B.C.D Host  ###############')
    step('################ check traffic  ###############')
    step('################ on multiple ports ###############')
    acl_permit_icmp_on_multiple_ports(ops1, hs1, hs2, topology, step)


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
