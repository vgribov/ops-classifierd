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
"""

from pytest import mark
from re import findall
from re import search
from topology_lib_scapy.library import ScapyThread
from topology_lib_scapy.library import send_traffic
from topology_lib_scapy.library import sniff_traffic


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

filter_udp = 'udp and port 48621 and ip src 1.1.1.1 and ip dst 1.1.1.2'
filter_udp_other = 'udp and port 5555 and ip src 1.1.1.1 and ip dst 1.1.1.2'
filter_icmp = 'icmp and ip src 1.1.1.1 and ip dst 1.1.1.2'
filter_udp_reverse = 'udp and port 48621 and ip src 1.1.1.2 and ip dst 1.1.1.1'
filter_icmp_reverse = 'icmp and ip src 1.1.1.2 and ip dst 1.1.1.1'
port_str = '1'
timeout = 25
count = 10


def configure_permit_acl(ops1, name, seq_num, proto, src_ip,
                         src_port, dst_ip, dst_port):
    """
    Configure an ACL with one permit rule
    """

    with ops1.libs.vtysh.ConfigAccessListIpTestname(name) as ctx:
        ctx.permit('', seq_num, proto, src_ip, src_port, dst_ip, dst_port)


def configure_deny_acl(ops1, name, seq_num, proto, src_ip,
                       src_port, dst_ip, dst_port):
    """
    Configure an ACL with one deny rule
    """

    with ops1.libs.vtysh.ConfigAccessListIpTestname(name) as ctx:
        ctx.deny('', seq_num, proto, src_ip, src_port, dst_ip, dst_port)


def acl_permit_udp_any_any(ops1, hs1, hs2, topology, step):
    """
    This test adds a "1 permit udp any any" rule on interface 1.
    It then sends 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2
    """
    global filter_udp, timeout, count, port_str

    step('1.a Configure an ACL with 1 permit udp any any rule')
    configure_permit_acl(ops1, 'test', '1', 'udp', 'any', '', 'any', '')
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


def acl_deny_udp_any_any(ops1, hs1, hs2, topology, step):
    """
    This test adds a "1 deny udp any any" rule on interface 1.
    It then sends 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2
    """
    global filter_udp, timeout, count, port_str

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


def acl_permit_udp_hs1_hs2(ops1, hs1, hs2, topology, step):
    """
    This test adds a "1 permit udp 1.1.1.1 1.1.1.2" rule on interface 1.
    It then sends 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_icmp, timeout, count, port_str

    step('3.a Configure an ACL with 1 permit udp 1.1.1.1 1.1.1.2 rule')
    configure_permit_acl(ops1, 'test', '1', 'udp', '1.1.1.1', '', '1.1.1.2',
                         '')
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


def acl_deny_udp_hs1_hs2(ops1, hs1, hs2, topology, step):
    """
    This test adds a "1 deny udp 1.1.1.1 1.1.1.2" rule on interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are denied on hs2. Also, it verifies that other
    protocol traffic is received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_icmp, timeout, count, port_str

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


def acl_permit_udp_prefix_len_mask(ops1, hs1, hs2, topology, step):
    """
    This test adds a "1 permit udp 1.1.1.0/31 1.1.1.0/30" rule on interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_icmp, timeout, count, port_str

    step('5.a Configure an ACL with 1 permit udp 1.1.1.0/31 1.1.1.0/30 rule')
    configure_permit_acl(ops1, 'test', '1', 'udp', '1.1.1.0/31', '',
                         '1.1.1.0/30',
                         '')
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


def acl_deny_udp_prefix_len_mask(ops1, hs1, hs2, topology, step):
    """
    This test adds a "1 permit udp 1.1.1.0/31 1.1.1.0/30" rule on interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_icmp, timeout, count, port_str

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


def acl_permit_udp_dotted_netmask(ops1, hs1, hs2, topology, step):
    """
    This test adds a "1 permit udp 1.1.1.0/255.255.255.254
    1.1.1.0/255.255.255.252" rule on interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_icmp, timeout, count, port_str

    step('7.a Configure an ACL with 1 permit udp 1.1.1.0/255.255.255.254'
         ' 1.1.1.0/255.255.255.252 rule')
    configure_permit_acl(
        ops1, 'test', '1', 'udp', 'any', '',
        '1.1.1.0/255.255.255.252', '')
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


def acl_deny_udp_dotted_netmask(ops1, hs1, hs2, topology, step):
    """
    This test adds a "1 permit udp 1.1.1.0/255.255.255.254
    1.1.1.0/255.255.255.252" rule on interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_icmp, timeout, count, port_str

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


def acl_permit_udp_non_contiguous_mask(ops1, hs1, hs2, topology, step):
    """
    This test adds a "1 permit udp 1.1.1.0/255.255.255.254
    1.1.1.0/255.255.255.252" rule on interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_icmp, timeout, count, port_str

    step('9.a Configure an ACL with 1 permit udp 1.0.1.0/255.0.255.254'
         ' any rule')
    configure_permit_acl(
        ops1, 'test', '1', 'udp', '1.0.1.0/255.0.255.254', '',
        'any', '')
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


def acl_deny_udp_non_contiguous_mask(ops1, hs1, hs2, topology, step):
    """
    This test adds a "1 deny udp 1.1.1.0/255.255.255.254
    any" rule on interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_icmp, timeout, count, port_str

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


def acl_permit_udp_dport_eq_param(ops1, hs1, hs2, topology, step):
    """
    This test adds a "1 permit udp 1.1.1.1 1.1.1.2 eq 48621" rule on
    interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_udp_other, timeout, count, port_str

    step('11.a Configure an ACL with 1 permit udp 1.1.1.1 1.1.1.2 '
         'eq 48621 rule')
    configure_permit_acl(ops1, 'test', '1', 'udp', '1.1.1.1', '',
                         '1.1.1.2',
                         'eq 48621')
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


def acl_deny_udp_dport_eq_param(ops1, hs1, hs2, topology, step):
    """
    This test adds a "1 deny udp 1.1.1.1 1.1.1.2 eq 48621" rule on
    interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_udp_other, timeout, count, port_str

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


def acl_permit_udp_sport_eq_param(ops1, hs1, hs2, topology, step):
    """
    This test adds a "1 permit udp 1.1.1.1 eq 5555 1.1.1.2" rule on
    interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_udp_other, timeout, count, port_str

    step('13.a Configure an ACL with 1 permit udp 1.1.1.1 eq 5555 '
         '1.1.1.2 rule')
    configure_permit_acl(ops1, 'test', '1', 'udp', '1.1.1.1', 'eq 5555',
                         '1.1.1.2',
                         '')
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


def acl_deny_udp_sport_eq_param(ops1, hs1, hs2, topology, step):
    """
    This test adds a "1 deny udp 1.1.1.1 eq 5555 1.1.1.2" rule on
    interface 1.
    It then passes 10 UDP packets from hs1 to hs2 and verifies that
    10 UDP packets are received on hs2. Also, it verifies that other
    protocol traffic is not received by hs2 by sending 10 ICMP packets.
    """
    global filter_udp, filter_udp_other, timeout, count, port_str

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


def acl_modify_after_sending_udp_traffic(ops1, hs1, hs2, topology, step):
    """
    This test sends some traffic after applying an ACL to interface 1.
    It then stops traffic, modifies the ACL and verifies that traffic behavior
    complies with the applied ACL
    """
    global filter_udp, filter_icmp, count, timeout, port_str

    step('15.a Configure an ACL with 1 permit udp 1.1.1.1 1.1.1.2 rule')
    configure_permit_acl(
                     ops1, 'test', '1', 'udp', '1.1.1.1', '', '1.1.1.2', '')
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


def acl_deny_udp_on_multiple_ports(ops1, hs1, hs2, topology, step):
    """
    This tests applies a deny rule for UDP and permit rule for ICMP on
    interfaces 1 and 2. Then, it passes UDP traffic in both directions
    and verifies that traffic is blocked. Next, it passes ICMP traffic
    and verifies that the responses are received.
    """
    global filter_udp, filter_icmp, filter_udp_reverse, filter_icmp_reverse
    global count, timeout, port_str

    step('16.a Configure a deny udp and permit icmp rule on ACL test')
    configure_deny_acl(ops1, 'test', '1', 'udp', '1.1.1.1', '',
                       '1.1.1.2', '')
    test1_result = ops1('show run')

    assert search(
       ''
       r'1\s+deny\s+udp\s+1.1.1.1\s+'
       '1.1.1.2'.format(**locals()), test1_result
    )

    configure_permit_acl(ops1, 'test', '2', 'icmp', 'any', '', 'any', '')
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
    if rxthread_icmp.outresult():
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


def acl_permit_icmp_on_multiple_ports(ops1, hs1, hs2, topology, step):
    """
    This test sends ICMP traffic from hs1 to hs2 after applying a permit
    ACL to interface 1. After it verifies that hs2 receives 10 packets,
    it sends traffic in the reverse direction and verifies that traffic
    behavior complies with the applied permit ACL
    """
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
    filter_str = 'icmp and ip src 1.1.1.1 and ip dst 1.1.1.2'
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
    ip_packet = hs2.libs.scapy.ip("dst='1.1.1.1', src='1.1.1.2'")
    icmp_packet = hs2.libs.scapy.icmp()
    filter_str = 'icmp and ip src 1.1.1.2 and ip dst 1.1.1.1'

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


def acl_replace_with_icmp_traffic(ops1, hs1, hs2, topology, step):
    """
    This test sends 10 ICMP packets from hs1 to hs2 with an ACL applied
    on interface 1. Verifies that the packets have been received on hs2.
    It then replaces this ACL with a deny ACL and verifies that no traffic
    is seen on hs2.
    """
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
    filter_str = 'icmp and ip src 1.1.1.1 and ip dst 1.1.1.2'
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
                'hs2', topology, '', [], filter_str, count, port_str, timeout)

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


@mark.test_id(10405)
@mark.platform_incompatible(['docker'])
def test_classifierd_ft_acl_tier_2(topology, step):
    """
    Test traffic after applying ACEs to ports.

    Build a topology of one switch and two hosts on the same subnet.
    """
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

    step('Wait until interfaces are up')
    for portlbl in ['1', '2']:
        wait_until_interface_up(ops1, portlbl)

    ping = hs2.libs.ping.ping(1, '1.1.1.1')

    step('Start scapy on host workstations')
    hs1.libs.scapy.start_scapy()
    hs2.libs.scapy.start_scapy()

    step('Test1 : acl_udp_any_any_permit')
    acl_permit_udp_any_any(ops1, hs1, hs2, topology, step)
    step('Test2: acl_udp_any_any_deny')
    acl_deny_udp_any_any(ops1, hs1, hs2, topology, step)
    step('Test3: acl_permit_udp_hs1_hs2')
    acl_permit_udp_hs1_hs2(ops1, hs1, hs2, topology, step)
    step('Test4: acl_deny_udp_hs1_hs2')
    acl_deny_udp_hs1_hs2(ops1, hs1, hs2, topology, step)
    step('Test5: acl_permit_udp_prefix_len_mask')
    acl_permit_udp_prefix_len_mask(ops1, hs1, hs2, topology, step)
    step('Test6: acl_deny_udp_prefix_len_mask')
    acl_deny_udp_prefix_len_mask(ops1, hs1, hs2, topology, step)
    step('Test7: acl_permit_udp_dotted_netmask')
    acl_permit_udp_dotted_netmask(ops1, hs1, hs2, topology, step)
    step('Test8: acl_deny_udp_dotted_netmask')
    acl_deny_udp_dotted_netmask(ops1, hs1, hs2, topology, step)
    step('Test9: acl_permit_udp_non_contiguous_mask')
    acl_permit_udp_non_contiguous_mask(ops1, hs1, hs2, topology, step)
    step('Test10: acl_deny_udp_non_contiguous_mask')
    acl_deny_udp_non_contiguous_mask(ops1, hs1, hs2, topology, step)
    step('Test11: acl_permit_udp_dport_eq_param')
    acl_permit_udp_dport_eq_param(ops1, hs1, hs2, topology, step)
    step('Test12: acl_deny_udp_dport_eq_param')
    acl_deny_udp_sport_eq_param(ops1, hs1, hs2, topology, step)
    step('Test13: acl_deny_udp_dport_eq_param')
    acl_permit_udp_sport_eq_param(ops1, hs1, hs2, topology, step)
    step('Test14: acl_deny_udp_dport_eq_param')
    acl_deny_udp_dport_eq_param(ops1, hs1, hs2, topology, step)
    step('Test15: acl_modify_after_sending_udp_traffic')
    acl_modify_after_sending_udp_traffic(ops1, hs1, hs2, topology, step)
    step('Test16: acl_deny_udp_on_multiple_ports')
    acl_deny_udp_on_multiple_ports(ops1, hs1, hs2, topology, step)
    step('Test17: acl_permit_icmp_on_multiple_ports')
    acl_permit_icmp_on_multiple_ports(ops1, hs1, hs2, topology, step)
    step('Test18: acl_replace_with_icmp_traffic')
    acl_replace_with_icmp_traffic(ops1, hs1, hs2, topology, step)


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
