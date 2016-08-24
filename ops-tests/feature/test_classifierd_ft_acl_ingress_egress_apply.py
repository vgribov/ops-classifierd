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
OpenSwitch Test for ACE apply to interfaces.
"""

from pytest import mark
from re import search
import pytest
from topology_lib_vtysh import exceptions

from acl_classifier_common_lib import configure_acl_l3
from acl_classifier_common_lib import unconfigure_acl
from acl_classifier_common_lib import apply_acl
from acl_classifier_common_lib import wait_on_warnings

TOPOLOGY = """
#+--------+
#|  ops1  |
#+--------+

# Nodes
[type=openswitch name="openswitch 1"] ops1
"""


@mark.test_id(10403)
def test_ace_apply(topology, step):
    test_num = 0

    """
    Test apply of ACEs to ports.

    Build a topology of one switch. Tested the ability to properly add ACL,
    delete ACL.
    """
    ops1 = topology.get('ops1')
    assert ops1 is not None

    acl_name = 'test1'
    seq_num = '1'

    test_num += 1
    step(
        '#### T{test_num} Add Permit ACE ####\n'
        '#### to existing IPv4 ACL ####'
        .format(**locals())
        )
    configure_acl_l3(
        sw=ops1, acl_addr_type='ip', acl_name=acl_name, seq_num=seq_num,
        action='permit', proto='pim', src_ip='1.2.3.4', src_port='',
        dst_ip='5.6.7.8', dst_port='', count='', log=''
        )

    test_num += 1
    step(
        '#### T{test_num} Add Deny ACE ####\n'
        '#### to existing IPv4 ACL ####'
        .format(**locals())
        )
    configure_acl_l3(
        sw=ops1, acl_addr_type='ip', acl_name=acl_name, seq_num=seq_num,
        action='deny', proto='igmp', src_ip='1.2.3.4', src_port='',
        dst_ip='5.6.7.8', dst_port='', count='', log=''
        )

    test_num += 1
    step(
        '#### T{test_num} Add Permit ACE ####\n'
        '#### to existing IPv4 ACL ####\n'
        '#### with just count ####'
        .format(**locals())
        )
    configure_acl_l3(
        sw=ops1, acl_addr_type='ip', acl_name=acl_name, seq_num=seq_num,
        action='permit', proto='igmp', src_ip='9.10.11.12', src_port='',
        dst_ip='13.14.15.16', dst_port='', count='count', log=''
        )

    test_num += 1
    step(
        '#### T{test_num} Add Permit ACE ####\n'
        '#### to existing IPv4 ACL ####\n'
        '#### with count and log ####'
        .format(**locals())
        )
    configure_acl_l3(
        sw=ops1, acl_addr_type='ip', acl_name=acl_name, seq_num=seq_num,
        action='permit', proto='igmp', src_ip='17.18.19.20', src_port='',
        dst_ip='21.22.23.24', dst_port='', count='count', log='log'
        )

    test_num += 1
    step(
        '#### T{test_num} Add Permit ACE ####\n'
        '#### to existing IPv4 ACL ####\n'
        '#### with just log ####'
        .format(**locals())
        )
    configure_acl_l3(
        sw=ops1, acl_addr_type='ip', acl_name=acl_name, seq_num=seq_num,
        action='permit', proto='igmp', src_ip='25.26.27.28', src_port='',
        dst_ip='29.30.31.32', dst_port='', count='', log='log'
        )

    test_num += 1
    step(
        '#### T{test_num} Remove ACE ####\n'
        '#### from existing IPv4 ACL ####'
        .format(**locals())
        )
    unconfigure_ace(
        sw=ops1, acl_addr_type='ip', acl_name=acl_name,
        seq_num=seq_num
        )

    test_num += 1
    step(
        '#### T{test_num} Remove IPv4 ACL ####'
        .format(**locals())
        )
    unconfigure_acl(sw=ops1, acl_addr_type='ip', acl_name=acl_name)

    for direction in ['in', 'out']:

        dir_synonym = "Ingress" if direction == 'in' else "Egress"
        acl_name = 'testApplyACL_{dir_synonym}'.format(**locals())

        test_num += 1
        step(
            '## T{test_num} Applying {dir_synonym} IPV4 ACL  ##\n'
            '#### T{test_num}a Apply {dir_synonym} IPV4 ACL ####\n'
            '#### to interface ####\n'
            '#### ACL does not exist ####'
            .format(**locals())
            )
        with pytest.raises(exceptions.AclDoesNotExistException):
            apply_acl(
                sw=ops1, app_type='port', interface_num='4',
                acl_addr_type='ip', acl_name=acl_name, direction=direction
                )

        step(
            '#### T{test_num}b Apply {dir_synonym} IPV4 ACL ####\n'
            '#### to interface ####\n'
            '#### igmp protocol ####'
            .format(**locals())
            )
        seq_num = '4'
        configure_acl_l3(
            sw=ops1, acl_addr_type='ip', acl_name=acl_name, seq_num=seq_num,
            action='permit', proto='igmp', src_ip='1.2.3.4/255.0.0.0',
            src_port='', dst_ip='5.6.7.8/255.255.0.0', dst_port='', count='',
            log=''
            )
        interface_num = '4'
        apply_acl(
            sw=ops1, app_type='port', interface_num='4', acl_addr_type='ip',
            acl_name=acl_name, direction=direction
            )
        unconfigure_ace(
            sw=ops1, acl_addr_type='ip', acl_name=acl_name, seq_num=seq_num
            )

        test_num += 1
        step(
            '#### T{test_num} Apply {dir_synonym} no ACL ####\n'
            '#### on interface 4 ####'
            .format(**locals())
            )
        no_apply_interface(
            sw=ops1, app_type='port', interface_num=interface_num,
            acl_addr_type='ip', acl_name=acl_name, direction=direction
            )

        test_num += 1
        step(
            '#### T{test_num} Apply {dir_synonym} IPV4 ACL ####\n'
            '#### to interface ####\n'
            '#### A.B.C.D/M Network ####'
            .format(**locals())
            )
        common_apply_test(
            sw=ops1, acl_addr_type='ip', acl_name=acl_name, seq_num='6',
            action='permit', proto='igmp',
            src_ip='1.2.3.4/8', src_port='',
            dst_ip='5.6.7.8/24', dst_port='',
            app_type='port', interface_num='5', direction=direction,
            count='', log=''
            )

        test_num += 1
        step(
            '#### T{test_num} Apply {dir_synonym} IPV4 ACL ####\n'
            '#### to interface ####\n'
            '#### A.B.C.D Host count ####'
            .format(**locals())
            )
        common_apply_test(
            sw=ops1, acl_addr_type='ip', acl_name=acl_name, seq_num='7',
            action='permit', proto='igmp',
            src_ip='1.2.3.4', src_port='',
            dst_ip='5.6.7.8', dst_port='',
            app_type='port', interface_num='7', direction=direction,
            count='count', log=''
            )

        test_num += 1
        step(
            '#### T{test_num} Apply {dir_synonym} IPV4 ACL ####\n'
            '#### to interface ####\n'
            '#### Numbered proto and any host log ####'
            .format(**locals())
            )
        common_apply_test(
            sw=ops1, acl_addr_type='ip', acl_name=acl_name, seq_num='8',
            action='permit', proto='4',
            src_ip='any', src_port='',
            dst_ip='any', dst_port='',
            app_type='port', interface_num='8', direction=direction,
            count='', log='log'
            )

        test_num += 1
        step(
            '#### T{test_num} Apply {dir_synonym} IPV4 ACL ####\n'
            '#### to interface ####\n'
            '#### sctp eq L4 count log####'
            .format(**locals())
            )
        common_apply_test(
            sw=ops1, acl_addr_type='ip', acl_name=acl_name, seq_num='9',
            action='permit', proto='sctp',
            src_ip='172.21.30.4', src_port='eq 10',
            dst_ip='5.6.7.8/24', dst_port='eq 11',
            app_type='port', interface_num='9', direction=direction,
            count='count', log='log'
            )

        test_num += 1
        step(
            '#### T{test_num} Apply {dir_synonym} IPV4 ACL ####\n'
            '#### to interface ####\n'
            '#### sctp eq L4 ####'
            .format(**locals())
            )
        common_apply_test(
            sw=ops1, acl_addr_type='ip', acl_name=acl_name, seq_num='10',
            action='permit', proto='sctp',
            src_ip='172.21.30.4', src_port='eq 10',
            dst_ip='5.6.7.8/24', dst_port='eq 11',
            app_type='port', interface_num='10', direction=direction,
            count='', log=''
            )

        test_num += 1
        step(
            '#### T{test_num} Apply {dir_synonym} IPV4 ACL ####\n'
            '#### to interface ####\n'
            '#### sctp gt L4 count ####'
            .format(**locals())
            )
        common_apply_test(
            sw=ops1, acl_addr_type='ip', acl_name=acl_name, seq_num='11',
            action='permit', proto='sctp',
            src_ip='172.21.30.4/24', src_port='gt 10',
            dst_ip='5.6.7.8/24', dst_port='gt 11',
            app_type='port', interface_num='11', direction=direction,
            count='count', log=''
            )

        test_num += 1
        step(
            '#### T{test_num} Apply {dir_synonym} IPV4 ACL ####\n'
            '#### to interface ####\n'
            '#### sctp lt L4 log ####'
            .format(**locals())
            )
        common_apply_test(
            sw=ops1, acl_addr_type='ip', acl_name=acl_name, seq_num='12',
            action='permit', proto='sctp',
            src_ip='172.21.30.4/24', src_port='lt 10',
            dst_ip='5.6.7.8/24', dst_port='lt 11',
            app_type='port', interface_num='12', direction=direction,
            count='', log='log'
            )

        test_num += 1
        step(
            '#### T{test_num} Apply {dir_synonym} IPV4 ACL ####\n'
            '#### to interface ####\n'
            '#### sctp range L4 count log ####'
            .format(**locals())
            )
        common_apply_test(
            sw=ops1, acl_addr_type='ip', acl_name=acl_name, seq_num='13',
            action='permit', proto='sctp',
            src_ip='1.2.3.4/1', src_port='range 100 500',
            dst_ip='5.6.7.8/32', dst_port='range 40 50',
            app_type='port', interface_num='13', direction=direction,
            count='count', log='log'
            )

        test_num += 1
        step(
            '#### T{test_num} Apply {dir_synonym} IPV4 ACL ####\n'
            '#### to interface ####\n'
            '#### tcp deny eq L4 ####'
            .format(**locals())
            )
        common_apply_test(
            sw=ops1, acl_addr_type='ip', acl_name=acl_name, seq_num='14',
            action='deny', proto='tcp',
            src_ip='1.2.3.4/8', src_port='eq 4',
            dst_ip='5.6.7.8/24', dst_port='eq 40',
            app_type='port', interface_num='14', direction=direction,
            count='', log=''
            )

        test_num += 1
        step(
            '#### T{test_num} Apply {dir_synonym} IPV4 ACL ####\n'
            '#### to interface ####\n'
            '#### tcp deny range L4 count ####'
            .format(**locals())
            )
        common_apply_test(
            sw=ops1, acl_addr_type='ip', acl_name=acl_name, seq_num='15',
            action='deny', proto='tcp',
            src_ip='1.2.3.4/8', src_port='range 4 6',
            dst_ip='5.6.7.8/24', dst_port='range 40 60',
            app_type='port', interface_num='15', direction=direction,
            count='count', log=''
            )

        test_num += 1
        step(
            '#### T{test_num} Remove {dir_synonym} IPV4 ACL ####'
            .format(**locals())
            )
        unconfigure_acl(sw=ops1, acl_addr_type='ip', acl_name=acl_name)
    # END for direction in ['in' : 'out']:

    # Beginning of mixing ingress with egress using a single ACL
    acl_name = "testIngressEgressOneACL"
    for dir_list in [['in', 'out'], ['out', 'in']]:
        test_num += 1
        step(
            '#### T{test_num} Mix Ingress and Egress IPV4 ACL ####\n'
            '#### On one port, ACL, and ACE ####\n'
            '#### deny udp any Host L4 range ####'
            .format(**locals())
            )
        common_in_out_apply_one_acl_one_ace_test(
            sw=ops1, acl_addr_type='ip', acl_name=acl_name,
            seq_num='1', action='deny', proto='udp',
            src_ip='any', src_port='',
            dst_ip='1.1.1.1', dst_port='range 0 65535',
            app_type='port', interface_num='1', dir_list=dir_list,
            count='', log=''
            )

        test_num += 1
        step(
            '#### T{test_num} Mix Ingress and Egress IPV4 ACL ####\n'
            '#### On one port, ACL, and ACE ####\n'
            '#### permit tcp Network L4 lt Non-contiguous L4 gt count ####'
            .format(**locals())
            )
        common_in_out_apply_one_acl_one_ace_test(
            sw=ops1, acl_addr_type='ip', acl_name=acl_name,
            seq_num='2', action='permit', proto='tcp',
            src_ip='1.1.1.0/24', src_port='lt 42',
            dst_ip='1.1.0.0/255.0.255.255', dst_port='gt 50',
            app_type='port', interface_num='2', dir_list=dir_list,
            count='count', log=''
            )

        test_num += 1
        step(
            '#### T{test_num} Mix Ingress and Egress IPV4 ACL ####\n'
            '#### On one port, ACL, and ACE ####\n'
            '#### deny sctp Host L4 eq any log ####'
            .format(**locals())
            )
        common_in_out_apply_one_acl_one_ace_test(
            sw=ops1, acl_addr_type='ip', acl_name=acl_name,
            seq_num='3', action='deny', proto='sctp',
            src_ip='1.1.1.1', src_port='eq 1000',
            dst_ip='any', dst_port='',
            app_type='port', interface_num='3', dir_list=dir_list,
            count='', log='log'
            )

        test_num += 1
        step(
            '#### T{test_num} Mix Ingress and Egress IPV4 ACL ####\n'
            '#### On one port, ACL, and ACE ####\n'
            '#### permit udp Host L4 range Network L4 lt count log ####'
            .format(**locals())
            )
        common_in_out_apply_one_acl_one_ace_test(
            sw=ops1, acl_addr_type='ip', acl_name=acl_name,
            seq_num='4', action='permit', proto='udp',
            src_ip='1.1.1.1', src_port='range 1 65534',
            dst_ip='1.1.1.0/255.255.255.0', dst_port='lt 65535',
            app_type='port', interface_num='4', dir_list=dir_list,
            count='count', log='log'
            )

        test_num += 1
        step(
            '#### T{test_num} Mix Ingress and Egress IPV4 ACL ####\n'
            '#### On one port, ACL, and ACE ####\n'
            '#### deny tcp non-contiguous Network gt Network eq ####'
            .format(**locals())
            )
        common_in_out_apply_one_acl_one_ace_test(
            sw=ops1, acl_addr_type='ip', acl_name=acl_name,
            seq_num='5', action='deny', proto='tcp',
            src_ip='18.32.144.40/254.228.144.172', src_port='gt 0',
            dst_ip='1.1.0.0/16', dst_port='eq 42',
            app_type='port', interface_num='5', dir_list=dir_list,
            count='', log=''
            )

        test_num += 1
        step(
            '#### T{test_num} Mix Ingress and Egress IPV4 ACL ####\n'
            '#### On one port, ACL, and ACE ####\n'
            '#### permit sctp any Host count ####'
            .format(**locals())
            )
        common_in_out_apply_one_acl_one_ace_test(
            sw=ops1, acl_addr_type='ip', acl_name=acl_name,
            seq_num='6', action='permit', proto='sctp',
            src_ip='any', src_port='',
            dst_ip='1.1.1.1', dst_port='',
            app_type='port', interface_num='6', dir_list=dir_list,
            count='count', log=''
            )

        test_num += 1
        step(
            '#### T{test_num} Mix Ingress and Egress IPV4 ACL ####\n'
            '#### On one port, ACL, and ACE ####\n'
            '#### deny icmp any Host log ####'
            .format(**locals())
            )
        common_in_out_apply_one_acl_one_ace_test(
            sw=ops1, acl_addr_type='ip', acl_name=acl_name,
            seq_num='7', action='deny', proto='icmp',
            src_ip='any', src_port='',
            dst_ip='1.1.1.1', dst_port='',
            app_type='port', interface_num='7', dir_list=dir_list,
            count='', log='log'
            )

        test_num += 1
        step(
            '#### T{test_num} Mix Ingress and Egress IPV4 ACL ####\n'
            '#### On one port, ACL, and ACE ####\n'
            '#### permit 255 Network Network count log ####'
            .format(**locals())
            )
        common_in_out_apply_one_acl_one_ace_test(
            sw=ops1, acl_addr_type='ip', acl_name=acl_name,
            seq_num='8', action='permit', proto='255',
            src_ip='1.1.1.0/24', src_port='',
            dst_ip='1.1.0.0/255.255.0.0', dst_port='',
            app_type='port', interface_num='8', dir_list=dir_list,
            count='count', log='log'
            )

        test_num += 1
        step(
            '#### T{test_num} Mix Ingress and Egress IPV4 ACL ####\n'
            '#### On one port, ACL, and ACE ####\n'
            '#### deny 0 Non-contiguous any ####'
            .format(**locals())
            )
        common_in_out_apply_one_acl_one_ace_test(
            sw=ops1, acl_addr_type='ip', acl_name=acl_name,
            seq_num='9', action='deny', proto='0',
            src_ip='255.0.255.255/255.0.255.255', src_port='',
            dst_ip='any', dst_port='',
            app_type='port', interface_num='9', dir_list=dir_list,
            count='', log=''
            )
    # End for dir_list in [['in', 'out'], ['out', 'in']]:

    test_num += 1
    step(
        '#### T{test_num} Remove Ingress Egress IPV4 ACL ####'
        .format(**locals())
        )
    unconfigure_acl(sw=ops1, acl_addr_type='ip', acl_name=acl_name)

    # Begin testing different Ingress and Egress ACLs applied to one port
    acl_name_in = 'testIngress'
    acl_name_out = 'testEgress'
    test_num += 1
    step(
        '#### T{test_num} Mix Ingress and Egress IPV4 ACL ####\n'
        '#### On one port with two ACLs with one ACE each ####\n'
        '#### Ingress permit udp any Network L4 lt ####\n'
        '#### Egress deny tcp Host L4 range Network L4 gt ####'
        .format(**locals())
        )
    common_in_out_apply_different_acl_test(
        sw=ops1, acl_addr_type='ip',
        acl_name_list=[acl_name_in, acl_name_out],
        seq_num_list=['1', '1'],
        action_list=['permit', 'deny'],
        proto_list=['udp', 'tcp'],
        src_ip_list=['any', '1.1.1.1'],
        src_port_list=['', 'range 1 2'],
        dst_ip_list=['1.1.1.0/24', '1.1.0.0/255.255.0.0'],
        dst_port_list=['lt 42', 'gt 50'],
        app_type='port', interface_num='1',
        dir_list=['in', 'out'],
        count_list=['', ''],
        log_list=['', '']
        )

    test_num += 1
    step(
        '#### T{test_num} Mix Ingress and Egress IPV4 ACL ####\n'
        '#### On one port with two ACLs with one ACE each count ####\n'
        '#### Egress deny sctp non-contiguous L4 eq any log ####\n'
        '#### Ingress permit 250 any Host ####'
        .format(**locals())
        )
    common_in_out_apply_different_acl_test(
        sw=ops1, acl_addr_type='ip',
        acl_name_list=[acl_name_out, acl_name_in],
        seq_num_list=['2', '500'],
        action_list=['deny', 'permit'],
        proto_list=['sctp', '250'],
        src_ip_list=['1.0.1.1/255.0.255.255', 'any'],
        src_port_list=['eq 1024', ''],
        dst_ip_list=['any', '1.1.1.2'],
        dst_port_list=['', ''],
        app_type='port', interface_num='2',
        dir_list=['out', 'in'],
        count_list=['count', ''],
        log_list=['', 'log']
        )

    test_num += 1
    step(
        '#### T{test_num} Mix Ingress and Egress IPV4 ACL ####\n'
        '#### On one port with two ACLs with one ACE each ####\n'
        '#### Ingress permit icmp any any log ####\n'
        '#### Egress permit icmp any any count ####'
        .format(**locals())
        )
    common_in_out_apply_different_acl_test(
        sw=ops1, acl_addr_type='ip',
        acl_name_list=[acl_name_in, acl_name_out],
        seq_num_list=['4', '4'],
        action_list=['permit', 'permit'],
        proto_list=['icmp', 'icmp'],
        src_ip_list=['any', 'any'],
        src_port_list=['', ''],
        dst_ip_list=['any', 'any'],
        dst_port_list=['', ''],
        app_type='port', interface_num='3',
        dir_list=['in', 'out'],
        count_list=['', 'count'],
        log_list=['log', '']
        )

    test_num += 1
    step(
        '#### T{test_num} Mix Ingress and Egress IPV4 ACL ####\n'
        '#### On one port with two ACLs with one ACE each ####\n'
        '#### Egress deny igmp Network Network count log ####\n'
        '#### Ingress deny pim non-contiguous any count log ####'
        .format(**locals())
        )
    common_in_out_apply_different_acl_test(
        sw=ops1, acl_addr_type='ip',
        acl_name_list=[acl_name_out, acl_name_in],
        seq_num_list=['4', '5'],
        action_list=['deny', 'deny'],
        proto_list=['igmp', 'pim'],
        src_ip_list=['1.1.1.0/24', '1.0.1.1/255.0.255.255'],
        src_port_list=['', ''],
        dst_ip_list=['1.1.0.0/255.255.0.0', 'any'],
        dst_port_list=['', ''],
        app_type='port', interface_num='4',
        dir_list=['out', 'in'],
        count_list=['count', 'count'],
        log_list=['log', 'log']
        )

    test_num += 1
    step(
        '#### T{test_num} Remove Ingress IPV4 ACL ####'
        .format(**locals())
        )
    unconfigure_acl(sw=ops1, acl_addr_type='ip', acl_name=acl_name_in)

    test_num += 1
    step(
        '#### T{test_num} Remove Ingress IPV4 ACL ####'
        .format(**locals())
        )
    unconfigure_acl(sw=ops1, acl_addr_type='ip', acl_name=acl_name_out)


# Helper functions


def no_apply_interface(
        sw, app_type, interface_num, acl_addr_type, acl_name, direction
        ):

    assert sw is not None
    assert app_type in ('port', 'vlan')
    assert isinstance(interface_num, str)
    assert acl_addr_type in ('ip', 'ipv6', 'mac')
    assert isinstance(acl_name, str)
    assert direction in ('in', 'out')

    print(">>>>>>>>>>>>>>>> unapplying the {acl_name} from interface "
          "{interface_num} for the "
          "direction {direction}".format(**locals()))

    if app_type == 'port':
        if acl_addr_type == 'ip':
            with sw.libs.vtysh.ConfigInterface(interface_num) as ctx:
                if direction == 'in':
                    ctx.no_apply_access_list_ip_in(acl_name)
                    pass
                else:
                    ctx.no_apply_access_list_ip_out(acl_name)
                    pass
        else:
            print(
                "<%s> address type is not supported in no_apply_interface()"
                % (acl_addr_type)
                )
            assert False
    else:
        print(
            "<%s> ACL application type is not supported in"
            " no_apply_interface()" % (app_type)
            )
        assert False

    if app_type == 'port':
        app_type = 'interface'

    wait_on_warnings(sw=sw, retries=3, polling_frequency=2)
    test_result = sw(
            'show access-list {app_type} {interface_num} {acl_addr_type} '
            'commands'.format(**locals())
            )
    print(">>>>>>>>.after\n" + test_result)
    print(">>>> The search is search(r'(apply\s+access-list\s+{acl_addr_type}"
          "\s+{acl_name}\s+{direction})'".format(**locals()))
    assert search(
       r'(apply\s+access-list\s+{acl_addr_type}\s+{acl_name}\s+{direction})'
       .format(**locals()), test_result
       ) is None


def unconfigure_ace(sw, acl_addr_type, acl_name, seq_num):

    assert sw is not None
    assert acl_addr_type in ('ip', 'ipv6', 'mac')
    assert isinstance(acl_name, str)
    assert isinstance(seq_num, str)

    if acl_addr_type == 'ip':
        with sw.libs.vtysh.ConfigAccessListIpTestname(acl_name) as ctx:
            ctx.no(seq_num)
    else:
        print(
            "<%s> ACL address type is not supported in"
            " unconfigure_ace()" % (acl_addr_type)
            )

    wait_on_warnings(sw=sw, retries=3, polling_frequency=2)

    test_result = sw(
            'show access-list {acl_addr_type} {acl_name} commands'
            .format(**locals())
            )
    print(test_result)
    assert search(r'\n\s+{seq_num}'.format(**locals()), test_result) is None


def common_apply_test(
        sw, acl_addr_type, acl_name, seq_num, action, proto,
        src_ip, src_port, dst_ip, dst_port, app_type, interface_num,
        direction, count, log
        ):

    assert sw is not None
    assert acl_addr_type in ('ip', 'ipv6', 'mac')
    assert isinstance(acl_name, str)
    assert isinstance(seq_num, str)
    assert action in ('permit', 'deny')
    assert isinstance(proto, str)
    assert isinstance(src_ip, str)
    assert isinstance(src_port, str)
    assert isinstance(dst_ip, str)
    assert isinstance(dst_port, str)
    assert app_type in ('port', 'vlan')
    assert isinstance(interface_num, str)
    assert direction in ('in', 'out')
    assert count in ('count', '')
    assert log in ('log', '')

    common_in_out_apply_one_acl_one_ace_test(
        sw=sw, acl_addr_type=acl_addr_type, acl_name=acl_name, seq_num=seq_num,
        action=action, proto=proto, src_ip=src_ip, src_port=src_port,
        dst_ip=dst_ip, dst_port=dst_port, app_type=app_type,
        interface_num=interface_num, dir_list=[direction],
        count=count, log=log
    )


def common_in_out_apply_one_acl_one_ace_test(
        sw, acl_addr_type, acl_name, seq_num, action, proto,
        src_ip, src_port, dst_ip, dst_port, app_type, interface_num,
        dir_list, count, log
        ):

    assert sw is not None
    assert acl_addr_type in ('ip', 'ipv6', 'mac')
    assert isinstance(acl_name, str)
    assert isinstance(seq_num, str)
    assert action in ('permit', 'deny')
    assert isinstance(proto, str)
    assert isinstance(src_ip, str)
    assert isinstance(src_port, str)
    assert isinstance(dst_ip, str)
    assert isinstance(dst_port, str)
    assert app_type in ('port', 'vlan')
    assert isinstance(interface_num, str)
    assert isinstance(dir_list, list)
    assert count in ('count', '')
    assert log in ('log', '')

    for direction in dir_list:
        assert direction in ['in', 'out']

    configure_acl_l3(
        sw=sw, acl_addr_type=acl_addr_type, acl_name=acl_name, seq_num=seq_num,
        action=action, proto=proto, src_ip=src_ip,
        src_port=src_port, dst_ip=dst_ip, dst_port=dst_port, count=count,
        log=log
        )
    for direction in dir_list:
        apply_acl(
            sw=sw, app_type=app_type, interface_num=interface_num,
            acl_addr_type=acl_addr_type, acl_name=acl_name, direction=direction
            )
    for direction in dir_list:
        no_apply_interface(
            sw=sw, app_type=app_type, interface_num=interface_num,
            acl_addr_type=acl_addr_type, acl_name=acl_name, direction=direction
            )
    unconfigure_ace(
        sw=sw, acl_addr_type=acl_addr_type, acl_name=acl_name,
        seq_num=seq_num
        )


def common_in_out_apply_different_acl_test(
        sw, acl_addr_type, acl_name_list, seq_num_list, action_list,
        proto_list, src_ip_list, src_port_list, dst_ip_list, dst_port_list,
        app_type, interface_num, dir_list, count_list, log_list
        ):

    assert sw is not None
    assert acl_addr_type in ('ip', 'ipv6', 'mac')
    assert isinstance(acl_name_list, list)
    for acl_name in acl_name_list:
        assert isinstance(acl_name, str)
    assert isinstance(seq_num_list, list)
    for seq_num in seq_num_list:
        assert isinstance(seq_num, str)
    assert isinstance(action_list, list)
    for action in action_list:
        assert action in ('permit', 'deny')
    assert isinstance(proto_list, list)
    for proto in proto_list:
        assert isinstance(proto, str)
    assert isinstance(src_ip_list, list)
    for src_ip in src_ip_list:
        assert isinstance(src_ip, str)
    assert isinstance(src_port_list, list)
    for src_port in src_port_list:
        assert isinstance(src_port, str)
    assert isinstance(dst_ip_list, list)
    for dst_ip in dst_ip_list:
        assert isinstance(dst_ip, str)
    assert app_type in ('port', 'vlan')
    assert isinstance(interface_num, str)
    assert isinstance(dir_list, list)
    for direction in dir_list:
        assert direction in ['in', 'out']
    assert isinstance(count_list, list)
    for count in count_list:
        assert count in ('count', '')
    assert isinstance(log_list, list)
    for log in log_list:
        assert log in ('log', '')

    # For each acl named, there needs to be one ACE and one direction for the
    # acl to applied to the one interface
    for i in list(range(len(acl_name_list))):
        configure_acl_l3(
            sw=sw, acl_addr_type=acl_addr_type, acl_name=acl_name_list[i],
            seq_num=seq_num_list[i], action=action_list[i],
            proto=proto_list[i], src_ip=src_ip_list[i],
            src_port=src_port_list[i], dst_ip=dst_ip_list[i],
            dst_port=dst_port_list[i], count=count_list[i], log=log_list[i]
            )
    for i in list(range(len(acl_name_list))):
        apply_acl(
            sw=sw, app_type=app_type, interface_num=interface_num,
            acl_addr_type=acl_addr_type, acl_name=acl_name_list[i],
            direction=dir_list[i]
            )
    for i in list(range(len(acl_name_list))):
        no_apply_interface(
            sw=sw, app_type=app_type, interface_num=interface_num,
            acl_addr_type=acl_addr_type, acl_name=acl_name_list[i],
            direction=dir_list[i]
            )
    for i in list(range(len(acl_name_list))):
        unconfigure_ace(
            sw=sw, acl_addr_type=acl_addr_type, acl_name=acl_name_list[i],
            seq_num=seq_num_list[i]
            )
