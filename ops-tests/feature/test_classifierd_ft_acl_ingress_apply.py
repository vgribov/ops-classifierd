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

from pytest import mark, raises
from topology_lib_vtysh import exceptions
import time

TOPOLOGY = """
# +--------+
# |  ops1  |
# +--------+

# Nodes
[type=openswitch name="OpenSwitch 1"] ops1

# Links
"""


@mark.gate
@mark.test_id(10403)
def test_ace_apply(topology, step):
    """
    Test apply of ACEs to ports.

    Build a topology of one switch. Tested the ability to properly add ACL,
    delete ACL.
    """
    ops1 = topology.get('ops1')

    assert ops1 is not None

    # check if running in Docker -- will need to sleep after apply
    # and un-apply if so.
    _shell = ops1.get_shell('bash')
    _shell.send_command('ovs-appctl container/show-acl')
    out = _shell.get_response()
    print(out)
    if "server returned an error" in out:
        print("TEST ON HARDWARE")
        in_docker = 0
    else:
        print("TEST IN DOCKER")
        in_docker = 1

    step('################ T0 Make sure there are no ACLs defined ###########')
    out = ops1.libs.vtysh.show_access_list_commands('')
    for acl_type in out['access-list']:
        for acl_name in out['access-list'][acl_type]:
            print("Cleaning: " + acl_type + " " + acl_name)
            with ops1.libs.vtysh.Configure() as ctx:
                ctx.no_access_list(type=acl_type, access_list=acl_name)

    step('################ T1 Add Permit ACE ###########')
    step('################ to existing ACL ###############')

    with ops1.libs.vtysh.ConfigAccessListIp('test1') as ctx:
        ctx.permit('', '1', 'pim', '1.2.3.4', '', '5.6.7.8', '')
    out = ops1.libs.vtysh.show_access_list_commands('')
    assert('test1' in out['access-list']['ip'])

    step('################ T2 Replace ACE with Deny ###########')
    step('################ in existing ACL ###############')

    with ops1.libs.vtysh.ConfigAccessListIp('test1') as ctx:
        ctx.deny('', '1', 'igmp', '1.2.3.4', '', '5.6.7.8', '')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_running_config()
    assert('test1' in out['access-list']['ip'])
    aces = out['access-list']['ip']['test1']['aces']
    assert(len(aces) == 1)

    step('################ T3 Remove ACE ###########')
    step('################ from existing ACL ###############')

    with ops1.libs.vtysh.ConfigAccessListIp('test1') as ctx:
        ctx.no('1')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_running_config()
    assert('test1' in out['access-list']['ip'])
    aces = out['access-list']['ip']['test1']['aces']
    assert(len(aces) == 0)

    step('################ T4a Apply ACL ###########')
    step('################ to interface ###############')
    step('################ ACL does not exist ###############')
    with raises(exceptions.AclDoesNotExistException):
        with ops1.libs.vtysh.ConfigInterface('4') as ctx:
            ctx.apply_access_list('ip', 'test4', 'in')

    step('################ T4b Apply ACL ###########')
    step('################ to interface ###############')
    step('################ igmp protocol  ###############')

    with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
        ctx.permit(
            '',
            '4', 'igmp', '1.2.3.4/255.0.0.0',
            '', '5.6.7.8/255.255.0.0', '')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('')
    assert('test4' in out['access-list']['ip'])
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 1)
    ace = out['access-list']['ip']['test4']['aces'][0]
    assert(ace['seq'] == '4')
    assert(ace['action'] == 'permit')
    assert(ace['protocol'] == 'igmp')
    assert(ace['src'] == '1.2.3.4')
    assert(ace['dst'] == '5.6.7.8')

    with ops1.libs.vtysh.ConfigInterface('4') as ctx:
        ctx.apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    acl = out['access-list']['ip']['test4']
    assert(acl['applied'] == 'yes')

    with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
        ctx.no('4')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 0)

    step('################ T5 Apply no ACL ###########')
    step('################ on interface 4 ###############')

    with ops1.libs.vtysh.ConfigInterface('4') as ctx:
        ctx.no_apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('')
    acl = out['access-list']['ip']['test4']
    assert('applied' not in acl)

    step('################ T6 Apply ACL ###########')
    step('################ to interface ###############')
    step('################ A.B.C.D/M Network  ###############')

    with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
        ctx.permit(
            '',
            '6', 'igmp', '1.2.3.4/8',
            '', '5.6.7.8/24', '')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_running_config()
    assert('test4' in out['access-list']['ip'])
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 1)
    ace = out['access-list']['ip']['test4']['aces'][0]
    assert(ace['seq'] == '6')
    assert(ace['action'] == 'permit')
    assert(ace['protocol'] == 'igmp')
    assert(ace['src_mask'] == '255.0.0.0')
    assert(ace['dst_mask'] == '255.255.255.0')

    with ops1.libs.vtysh.ConfigInterface('5') as ctx:
        ctx.apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    acl = out['access-list']['ip']['test4']
    assert(acl['applied'] == 'yes')

    with ops1.libs.vtysh.ConfigInterface('5') as ctx:
        ctx.no_apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    acl = out['access-list']['ip']['test4']
    assert('applied' not in acl)

    with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
        ctx.no('6')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_running_config()
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 0)

    step('################ T7 Apply ACL ###########')
    step('################ to interface ###############')
    step('################ A.B.C.D Host  ###############')

    with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
        ctx.permit(
            '',
            '7', 'igmp', '1.2.3.4',
            '', '5.6.7.8', '')

    with ops1.libs.vtysh.ConfigInterface('7') as ctx:
        ctx.apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_running_config()
    assert('test4' in out['access-list']['ip'])
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 1)
    ace = out['access-list']['ip']['test4']['aces'][0]
    assert(ace['seq'] == '7')
    assert(ace['action'] == 'permit')
    assert(ace['protocol'] == 'igmp')
    assert(ace['src'] == '1.2.3.4')
    assert(ace['dst_mask'] is None)

    with ops1.libs.vtysh.ConfigInterface('7') as ctx:
        ctx.apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    acl = out['access-list']['ip']['test4']
    assert(acl['applied'] == 'yes')

    with ops1.libs.vtysh.ConfigInterface('7') as ctx:
        ctx.no_apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    acl = out['access-list']['ip']['test4']
    assert('applied' not in acl)

    with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
        ctx.no('7')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_running_config()
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 0)

    step('################ T8 Apply IPV4 ACL ###########')
    step('################ to interface ###############')
    step('################ proto any Host  ###############')

    with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
        ctx.permit(
            '',
            '8', '4', 'any',
            '', 'any', '')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_running_config()
    assert('test4' in out['access-list']['ip'])
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 1)
    ace = out['access-list']['ip']['test4']['aces'][0]
    assert(ace['seq'] == '8')
    assert(ace['action'] == 'permit')
    assert(ace['protocol'] == '4')
    assert(ace['src'] == 'any')

    with ops1.libs.vtysh.ConfigInterface('8') as ctx:
        ctx.apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    acl = out['access-list']['ip']['test4']
    assert(acl['applied'] == 'yes')

    with ops1.libs.vtysh.ConfigInterface('8') as ctx:
        ctx.no_apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    acl = out['access-list']['ip']['test4']
    assert('applied' not in acl)

    step('################ T9 Apply ACL ###########')
    step('################ to interface ###############')
    step('################ sctp eq L4  ###############')

    with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
        ctx.permit(
            '',
            '9', 'sctp', '172.21.30.4/24',
            'eq 10', '5.6.7.8/24', 'eq 11')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('test4' in out['access-list']['ip'])
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 2)  # ace from test 8 was not removed!
    ace = out['access-list']['ip']['test4']['aces'][1]
    assert(ace['seq'] == '9')
    assert(ace['protocol'] == 'sctp')
    assert(ace['src_eq'] == '10')
    assert(ace['dst_eq'] == '11')

    with ops1.libs.vtysh.ConfigInterface('9') as ctx:
        ctx.apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    acl = out['access-list']['ip']['test4']
    assert(acl['applied'] == 'yes')

    with ops1.libs.vtysh.ConfigInterface('9') as ctx:
        ctx.no_apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    acl = out['access-list']['ip']['test4']
    assert('applied' not in acl)

    with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
        ctx.no('9')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_running_config()
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 1)

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list('ip', 'test4')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('test4' not in out['access-list']['ip'])

    step('################ T10 Apply ACL ###########')
    step('################ to interface ###############')
    step('################ sctp eq L4  ###############')

    with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
        ctx.permit(
            '',
            '10', 'sctp', '172.21.30.4/24',
            'eq 10', '5.6.7.8/24', 'eq 11')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_running_config()
    assert('test4' in out['access-list']['ip'])
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 1)
    ace = out['access-list']['ip']['test4']['aces'][0]
    assert(ace['seq'] == '10')
    assert(ace['action'] == 'permit')
    assert(ace['protocol'] == 'sctp')

    with ops1.libs.vtysh.ConfigInterface('10') as ctx:
        ctx.apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    acl = out['access-list']['ip']['test4']
    assert(acl['applied'] == 'yes')

    with ops1.libs.vtysh.ConfigInterface('10') as ctx:
        ctx.no_apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    acl = out['access-list']['ip']['test4']
    assert('applied' not in acl)

    with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
        ctx.no('10')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_running_config()
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 0)

    step('################ T11 Apply ACL ###########')
    step('################ to interface ###############')
    step('################ sctp gt L4  ###############')

    with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
        ctx.permit(
            '',
            '11', 'sctp', '172.21.30.4/24',
            'gt 10', '5.6.7.8/24', 'gt 11')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_running_config()
    assert('test4' in out['access-list']['ip'])
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 1)
    ace = out['access-list']['ip']['test4']['aces'][0]
    assert(ace['seq'] == '11')
    assert(ace['dst_gt'] == '11')

    with ops1.libs.vtysh.ConfigInterface('11') as ctx:
        ctx.apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    acl = out['access-list']['ip']['test4']
    assert(acl['applied'] == 'yes')

    with ops1.libs.vtysh.ConfigInterface('11') as ctx:
        ctx.no_apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    acl = out['access-list']['ip']['test4']
    assert('applied' not in acl)

    with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
        ctx.no('11')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_running_config()
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 0)

    step('################ T12 Apply ACL ###########')
    step('################ to interface ###############')
    step('################ sctp lt L4  ###############')

    with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
        ctx.permit(
            '',
            '12', 'sctp', '172.21.30.4/24',
            'lt 10', '5.6.7.8/24', 'lt 11')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_running_config()
    assert('test4' in out['access-list']['ip'])
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 1)
    ace = out['access-list']['ip']['test4']['aces'][0]
    assert(ace['seq'] == '12')
    assert(ace['src_lt'] == '10')

    with ops1.libs.vtysh.ConfigInterface('12') as ctx:
        ctx.apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    acl = out['access-list']['ip']['test4']
    assert(acl['applied'] == 'yes')

    with ops1.libs.vtysh.ConfigInterface('12') as ctx:
        ctx.no_apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    acl = out['access-list']['ip']['test4']
    assert('applied' not in acl)

    with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
        ctx.no('12')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_running_config()
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 0)

    step('################ T13 Apply ACL ###########')
    step('################ to interface ###############')
    step('################ sctp range L4  ###############')
    step('################ EchoCommandException  ###############')

    with raises(exceptions.EchoCommandException):
        with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
            ctx.permit(
                '',
                '13', 'sctp', '1.2.3.4/1', 'range 100 500',
                '5.6.7.8/32', 'range 40 50')
    out = ops1.libs.vtysh.show_running_config()
    assert('test4' in out['access-list']['ip'])
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 1)
    ace = out['access-list']['ip']['test4']['aces'][0]
    assert(ace['seq'] == '13')
    assert(ace['src_range'] == '100 500')
    assert(ace['dst_op'] == 'range 40 50')

    with ops1.libs.vtysh.ConfigInterface('13') as ctx:
        ctx.apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    acl = out['access-list']['ip']['test4']
    assert(acl['applied'] == 'yes')

    with ops1.libs.vtysh.ConfigInterface('13') as ctx:
        ctx.no_apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    acl = out['access-list']['ip']['test4']
    assert('applied' not in acl)

    with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
        ctx.no('13')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_running_config()
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 0)

    step('################ T14 Apply ACL ###########')
    step('################ to interface tcp ###############')
    step('################ 6(UnknownCommand) eq L4  ###############')

    with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
        ctx.deny(
                '',
                '14', 'tcp', '1.2.3.4/8', 'eq 4',
                '5.6.7.8/24', 'eq 40')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_running_config()
    assert('test4' in out['access-list']['ip'])
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 1)
    ace = out['access-list']['ip']['test4']['aces'][0]
    assert(ace['seq'] == '14')
    assert(ace['src_eq'] == '4')

    with ops1.libs.vtysh.ConfigInterface('14') as ctx:
        ctx.apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    acl = out['access-list']['ip']['test4']
    assert(acl['applied'] == 'yes')

    with ops1.libs.vtysh.ConfigInterface('14') as ctx:
        ctx.no_apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    acl = out['access-list']['ip']['test4']
    assert('applied' not in acl)

    with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
        ctx.no('14')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_running_config()
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 0)

    step('################ T15 Apply ACL ###########')
    step('################ to interface tcp ###############')
    step('################ range L4  ###############')

    with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
        ctx.deny(
                '',
                '15', 'tcp', '1.2.3.4/8', 'range 4 6',
                '5.6.7.8/24', 'range 40 60')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_running_config()
    assert('test4' in out['access-list']['ip'])
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 1)
    ace = out['access-list']['ip']['test4']['aces'][0]
    assert(ace['seq'] == '15')
    assert(ace['dst_range'] == '40 60')

    with ops1.libs.vtysh.ConfigInterface('15') as ctx:
        ctx.apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    acl = out['access-list']['ip']['test4']
    assert(acl['applied'] == 'yes')

    with ops1.libs.vtysh.ConfigInterface('15') as ctx:
        ctx.no_apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    acl = out['access-list']['ip']['test4']
    assert('applied' not in acl)

    with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
        ctx.no('15')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_running_config()
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 0)
