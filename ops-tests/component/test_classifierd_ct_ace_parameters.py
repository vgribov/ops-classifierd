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
OpenSwitch Test for adding ACL entries.
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
@mark.test_id(10402)
def test_ace_parameters(topology, step):
    """
    Adding ACL entries

    Build a topology of one switch. Tested the ability to properly add ACE
    """
    ops1 = topology.get('ops1')

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

    assert ops1 is not None

    step('################ T0 Make sure there are no ACLs defined ###########')
    out = ops1.libs.vtysh.show_access_list_commands('')
    for acl_type in out['access-list']:
        for acl_name in out['access-list'][acl_type]:
            print("Cleaning: " + acl_type + " " + acl_name)
            with ops1.libs.vtysh.Configure() as ctx:
                ctx.no_access_list(type=acl_type, access_list=acl_name)

    step('################ T1 Add Permit ACE ###########')
    step('################ to existing ACL ###############')

    # NOTE: tests 1-3 use access-list 'test1'
    acl_test = 'test1'

    with ops1.libs.vtysh.ConfigAccessListIp(acl_test) as ctx:
        ctx.permit('', '1', 'pim', '1.2.3.4', '', '5.6.7.8', '')
    out = ops1.libs.vtysh.show_access_list_commands('')
    assert(acl_test in out['access-list']['ip'])
    aces = out['access-list']['ip'][acl_test]['aces']
    assert(len(aces) == 1)

    step('################ T2 Add Deny ACE ###########')
    step('################ to existing ACL ###############')

    with ops1.libs.vtysh.ConfigAccessListIp(acl_test) as ctx:
        ctx.deny('', '1', 'igmp', '1.2.3.4', '', '5.6.7.8', '')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    aces = out['access-list']['ip'][acl_test]['aces']
    assert(len(aces) == 1)
    ace = out['access-list']['ip'][acl_test]['aces'][0]
    assert(ace['action'] == 'deny')
    assert(ace['protocol'] == 'igmp')

    step('################ T3 Remove ACE ###########')
    step('################ from existing ACL ###############')

    with ops1.libs.vtysh.ConfigAccessListIp(acl_test) as ctx:
        ctx.no('1')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert(acl_test in out['access-list']['ip'])
    aces = out['access-list']['ip'][acl_test]['aces']
    assert(len(aces) == 0)

    step('################ T4a Apply ACL ###########')
    step('################ to interface ###############')
    step('################ ACL does not exist ###############')

    with raises(exceptions.AclDoesNotExistException):
        with ops1.libs.vtysh.ConfigInterface('4') as ctx:
            ctx.apply_access_list('ip', 'test4', 'in')

    step('################ T4b Apply ACL ###########')
    step('################ to interface ###############')
    step('################ Create ACL first ###############')

    with ops1.libs.vtysh.ConfigAccessListIp('test4') as ctx:
        ctx.permit(
            '',
            '8', 'igmp', '1.2.3.4/255.0.0.0',
            '', '5.6.7.8/255.255.0.0', '')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('')
    assert('test4' in out['access-list']['ip'])
    aces = out['access-list']['ip']['test4']['aces']
    assert(len(aces) == 1)
    ace = out['access-list']['ip']['test4']['aces'][0]
    assert(ace['seq'] == '8')
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

    step('################ T5 Remove ACL ###########')
    step('################ on interface ###############')

    with ops1.libs.vtysh.ConfigInterface('4') as ctx:
        ctx.no_apply_access_list('ip', 'test4', 'in')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('')
    acl = out['access-list']['ip']['test4']
    assert('applied' not in acl)

    step('################ T6 Replace an ACE ###########')
    step('################ in existing ACL ###############')

    # NOTE: tests 6-10 use access-list 'test1'
    acl_test = 'test1'

    with ops1.libs.vtysh.ConfigAccessListIp(acl_test) as ctx:
        ctx.permit('', '25', 'sctp', '1.2.3.4/8', '', '5.6.7.8/24', '')
    out = ops1.libs.vtysh.show_running_config()
    assert(acl_test in out['access-list']['ip'])
    aces = out['access-list']['ip'][acl_test]['aces']
    assert(len(aces) == 1)
    ace = aces[0]
    assert(ace['seq'] == '25')
    assert(ace['src'] == '1.2.3.4')
    assert(ace['src_mask'] == '255.0.0.0')
    assert(ace['src_op'] is None)
    assert(ace['dst'] == '5.6.7.8')
    assert(ace['dst_mask'] == '255.255.255.0')
    assert(ace['dst_eq'] is None)

    with ops1.libs.vtysh.ConfigAccessListIp(acl_test) as ctx:
        ctx.permit('', '25', 'sctp', '172.21.30.4/24', 'eq 10', 'any', 'eq 20')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    aces = out['access-list']['ip'][acl_test]['aces']
    assert(len(aces) == 1)
    ace = aces[0]
    assert(ace['src'] == '172.21.30.4')
    assert(ace['src_mask'] == '255.255.255.0')
    assert(ace['src_op'] == 'eq 10')
    assert(ace['dst'] == 'any')
    assert(ace['dst_mask'] is None)
    assert(ace['dst_eq'] == '20')

    step('################ T7 Remove ACE from ACL ###########')
    step('################ Remove ACL ###############')

    with ops1.libs.vtysh.ConfigAccessListIp(acl_test) as ctx:
        ctx.no('25')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    aces = out['access-list']['ip'][acl_test]['aces']
    assert(len(aces) == 0)

    step('################ Remove ACL ###############')
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list('ip', acl_test)
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert(acl_test not in out['access-list']['ip'])

    step('################ T8 Add ACE sctp ###########')
    step('################ invalid L4 src port ###############')

    with raises(exceptions.UnknownCommandException):
        with ops1.libs.vtysh.ConfigAccessListIp(acl_test) as ctx:
            ctx.permit(
                '',
                '30', 'sctp', '1.2.3.4/8', 'eq 66000',
                '5.6.7.8/24', 'eq 40')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert(acl_test in out['access-list']['ip'])
    aces = out['access-list']['ip'][acl_test]['aces']
    assert(len(aces) == 0)

    step('################ T9 Add ACE sctp ###########')
    step('################ valid L4 src, dst port ###############')

    with ops1.libs.vtysh.ConfigAccessListIp(acl_test) as ctx:
        ctx.deny(
                '',
                '30', 'sctp', '1.2.3.4/8', 'eq 65000',
                '5.6.7.8/24', 'eq 40')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert(acl_test in out['access-list']['ip'])
    aces = out['access-list']['ip'][acl_test]['aces']
    assert(len(aces) == 1)
    ace = aces[0]
    assert(ace['src_eq'] == '65000')
    assert(ace['dst_eq'] == '40')

    step('################ T10 Add ACE sctp ###########')
    step('################ invalid L4 dst port ###############')

    with raises(exceptions.UnknownCommandException):
        with ops1.libs.vtysh.ConfigAccessListIp(acl_test) as ctx:
            ctx.permit(
                '',
                '30', 'sctp', '1.2.3.4/8', 'eq 4',
                '5.6.7.8/24', 'eq 66000')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert(acl_test in out['access-list']['ip'])
    aces = out['access-list']['ip'][acl_test]['aces']
    assert(len(aces) == 1)
    ace = aces[0]
    assert(ace['src_eq'] == '65000')
    assert(ace['dst_eq'] == '40')

    step('################ T11 Add ACE sctp ###########')
    step('################ range min,max port ###############')
    step('################ ECHO WORKAROUND ###############')
    acl_test = 'test11'
    with raises(exceptions.EchoCommandException):
        with ops1.libs.vtysh.ConfigAccessListIp(acl_test) as ctx:
            ctx.permit(
                '',
                '40', 'sctp', '1.2.3.4/1', 'range 100 500',
                '5.6.7.8/32', 'range 40 50')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert(acl_test in out['access-list']['ip'])
    aces = out['access-list']['ip'][acl_test]['aces']
    assert(len(aces) == 1)
    ace = aces[0]
    assert(ace['src_range'] == '100 500')
    assert(ace['dst_range'] == '40 50')

    step('################ T12 Add ACE sctp ###########')
    step('################ range min,max port ###############')
    acl_test = 'test12'
    with raises(exceptions.InvalidL4SourcePortRangeException):
        with ops1.libs.vtysh.ConfigAccessListIp(acl_test) as ctx:
            ctx.permit(
                '',
                '12', 'sctp', '1.2.3.4/1', 'range 100 5',
                '5.6.7.8/32', 'range 400 50')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert(acl_test in out['access-list']['ip'])
    aces = out['access-list']['ip'][acl_test]['aces']
    assert(len(aces) == 0)

    step('################ T12 Add ACE sctp ###########')
    step('################ range min,max port ###############')

    with raises(exceptions.InvalidL4SourcePortRangeException):
        with ops1.libs.vtysh.ConfigAccessListIp(acl_test) as ctx:
            ctx.permit(
                '',
                '12', 'sctp', 'any', 'range 100 5',
                'any', 'range 400 50')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert(acl_test in out['access-list']['ip'])
    aces = out['access-list']['ip'][acl_test]['aces']
    assert(len(aces) == 0)

    step('################ T13 Add ACE sctp ###########')
    step('################ invalid prefix ###############')

    acl_test = 'test13'
    with raises(exceptions.UnknownCommandException):
        with ops1.libs.vtysh.ConfigAccessListIp(acl_test) as ctx:
            ctx.permit(
                '',
                '13', 'sctp', '1.2.3.4/40', 'eq 100 ',
                '5.6.7.8/60', 'eq 40')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert(acl_test in out['access-list']['ip'])
    aces = out['access-list']['ip'][acl_test]['aces']
    assert(len(aces) == 0)

    step('################ T14 Add ACE sctp ###########')
    step('################ invalid subnet mask ###############')

    acl_test = 'test14'
    with raises(exceptions.UnknownCommandException):
        with ops1.libs.vtysh.ConfigAccessListIp(acl_test) as ctx:
            ctx.permit(
                '',
                '14', 'sctp', '1.2.3.4/259.1.1.1', 'eq 100 ',
                '5.6.7.8/271.0.0.0', 'eq 40')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert(acl_test in out['access-list']['ip'])
    aces = out['access-list']['ip'][acl_test]['aces']
    assert(len(aces) == 0)

    step('################ T15 Add ACE ###########')
    step('################ invalid numeric proto ###############')

    acl_test = 'test15'
    with raises(exceptions.UnknownCommandException):
        with ops1.libs.vtysh.ConfigAccessListIp(acl_test) as ctx:
            ctx.permit(
                '',
                '15', '290', '1.2.3.4/255.255.255.0', '',
                '5.6.7.8/255.0.0.0', '')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert(acl_test in out['access-list']['ip'])
    aces = out['access-list']['ip'][acl_test]['aces']
    assert(len(aces) == 0)

    step('################ T16 Add ACE ###########')
    step('################ unsupported proto ###############')

    acl_test = 'test16'
    with raises(exceptions.UnknownCommandException):
        with ops1.libs.vtysh.ConfigAccessListIp(acl_test) as ctx:
            ctx.permit(
                '',
                '16', '999', '1.2.3.4', '',
                '5.6.7.8', '')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert(acl_test in out['access-list']['ip'])
    aces = out['access-list']['ip'][acl_test]['aces']
    assert(len(aces) == 0)

    step('################ T17 Add Maximum ###########')
    step('################ Allowed ACE ###############')
    step('################ Command success. ###############')

    acl_test = 'test17'
    max_aces = 512
    with raises(exceptions.MaxACEsException):
        with ops1.libs.vtysh.ConfigAccessListIp(acl_test) as ctx:
            for i in range(1, 514):
                ctx.deny(
                    '',
                    i, 'udp', '1.2.3.4/8', 'eq 4',
                    '5.6.7.8/24', 'eq 40')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert(acl_test in out['access-list']['ip'])
    aces = out['access-list']['ip'][acl_test]['aces']
    assert(len(aces) == max_aces)

    step('################ T18 Add ACE ###########')
    step('################ Resequence ACEs###############')

    with ops1.libs.vtysh.ConfigAccessListIp('test18') as ctx:
        ctx.permit('', '25', 'sctp', '172.21.30.4/24', 'eq 10', 'any', 'eq 20')
        ctx.permit('', '35', 'tcp', '172.21.30.4/24', 'eq 10', 'any', 'eq 20')
        ctx.permit('', '45', 'udp', '172.21.30.4/24', 'eq 10', 'any', 'eq 20')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('test18' in out['access-list']['ip'])
    aces = out['access-list']['ip']['test18']['aces']
    assert(len(aces) == 3)
    assert(aces[0]['seq'] == '25')
    assert(aces[1]['seq'] == '35')
    assert(aces[2]['seq'] == '45')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list_resequence('ip', 'test18', '1', '10')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    aces = out['access-list']['ip']['test18']['aces']
    assert(len(aces) == 3)
    assert(aces[0]['seq'] == '1')
    assert(aces[1]['seq'] == '11')
    assert(aces[1]['action'] == 'permit')
    assert(aces[2]['seq'] == '21')

    step('################ T19 Add ACE ###########')
    step('################ Resequence ACEs###############')
    step('################ Negative Test###############')

    with raises(exceptions.ResequenceNumberException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.access_list_resequence('ip', 'test18', '4294967295', '10')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    # sequence should not change
    aces = out['access-list']['ip']['test18']['aces']
    assert(len(aces) == 3)
    assert(aces[0]['seq'] == '1')
    assert(aces[1]['seq'] == '11')
    assert(aces[2]['seq'] == '21')

    step('################ T20 Replace deny ACE ###########')
    step('################ with Permit ACE ###############')

    with ops1.libs.vtysh.ConfigAccessListIp('test18') as ctx:
        ctx.deny('',
                 '11', 'tcp', '172.21.30.4/24', 'eq 10',
                 'any', 'eq 20')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    aces = out['access-list']['ip']['test18']['aces']
    assert(aces[1]['action'] == 'deny')

    step('################ T21 Remove ACE ###########')
    step('################ Negative Test ###############')

    with raises(exceptions.AceDoesNotExistException):
        with ops1.libs.vtysh.ConfigAccessListIp('test18') as ctx:
            ctx.no('4101')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    aces = out['access-list']['ip']['test18']['aces']
    assert(len(aces) == 3)

    step('################ T22 Remove ACE ###########')
    step('################ Positive Test ###############')
    with ops1.libs.vtysh.ConfigAccessListIp('test17') as ctx:
        ctx.no('401')
    if in_docker:
        time.sleep(2)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    aces = out['access-list']['ip']['test17']['aces']
    assert(len(aces) == (max_aces - 1))
