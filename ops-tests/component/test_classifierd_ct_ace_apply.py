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
import time

TOPOLOGY = """
# +--------+
# |  ops1  |
# +--------+

# Nodes
[type=openswitch name="OpenSwitch 1"] ops1

# Links
"""


@mark.test_id(10403)
def test_ace_apply(topology, step):
    step('################ Introduce delay in ACE ###########')
    step('################ creation in case docker ###############')
    step('################ is not up for > 45 seconds ###############')

    # Temporarily adding a sleep time at boot up to ensure switchd
    # deamonizing completely. Will remove sleep when test framework
    # implements switchd deamonizing checking
    time.sleep(60)

    """
    Test apply of ACEs to ports.

    Build a topology of one switch. Tested the ability to properly add ACL,
    delete ACL.
    """
    ops1 = topology.get('ops1')

    assert ops1 is not None

    step('################ T1 Add Permit ACE ###########')
    step('################ to existing ACL ###############')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test1') as ctx:
        ctx.permit('', '1', 'pim', '1.2.3.4', '', '5.6.7.8', '')

    test1_result = ops1('show run')

    # Test pass criteria
    assert search(
       ''
       r'1\s+permit\s+pim\s+[0-9]\.[0-9]\.[0-9]\.[0-9]'
       '\s+[0-9]\.[0-9]\.[0-9]\.[0-9]'.format(
                                         **locals()
                                       ), test1_result
    )
    step('################ T2 Add Deny ACE ###########')
    step('################ to existing ACL ###############')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test1') as ctx:
        ctx.deny('', '1', 'igmp', '1.2.3.4', '', '5.6.7.8', '')

    test1_result = ops1('show run')

    # Verify acl presents after created.
    assert search(
       ''
       r'1\s+deny\s+igmp\s+[0-9]\.[0-9]\.[0-9]\.[0-9]'
       '\s+[0-9]\.[0-9]\.[0-9]\.[0-9]'.format(
                                         **locals()
                                       ), test1_result
    )

    step('################ T3 Remove ACE ###########')
    step('################ from existing ACL ###############')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test1') as ctx:
        ctx.no('1')

    test1_result = ops1('show run')

    # Verify sequence number 1 is missing
    assert search(
       r'(?!1\s+\S+)'.format(
                                         **locals()
                                       ), test1_result
    )

    step('################ T4a Apply ACL ###########')
    step('################ to interface ###############')
    step('################ ACL does not exist ###############')
    with pytest.raises(exceptions.AclDoesNotExistException):
        with ops1.libs.vtysh.ConfigInterface('4') as ctx:
            ctx.apply_access_list_ip_in('test4')

    step('################ T4b Apply ACL ###########')
    step('################ to interface ###############')
    step('################ igmp protocol  ###############')

    # time.sleep(1)
    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.permit(
            '',
            '4', 'igmp', '1.2.3.4/255.0.0.0',
            '', '5.6.7.8/255.255.0.0', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'4\s+permit\s+igmp\s+[0-9]\.[0-9]\.[0-9]\.[0-9]/255\.0\.0\.0'
       '\s+[0-9]\.[0-9]\.[0-9]\.[0-9]/255\.255\.0\.0'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('4') as ctx:
        ctx.apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    assert search(
       r'(access-list\s+ip\s+test4\s+\in)'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.no('4')

    step('################ T5 Apply no ACL ###########')
    step('################ on interface 4 ###############')

    with ops1.libs.vtysh.ConfigInterface('4') as ctx:
        ctx.no_apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    assert search(
       r'(?!access-list\s+ip\s+test4\s+\in)'.format(
                                         **locals()
                                       ), test1_result
    )

    step('################ T6 Apply ACL ###########')
    step('################ to interface ###############')
    step('################ A.B.C.D/M Network  ###############')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.permit(
            '',
            '6', 'igmp', '1.2.3.4/8',
            '', '5.6.7.8/24', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'6\s+permit\s+igmp\s+[0-9]\.[0-9]\.[0-9]\.[0-9]/255\.0\.0\.0'
       '\s+[0-9]\.[0-9]\.[0-9]\.[0-9]/255\.255\.255\.0'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('5') as ctx:
        ctx.apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    assert search(
       r'(access-list\s+ip\s+test4\s+\in)'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('5') as ctx:
        ctx.no_apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.no('6')

    step('################ T7 Apply ACL ###########')
    step('################ to interface ###############')
    step('################ A.B.C.D Host  ###############')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.permit(
            '',
            '7', 'igmp', '1.2.3.4',
            '', '5.6.7.8', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'7\s+permit\s+igmp\s+[0-9]\.[0-9]\.[0-9]\.[0-9]'
       '\s+[0-9]\.[0-9]\.[0-9]\.[0-9]'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('7') as ctx:
        ctx.apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    assert search(
       r'(access-list\s+ip\s+test4\s+\in)'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('7') as ctx:
        ctx.no_apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.no('7')

    step('################ T8 Apply IPV4 ACL ###########')
    step('################ to interface ###############')
    step('################ proto any Host  ###############')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.permit(
            '',
            '8', '4', 'any',
            '', 'any', '')

    test1_result = ops1('show run')

    assert search(
       ''
       r'8\s+permit\s+4\s+any\s+any'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('8') as ctx:
        ctx.apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    assert search(
       r'(access-list\s+ip\s+test4\s+\in)'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('8') as ctx:
        ctx.no_apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    step('################ T9 Apply ACL ###########')
    step('################ to interface ###############')
    step('################ sctp eq L4  ###############')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.permit(
            '',
            '9', 'sctp', '172.21.30.4/24',
            'eq 10', '5.6.7.8/24', 'eq 11')

    test1_result = ops1('show run')

    assert search(
       ''
       r'9\s+permit\s+sctp\s+172\.21\.30\.4/255\.255\.255\.0'
       '\s+eq\s+10\s+[0-9]\.[0-9]\.[0-9]\.[0-9]/255\.255\.255\.0'
       '\s+eq\s+11'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('9') as ctx:
        ctx.apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    assert search(
       r'(access-list\s+ip\s+test4\s+\in)'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('9') as ctx:
        ctx.no_apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.no('9')

    step('################ T10 Apply ACL ###########')
    step('################ to interface ###############')
    step('################ sctp eq L4  ###############')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.permit(
            '',
            '10', 'sctp', '172.21.30.4/24',
            'eq 10', '5.6.7.8/24', 'eq 11')

    test1_result = ops1('show run')

    assert search(
       ''
       r'10\s+permit\s+sctp\s+172\.21\.30\.4/255\.255\.255\.0'
       '\s+eq\s+10\s+[0-9]\.[0-9]\.[0-9]\.[0-9]/255\.255\.255\.0'
       '\s+eq\s+11'.format(
                                         **locals()
                                       ), test1_result
    )
    with ops1.libs.vtysh.ConfigInterface('10') as ctx:
        ctx.apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    assert search(
       r'(access-list\s+ip\s+test4\s+\in)'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('10') as ctx:
        ctx.no_apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.no('10')

    step('################ T11 Apply ACL ###########')
    step('################ to interface ###############')
    step('################ sctp gt L4  ###############')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.permit(
            '',
            '11', 'sctp', '172.21.30.4/24',
            'gt 10', '5.6.7.8/24', 'gt 11')

    test1_result = ops1('show run')

    assert search(
       ''
       r'11\s+permit\s+sctp\s+172\.21\.30\.4/255\.255\.255\.0'
       '\s+gt\s+10\s+[0-9]\.[0-9]\.[0-9]\.[0-9]/255\.255\.255\.0'
       '\s+gt\s+11'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('11') as ctx:
        ctx.apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    assert search(
       r'(access-list\s+ip\s+test4\s+\in)'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('11') as ctx:
        ctx.no_apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.no('11')

    step('################ T12 Apply ACL ###########')
    step('################ to interface ###############')
    step('################ sctp lt L4  ###############')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.permit(
            '',
            '12', 'sctp', '172.21.30.4/24',
            'lt 10', '5.6.7.8/24', 'lt 11')

    test1_result = ops1('show run')

    assert search(
       ''
       r'12\s+permit\s+sctp\s+172\.21\.30\.4/255\.255\.255\.0'
       '\s+lt\s+10\s+[0-9]\.[0-9]\.[0-9]\.[0-9]/255\.255\.255\.0'
       '\s+lt\s+11'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('12') as ctx:
        ctx.apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    assert search(
       r'(access-list\s+ip\s+test4\s+\in)'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('12') as ctx:
        ctx.no_apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.no('12')

    step('################ T13 Apply ACL ###########')
    step('################ to interface ###############')
    step('################ sctp range L4  ###############')
    step('################ EchoCommandException  ###############')

    with pytest.raises(exceptions.EchoCommandException):
        with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
            ctx.permit(
                '',
                '13', 'sctp', '1.2.3.4/1', 'range 100 500',
                '5.6.7.8/32', 'range 40 50')

    test1_result = ops1('show run')

    assert search(
       ''
       r'13\s+permit\s+sctp\s+1\.2\.3\.4/128\.0\.0\.0'
       '\s+range\s+100\s+500\s+5\.6\.7\.8\s+range\s+40\s+50'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('13') as ctx:
        ctx.apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    assert search(
       r'(access-list\s+ip\s+test4\s+\in)'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('13') as ctx:
        ctx.no_apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.no('13')

    step('################ T14 Apply ACL ###########')
    step('################ to interface tcp ###############')
    step('################ 6(UnknownCommand) eq L4  ###############')
    step('################ EchoCommandException  ###############')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.deny(
                '',
                '14', 'tcp', '1.2.3.4/8', 'eq 4',
                '5.6.7.8/24', 'eq 40')

    test1_result = ops1('show run')

    assert search(
       ''
       r'14\s+deny\s+tcp\s+1\.2\.3\.4/255\.0\.0\.0'
       '\s+eq\s+4\s+5\.6\.7\.8/255\.255\.255\.0\s+eq\s+40'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('14') as ctx:
        ctx.apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    assert search(
       r'(access-list\s+ip\s+test4\s+\in)'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('14') as ctx:
        ctx.no_apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.no('14')

    step('################ T15 Apply ACL ###########')
    step('################ to interface tcp ###############')
    step('################ range L4  ###############')
    step('################ EchoCommandException  ###############')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.deny(
                '',
                '15', 'tcp', '1.2.3.4/8', 'range 4 6',
                '5.6.7.8/24', 'range 40 60')

    test1_result = ops1('show run')

    assert search(
       ''
       r'15\s+deny\s+tcp\s+1\.2\.3\.4/255\.0\.0\.0'
       '\s+range\s+4\s+6\s+5\.6\.7\.8/255\.255\.255\.0'
       '\s+range\s+40\s+60'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('15') as ctx:
        ctx.apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    assert search(
       r'(access-list\s+ip\s+test4\s+\in)'.format(
                                         **locals()
                                       ), test1_result
    )

    with ops1.libs.vtysh.ConfigInterface('15') as ctx:
        ctx.no_apply_access_list_ip_in('test4')

    test1_result = ops1('show run')

    with ops1.libs.vtysh.ConfigAccessListIpTestname('test4') as ctx:
        ctx.no('15')
