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

import re

from copy import deepcopy
import sys
import time

from pytest import raises, mark, fixture
from topology_lib_vtysh.exceptions import IncompleteCommandException
from topology_lib_vtysh.exceptions import FailedCommandException
from topology_lib_vtysh.exceptions import UnknownCommandException

TOPOLOGY = """
# +-------+
# |  ops1 |
# +-------+

# Nodes
[type=openswitch name="OpenSwitch 1"] ops1

# Ports
ops1:1
"""

ops1 = None
p1 = None
switch_ip = None

@fixture(scope="module")
def setup(topology):
    global ops1
    ops1 = topology.get("ops1")
    assert ops1 is not None

    global p1
    p1 = ops1.ports['1']
    assert p1 is not None

    global switch_ip
    switch_ip = get_switch_ip(ops1)
    assert switch_ip is not None

    with ops1.libs.vtysh.ConfigVlan('1') as ctx:
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_routing()
        ctx.vlan_access(1)
        ctx.vlan_trunk_allowed(1)
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterfaceLag('10') as ctx:
        ctx.no_shutdown()

def get_switch_ip(switch):
    switch_ip = switch('python -c \"import socket; '
                       'print socket.gethostbyname(socket.gethostname())\"',
                       shell='bash')
    switch_ip = switch_ip.rstrip('\r\n')
    return switch_ip

### Returns true if the given string contains a line that contains each
### string in the given list of strings.
def contains_line_with(string, strings):
    for line in string.splitlines():
        found_all_strings = True
        for s in strings:
            found_all_strings = found_all_strings and (s in line)

        if found_all_strings:
            return True

    return False

def setUp_qosApplyGlobal():
    with ops1.libs.vtysh.ConfigQueueProfile('profile1') as ctx:
        ctx.map_queue_local_priority('4', '3')
        ctx.map_queue_local_priority('5', '2')
        ctx.map_queue_local_priority('6', '1')
        ctx.map_queue_local_priority('7', '0')
        ctx.map_queue_local_priority('0', '7')
        ctx.map_queue_local_priority('1', '6')
        ctx.map_queue_local_priority('2', '5')
        ctx.map_queue_local_priority('3', '4')
    with ops1.libs.vtysh.ConfigScheduleProfile('profile1') as ctx:
        ctx.dwrr_queue_weight('4', '40')
        ctx.dwrr_queue_weight('5', '50')
        ctx.dwrr_queue_weight('6', '60')
        ctx.dwrr_queue_weight('7', '70')
        ctx.dwrr_queue_weight('0', '1')
        ctx.dwrr_queue_weight('1', '10')
        ctx.dwrr_queue_weight('2', '20')
        ctx.dwrr_queue_weight('3', '30')

    with ops1.libs.vtysh.ConfigQueueProfile('SingleQ') as ctx:
        ctx.map_queue_local_priority('0', '0,1,2,3,4,5,6,7')
    with ops1.libs.vtysh.ConfigScheduleProfile('SingleQ') as ctx:
        ctx.strict_queue('0')

    with ops1.libs.vtysh.ConfigScheduleProfile('AllStrict') as ctx:
        ctx.strict_queue('4')
        ctx.strict_queue('5')
        ctx.strict_queue('6')
        ctx.strict_queue('7')
        ctx.strict_queue('0')
        ctx.strict_queue('1')
        ctx.strict_queue('2')
        ctx.strict_queue('3')

    with ops1.libs.vtysh.ConfigScheduleProfile('AllWrr') as ctx:
        ctx.dwrr_queue_weight('4', '40')
        ctx.dwrr_queue_weight('5', '50')
        ctx.dwrr_queue_weight('6', '60')
        ctx.dwrr_queue_weight('7', '70')
        ctx.dwrr_queue_weight('0', '1')
        ctx.dwrr_queue_weight('1', '10')
        ctx.dwrr_queue_weight('2', '20')
        ctx.dwrr_queue_weight('3', '30')

    with ops1.libs.vtysh.ConfigScheduleProfile('awwms') as ctx:
        ctx.dwrr_queue_weight('4', '40')
        ctx.dwrr_queue_weight('5', '50')
        ctx.dwrr_queue_weight('6', '60')
        ctx.strict_queue('7')
        ctx.dwrr_queue_weight('0', '1')
        ctx.dwrr_queue_weight('1', '10')
        ctx.dwrr_queue_weight('2', '20')
        ctx.dwrr_queue_weight('3', '30')

    with ops1.libs.vtysh.ConfigScheduleProfile('HigherStrictLowerWrr') as ctx:
        ctx.strict_queue('4')
        ctx.strict_queue('5')
        ctx.strict_queue('6')
        ctx.strict_queue('7')
        ctx.dwrr_queue_weight('0', '1')
        ctx.dwrr_queue_weight('1', '10')
        ctx.dwrr_queue_weight('2', '20')
        ctx.dwrr_queue_weight('3', '30')

    with ops1.libs.vtysh.ConfigScheduleProfile('LowerStrictHigherWrr') as ctx:
        ctx.dwrr_queue_weight('4', '40')
        ctx.dwrr_queue_weight('5', '50')
        ctx.dwrr_queue_weight('6', '60')
        ctx.dwrr_queue_weight('7', '70')
        ctx.strict_queue('0')
        ctx.strict_queue('1')
        ctx.strict_queue('2')
        ctx.strict_queue('3')

def setUp_qosDscpPort():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_qos_trust()
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_qos_trust()
        ctx.no_qos_dscp()

def get_local_priority_range():
    out = ops1.libs.vtysh.show_qos_cos_map("default")

    min_local_priority = sys.maxsize
    max_local_priority = -1
    for key, value in out.items():
        local_priority = int(value['local_priority'])

        if local_priority > max_local_priority:
            max_local_priority = local_priority

        if local_priority < min_local_priority:
            min_local_priority = local_priority

    local_priority_range = [min_local_priority, max_local_priority]
    return local_priority_range

def case_qosApplyGlobalCommand():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('profile1', 'profile1')

    out = ops1.libs.vtysh.show_qos_queue_profile()
    assert out['profile1']['profile_status'] == 'applied'
    assert out['profile1']['profile_name'] == 'profile1'
    out = ops1.libs.vtysh.show_qos_schedule_profile()
    assert out['profile1']['profile_status'] == 'applied'
    assert out['profile1']['profile_name'] == 'profile1'

def case_qosApplyGlobalCommandWithDuplicateQueueProfileQueue():
    with ops1.libs.vtysh.ConfigQueueProfile(
            'DuplicateQueueProfileQueue') as ctx:
        ctx.map_queue_local_priority('4', '3')
        ctx.map_queue_local_priority('5', '2')
        ctx.map_queue_local_priority('6', '1')
        ctx.map_queue_local_priority('7', '0')
        ctx.map_queue_local_priority('0', '7')
        ctx.map_queue_local_priority('1', '7')
        ctx.map_queue_local_priority('2', '5')
        ctx.map_queue_local_priority('3', '4')

    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.apply_qos_queue_profile_schedule_profile(
                'DuplicateQueueProfileQueue', 'profile1')

def case_qosApplyGlobalCommandWithMissingQueueProfileQueue():
    with ops1.libs.vtysh.ConfigQueueProfile(
            'MissingQueueProfileQueue') as ctx:
        ctx.map_queue_local_priority('4', '3')
        ctx.map_queue_local_priority('5', '2')
        ctx.map_queue_local_priority('6', '1')
        ctx.map_queue_local_priority('0', '7,0')
        ctx.map_queue_local_priority('1', '6')
        ctx.map_queue_local_priority('2', '5')
        ctx.map_queue_local_priority('3', '4')

    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.apply_qos_queue_profile_schedule_profile(
                'MissingQueueProfileQueue', 'profile1')

def case_qosApplyGlobalCommandWithMissingScheduleProfileQueue():
    with ops1.libs.vtysh.ConfigScheduleProfile(
            'MissingScheduleProfileQueue') as ctx:
        ctx.dwrr_queue_weight('4', '40')
        ctx.dwrr_queue_weight('5', '50')
        ctx.dwrr_queue_weight('6', '60')
        ctx.dwrr_queue_weight('0', '1')
        ctx.dwrr_queue_weight('1', '10')
        ctx.dwrr_queue_weight('2', '20')
        ctx.dwrr_queue_weight('3', '30')

    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.apply_qos_queue_profile_schedule_profile(
                'profile1', 'MissingScheduleProfileQueue')

def case_qosApplyGlobalCommandWithIllegalQueueProfile():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.apply_qos_queue_profile_schedule_profile('p&^%$1', 'profile1')

def case_qosApplyGlobalCommandWithNullQueueProfile():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.apply_qos_queue_profile_schedule_profile('', 'profile1')

def case_qosApplyGlobalCommandWithMissingQueueProfile():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.apply_qos_queue_profile_schedule_profile('missing', 'profile1')

def case_qosApplyGlobalCommandWithIllegalScheduleProfile():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.apply_qos_queue_profile_schedule_profile('profile1', 'p&^%$1')

def case_qosApplyGlobalCommandWithNullScheduleProfile():
    with raises(IncompleteCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.apply_qos_queue_profile_schedule_profile('profile1', '')

def case_qosApplyGlobalCommandWithMissingScheduleProfile():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.apply_qos_queue_profile_schedule_profile('profile1', 'missing')

def case_qosApplyGlobalCommandWithStrictScheduleProfile():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('default', 'strict')

    out = ops1.libs.vtysh.show_qos_queue_profile()
    assert out['default']['profile_status'] == 'applied'
    assert out['default']['profile_name'] == 'default'
    out = ops1.libs.vtysh.show_qos_schedule_profile()
    assert out['strict']['profile_status'] == 'applied'
    assert out['strict']['profile_name'] == 'strict'

def case_qosApplyGlobalCommandWithAllStrict():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('profile1', 'AllStrict')

    out = ops1.libs.vtysh.show_qos_queue_profile()
    assert out['profile1']['profile_status'] == 'applied'
    assert out['profile1']['profile_name'] == 'profile1'
    out = ops1.libs.vtysh.show_qos_schedule_profile()
    assert out['AllStrict']['profile_status'] == 'applied'
    assert out['AllStrict']['profile_name'] == 'AllStrict'

def case_qosApplyGlobalCommandWithAllWrr():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('profile1', 'AllWrr')

    out = ops1.libs.vtysh.show_qos_queue_profile()
    assert out['profile1']['profile_status'] == 'applied'
    assert out['profile1']['profile_name'] == 'profile1'
    out = ops1.libs.vtysh.show_qos_schedule_profile()
    assert out['AllWrr']['profile_status'] == 'applied'
    assert out['AllWrr']['profile_name'] == 'AllWrr'

def case_qosApplyGlobalCommandWithAllWrrWithMaxStrict():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile(
            'profile1', 'awwms')

    out = ops1.libs.vtysh.show_qos_queue_profile()
    assert out['profile1']['profile_status'] == 'applied'
    assert out['profile1']['profile_name'] == 'profile1'
    out = ops1.libs.vtysh.show_qos_schedule_profile()
    assert out['awwms']['profile_status'] == 'applied'
    assert out['awwms']['profile_name'] == 'awwms'

def case_qosApplyGlobalCommandWithHigherStrictLowerWrr():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.apply_qos_queue_profile_schedule_profile(
                'profile1', 'HigherStrictLowerWrr')

def case_qosApplyGlobalCommandWithLowerStrictHigherWrr():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.apply_qos_queue_profile_schedule_profile(
                'profile1', 'LowerStrictHigherWrr')

def case_qosApplyGlobalCommandAndThenRestoreDefaultQueueProfile():
    with ops1.libs.vtysh.ConfigQueueProfile('default') as ctx:
        ctx.name_queue('0', 'q1')
    out = ops1.libs.vtysh.show_qos_queue_profile('default')
    assert out['0']['local_priorities'] == '0'
    assert out['0']['name'] == 'q1'

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_qos_queue_profile('default')
    out = ops1.libs.vtysh.show_qos_queue_profile('default')
    assert out['0']['local_priorities'] == '0'
    assert out['0']['name'] == 'Scavenger_and_backup_data'

def case_qosApplyGlobalCommandAndThenRestoreDefaultScheduleProfile():
    with ops1.libs.vtysh.ConfigScheduleProfile('default') as ctx:
        ctx.strict_queue('0')
    out = ops1.libs.vtysh.show_qos_schedule_profile('default')
    assert out['0']['algorithm'] == 'strict'
    assert out['0']['weight'] == ''

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_qos_schedule_profile('default')
    out = ops1.libs.vtysh.show_qos_schedule_profile('default')
    assert out['0']['algorithm'] == 'dwrr'
    assert out['0']['weight'] == '1'

def case_qosApplyGlobalCommandWithPortScheduleProfileWithDifferentQueues():
    # Apply the one-queue profiles to system and port.
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('SingleQ', 'SingleQ')
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_qos_schedule_profile('SingleQ')

    # Globally applying the default profiles should fail, since they
    # have 8 queues rather than 1 queue.
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.apply_qos_queue_profile_schedule_profile('default', 'default')

    # Un-apply the one-queue profiles.
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_apply_qos_schedule_profile()
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('default', 'default')

def case_qosApplyGlobalCommandWithPortScheduleProfileStrict():
    # Apply the one-queue profiles to system.
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('SingleQ', 'SingleQ')

    # Apply strict to port.
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_qos_schedule_profile('strict')

    # Globally applying the default profiles should succeed, since the
    # port schedule profile is just strict.
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('default', 'default')
    out = ops1.libs.vtysh.show_qos_queue_profile()
    assert out['default']['profile_status'] == 'applied'
    assert out['default']['profile_name'] == 'default'
    out = ops1.libs.vtysh.show_qos_schedule_profile()
    assert out['default']['profile_status'] == 'applied'
    assert out['default']['profile_name'] == 'default'

    # Un-apply the one-queue profiles.
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_apply_qos_schedule_profile()
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('default', 'default')

def case_qosApplyPortCommand():
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_qos_schedule_profile('profile1')
    out = ops1.libs.vtysh.show_qos_schedule_profile()
    assert out['profile1']['profile_status'] == 'applied'
    assert out['profile1']['profile_name'] == 'profile1'

def case_qosApplyPortCommandWithMissingScheduleProfileQueue():
    with ops1.libs.vtysh.ConfigScheduleProfile('MissingScheduleProfileQueue') as ctx:
        ctx.dwrr_queue_weight('4', '40')
        ctx.dwrr_queue_weight('5', '50')
        ctx.dwrr_queue_weight('6', '60')
        ctx.dwrr_queue_weight('0', '1')
        ctx.dwrr_queue_weight('1', '10')
        ctx.dwrr_queue_weight('2', '20')
        ctx.dwrr_queue_weight('3', '30')

    with raises(FailedCommandException):
        with ops1.libs.vtysh.ConfigInterface('1') as ctx:
            ctx.apply_qos_schedule_profile('MissingScheduleProfileQueue')

def case_qosApplyPortCommandWithIllegalScheduleProfile():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.ConfigInterface('1') as ctx:
            ctx.apply_qos_schedule_profile('p&^%$1')

def case_qosApplyPortCommandWithNullScheduleProfile():
    with raises(IncompleteCommandException):
        with ops1.libs.vtysh.ConfigInterface('1') as ctx:
            ctx.apply_qos_schedule_profile('')

def case_qosApplyPortCommandWithInterfaceInLag():
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.lag('10')
    with raises(FailedCommandException):
        with ops1.libs.vtysh.ConfigInterface('1') as ctx:
            ctx.apply_qos_schedule_profile('profile1')
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_lag('10')

def case_qosApplyPortCommandWithMissingScheduleProfile():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.ConfigInterface('1') as ctx:
            ctx.apply_qos_schedule_profile('missing')

def case_qosApplyPortCommandWithStrictScheduleProfile():
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_qos_schedule_profile('strict')

    out = ops1.libs.vtysh.show_qos_schedule_profile()
    assert out['strict']['profile_status'] == 'applied'
    assert out['strict']['profile_name'] == 'strict'

def case_qosApplyPortCommandWithAllStrict():
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_qos_schedule_profile('AllStrict')

    out = ops1.libs.vtysh.show_qos_schedule_profile()
    assert out['AllStrict']['profile_status'] == 'applied'
    assert out['AllStrict']['profile_name'] == 'AllStrict'

def case_qosApplyPortCommandWithAllWrr():
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_qos_schedule_profile('AllWrr')

    out = ops1.libs.vtysh.show_qos_schedule_profile()
    assert out['AllWrr']['profile_status'] == 'applied'
    assert out['AllWrr']['profile_name'] == 'AllWrr'

def case_qosApplyPortCommandWithAllWrrWithMaxStrict():
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_qos_schedule_profile('awwms')

    out = ops1.libs.vtysh.show_qos_schedule_profile()
    assert out['awwms']['profile_status'] == 'applied'
    assert out['awwms']['profile_name'] == 'awwms'

def case_qosApplyPortCommandWithHigherStrictLowerWrr():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.ConfigInterface('1') as ctx:
            ctx.apply_qos_schedule_profile('HigherStrictLowerWrr')

def case_qosApplyPortCommandWithLowerStrictHigherWrr():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.ConfigInterface('1') as ctx:
            ctx.apply_qos_schedule_profile('LowerStrictHigherWrr')

def case_qosApplyPortNoCommand():
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_qos_schedule_profile('profile1')
        ctx.no_apply_qos_schedule_profile()

    out = ops1.libs.vtysh.show_qos_schedule_profile()
    assert out['profile1']['profile_status'] == 'complete'
    assert out['profile1']['profile_name'] == 'profile1'

def case_qosApplyPortNoCommandWithInterfaceInLag():
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.lag('10')
    with raises(FailedCommandException):
        with ops1.libs.vtysh.ConfigInterface('1') as ctx:
            ctx.no_apply_qos_schedule_profile()
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_lag('10')

def case_qosCosMapCommand():
    code_point = '7'

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_cos_map_local_priority_color_name(
            code_point, '1', 'red', 'MyName1')
        ctx.qos_cos_map_local_priority_color_name(
            code_point, '2', 'yellow', 'MyName2')

    out = ops1.libs.vtysh.show_qos_cos_map()
    assert out[code_point]['code_point'] == '7'
    assert out[code_point]['local_priority'] == '2'
    assert out[code_point]['color'] == 'yellow'
    assert out[code_point]['name'] == 'MyName2'

def case_qosCosMapCommandWithIllegalCodePoint():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_cos_map_local_priority_color_name(
                '-1', '2', 'yellow', 'MyName2')
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_cos_map_local_priority_color_name(
                '8', '2', 'yellow', 'MyName2')

def case_qosCosMapCommandWithNullCodePoint():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_cos_map_local_priority_color_name(
                '', '2', 'yellow', 'MyName2')

def case_qosCosMapCommandWithIllegalLocalPriority():
    local_priority_range = get_local_priority_range()

    with raises(UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_cos_map_local_priority_color_name(
                '7', str(local_priority_range[0] - 1), 'yellow', 'MyName2')
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_cos_map_local_priority_color_name(
                '7', str(local_priority_range[1] + 1), 'yellow', 'MyName2')

def case_qosCosMapCommandWithNullLocalPriority():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_cos_map_local_priority_color_name(
                '7', '', 'yellow', 'MyName2')

def case_qosCosMapCommandWithIllegalColor():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_cos_map_local_priority_color_name(
                '7', '2', 'illegal', 'MyName2')

def case_qosCosMapCommandWithNullColor():
    code_point = '7'
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_cos_map_local_priority_name(code_point, '2', 'MyName2')

    out = ops1.libs.vtysh.show_qos_cos_map()
    assert out[code_point]['code_point'] == '7'
    assert out[code_point]['local_priority'] == '2'
    assert out[code_point]['color'] == 'green'
    assert out[code_point]['name'] == 'MyName2'

    with raises(UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_cos_map_local_priority_color_name(
                '7', '2', '', 'MyName2')

def case_qosCosMapCommandWithIllegalName():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_cos_map_local_priority_color_name(
                '7', '2', 'yellow', 'NameThatIsLongerThan64Characterssssssss'
                    'ssssssssssssssssssssssssss')
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_cos_map_local_priority_color_name(
                '7', '2', 'yellow', 'NameWithIllegalCh@r@cter$')

def case_qosCosMapCommandWithNullName():
    code_point = '7'
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_cos_map_local_priority_color(code_point, '2', 'yellow')

    out = ops1.libs.vtysh.show_qos_cos_map()
    assert out[code_point]['code_point'] == '7'
    assert out[code_point]['local_priority'] == '2'
    assert out[code_point]['color'] == 'yellow'
    assert out[code_point]['name'] == ''

    with raises(IncompleteCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_cos_map_local_priority_color_name(
                code_point, '2', 'yellow', '')

def case_qosCosMapNoCommand():
    code_point = '7'
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_cos_map_local_priority_color_name(
            code_point, '2', 'yellow', 'MyName2')
        ctx.no_qos_cos_map('7')

    out = ops1.libs.vtysh.show_qos_cos_map()
    assert out[code_point]['code_point'] == '7'
    assert out[code_point]['local_priority'] == '7'
    assert out[code_point]['color'] == 'green'
    assert out[code_point]['name'] == 'Network_Control'

def case_qosDscpMapCommand():
    code_point = '38'
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_dscp_map_local_priority_color_name(
            code_point, '1', 'green', 'MyName1')
        ctx.qos_dscp_map_local_priority_color_name(
            code_point, '2', 'yellow', 'MyName2')

    out = ops1.libs.vtysh.show_qos_dscp_map()
    assert out[code_point]['code_point'] == '38'
    assert out[code_point]['local_priority'] == '2'
    assert out[code_point]['color'] == 'yellow'
    assert out[code_point]['name'] == 'MyName2'

def case_qosDscpMapCommandWithIllegalCodePoint():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_dscp_map_local_priority_color_name(
                '-1', '2', 'yellow', 'MyName2')
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_dscp_map_local_priority_color_name(
                '64', '2', 'yellow', 'MyName2')

def case_qosDscpMapCommandWithNullCodePoint():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_dscp_map_local_priority_color_name(
                '', '2', 'yellow', 'MyName2')

def case_qosDscpMapCommandWithIllegalLocalPriority():
    local_priority_range = get_local_priority_range()

    with raises(UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_dscp_map_local_priority_color_name(
                '38', str(local_priority_range[0] - 1), 'yellow', 'MyName2')
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_dscp_map_local_priority_color_name(
                '38', str(local_priority_range[1] + 1), 'yellow', 'MyName2')

def case_qosDscpMapCommandWithNullLocalPriority():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_dscp_map_local_priority_color_name(
                '38', '', 'yellow', 'MyName2')

def case_qosDscpMapCommandWithIllegalColor():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_dscp_map_local_priority_color_name(
                '38', '2', 'illegal', 'MyName2')

def case_qosDscpMapCommandWithNullColor():
    code_point = '38'
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_dscp_map_local_priority_name(
            code_point, '2', 'MyName2')

    out = ops1.libs.vtysh.show_qos_dscp_map()
    assert out[code_point]['code_point'] == '38'
    assert out[code_point]['local_priority'] == '2'
    assert out[code_point]['color'] == 'green'
    assert out[code_point]['name'] == 'MyName2'

    with raises(UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_dscp_map_local_priority_color_name(
                '38', '2', '', 'MyName2')

def case_qosDscpMapCommandWithIllegalName():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_dscp_map_local_priority_color_name(
                '38', '2', 'yellow', 'NameThatIsLongerThan64Characterssssssss'
                    'ssssssssssssssssssssssssss')
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_dscp_map_local_priority_color_name(
                '38', '2', 'yellow', 'NameWithIllegalCh@r@cter$')

def case_qosDscpMapCommandWithNullName():
    code_point = '38'
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_dscp_map_local_priority_color(
            code_point, '2', 'yellow')

    out = ops1.libs.vtysh.show_qos_dscp_map()
    assert out[code_point]['code_point'] == '38'
    assert out[code_point]['local_priority'] == '2'
    assert out[code_point]['color'] == 'yellow'
    assert out[code_point]['name'] == ''

    with raises(IncompleteCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_dscp_map_local_priority_color_name(
                '38', '2', 'yellow', '')

def case_qosDscpMapNoCommand():
    code_point = '38'
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_dscp_map_local_priority_color_name(
            code_point, '2', 'yellow', 'MyName2')
        ctx.no_qos_dscp_map('38')

    out = ops1.libs.vtysh.show_qos_dscp_map()
    assert out[code_point]['code_point'] == '38'
    assert out[code_point]['local_priority'] == '4'
    assert out[code_point]['color'] == 'red'
    assert out[code_point]['name'] == 'AF43'

def case_qosDscpPortCommand():
    setUp_qosDscpPort()

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.qos_trust('none')
        ctx.qos_dscp('1')

    out = ops1.libs.vtysh.show_interface(p1)
    assert out['qos_dscp'] == 1

def case_qosDscpPortCommandWithSystemTrustNoneAndPortTrustDscp():
    setUp_qosDscpPort()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_trust('none')
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.qos_trust('dscp')
    with raises(FailedCommandException):
        with ops1.libs.vtysh.ConfigInterface('1') as ctx:
            ctx.qos_dscp('1')

def case_qosDscpPortCommandWithSystemTrustNoneAndPortTrustMissing():
    setUp_qosDscpPort()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_trust('none')
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_qos_trust()
        ctx.qos_dscp('1')

    out = ops1.libs.vtysh.show_interface(p1)
    assert out['qos_dscp'] == 1

def case_qosDscpPortCommandWithSystemTrustDscpAndPortTrustNone():
    setUp_qosDscpPort()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_trust('dscp')
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.qos_trust('none')
        ctx.qos_dscp('1')

    out = ops1.libs.vtysh.show_interface(p1)
    assert out['qos_dscp'] == 1

def case_qosDscpPortCommandWithSystemTrustDscpAndPortTrustMissing():
    setUp_qosDscpPort()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_trust('dscp')
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_qos_trust()
    with raises(FailedCommandException):
        with ops1.libs.vtysh.ConfigInterface('1') as ctx:
            ctx.qos_dscp('1')

def case_qosDscpPortCommandWithIllegalQosDscp():
    setUp_qosDscpPort()

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.qos_trust('none')
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigInterface('1') as ctx:
            ctx.qos_dscp('-1')
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigInterface('1') as ctx:
            ctx.qos_dscp('64')

def case_qosDscpPortCommandWithNullQosDscp():
    setUp_qosDscpPort()

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.qos_trust('none')
    with raises(IncompleteCommandException):
        with ops1.libs.vtysh.ConfigInterface('1') as ctx:
            ctx.qos_dscp('')

def case_qosDscpPortCommandWithInterfaceInLag():
    setUp_qosDscpPort()

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.lag('10')
    with raises(FailedCommandException):
        with ops1.libs.vtysh.ConfigInterface('1') as ctx:
            ctx.qos_dscp('1')

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_lag('10')

def case_qosDscpPortNoCommand():
    setUp_qosDscpPort()

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.qos_trust('none')
        ctx.qos_dscp('1')
    out = ops1.libs.vtysh.show_interface(p1)
    assert out['qos_dscp'] == 1

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_qos_dscp()
    out = ops1.libs.vtysh.show_interface(p1)
    assert out['qos_dscp'] == None

def case_qosDscpPortNoCommandWithInterfaceInLag():
    setUp_qosDscpPort()

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.lag('10')
    with raises(FailedCommandException):
        with ops1.libs.vtysh.ConfigInterface('1') as ctx:
            ctx.no_qos_dscp()

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_lag('10')

def case_qosQueueProfileCommand():
    with ops1.libs.vtysh.ConfigQueueProfile('NewProfile') as ctx:
        ctx.map_queue_local_priority('0', '0')

    out = ops1.libs.vtysh.show_qos_queue_profile()
    assert out['NewProfile']['profile_status'] == 'incomplete'
    assert out['NewProfile']['profile_name'] == 'NewProfile'

def case_qosQueueProfileCommandWithIllegalName():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_queue_profile(
                'NameThatIsLongerThan64Characterssssssssssssss'
                    'ssssssssssssssssssss')
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_queue_profile(
                'NameWithIllegalCh@r@cter$')

def case_qosQueueProfileCommandWithNullName():
    with raises(IncompleteCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_queue_profile('')

def case_qosQueueProfileCommandWithStrictName():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_queue_profile('strict')

def case_qosQueueProfileCommandWithAppliedProfile():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_queue_profile('default')

def case_qosQueueProfileNoCommand():
    with ops1.libs.vtysh.ConfigQueueProfile('NewProfile') as ctx:
        ctx.map_queue_local_priority('0', '0')
    out = ops1.libs.vtysh.show_qos_queue_profile()
    assert out['NewProfile']['profile_status'] == 'incomplete'
    assert out['NewProfile']['profile_name'] == 'NewProfile'

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_qos_queue_profile('NewProfile')
    out = ops1.libs.vtysh.show_qos_queue_profile()
    assert 'NewProfile' not in out

def case_qosQueueProfileNoCommandWithIllegalName():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.no_qos_queue_profile(
                'NameThatIsLongerThan64Characterssssssssssssss'
                    'ssssssssssssssssssss')
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.no_qos_queue_profile('NameWithIllegalCh@r@cter$')

def case_qosQueueProfileNoCommandWithNullName():
    with raises(IncompleteCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.no_qos_queue_profile('')

def case_qosQueueProfileNoCommandWithStrictName():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.no_qos_queue_profile('strict')

def case_qosQueueProfileNoCommandWithAppliedProfile():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.no_qos_queue_profile('default')

def case_qosQueueProfileNoCommandWithNonExistentProfile():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.no_qos_queue_profile('NonExistent')

def case_qosQueueProfileNameCommand():
    with ops1.libs.vtysh.ConfigQueueProfile('NameCommand') as ctx:
        ctx.name_queue('0', 'QueueName')

    out = ops1.libs.vtysh.show_qos_queue_profile('NameCommand')
    assert out['0']['local_priorities'] == ''
    assert out['0']['name'] == 'QueueName'

def case_qosQueueProfileNameCommandWithIllegalName():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('IllegalQueueName') as ctx:
            ctx.name_queue('0',
                'NameThatIsLongerThan64Characterssssssssssssssss'
                    'ssssssssssssssssss')
    with raises(FailedCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('IllegalQueueName') as ctx:
            ctx.name_queue('0', 'NameWithIllegalCh@r@cter$')

def case_qosQueueProfileNameCommandWithNullName():
    with raises(IncompleteCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('NullName') as ctx:
            ctx.name_queue('0', '')

def case_qosQueueProfileNameCommandWithIllegalQueue():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('IllegalQueue') as ctx:
            ctx.name_queue('-1', 'QueueName')
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('IllegalQueue') as ctx:
            ctx.name_queue('8', 'QueueName')

def case_qosQueueProfileNameCommandWithNullQueue():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('IllegalQueue') as ctx:
            ctx.name_queue('', 'QueueName')

def case_qosQueueProfileNameNoCommand():
    with ops1.libs.vtysh.ConfigQueueProfile('TestNoCommand') as ctx:
        ctx.name_queue('0', 'QueueName')
    out = ops1.libs.vtysh.show_qos_queue_profile('TestNoCommand')
    assert out['0']['local_priorities'] == ''
    assert out['0']['name'] == 'QueueName'

    with ops1.libs.vtysh.ConfigQueueProfile('TestNoCommand') as ctx:
        ctx.no_name_queue('0')
    out = ops1.libs.vtysh.show_qos_queue_profile('TestNoCommand')
    assert '0' not in out

def case_qosQueueProfileNameNoCommandWithIllegalQueue():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('IllegalQueue') as ctx:
            ctx.no_name_queue('-1')
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('IllegalQueue') as ctx:
            ctx.no_name_queue('8')

def case_qosQueueProfileNameNoCommandWithNullQueue():
    with raises(IncompleteCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('IllegalQueue') as ctx:
            ctx.no_name_queue('')

def case_qosQueueProfileNameNoCommandWithMissingQueue():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('IllegalQueue') as ctx:
            ctx.no_name_queue('7')

def case_qosQueueProfileMapCommand():
    with ops1.libs.vtysh.ConfigQueueProfile('MapCommand') as ctx:
        ctx.map_queue_local_priority('1', '2')
    out = ops1.libs.vtysh.show_qos_queue_profile('MapCommand')
    assert out['1']['local_priorities'] == '2'
    assert out['1']['name'] == ''

def case_qosQueueProfileMapCommandWithIllegalQueue():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('MapIllegalQueue') as ctx:
            ctx.map_queue_local_priority('-1', '2')
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('MapIllegalQueue') as ctx:
            ctx.map_queue_local_priority('8', '2')

def case_qosQueueProfileMapCommandWithNullQueue():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('MapIllegalQueue') as ctx:
            ctx.map_queue_local_priority('', '2')

def case_qosQueueProfileMapCommandWithIllegalPriority():
    local_priority_range = get_local_priority_range()

    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('MapIllegalQueue') as ctx:
            ctx.map_queue_local_priority('1', str(local_priority_range[0] - 1))
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('MapIllegalQueue') as ctx:
            ctx.map_queue_local_priority('1', str(local_priority_range[1] + 1))

def case_qosQueueProfileMapCommandWithNullPriority():
    with raises(IncompleteCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('MapIllegalQueue') as ctx:
            ctx.map_queue_local_priority('1', '')

def case_qosQueueProfileMapCommandAddsListOfPriorities():
    with ops1.libs.vtysh.ConfigQueueProfile('ListOfPriorities') as ctx:
        ctx.map_queue_local_priority('1', '1,2')
        ctx.map_queue_local_priority('1', '3,4')
    out = ops1.libs.vtysh.show_qos_queue_profile('ListOfPriorities')
    assert out['1']['local_priorities'] == '1,2,3,4'
    assert out['1']['name'] == ''

def case_qosQueueProfileMapNoCommand():
    with ops1.libs.vtysh.ConfigQueueProfile('MapNoCommand') as ctx:
        ctx.map_queue_local_priority('1', '2')
    out = ops1.libs.vtysh.show_qos_queue_profile('MapNoCommand')
    assert out['1']['local_priorities'] == '2'
    assert out['1']['name'] == ''

    with ops1.libs.vtysh.ConfigQueueProfile('MapNoCommand') as ctx:
        ctx.no_map_queue('1')
    out = ops1.libs.vtysh.show_qos_queue_profile('MapNoCommand')
    assert '1' not in out

def case_qosQueueProfileMapNoCommandWithIllegalQueue():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('MapIllegalQueue') as ctx:
            ctx.no_map_queue_local_priority('-1', '2')
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('MapIllegalQueue') as ctx:
            ctx.no_map_queue_local_priority('8', '2')

def case_qosQueueProfileMapNoCommandWithNullQueue():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('MapIllegalQueue') as ctx:
            ctx.no_map_queue_local_priority('', '2')

def case_qosQueueProfileMapNoCommandWithIllegalPriority():
    local_priority_range = get_local_priority_range()

    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('MapIllegalQueue') as ctx:
            ctx.no_map_queue_local_priority(
                '1', str(local_priority_range[0] - 1))
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('MapIllegalQueue') as ctx:
            ctx.no_map_queue_local_priority(
                '1', str(local_priority_range[1] + 1))

def case_qosQueueProfileMapNoCommandWithNullPriority():
    with raises(IncompleteCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('MapIllegalQueue') as ctx:
            ctx.no_map_queue_local_priority('1', '')

def case_qosQueueProfileMapNoCommandDeletesSinglePriority():
    with ops1.libs.vtysh.ConfigQueueProfile('DeletesSinglePriority') as ctx:
        ctx.map_queue_local_priority('1', '2')
        ctx.map_queue_local_priority('1', '3')
    out = ops1.libs.vtysh.show_qos_queue_profile('DeletesSinglePriority')
    assert out['1']['local_priorities'] == '2,3'
    assert out['1']['name'] == ''

    with ops1.libs.vtysh.ConfigQueueProfile('DeletesSinglePriority') as ctx:
        ctx.no_map_queue_local_priority('1', '2')
    out = ops1.libs.vtysh.show_qos_queue_profile('DeletesSinglePriority')
    assert out['1']['local_priorities'] == '3'
    assert out['1']['name'] == ''

def case_qosQueueProfileMapNoCommandDeletesAllPriorities():
    with ops1.libs.vtysh.ConfigQueueProfile('DeletesAllPriorities') as ctx:
        ctx.map_queue_local_priority('1', '2')
        ctx.map_queue_local_priority('1', '3')
    out = ops1.libs.vtysh.show_qos_queue_profile('DeletesAllPriorities')
    assert out['1']['local_priorities'] == '2,3'
    assert out['1']['name'] == ''

    with ops1.libs.vtysh.ConfigQueueProfile('DeletesAllPriorities') as ctx:
        ctx.no_map_queue('1')
    out = ops1.libs.vtysh.show_qos_queue_profile('DeletesAllPriorities')
    assert '1' not in out

def case_qosQueueProfileMapNoCommandDeletesListOfPriorities():
    with ops1.libs.vtysh.ConfigQueueProfile('DeletesList') as ctx:
        ctx.map_queue_local_priority('1', '1,2')
        ctx.map_queue_local_priority('1', '3,4')
    out = ops1.libs.vtysh.show_qos_queue_profile('DeletesList')
    assert out['1']['local_priorities'] == '1,2,3,4'
    assert out['1']['name'] == ''

    with ops1.libs.vtysh.ConfigQueueProfile('DeletesList') as ctx:
        ctx.no_map_queue_local_priority('1', '2,3')
    out = ops1.libs.vtysh.show_qos_queue_profile('DeletesList')
    assert out['1']['local_priorities'] == '1,4'
    assert out['1']['name'] == ''

def case_qosQueueProfileMapNoCommandWithMissingQueue():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.ConfigQueueProfile('MapIllegalQueue') as ctx:
            ctx.no_map_queue('7')

def case_qosScheduleProfileCommand():
    with ops1.libs.vtysh.ConfigScheduleProfile('NewProfile') as ctx:
        ctx.strict_queue('0')

    out = ops1.libs.vtysh.show_qos_schedule_profile()
    assert out['NewProfile']['profile_status'] == 'complete'
    assert out['NewProfile']['profile_name'] == 'NewProfile'

def case_qosScheduleProfileCommandWithIllegalName():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_schedule_profile(
                'NameThatIsLongerThan64Characterssssssssssssss'
                    'ssssssssssssssssssss')
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_schedule_profile(
                'NameWithIllegalCh@r@cter$')

def case_qosScheduleProfileCommandWithNullName():
    with raises(IncompleteCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_schedule_profile('')

def case_qosScheduleProfileCommandWithStrictName():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_schedule_profile('strict')

def case_qosScheduleProfileCommandWithAppliedProfile():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_schedule_profile('default')

def case_qosScheduleProfileNoCommand():
    with ops1.libs.vtysh.ConfigScheduleProfile('NewProfile') as ctx:
        ctx.strict_queue('0')
    out = ops1.libs.vtysh.show_qos_schedule_profile()
    assert out['NewProfile']['profile_status'] == 'complete'
    assert out['NewProfile']['profile_name'] == 'NewProfile'

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_qos_schedule_profile('NewProfile')
    out = ops1.libs.vtysh.show_qos_schedule_profile()
    assert 'NewProfile' not in out

def case_qosScheduleProfileNoCommandWithIllegalName():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.no_qos_schedule_profile(
                'NameThatIsLongerThan64Characterssssssssssssss'
                    'ssssssssssssssssssss')
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.no_qos_schedule_profile('NameWithIllegalCh@r@cter$')

def case_qosScheduleProfileNoCommandWithNullName():
    with raises(IncompleteCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.no_qos_schedule_profile('')

def case_qosScheduleProfileNoCommandWithStrictName():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.no_qos_schedule_profile('strict')

def case_qosScheduleProfileNoCommandWithAppliedProfile():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.no_qos_schedule_profile('default')

def case_qosScheduleProfileNoCommandWithNonExistentProfile():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.no_qos_schedule_profile('NonExistent')

def case_qosScheduleProfileStrictCommand():
    with ops1.libs.vtysh.ConfigScheduleProfile('NewProfile') as ctx:
        ctx.strict_queue('1')
    out = ops1.libs.vtysh.show_qos_schedule_profile('NewProfile')
    assert out['1']['algorithm'] == 'strict'
    assert out['1']['weight'] == ''

def case_qosScheduleProfileStrictCommandWithIllegalQueue():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigScheduleProfile('IllegalQueue') as ctx:
            ctx.strict_queue('-1')
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigScheduleProfile('IllegalQueue') as ctx:
            ctx.strict_queue('8')

def case_qosScheduleProfileStrictCommandWithNullQueue():
    with raises(IncompleteCommandException):
        with ops1.libs.vtysh.ConfigScheduleProfile('IllegalQueue') as ctx:
            ctx.strict_queue('')

def case_qosScheduleProfileStrictNoCommand():
    with ops1.libs.vtysh.ConfigScheduleProfile('NoCommand') as ctx:
        ctx.strict_queue('1')
    out = ops1.libs.vtysh.show_qos_schedule_profile('NoCommand')
    assert out['1']['algorithm'] == 'strict'
    assert out['1']['weight'] == ''

    with ops1.libs.vtysh.ConfigScheduleProfile('NoCommand') as ctx:
        ctx.no_strict_queue('1')
    out = ops1.libs.vtysh.show_qos_schedule_profile('NoCommand')
    assert '1' not in out

def case_qosScheduleProfileStrictNoCommandWithIllegalQueue():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigScheduleProfile('IllegalQueue') as ctx:
            ctx.no_strict_queue('-1')
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigScheduleProfile('IllegalQueue') as ctx:
            ctx.no_strict_queue('8')

def case_qosScheduleProfileStrictNoCommandWithNullQueue():
    with raises(IncompleteCommandException):
        with ops1.libs.vtysh.ConfigScheduleProfile('IllegalQueue') as ctx:
            ctx.no_strict_queue('')

def case_qosScheduleProfileStrictNoCommandWithMissingQueue():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.ConfigScheduleProfile('IllegalQueue') as ctx:
            ctx.no_strict_queue('7')

def case_qosScheduleProfileWrrCommand():
    with ops1.libs.vtysh.ConfigScheduleProfile('NewProfile') as ctx:
        ctx.dwrr_queue_weight('1', '2')
    out = ops1.libs.vtysh.show_qos_schedule_profile('NewProfile')
    assert out['1']['algorithm'] == 'dwrr'
    assert out['1']['weight'] == '2'

def case_qosScheduleProfileWrrCommandWithIllegalQueue():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigScheduleProfile('IllegalQueue') as ctx:
            ctx.dwrr_queue_weight('-1', '2')
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigScheduleProfile('IllegalQueue') as ctx:
            ctx.dwrr_queue_weight('8', '2')

def case_qosScheduleProfileWrrCommandWithNullQueue():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigScheduleProfile('IllegalQueue') as ctx:
            ctx.dwrr_queue_weight('', '2')

def case_qosScheduleProfileWrrCommandWithIllegalWeight():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigScheduleProfile('IllegalQueue') as ctx:
            ctx.dwrr_queue_weight('1', '0')
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigScheduleProfile('IllegalQueue') as ctx:
            ctx.dwrr_queue_weight('1', '128')

def case_qosScheduleProfileWrrCommandWithNullWeight():
    with raises(IncompleteCommandException):
        with ops1.libs.vtysh.ConfigScheduleProfile('IllegalQueue') as ctx:
            ctx.dwrr_queue_weight('1', '')

def case_qosScheduleProfileWrrNoCommand():
    with ops1.libs.vtysh.ConfigScheduleProfile('NoCommand') as ctx:
        ctx.dwrr_queue_weight('1', '2')
    out = ops1.libs.vtysh.show_qos_schedule_profile('NoCommand')
    assert out['1']['algorithm'] == 'dwrr'
    assert out['1']['weight'] == '2'

    with ops1.libs.vtysh.ConfigScheduleProfile('NoCommand') as ctx:
        ctx.no_dwrr_queue('1')
    out = ops1.libs.vtysh.show_qos_schedule_profile('NoCommand')
    assert '1' not in out

def case_qosScheduleProfileWrrNoCommandWithIllegalQueue():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigScheduleProfile('IllegalQueue') as ctx:
            ctx.no_dwrr_queue('-1')
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigScheduleProfile('IllegalQueue') as ctx:
            ctx.no_dwrr_queue('8')

def case_qosScheduleProfileWrrNoCommandWithNullQueue():
    with raises(IncompleteCommandException):
        with ops1.libs.vtysh.ConfigScheduleProfile('IllegalQueue') as ctx:
            ctx.no_dwrr_queue('')

def case_qosScheduleProfileWrrNoCommandWithMissingQueue():
    with raises(FailedCommandException):
        with ops1.libs.vtysh.ConfigScheduleProfile('IllegalQueue') as ctx:
            ctx.no_dwrr_queue('7')

def case_qosTrustGlobalCommand():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_trust('dscp')
        ctx.qos_trust('cos')

    out = ops1.libs.vtysh.show_qos_trust()
    assert out['trust'] == 'cos'

def case_qosTrustGlobalCommandWithIllegalQosTrust():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_trust('illegal')

def case_qosTrustGlobalCommandWithNullQosTrust():
    with raises(IncompleteCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.qos_trust('')

def case_qosTrustGlobalNoCommand():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_trust('dscp')
        ctx.no_qos_trust()

    out = ops1.libs.vtysh.show_qos_trust()
    assert out['trust'] == 'none'

def case_qosTrustPortCommand():
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.qos_trust('dscp')
        ctx.qos_trust('cos')

    out = ops1.libs.vtysh.show_interface(p1)
    assert out['qos_trust'] == 'cos'

def case_qosTrustPortCommandWithIllegalQosTrust():
    with raises(UnknownCommandException):
        with ops1.libs.vtysh.ConfigInterface('1') as ctx:
            ctx.qos_trust('illegal')

def case_qosTrustPortCommandWithNullQosTrust():
    with raises(IncompleteCommandException):
        with ops1.libs.vtysh.ConfigInterface('1') as ctx:
            ctx.qos_trust('')

def case_qosTrustPortCommandWithInterfaceInLag():
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.lag('10')
    with raises(FailedCommandException):
        with ops1.libs.vtysh.ConfigInterface('1') as ctx:
            ctx.qos_trust('cos')
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_lag('10')

def case_qosTrustPortNoCommand():
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.qos_trust('dscp')
        ctx.no_qos_trust()

    out = ops1.libs.vtysh.show_interface(p1)
    assert out['qos_trust'] == 'none'

def case_qosTrustPortNoCommandWithInterfaceInLag():
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.lag('10')
    with raises(FailedCommandException):
        with ops1.libs.vtysh.ConfigInterface('1') as ctx:
            ctx.no_qos_trust()
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_lag('10')

@mark.gate
def test_qos_ct_cli(topology, setup):
    setUp_qosApplyGlobal()
    case_qosApplyGlobalCommand()
    case_qosApplyGlobalCommandWithDuplicateQueueProfileQueue()
    case_qosApplyGlobalCommandWithMissingQueueProfileQueue()
    case_qosApplyGlobalCommandWithMissingScheduleProfileQueue()
    case_qosApplyGlobalCommandWithIllegalQueueProfile()
    case_qosApplyGlobalCommandWithNullQueueProfile()
    case_qosApplyGlobalCommandWithMissingQueueProfile()
    case_qosApplyGlobalCommandWithIllegalScheduleProfile()
    case_qosApplyGlobalCommandWithNullScheduleProfile()
    case_qosApplyGlobalCommandWithMissingScheduleProfile()
    case_qosApplyGlobalCommandWithStrictScheduleProfile()
    case_qosApplyGlobalCommandWithAllStrict()
    case_qosApplyGlobalCommandWithAllWrr()
    case_qosApplyGlobalCommandWithAllWrrWithMaxStrict()
    case_qosApplyGlobalCommandWithHigherStrictLowerWrr()
    case_qosApplyGlobalCommandWithLowerStrictHigherWrr()
    case_qosApplyGlobalCommandAndThenRestoreDefaultQueueProfile()
    case_qosApplyGlobalCommandAndThenRestoreDefaultScheduleProfile()
    case_qosApplyGlobalCommandWithPortScheduleProfileWithDifferentQueues()
    case_qosApplyGlobalCommandWithPortScheduleProfileStrict()

    case_qosApplyPortCommand()
    case_qosApplyPortCommandWithMissingScheduleProfileQueue()
    case_qosApplyPortCommandWithIllegalScheduleProfile()
    case_qosApplyPortCommandWithNullScheduleProfile()
    case_qosApplyPortCommandWithInterfaceInLag()
    case_qosApplyPortCommandWithMissingScheduleProfile()
    case_qosApplyPortCommandWithStrictScheduleProfile()
    case_qosApplyPortCommandWithAllStrict()
    case_qosApplyPortCommandWithAllWrr()
    case_qosApplyPortCommandWithAllWrrWithMaxStrict()
    case_qosApplyPortCommandWithHigherStrictLowerWrr()
    case_qosApplyPortCommandWithLowerStrictHigherWrr()
    case_qosApplyPortNoCommand()
    case_qosApplyPortNoCommandWithInterfaceInLag()

    case_qosCosMapCommand()
    case_qosCosMapCommandWithIllegalCodePoint()
    case_qosCosMapCommandWithNullCodePoint()
    case_qosCosMapCommandWithIllegalLocalPriority()
    case_qosCosMapCommandWithNullLocalPriority()
    case_qosCosMapCommandWithIllegalColor()
    case_qosCosMapCommandWithNullColor()
    case_qosCosMapCommandWithIllegalName()
    case_qosCosMapCommandWithNullName()
    case_qosCosMapNoCommand()

    case_qosDscpMapCommand()
    case_qosDscpMapCommandWithIllegalCodePoint()
    case_qosDscpMapCommandWithNullCodePoint()
    case_qosDscpMapCommandWithIllegalLocalPriority()
    case_qosDscpMapCommandWithNullLocalPriority()
    case_qosDscpMapCommandWithIllegalColor()
    case_qosDscpMapCommandWithNullColor()
    case_qosDscpMapCommandWithIllegalName()
    case_qosDscpMapCommandWithNullName()
    case_qosDscpMapNoCommand()

    case_qosDscpPortCommand()
    case_qosDscpPortCommandWithSystemTrustNoneAndPortTrustDscp()
    case_qosDscpPortCommandWithSystemTrustNoneAndPortTrustMissing()
    case_qosDscpPortCommandWithSystemTrustDscpAndPortTrustNone()
    case_qosDscpPortCommandWithSystemTrustDscpAndPortTrustMissing()
    case_qosDscpPortCommandWithIllegalQosDscp()
    case_qosDscpPortCommandWithNullQosDscp()
    case_qosDscpPortCommandWithInterfaceInLag()
    case_qosDscpPortNoCommand()
    case_qosDscpPortNoCommandWithInterfaceInLag()

    case_qosQueueProfileCommand()
    case_qosQueueProfileCommandWithIllegalName()
    case_qosQueueProfileCommandWithNullName()
    case_qosQueueProfileCommandWithStrictName()
    case_qosQueueProfileCommandWithAppliedProfile()
    case_qosQueueProfileNoCommand()
    case_qosQueueProfileNoCommandWithIllegalName()
    case_qosQueueProfileNoCommandWithNullName()
    case_qosQueueProfileNoCommandWithStrictName()
    case_qosQueueProfileNoCommandWithAppliedProfile()
    case_qosQueueProfileNoCommandWithNonExistentProfile()
    case_qosQueueProfileNameCommand()
    case_qosQueueProfileNameCommandWithIllegalName()
    case_qosQueueProfileNameCommandWithNullName()
    case_qosQueueProfileNameCommandWithIllegalQueue()
    case_qosQueueProfileNameCommandWithNullQueue()
    case_qosQueueProfileNameNoCommand()
    case_qosQueueProfileNameNoCommandWithIllegalQueue()
    case_qosQueueProfileNameNoCommandWithNullQueue()
    case_qosQueueProfileNameNoCommandWithMissingQueue()
    case_qosQueueProfileMapCommand()
    case_qosQueueProfileMapCommandWithIllegalQueue()
    case_qosQueueProfileMapCommandWithNullQueue()
    case_qosQueueProfileMapCommandWithIllegalPriority()
    case_qosQueueProfileMapCommandWithNullPriority()
    case_qosQueueProfileMapCommandAddsListOfPriorities()
    case_qosQueueProfileMapNoCommand()
    case_qosQueueProfileMapNoCommandWithIllegalQueue()
    case_qosQueueProfileMapNoCommandWithNullQueue()
    case_qosQueueProfileMapNoCommandWithIllegalPriority()
    case_qosQueueProfileMapNoCommandWithNullPriority()
    case_qosQueueProfileMapNoCommandDeletesSinglePriority()
    case_qosQueueProfileMapNoCommandDeletesAllPriorities()
    case_qosQueueProfileMapNoCommandDeletesListOfPriorities()
    case_qosQueueProfileMapNoCommandWithMissingQueue()

    case_qosScheduleProfileCommand()
    case_qosScheduleProfileCommandWithIllegalName()
    case_qosScheduleProfileCommandWithNullName()
    case_qosScheduleProfileCommandWithStrictName()
    case_qosScheduleProfileCommandWithAppliedProfile()
    case_qosScheduleProfileNoCommand()
    case_qosScheduleProfileNoCommandWithIllegalName()
    case_qosScheduleProfileNoCommandWithNullName()
    case_qosScheduleProfileNoCommandWithStrictName()
    case_qosScheduleProfileNoCommandWithAppliedProfile()
    case_qosScheduleProfileNoCommandWithNonExistentProfile()
    case_qosScheduleProfileStrictCommand()
    case_qosScheduleProfileStrictCommandWithIllegalQueue()
    case_qosScheduleProfileStrictCommandWithNullQueue()
    case_qosScheduleProfileStrictNoCommand()
    case_qosScheduleProfileStrictNoCommandWithIllegalQueue()
    case_qosScheduleProfileStrictNoCommandWithNullQueue()
    case_qosScheduleProfileStrictNoCommandWithMissingQueue()
    case_qosScheduleProfileWrrCommand()
    case_qosScheduleProfileWrrCommandWithIllegalQueue()
    case_qosScheduleProfileWrrCommandWithNullQueue()
    case_qosScheduleProfileWrrCommandWithIllegalWeight()
    case_qosScheduleProfileWrrCommandWithNullWeight()
    case_qosScheduleProfileWrrNoCommand()
    case_qosScheduleProfileWrrNoCommandWithIllegalQueue()
    case_qosScheduleProfileWrrNoCommandWithNullQueue()
    case_qosScheduleProfileWrrNoCommandWithMissingQueue()

    case_qosTrustGlobalCommand()
    case_qosTrustGlobalCommandWithIllegalQosTrust()
    case_qosTrustGlobalCommandWithNullQosTrust()
    case_qosTrustGlobalNoCommand()

    case_qosTrustPortCommand()
    case_qosTrustPortCommandWithIllegalQosTrust()
    case_qosTrustPortCommandWithNullQosTrust()
    case_qosTrustPortCommandWithInterfaceInLag()
    case_qosTrustPortNoCommand()
    case_qosTrustPortNoCommandWithInterfaceInLag()
