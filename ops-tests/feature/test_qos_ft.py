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

import pytest
from copy import deepcopy
import sys
import time

from pytest import raises
from topology_lib_vtysh.exceptions import IncompleteCommandException
from topology_lib_vtysh.exceptions import TcamResourcesException
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

@pytest.fixture(scope="module")
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

    wait_for_queue_statistics(ops1)

def wait_for_queue_statistics(ops1):
    out = ops1.libs.vtysh.show_interface_queues(p1)
    i = 0
    while out[p1] == {}:
        i = i + 1
        time.sleep(1)
        assert i < 90
        out = ops1.libs.vtysh.show_interface_queues(p1)

def wait_for_status(ops1):
    # 'status' will appear in the output until switchd has updated it.
    # Wait for switchd to update 'status'
    out = ops1.libs.vtysh.show_interface(p1)
    i = 0
    while out['qos_schedule_profile_status'] is not None:
        i = i + 1
        time.sleep(1)
        assert i < 90
        out = ops1.libs.vtysh.show_interface(p1)

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

    with ops1.libs.vtysh.ConfigQueueProfile('IncompleteProfile') as ctx:
        ctx.map_queue_local_priority('0', '0')
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_schedule_profile('IncompleteProfile')

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

def case_qosApplyGlobalShow():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('profile1', 'profile1')

    out = ops1.libs.vtysh.show_running_config()
    assert out['apply_qos']['queue-profile'] == 'profile1'
    assert out['apply_qos']['schedule-profile'] == 'profile1'

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('default', 'default')

def case_qosApplyPortShow():
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_qos_schedule_profile('strict')

    wait_for_status(ops1)

    out = ops1.libs.vtysh.show_running_config()
    assert out['interface'][p1]['apply_qos']['schedule-profile'] == 'strict'
    out = ops1.libs.vtysh.show_running_config_interface(p1)
    assert out['interface'][p1]['apply_qos']['schedule-profile'] == 'strict'
    out = ops1.libs.vtysh.show_interface(p1)
    assert out['qos_schedule_profile'] == 'strict'

    # Test lag.
    with ops1.libs.vtysh.ConfigInterfaceLag('10') as ctx:
        ctx.apply_qos_schedule_profile('default')

    out = ops1.libs.vtysh.show_running_config()
    assert out['interface']['lag']['10']['apply_qos']['schedule-profile'] == 'default'
    out = ops1.libs.vtysh.show_running_config_interface('lag10')
    assert out['interface']['lag']['10']['apply_qos']['schedule-profile'] == 'default'
    out = ops1.libs.vtysh.show_interface('lag10')
    assert out['qos_schedule_profile'] == 'default'

    # Test that interface shows the lag's config.
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.lag('10')

    out = ops1.libs.vtysh.show_running_config()
    assert 'apply_qos' not in out['interface'][p1]
    out = ops1.libs.vtysh.show_running_config_interface(p1)
    assert 'apply_qos' not in out['interface'][p1]
    out = ops1.libs.vtysh.show_interface(p1)
    assert out['qos_schedule_profile'] == 'default'

    # Clean up.
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_lag('10')
    with ops1.libs.vtysh.ConfigInterfaceLag('10') as ctx:
        ctx.no_qos_trust()
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_qos_trust()

def case_qosCosMapShowRunningConfigWithDefault():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_cos_map_local_priority_color_name(
            '1', '0', 'green', 'Background')

    out = ops1.libs.vtysh.show_running_config()
    assert out['qos_cos_map'] == {}

def case_qosCosMapShow():
    code_point = '7'
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_cos_map_local_priority_color_name(
            code_point, '2', 'yellow', 'MyName2')

    out = ops1.libs.vtysh.show_running_config()
    assert out['qos_cos_map'][code_point]['local-priority'] == '2'
    assert out['qos_cos_map'][code_point]['color'] == 'yellow'
    assert out['qos_cos_map'][code_point]['name'] == 'MyName2'

    out = ops1.libs.vtysh.show_qos_cos_map()
    assert out[code_point]['code_point'] == '7'
    assert out[code_point]['local_priority'] == '2'
    assert out[code_point]['color'] == 'yellow'
    assert out[code_point]['name'] == 'MyName2'

    out = ops1.libs.vtysh.show_qos_cos_map('default')
    assert out[code_point]['code_point'] == '7'
    assert out[code_point]['local_priority'] == '7'
    assert out[code_point]['color'] == 'green'
    assert out[code_point]['name'] == 'Network_Control'

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_qos_cos_map(code_point)

def case_qosDscpMapShowRunningConfigWithDefault():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_dscp_map_local_priority_color_name(
            '38', '4', 'red', 'AF43')

    out = ops1.libs.vtysh.show_running_config()
    assert out['qos_dscp_map'] == {}

def case_qosDscpMapShow():
    code_point = '38'
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_dscp_map_local_priority_color_name(
            code_point, '2', 'yellow', 'MyName2')

    out = ops1.libs.vtysh.show_running_config()
    assert out['qos_dscp_map'][code_point]['local-priority'] == '2'
    assert out['qos_dscp_map'][code_point]['color'] == 'yellow'
    assert out['qos_dscp_map'][code_point]['name'] == 'MyName2'

    out = ops1.libs.vtysh.show_qos_dscp_map()
    assert out[code_point]['code_point'] == '38'
    assert out[code_point]['local_priority'] == '2'
    assert out[code_point]['color'] == 'yellow'
    assert out[code_point]['name'] == 'MyName2'

    out = ops1.libs.vtysh.show_qos_dscp_map('default')
    assert out[code_point]['code_point'] == '38'
    assert out[code_point]['local_priority'] == '4'
    assert out[code_point]['color'] == 'red'
    assert out[code_point]['name'] == 'AF43'

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_qos_dscp_map(code_point)

def case_qosDscpPortShow():
    setUp_qosDscpPort()

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.qos_trust('none')
        ctx.qos_dscp('1')

    out = ops1.libs.vtysh.show_running_config()
    assert out['interface'][p1]['qos_dscp'] == '1'
    out = ops1.libs.vtysh.show_running_config_interface(p1)
    assert out['interface'][p1]['qos_dscp'] == '1'
    out = ops1.libs.vtysh.show_interface(p1)
    assert out['qos_dscp'] == 1

    # Test lag.
    with ops1.libs.vtysh.ConfigInterfaceLag('10') as ctx:
        ctx.qos_trust('none')
        ctx.qos_dscp('2')

    out = ops1.libs.vtysh.show_running_config()
    assert out['interface']['lag']['10']['qos_dscp'] == '2'
    out = ops1.libs.vtysh.show_running_config_interface('lag10')
    assert out['interface']['lag']['10']['qos_dscp'] == '2'
    out = ops1.libs.vtysh.show_interface('lag10')
    assert out['qos_dscp'] == 2

    # Test that interface shows the lag's config.
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.lag('10')

    out = ops1.libs.vtysh.show_running_config()
    assert 'qos_dscp' not in out['interface'][p1]
    out = ops1.libs.vtysh.show_running_config_interface(p1)
    assert 'qos_dscp' not in out['interface'][p1]
    out = ops1.libs.vtysh.show_interface(p1)
    assert out['qos_dscp'] == 2

    # Clean up.
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_lag('10')
    with ops1.libs.vtysh.ConfigInterfaceLag('10') as ctx:
        ctx.no_qos_trust()
        ctx.no_qos_dscp()
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_qos_trust()
        ctx.no_qos_dscp()

def case_qosQueueProfileShowCommand():
    with ops1.libs.vtysh.ConfigQueueProfile('profile2') as ctx:
        ctx.name_queue('0', 'MyName1')
        ctx.map_queue_local_priority('2', '3')

    out = ops1.libs.vtysh.show_qos_queue_profile('profile2')
    assert out['0']['name'] == 'MyName1'
    assert out['2']['local_priorities'] == '3'

    out = ops1.libs.vtysh.show_running_config()
    assert out['qos_queue_profile']['profile2']['0']['name'] == 'MyName1'
    assert out['qos_queue_profile']['profile2']['2']['local_priorities'] == '3'

def case_qosQueueProfileShowCommandWithIllegalName():
    # TODO: Use vtysh communication library.
    out = ops1('show qos queue-profile '
                         'NameThatIsLongerThan64Characterssssssssssssssss'
                         'ssssssssssssssssss')
    assert 'length up to' in out
    out = ops1('show qos queue-profile '
                         'NameWithIllegalCh@r@cter$')
    assert 'The allowed characters are' in out

def case_qosQueueProfileShowCommandShowsAllProfiles():
    out = ops1.libs.vtysh.show_qos_queue_profile()
    assert out['IncompleteProfile']['profile_status'] == 'incomplete'
    assert out['profile1']['profile_status'] == 'complete'
    assert out['default']['profile_status'] == 'applied'

def case_qosQueueProfileShowCommandFactoryDefault():
    out = ops1.libs.vtysh.show_qos_queue_profile('factory-default')
    assert out['0']['local_priorities'] == '0'
    assert out['0']['name'] == 'Scavenger_and_backup_data'

def case_qosQueueProfileShowCommandWithNonExistentProfile():
    # TODO: Use vtysh communication library.
    out = ops1('show qos queue-profile NonExistent')
    assert 'does not exist' in out

def case_qosShowQueueStatisticsCommandWithSingleInterface():
    out = ops1.libs.vtysh.show_interface_queues(p1)

    for queue in range(0, 8):
        queue = 'Q' + str(queue)
        assert queue in out[p1]

def case_qosShowQueueStatisticsCommandWithAllInterfaces():
    out = ops1.libs.vtysh.show_interface_queues()

    for interface in out:
        for queue in range(0, 8):
            queue = 'Q' + str(queue)
            assert queue in out[interface]

def case_qosScheduleProfileShowCommand():
    with ops1.libs.vtysh.ConfigScheduleProfile('profile2') as ctx:
        ctx.strict_queue('1')
        ctx.dwrr_queue_weight('3', '30')

    out = ops1.libs.vtysh.show_qos_schedule_profile('profile2')
    assert out['1']['algorithm'] == 'strict'
    assert out['3']['algorithm'] == 'dwrr'
    assert out['3']['weight'] == '30'

    out = ops1.libs.vtysh.show_running_config()
    assert out['qos_schedule_profile']['profile2']['1']['algorithm'] == 'strict'
    assert out['qos_schedule_profile']['profile2']['3']['algorithm'] == 'dwrr'
    assert out['qos_schedule_profile']['profile2']['3']['weight'] == '30'

def case_qosScheduleProfileShowCommandWithIllegalName():
    # TODO: Use vtysh communication library.
    out = ops1('show qos schedule-profile '
                         'NameThatIsLongerThan64Charactersssssssssssssss'
                         'sssssssssssssssssss')
    assert 'length up to' in out
    out = ops1('show qos schedule-profile '
                         'NameWithIllegalCh@r@cter$')
    assert 'The allowed characters are' in out

def case_qosScheduleProfileShowCommandShowsAllProfiles():
    out = ops1.libs.vtysh.show_qos_schedule_profile()
    assert out['IncompleteProfile']['profile_status'] == 'incomplete'
    assert out['profile1']['profile_status'] == 'complete'
    assert out['default']['profile_status'] == 'applied'

def case_qosScheduleProfileShowCommandFactoryDefault():
    out = ops1.libs.vtysh.show_qos_schedule_profile('factory-default')
    assert out['0']['algorithm'] == 'dwrr'
    assert out['0']['weight'] == '1'

def case_qosScheduleProfileShowCommandWithNonExistentProfile():
    # TODO: Use vtysh communication library.
    out = ops1('show qos schedule-profile NonExistent')
    assert 'does not exist' in out

def case_qosTrustGlobalShowRunningConfigWithDefault():
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_qos_trust()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_trust('none')

    out = ops1.libs.vtysh.show_running_config()
    assert out['qos_trust'] == {}

def case_qosTrustGlobalShow():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_trust('dscp')

    out = ops1.libs.vtysh.show_running_config()
    assert out['qos_trust'] == 'dscp'

    out = ops1.libs.vtysh.show_qos_trust()
    assert out['trust'] == 'dscp'

    out = ops1.libs.vtysh.show_qos_trust('default')
    assert out['trust'] == 'none'

def case_qosTrustPortShow():
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.qos_trust('dscp')

    out = ops1.libs.vtysh.show_running_config()
    assert out['interface'][p1]['qos_trust'] == 'dscp'
    out = ops1.libs.vtysh.show_running_config_interface(p1)
    assert out['interface'][p1]['qos_trust'] == 'dscp'
    out = ops1.libs.vtysh.show_interface(p1)
    assert out['qos_trust'] == 'dscp'

    # Test lag.
    with ops1.libs.vtysh.ConfigInterfaceLag('10') as ctx:
        ctx.qos_trust('cos')

    out = ops1.libs.vtysh.show_running_config()
    assert out['interface']['lag']['10']['qos_trust'] == 'cos'
    out = ops1.libs.vtysh.show_running_config_interface('lag10')
    assert out['interface']['lag']['10']['qos_trust'] == 'cos'
    out = ops1.libs.vtysh.show_interface('lag10')
    assert out['qos_trust'] == 'cos'

    # Test that interface shows the lag's config.
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.lag('10')

    out = ops1.libs.vtysh.show_running_config()
    assert 'qos_trust' not in out['interface'][p1]
    out = ops1.libs.vtysh.show_running_config_interface(p1)
    assert 'qos_trust' not in out['interface'][p1]
    out = ops1.libs.vtysh.show_interface(p1)
    assert out['qos_trust'] == 'cos'

    # Clean up.
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_lag('10')
    with ops1.libs.vtysh.ConfigInterfaceLag('10') as ctx:
        ctx.no_qos_trust()
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_qos_trust()

def test_qos_ft(topology, setup):
    setUp_qosApplyGlobal()

    case_qosApplyGlobalShow()

    case_qosApplyPortShow()

    case_qosCosMapShowRunningConfigWithDefault()
    case_qosCosMapShow()

    case_qosDscpMapShowRunningConfigWithDefault()
    case_qosDscpMapShow()

    case_qosDscpPortShow()

    case_qosQueueProfileShowCommand()
    case_qosQueueProfileShowCommandWithIllegalName()
    case_qosQueueProfileShowCommandShowsAllProfiles()
    case_qosQueueProfileShowCommandFactoryDefault()
    case_qosQueueProfileShowCommandWithNonExistentProfile()

    case_qosShowQueueStatisticsCommandWithSingleInterface()
    case_qosShowQueueStatisticsCommandWithAllInterfaces()

    case_qosScheduleProfileShowCommand()
    case_qosScheduleProfileShowCommandWithIllegalName()
    case_qosScheduleProfileShowCommandShowsAllProfiles()
    case_qosScheduleProfileShowCommandFactoryDefault()
    case_qosScheduleProfileShowCommandWithNonExistentProfile()

    case_qosTrustGlobalShowRunningConfigWithDefault()
    case_qosTrustGlobalShow()

    case_qosTrustPortShow()
