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
import time

TOPOLOGY = """
# +-------+
# |  ops1 |
# +-------+

# Nodes
[type=openswitch name="OpenSwitch 1"] ops1

# Ports
ops1:1
ops1:2
ops1:3
ops1:4
"""

ops1 = None
p1 = None
p2 = None
p3 = None
p4 = None
switch_ip = None

@pytest.fixture(scope="module")
def setup(topology):
    global ops1
    ops1 = topology.get("ops1")
    assert ops1 is not None

    global p1
    global p2
    global p3
    global p4

    p1 = ops1.ports['1']
    p2 = ops1.ports['2']
    p3 = ops1.ports['3']
    p4 = ops1.ports['4']

    assert p1 is not None
    assert p2 is not None
    assert p3 is not None
    assert p4 is not None

    global switch_ip
    switch_ip = get_switch_ip(ops1)
    assert switch_ip is not None

    # TODO: improve to a better check.
    # Give the openswitch container time to start up.
    time.sleep(20)

    ops1(format('end'))
    ops1(format('configure terminal'))

    ops1(format('vlan 1'))

    ops1(format('interface {p1}'))
    ops1(format('no routing'))
    ops1(format('vlan access 1'))
    ops1(format('vlan trunk allowed 1'))

    ops1(format('interface {p2}'))
    ops1(format('no routing'))
    ops1(format('vlan access 1'))
    ops1(format('vlan trunk allowed 1'))

    ops1(format('interface {p3}'))
    ops1(format('no routing'))
    ops1(format('vlan access 1'))
    ops1(format('vlan trunk allowed 1'))

    ops1(format('interface {p4}'))
    ops1(format('no routing'))
    ops1(format('vlan access 1'))
    ops1(format('vlan trunk allowed 1'))

    ops1(format('end'))

def get_switch_ip(switch):
    switch_ip = switch('python -c \"import socket; '
                       'print socket.gethostbyname(socket.gethostname())\"',
                       shell='bash')
    switch_ip = switch_ip.rstrip('\r\n')
    return switch_ip

def format(s):
    return s.format(**globals())

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

def case_1_activate_ms_foo_succeeds():
    ops1(format('configure terminal'))
    ops1(format('mirror session foo'))
    ops1(format('source interface {p2} both'))
    ops1(format('destination interface {p3}'))
    ops1(format('no shutdown'))
    ops1(format('end'))

    out = ops1(format('show mirror'))
    assert contains_line_with(out, ["foo", "active"])

    out = ops1(format('show mirror foo'))
    assert 'Mirror Session: foo' in out
    assert 'Status: active' in out
    assert format('Source: interface {p2} both') in out
    assert format('Destination: interface {p3}') in out

def case_2_add_second_source_to_active_mirror_session_foo_succeeds():
    ops1(format('configure terminal'))
    ops1(format('mirror session foo'))
    ops1(format('source interface {p1} rx'))
    ops1(format('end'))

    out = ops1(format('show mirror foo'))
    assert 'Mirror Session: foo' in out
    assert 'Status: active' in out
    assert format('Source: interface {p1} rx') in out
    assert format('Source: interface {p2} both') in out
    assert format('Destination: interface {p3}') in out

def case_3_remove_first_source_to_active_mirror_session_foo_succeeds():
    ops1(format('configure terminal'))
    ops1(format('mirror session foo'))
    ops1(format('no source interface {p2} tx'))
    ops1(format('end'))

    out = ops1(format('show mirror foo'))
    assert 'Mirror Session: foo' in out
    assert 'Status: active' in out
    assert format('Source: interface {p1} rx') in out
    assert format('Destination: interface {p3}') in out

def case_4_activate_mirror_session_bar_succeeds():
    ops1(format('configure terminal'))
    ops1(format('mirror session bar'))
    ops1(format('source interface {p2} tx'))
    ops1(format('destination interface {p4}'))
    ops1(format('no shutdown'))
    ops1(format('end'))

    out = ops1(format('show mirror'))
    assert contains_line_with(out, ["bar", "active"])

    out = ops1(format('show mirror bar'))
    assert 'Mirror Session: bar' in out
    assert 'Status: active' in out
    assert format('Source: interface {p2} tx') in out
    assert format('Destination: interface {p4}') in out

    out = ops1(format('show running-config'))
    assert 'mirror session foo' in out
    assert 'mirror session bar' in out

def case_5_attempt_another_session_using_existing_destination_fails():
    ops1(format('configure terminal'))
    ops1(format('mirror session dup'))
    ops1(format('source interface {p1} rx'))
    ops1(format('destination interface {p4}'))
    out = ops1(format('no shutdown'))
    assert 'already in use as destination in active session bar' in out
    ops1(format('end'))

    out = ops1(format('show mirror'))
    assert contains_line_with(out, ["dup", "shutdown"])

    out = ops1(format('show mirror dup'))
    assert 'Mirror Session: dup' in out
    assert 'Status: new' in out
    assert format('Source: interface {p1} rx') in out
    assert format('Destination: interface {p4}') in out

    ops1(format('configure terminal'))
    ops1(format('no mirror session dup'))
    ops1(format('end'))

def case_6_attempt_another_session_with_destination_using_existing_rx_source_interface_fails():
    ops1(format('configure terminal'))
    ops1(format('mirror session dup'))
    ops1(format('source interface {p2} rx'))
    ops1(format('destination interface {p1}'))
    out = ops1(format('no shutdown'))
    assert 'already in use as source in active session' in out
    ops1(format('end'))

    ops1(format('configure terminal'))
    ops1(format('no mirror session dup'))
    ops1(format('end'))

def case_7_attempt_another_session_with_destination_using_existing_tx_source_interface_fails():
    ops1(format('configure terminal'))
    ops1(format('mirror session dup'))
    ops1(format('source interface {p1} rx'))
    ops1(format('destination interface {p2}'))
    out = ops1(format('no shutdown'))
    assert 'already in use as source in active session' in out
    ops1(format('end'))

    ops1(format('configure terminal'))
    ops1(format('no mirror session dup'))
    ops1(format('end'))

def case_8_attempt_another_session_with_source_rx_using_existing_destination_interface_fails():
    ops1(format('configure terminal'))
    ops1(format('mirror session dup'))
    ops1(format('source interface {p3} rx'))
    ops1(format('destination interface {p4}'))
    out = ops1(format('no shutdown'))
    assert 'already in use as destination in active session' in out
    ops1(format('end'))

    ops1(format('configure terminal'))
    ops1(format('no mirror session dup'))
    ops1(format('end'))

def case_9_attempt_another_session_with_source_tx_using_existing_destination_interface_fails():
    ops1(format('configure terminal'))
    ops1(format('mirror session dup'))
    ops1(format('source interface {p3} tx'))
    ops1(format('destination interface {p4}'))
    out = ops1(format('no shutdown'))
    assert 'already in use as destination in active session' in out
    ops1(format('end'))

    ops1(format('configure terminal'))
    ops1(format('no mirror session dup'))
    ops1(format('end'))

def case_10_attempt_another_session_with_same_source_rx_and_destination_interface_fails():
    ops1(format('configure terminal'))
    ops1(format('mirror session dup'))
    ops1(format('source interface {p3} rx'))
    out = ops1(format('destination interface {p3}'))
    assert 'Cannot add destination' in out
    assert 'already a source' in out
    ops1(format('end'))

    ops1(format('configure terminal'))
    ops1(format('no mirror session dup'))
    ops1(format('end'))

def case_11_attempt_another_session_with_same_source_tx_and_destination_interface_fails():
    ops1(format('configure terminal'))
    ops1(format('mirror session dup'))
    ops1(format('source interface {p3} tx'))
    out = ops1(format('destination interface {p3}'))
    assert 'Cannot add destination' in out
    assert 'already a source' in out
    ops1(format('end'))

    ops1(format('configure terminal'))
    ops1(format('no mirror session dup'))
    ops1(format('end'))

def case_12_attempt_another_session_without_a_destination_interface_fails():
    ops1(format('configure terminal'))
    ops1(format('mirror session dup'))
    ops1(format('source interface {p1} tx'))
    out = ops1(format('no shutdown'))
    assert 'No mirror destination interface configured' in out
    ops1(format('end'))

    ops1(format('configure terminal'))
    ops1(format('no mirror session dup'))
    ops1(format('end'))

def case_13_create_inactive_duplicate_mirror_session_dup_succeeds():
    ops1(format('configure terminal'))
    ops1(format('mirror session dup'))
    ops1(format('source interface {p1} rx'))
    ops1(format('destination interface {p3}'))
    ops1(format('end'))

    out = ops1(format('show mirror'))
    assert contains_line_with(out, ["dup", "shutdown"])

def case_14_deactivate_mirror_session_foo():
    ops1(format('configure terminal'))
    ops1(format('mirror session foo'))
    ops1(format('shutdown'))
    ops1(format('end'))

    out = ops1(format('show mirror'))
    assert contains_line_with(out, ["foo", "shutdown"])

def case_15_activate_mirror_session_dup():
    ops1(format('configure terminal'))
    ops1(format('mirror session dup'))
    ops1(format('no shutdown'))
    ops1(format('end'))

    out = ops1(format('show mirror'))
    assert contains_line_with(out, ["dup", "active"])

def case_16_remove_inactive_mirror_session_foo_succeeds():
    ops1(format('configure terminal'))
    ops1(format('no mirror session foo'))
    ops1(format('no shutdown'))
    ops1(format('end'))

    out = ops1(format('show mirror'))
    assert 'foo' not in out

    out = ops1(format('show mirror foo'))
    assert 'Invalid mirror session' in out

def case_17_remove_active_mirror_session_dup_succeeds():
    ops1(format('configure terminal'))
    ops1(format('no mirror session dup'))
    ops1(format('end'))

    out = ops1(format('show mirror'))
    assert 'dup' not in out

    out = ops1(format('show mirror dup'))
    assert 'Invalid mirror session' in out

def case_18_remove_active_mirror_session_bar_succeeds():
    ops1(format('configure terminal'))
    ops1(format('no mirror session bar'))
    ops1(format('end'))

    out = ops1(format('show mirror bar'))
    assert 'Invalid mirror session' in out

    out = ops1(format('show mirror'))
    assert out == ''

    out = ops1(format('show running-config'))
    assert 'mirror session' not in out

def case_19_create_lag_succeeds():
    ops1(format('configure terminal'))

    ops1(format('interface lag 100'))
    ops1(format('no routing'))
    ops1(format('vlan access 1'))
    ops1(format('vlan trunk allowed 1'))
    ops1(format('no shutdown'))

    ops1(format('interface {p1}'))
    ops1(format('lag 100'))
    ops1(format('interface {p2}'))
    ops1(format('lag 100'))
    ops1(format('end'))

def case_20_mirror_session_with_source_lag_succeeds():
    ops1(format('configure terminal'))
    ops1(format('mirror session foo'))
    ops1(format('source interface lag100 rx'))
    ops1(format('destination interface {p3}'))
    ops1(format('no shutdown'))
    ops1(format('end'))

    out = ops1(format('show mirror'))
    # TODO: once mirror lags can be enabled in the container, uncomment this.
#     assert contains_line_with(out, ["foo", "active"])

    out = ops1(format('show mirror foo'))
    assert 'Mirror Session: foo' in out
    # TODO: once mirror lags can be enabled in the container, uncomment this.
#     assert 'Status: active' in out
    assert 'Source: interface lag100 rx' in out
    assert format('Destination: interface {p3}') in out

    ops1(format('configure terminal'))
    ops1(format('no mirror session foo'))
    ops1(format('end'))

def case_21_mirror_session_with_destination_lag_succeeds():
    ops1(format('configure terminal'))
    ops1(format('mirror session bar'))
    ops1(format('source interface {p3} rx'))
    ops1(format('destination interface lag100'))
    ops1(format('no shutdown'))
    ops1(format('end'))

    out = ops1(format('show mirror'))
    # TODO: once mirror lags can be enabled in the container, uncomment this.
#     assert contains_line_with(out, ["bar", "active"])

    out = ops1(format('show mirror bar'))
    assert 'Mirror Session: bar' in out
    # TODO: once mirror lags can be enabled in the container, uncomment this.
#     assert 'Status: active' in out
    assert format('Source: interface {p3} rx') in out
    assert 'Destination: interface lag100' in out

    ops1(format('configure terminal'))
    ops1(format('no mirror session bar'))
    ops1(format('end'))

def case_22_add_mirror_non_system_source_interface_fails():
    ops1(format('configure terminal'))
    ops1(format('mirror session non_system'))
    out = ops1(format('source interface bridge_normal rx'))
    assert 'Invalid interface' in out
    ops1(format('end'))

    ops1(format('configure terminal'))
    ops1(format('no mirror session non_system'))
    ops1(format('end'))

def case_23_add_mirror_non_system_destination_interface_fails():
    ops1(format('configure terminal'))
    ops1(format('mirror session non_system'))
    out = ops1(format('destination interface bridge_normal'))
    assert 'Invalid interface' in out
    ops1(format('end'))

    ops1(format('configure terminal'))
    ops1(format('no mirror session non_system'))
    ops1(format('end'))

@pytest.mark.skipif(True, reason="Once all pd/pi mirror code has been merged, enable this.")
def test_mirror_ct_cli(topology, setup):
    case_1_activate_ms_foo_succeeds()
    case_2_add_second_source_to_active_mirror_session_foo_succeeds()
    case_3_remove_first_source_to_active_mirror_session_foo_succeeds()
    case_4_activate_mirror_session_bar_succeeds()
    case_5_attempt_another_session_using_existing_destination_fails()
    case_6_attempt_another_session_with_destination_using_existing_rx_source_interface_fails()
    case_7_attempt_another_session_with_destination_using_existing_tx_source_interface_fails()
    case_8_attempt_another_session_with_source_rx_using_existing_destination_interface_fails()
    case_9_attempt_another_session_with_source_tx_using_existing_destination_interface_fails()
    case_10_attempt_another_session_with_same_source_rx_and_destination_interface_fails()
    case_11_attempt_another_session_with_same_source_tx_and_destination_interface_fails()
    case_12_attempt_another_session_without_a_destination_interface_fails()
    case_13_create_inactive_duplicate_mirror_session_dup_succeeds()
    case_14_deactivate_mirror_session_foo()
    case_15_activate_mirror_session_dup()
    case_16_remove_inactive_mirror_session_foo_succeeds()
    case_17_remove_active_mirror_session_dup_succeeds()
    case_18_remove_active_mirror_session_bar_succeeds()
    case_19_create_lag_succeeds()
    case_20_mirror_session_with_source_lag_succeeds()
    case_21_mirror_session_with_destination_lag_succeeds()
    case_22_add_mirror_non_system_source_interface_fails()
    case_23_add_mirror_non_system_destination_interface_fails()
