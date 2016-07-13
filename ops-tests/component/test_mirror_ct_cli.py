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

from pytest import mark, fixture
from copy import deepcopy
import time
import syslog
from pytest import raises
from topology_lib_vtysh.exceptions import UnknownVtyshException

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

# empirically tested -- in a stressed docker container, the maximum time to
# activate a mirror was 83 seconds.  Sad, but true.
testInitialSleep = 1
testRetryLimit = 90
testRetrySleep = 1

@fixture(scope="module")
def setup(topology):
    global ops1
    ops1 = topology.get("ops1")
    assert ops1 is not None

    global p1
    p1 = ops1.ports['1']
    assert p1 is not None

    global p2
    p2 = ops1.ports['2']
    assert p2 is not None

    global p3
    p3 = ops1.ports['3']
    assert p3 is not None

    global p4
    p4 = ops1.ports['4']
    assert p4 is not None

    global switch_ip
    switch_ip = get_switch_ip(ops1)
    assert switch_ip is not None

    # Give the openswitch container time to start up.
    # There is no sleep time that is certain to succeed, hence the use of
    #   retries following the first few mirror activation attempts
    time.sleep(testInitialSleep)

    ops1.libs.vtysh.ConfigVlan("1")

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_routing()
        ctx.vlan_access("1")
        ctx.vlan_trunk_allowed("1")

    with ops1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.no_routing()
        ctx.vlan_access("1")
        ctx.vlan_trunk_allowed("1")

    with ops1.libs.vtysh.ConfigInterface('3') as ctx:
        ctx.no_routing()
        ctx.vlan_access("1")
        ctx.vlan_trunk_allowed("1")

    with ops1.libs.vtysh.ConfigInterface('4') as ctx:
        ctx.no_routing()
        ctx.vlan_access("1")
        ctx.vlan_trunk_allowed("1")


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

### Find list index based on 'id'
#       "show mirror <name>" displays source interfaces in random order
#           source interface 2 tx
#       additionally, when a direction (tx|rx) is not defined, it displays
#       the parameters in reverse order:
#           source interface tx none
#
def interface_in_source_list(out, id):
    i = 0
    for source in out['source']:
        if source['id'] == id:
            return i
        i = i + 1
    return -1

def assertMirrorWithRetry(testcase, mirror, status, retries):
    out = ops1.libs.vtysh.show_mirror()
    i = 0
    syslog.syslog(syslog.LOG_INFO,
                  ">>>>> " + testcase + " show mirror " + str(i) + " " +
                  out[mirror]['name'] + "/" + out[mirror]['status'] + " <<<<<")
    while out[mirror]['status'] != status:
        i = i + 1
        time.sleep(testRetrySleep)
        assert i < retries
        out = ops1.libs.vtysh.show_mirror()
        syslog.syslog(syslog.LOG_INFO,
                      ">>>>> " + testcase + " show mirror x " + str(i) + " " +
                      out[mirror]['name'] + "/" + out[mirror]['status'] + " <<<<<")

    assert out[mirror]['name'] == mirror
    assert out[mirror]['status'] == status

    out = ops1.libs.vtysh.show_mirror(mirror)
    assert out['name'] == mirror
    assert out['status'] == status

def case_1_activate_ms_foo_succeeds():
    with ops1.libs.vtysh.ConfigMirrorSession("foo") as ctx:
        ctx.source_interface('2',"both")
        ctx.destination_interface('3')
        ctx.no_shutdown()

    assertMirrorWithRetry('case1','foo','active',testRetryLimit)

    out = ops1.libs.vtysh.show_mirror('foo')
    assert len(out['source']) == 1  #-- 'both' should have only 1 source listed
    assert out['source'][0]['type'] == 'interface'
    assert out['source'][0]['direction'] == 'both'
    assert out['source'][0]['id'] == p2
    assert out['destination']['type'] == 'interface'
    assert out['destination']['id'] == p3

def case_2_add_second_source_to_active_mirror_session_foo_succeeds():
    with ops1.libs.vtysh.ConfigMirrorSession("foo") as ctx:
        ctx.source_interface('1',"rx")

    out = ops1.libs.vtysh.show_mirror('foo')
    assert out['name'] == 'foo'
    assert out['status'] == 'active'
    assert len(out['source']) == 2
    int_idx = interface_in_source_list(out, p1)
    assert int_idx >= 0
    assert out['source'][int_idx]['type'] == 'interface'
    assert out['source'][int_idx]['direction'] == 'rx'
    int_idx = interface_in_source_list(out, p2)
    assert int_idx >= 0
    assert out['source'][int_idx]['type'] == 'interface'
    assert out['source'][int_idx]['direction'] == 'both'
    assert out['destination']['type'] == 'interface'
    assert out['destination']['id'] == p3

def case_3_remove_first_source_to_active_mirror_session_foo_succeeds():
    with ops1.libs.vtysh.ConfigMirrorSession("foo") as ctx:
        ctx.no_source_interface('2')  # 'both' is default

    out = ops1.libs.vtysh.show_mirror('foo')
    assert out['name'] == 'foo'
    assert out['status'] == 'active'
    assert len(out['source']) == 2
    int_idx = interface_in_source_list(out, p1)
    assert int_idx >= 0
    assert out['source'][int_idx]['type'] == 'interface'
    assert out['source'][int_idx]['direction'] == 'rx'
    int_idx = interface_in_source_list(out, "none")
    assert int_idx >= 0
    assert out['source'][int_idx]['type'] == 'interface'
    assert out['source'][int_idx]['direction'] == 'tx'
    assert out['destination']['type'] == 'interface'
    assert out['destination']['id'] == p3

def case_4_activate_mirror_session_bar_succeeds():
    with ops1.libs.vtysh.ConfigMirrorSession("bar") as ctx:
        ctx.source_interface('2',"tx")
        ctx.destination_interface('4')
        ctx.no_shutdown()

    assertMirrorWithRetry('case4','bar','active',testRetryLimit)
    out = ops1.libs.vtysh.show_mirror('bar')
    assert out['name'] == 'bar'
    assert out['status'] == 'active'
    assert len(out['source']) == 2
    int_idx = interface_in_source_list(out, p2)
    assert int_idx >= 0
    assert out['source'][int_idx]['type'] == 'interface'
    assert out['source'][int_idx]['direction'] == 'tx'
    int_idx = interface_in_source_list(out, "none")
    assert int_idx >= 0
    assert out['source'][int_idx]['type'] == 'interface'
    assert out['source'][int_idx]['direction'] == 'rx'
    assert out['destination']['type'] == 'interface'
    assert out['destination']['id'] == p4

    out = ops1.libs.vtysh.show_running_config()
    assert out['mirror_session']['foo'] == 'foo'
    assert out['mirror_session']['bar'] == 'bar'

def case_5_attempt_another_session_using_existing_destination_fails():
    with raises(UnknownVtyshException):
        with ops1.libs.vtysh.ConfigMirrorSession("dup") as ctx:
            ctx.source_interface('1',"rx")
            ctx.destination_interface('4')
            ctx.no_shutdown()

    assertMirrorWithRetry('case5','dup','shutdown',testRetryLimit)

    out = ops1.libs.vtysh.show_mirror('dup')
    assert len(out['source']) == 2
    int_idx = interface_in_source_list(out, p1)
    assert int_idx >= 0
    assert out['source'][int_idx]['type'] == 'interface'
    assert out['source'][int_idx]['direction'] == 'rx'
    int_idx = interface_in_source_list(out, "none")
    assert int_idx >= 0
    assert out['source'][int_idx]['type'] == 'interface'
    assert out['source'][int_idx]['direction'] == 'tx'
    assert out['destination']['type'] == 'interface'
    assert out['destination']['id'] == p4

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_mirror_session("dup")

def case_6_attempt_another_session_with_destination_using_existing_rx_source_interface_fails():
    with raises(UnknownVtyshException):
        with ops1.libs.vtysh.ConfigMirrorSession("dup") as ctx:
            ctx.source_interface('2',"rx")
            ctx.destination_interface('1')
            ctx.no_shutdown()

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_mirror_session("dup")

def case_7_attempt_another_session_with_destination_using_existing_tx_source_interface_fails():
    with raises(UnknownVtyshException):
        with ops1.libs.vtysh.ConfigMirrorSession("dup") as ctx:
            ctx.source_interface('1',"rx")
            ctx.destination_interface('2')
            out = ctx.no_shutdown()
            assert 'already in use as source in active session' in out

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_mirror_session("dup")

def case_8_attempt_another_session_with_source_rx_using_existing_destination_interface_fails():
    with raises(UnknownVtyshException):
        with ops1.libs.vtysh.ConfigMirrorSession("dup") as ctx:
            ctx.source_interface('3',"rx")
            ctx.destination_interface('4')
            out = ctx.no_shutdown()
            assert 'already in use as destination in active session' in out

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_mirror_session("dup")

def case_9_attempt_another_session_with_source_tx_using_existing_destination_interface_fails():
    with raises(UnknownVtyshException):
        with ops1.libs.vtysh.ConfigMirrorSession("dup") as ctx:
            ctx.source_interface('3',"tx")
            ctx.destination_interface('4')
            out = ctx.no_shutdown()
            assert 'already in use as destination in active session' in out

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_mirror_session("dup")

def case_10_attempt_another_session_with_same_source_rx_and_destination_interface_fails():
    with raises(UnknownVtyshException):
        with ops1.libs.vtysh.ConfigMirrorSession("dup") as ctx:
            ctx.source_interface('3',"rx")
            out = ctx.destination_interface('3')
            assert 'Cannot add destination' in out
            assert 'already a source' in out

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_mirror_session("dup")

def case_11_attempt_another_session_with_same_source_tx_and_destination_interface_fails():
    with raises(UnknownVtyshException):
        with ops1.libs.vtysh.ConfigMirrorSession("dup") as ctx:
            ctx.source_interface('3',"tx")
            out = ctx.destination_interface('3')
            assert 'Cannot add destination' in out
            assert 'already a source' in out

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_mirror_session("dup")

def case_12_attempt_another_session_without_a_destination_interface_fails():
    with raises(UnknownVtyshException):
        with ops1.libs.vtysh.ConfigMirrorSession("dup") as ctx:
            ctx.source_interface('3',"tx")
            out = ctx.no_shutdown()
            assert 'No mirror destination interface configured' in out

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_mirror_session("dup")

def case_13_create_inactive_duplicate_mirror_session_dup_succeeds():
    with ops1.libs.vtysh.ConfigMirrorSession("dup") as ctx:
        ctx.source_interface('1',"rx")
        ctx.destination_interface('3')

    out = ops1.libs.vtysh.show_mirror('')
    assert out['dup']['status'] == 'shutdown'

def case_14_deactivate_mirror_session_foo():
    with ops1.libs.vtysh.ConfigMirrorSession("foo") as ctx:
        ctx.shutdown()

    out = ops1.libs.vtysh.show_mirror('')
    assert out['foo']['status'] == 'shutdown'

def case_15_activate_mirror_session_dup():
    with ops1.libs.vtysh.ConfigMirrorSession("dup") as ctx:
        ctx.no_shutdown()

    out = ops1.libs.vtysh.show_mirror('')
    assert out['dup']['status'] == 'active'

def case_16_remove_inactive_mirror_session_foo_succeeds():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_mirror_session("foo")

    out = ops1.libs.vtysh.show_mirror('')
    assert 'foo' not in out.keys()

    out = ops1.libs.vtysh.show_mirror('foo')
    assert out is "Invalid"

def case_17_remove_active_mirror_session_dup_succeeds():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_mirror_session("dup")

    out = ops1.libs.vtysh.show_mirror('')
    assert 'dup' not in out.keys()

    out = ops1.libs.vtysh.show_mirror('dup')
    assert out is "Invalid"

def case_18_remove_active_mirror_session_bar_succeeds():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_mirror_session("bar")

    out = ops1.libs.vtysh.show_mirror('bar')
    assert out is "Invalid"

    out = ops1.libs.vtysh.show_mirror('')
    assert out is "None"

    out = ops1.libs.vtysh.show_running_config()
    assert not out['mirror_session']

def case_19_create_lag_succeeds():
    with ops1.libs.vtysh.ConfigInterfaceLag('100') as ctx:
        ctx.no_routing()
        ctx.vlan_access('1')
        ctx.vlan_trunk_allowed('1')
        ctx.no_shutdown()

    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.lag("100")
    with ops1.libs.vtysh.ConfigInterface('2') as ctx:
        ctx.lag("100")

def case_20_mirror_session_with_source_lag_succeeds():
    with ops1.libs.vtysh.ConfigMirrorSession("foo") as ctx:
        ctx.source_interface("lag100", 'rx')
        ctx.destination_interface('3')
        ctx.no_shutdown()

    out = ops1.libs.vtysh.show_mirror('')
    # TODO: once mirror lags can be enabled in the container, uncomment this.
#     assert out['foo']['status'] == 'active'

    out = ops1.libs.vtysh.show_mirror('foo')
    assert out['name'] == 'foo'
    # TODO: once mirror lags can be enabled in the container, uncomment this.
#    assert out['status'] == 'active'
    assert len(out['source']) == 2
    int_idx = interface_in_source_list(out, "lag100")
    assert int_idx >= 0
    assert out['source'][int_idx]['type'] == 'interface'
    assert out['source'][int_idx]['direction'] == 'rx'
    int_idx = interface_in_source_list(out, "none")
    assert int_idx >= 0
    assert out['source'][int_idx]['type'] == 'interface'
    assert out['source'][int_idx]['direction'] == 'tx'
    assert out['destination']['type'] == 'interface'
    assert out['destination']['id'] == p3

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_mirror_session('foo')

def case_21_mirror_session_with_destination_lag_succeeds():
    with ops1.libs.vtysh.ConfigMirrorSession("bar") as ctx:
        ctx.source_interface('3', 'rx')
        ctx.destination_interface("lag100")
        ctx.no_shutdown()

    out = ops1.libs.vtysh.show_mirror('')
    # TODO: once mirror lags can be enabled in the container, uncomment this.
#     assert out['bar']['status'] == 'active'

    out = ops1.libs.vtysh.show_mirror('bar')
    assert out['name'] == 'bar'
    # TODO: once mirror lags can be enabled in the container, uncomment this.
#    assert out['status'] == 'active'
    assert len(out['source']) == 2
    int_idx = interface_in_source_list(out, p3)
    assert int_idx >= 0
    assert out['source'][int_idx]['type'] == 'interface'
    assert out['source'][int_idx]['direction'] == 'rx'
    int_idx = interface_in_source_list(out, "none")
    assert int_idx >= 0
    assert out['source'][int_idx]['type'] == 'interface'
    assert out['source'][int_idx]['direction'] == 'tx'
    assert out['destination']['type'] == 'interface'
    assert out['destination']['id'] == "lag100"

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_mirror_session('bar')

def case_22_add_mirror_non_system_interface_fails():
    with ops1.libs.vtysh.ConfigInterface('3') as ctx:
        ctx.routing()

    with ops1.libs.vtysh.ConfigSubinterface('3', '1') as ctx:
        ctx.no_shutdown()

    with raises(UnknownVtyshException):
        with ops1.libs.vtysh.ConfigMirrorSession("non_system") as ctx:
            out = ctx.source_interface('3.1',"tx")
            assert 'Invalid interface' in out

    with raises(UnknownVtyshException):
        with ops1.libs.vtysh.ConfigMirrorSession("non_system") as ctx:
            out = ctx.destination_interface('3.1')
            assert 'Invalid interface' in out

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_mirror_session("non_system ")

    with ops1.libs.vtysh.ConfigInterface('3') as ctx:
        ctx.no_routing()
        ctx.vlan_access("1")
        ctx.vlan_trunk_allowed("1")

@mark.gate
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
    case_22_add_mirror_non_system_interface_fails()
