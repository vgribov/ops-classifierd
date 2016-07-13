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

import json
import http.client

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

def get_switch_ip(switch):
    switch_ip = switch('python -c \"import socket; '
                       'print socket.gethostbyname(socket.gethostname())\"',
                       shell='bash')
    switch_ip = switch_ip.rstrip('\r\n')
    return switch_ip

def format(s):
    return s.format(**globals())

def rest_sanity_check(switch_ip):
    login_url = "https://" + str(switch_ip) + "/login"
    result = ops1("curl -D /tmp/header$$ --noproxy " + str(switch_ip) + \
                  " -X POST --fail -ksSfL --url \"" + login_url + "\" " + \
                  "-H \"Content-Type: application/x-www-form-urlencoded\" " + \
                  "-d \"username=netop&password=netop\"", shell='bash')

    result = ops1("grep Set-Cookie /tmp/header$$|awk '{print $2}' " + \
                  "> /tmp/COOKIE", shell='bash')

    # Check if bridge_normal is ready, loop until ready or timeout finish
    system_path = "/rest/v1/system"
    bridge_path = "/rest/v1/system/bridges/bridge_normal"
    count = 1
    max_retries = 60  # 1 minute
    while count <= max_retries:
        try:
            login_url = "https://" + str(switch_ip) + "/login"
            ops1("curl -D /tmp/header$$ --noproxy " + str(switch_ip) + \
                 " -X POST --fail -ksSfL --url \"" + login_url + \
                 "\" -H \"Content-Type: " + \
                 "application/x-www-form-urlencoded\" " + \
                 "-d \"username=netop&password=netop\"", shell='bash')

            ops1("grep Set-Cookie /tmp/header$$|awk '{print $2}' " + \
                          "> /tmp/COOKIE", shell='bash')

            status_system, response_system = \
                execute_request(system_path, "GET", None, switch_ip)
            status_bridge, response_bridge = \
                execute_request(bridge_path, "GET", None, switch_ip)

            if status_system is http.client.OK and \
                    status_bridge is http.client.OK:
                break
        except:
            pass

        count += 1
        time.sleep(1)

    assert count <= max_retries, "Switch Sanity check failure: After waiting \
        %d seconds, the switch is still not ready to run the tests" \
        % max_retries

def execute_request(url, method, data, rest_server_ip):
    count = 1
    max_retries = 60  # 1 minute
    while count <= max_retries:
        command = '2>&1'

        curl_command = ('curl -v -k -H \"Content-Type: application/json\" '
                        '-H \"Cookie: $(cat /tmp/COOKIE)\" '
                        '--retry 3 ')
        curl_xmethod = '-X ' + method + ' '
        curl_url = '\"https://' + rest_server_ip + url + '\" '
        curl_command += curl_xmethod

        if (data):
            curl_command += '-d \'' + data + '\' '

        curl_command += curl_url

        if (command):
            curl_command += command

        result = ops1(curl_command, shell='bash')

        status_code = get_status_code(result)
        response_data = get_response_data(result)

        if status_code != http.client.UNAUTHORIZED:
            # Authentication succeeded. Return the response.
            return status_code, response_data

        # Save a copy of the cookie.
        login_url = "https://" + str(switch_ip) + "/login"
        ops1("curl -D /tmp/header$$ --noproxy " + str(switch_ip) + \
             " -X POST --fail -ksSfL --url \"" + login_url + \
             "\" -H \"Content-Type: " + \
             "application/x-www-form-urlencoded\" " + \
             "-d \"username=netop&password=netop\"", shell='bash')
        ops1("grep Set-Cookie /tmp/header$$|awk '{print $2}' " + \
                      "> /tmp/COOKIE", shell='bash')

        count += 1
        time.sleep(1)

    assert count <= max_retries, "Unable to send curl command."

def get_status_code(request_output):
    for line in request_output.split('\n'):
        if '< HTTP/1.1' in line:
            status_code = int(line.split(' ')[2])
            return status_code

def get_response_data(request_output):
    for line in request_output.split('\n'):
        if line.startswith('{'):
            return line
    return ''

def get_port_url(port):
    s = "/rest/v1/system/ports/" + port
    return format(s)

port_data = {
    "configuration": {
        "qos": "/rest/v1/system/qoss/profile1",
        "qos_config": {
            "qos_trust": "none",
            "dscp_override": "1"
        }
    }
}

q_profile_entry_post_url = "/rest/v1/system/q_profiles/profile1/q_profile_entries"
q_profile_entry_url = q_profile_entry_post_url + "/1"
q_profile_entry_data = {
    "configuration": {
        "description": "d1",
        "local_priorities": [6]
    }
}

q_profile_post_url = "/rest/v1/system/q_profiles"
q_profile_url = q_profile_post_url + "/profile1"
q_profile_data = {
    "configuration": {
        "name": "profile1",
        "q_profile_entries": {}
    }
}

qos_cos_map_entry_post_url = "/rest/v1/system/qos_cos_map_entries"
qos_cos_map_entry_url = qos_cos_map_entry_post_url + "/1"
qos_cos_map_entry_data = {
    "configuration": {
        "code_point": 1,
        "color": "green",
        "description": "d1",
        "local_priority": 2
    }
}

qos_dscp_map_entry_post_url = "/rest/v1/system/qos_dscp_map_entries"
qos_dscp_map_entry_url = qos_dscp_map_entry_post_url + "/1"
qos_dscp_map_entry_data = {
    "configuration": {
        "code_point": 1,
        "color": "green",
        "description": "d1",
        "local_priority": 2
    }
}

qos_post_url = "/rest/v1/system/qoss"
qos_url = qos_post_url + "/profile1"
qos_data = {
    "configuration": {
        "name": "profile1",
        "queues": {}
    }
}

queue_post_url = "/rest/v1/system/qoss/profile1/queues"
queue_url = queue_post_url + "/1"
queue_data = {
    "configuration": {
        "algorithm": "dwrr",
        "weight": 1
    }
}

system_url = "/rest/v1/system"
system_data = {
    "configuration": {
        "hostname": "",
        "asset_tag_number": "",
        "q_profile": "/rest/v1/system/q_profiles/default",
        "qos": "/rest/v1/system/qoss/default",
        "qos_config": {
            "qos_trust": "dscp"
        },
        "qos_cos_map_entries": [],
        "qos_dscp_map_entries": []
    }
}

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

    with ops1.libs.vtysh.ConfigScheduleProfile('AllWrrWithMaxStrict') as ctx:
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

def check_system_qos_status_has(s):
    # TODO: This check fails about 1 in 25 tries, so it is disabled for now.
    return

    count = 1
    max_retries = 60
    while count <= max_retries:
        try:
            response_status, response_data = execute_request(
                system_url, "GET",
                None, switch_ip)

            if s in response_data:
                # Found the string in the response_data; success
                return
        except:
            pass

        count += 1
        time.sleep(1)

    response_status, response_data = execute_request(
        system_url, "GET",
        None, switch_ip)

    assert s in response_data

def case_port_qos_patch():
    data = [{"op": "add", "path": "/qos_config",
             "value": {"qos_trust": "none"}}]

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

def case_port_qos_patch_validate_port_cos_has_port_trust_mode_none():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/qos_config",
             "value": {"qos_trust": "cos", "cos_override": "1"}}]

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'QoS COS override is not currently supported.' in response_data

def case_port_qos_patch_validate_port_dscp_has_port_trust_mode_none():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/qos_config",
             "value": {"qos_trust": "dscp", "dscp_override": "1"}}]

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'QoS DSCP override is only allowed if' in response_data

def case_port_qos_patch_validate_apply_port_queue_profile_is_null():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/q_profile",
             "value": "/rest/v1/system/q_profiles/profile1"}]

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'Port-level queue profile is not supported.' in response_data

def case_port_qos_patch_validate_apply_port_s_p_has_same_algorithms():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    ops1(format('no qos schedule-profile profile2'))
    ops1(format('qos schedule-profile profile2'))
    ops1(format('strict queue 4'))
    ops1(format('strict queue 5'))
    ops1(format('strict queue 6'))
    ops1(format('strict queue 7'))
    ops1(format('dwrr queue 0 weight 1'))
    ops1(format('dwrr queue 1 weight 10'))
    ops1(format('dwrr queue 2 weight 20'))
    ops1(format('dwrr queue 3 weight 30'))
    ops1(format('exit'))

    data = [{"op": "add", "path": "/qos",
             "value": "/rest/v1/system/qoss/profile2"}]

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'must have the same algorithm on all queues.' in response_data

def case_port_qos_patch_validate_apply_port_profiles_have_same_queues():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    ops1(format('no qos schedule-profile profile2'))
    ops1(format('qos schedule-profile profile2'))
    ops1(format('strict queue 5'))
    ops1(format('exit'))

    data = [{"op": "add", "path": "/qos",
             "value": "/rest/v1/system/qoss/profile2"}]

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'must contain all of the' in response_data

def case_port_qos_put():
    data = deepcopy(port_data)

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.OK
    assert response_data is ''

def case_port_qos_put_validate_port_cos_has_trust_mode_none():
    data = deepcopy(port_data)
    data["configuration"]["qos_config"]["cos_override"] = "1"

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'QoS COS override is not currently supported.' in response_data

def case_port_qos_put_port_dscp_with_sys_trust_none_port_trust_dscp():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_trust('none')

    data = deepcopy(port_data)
    data["configuration"]["qos_config"] = {
        "qos_trust": "dscp",
        "dscp_override": "1"
    }

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'QoS DSCP override is only allowed if' in response_data

def case_port_qos_put_port_dscp_with_sys_trust_none_port_trust_null():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_trust('none')

    data = deepcopy(port_data)
    data["configuration"]["qos_config"] = {
        "dscp_override": "1"
    }

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.OK
    assert response_data is ''

def case_port_qos_put_port_dscp_with_sys_trust_dscp_port_trust_none():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_trust('dscp')

    data = deepcopy(port_data)
    data["configuration"]["qos_config"] = {
        "qos_trust": "none",
        "dscp_override": "1"
    }

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.OK
    assert response_data is ''

def case_port_qos_put_port_dscp_with_sys_trust_dscp_port_trust_null():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.qos_trust('dscp')

    data = deepcopy(port_data)
    data["configuration"]["qos_config"] = {
        "dscp_override": "1"
    }

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'QoS DSCP override is only allowed if' in response_data

def case_port_qos_put_validate_apply_port_queue_profile_is_null():
    data = deepcopy(port_data)
    data["configuration"]["q_profile"] = "/rest/v1/system/q_profiles/profile1"

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'Port-level queue profile is not supported.' in response_data

def case_port_qos_put_validate_apply_port_s_p_has_same_algorithms():
    data = deepcopy(port_data)
    data["configuration"]["qos"] = "/rest/v1/system/qoss/HigherStrictLowerWrr"

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'must have the same algorithm on all queues.' in response_data

def case_port_qos_put_validate_apply_port_profiles_have_same_queues():
    data = deepcopy(port_data)
    data["configuration"]["qos"] = "/rest/v1/system/qoss/SingleQ"

    response_status, response_data = execute_request(
        get_port_url('{p1}'), "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'must contain all of the' in response_data

def case_q_profile_entry_post():
    data = deepcopy(q_profile_entry_data)
    data["configuration"]["queue_number"] = "1"

    response_status, response_data = execute_request(
        q_profile_entry_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.CREATED
    assert response_data is ''

def case_q_profile_entry_post_validate_profile_applied_cannot_be_a_or_d():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('profile1', 'profile1')

    data = deepcopy(q_profile_entry_data)
    data["configuration"]["queue_number"] = "1"

    response_status, response_data = execute_request(
        q_profile_entry_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_q_profile_entry_post_validate_profile_hw_default_cannot_be_a_or_d():
    data = deepcopy(q_profile_entry_data)
    data["configuration"]["queue_number"] = "1"

    q_profile_entry_post_url = "/rest/v1/system/q_profiles/" + \
        "factory-default/q_profile_entries"

    response_status, response_data = execute_request(
        q_profile_entry_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_q_profile_entry_post_validate_profile_entry_name_valid_chars():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('default', 'default')

    data = deepcopy(q_profile_entry_data)
    data["configuration"]["queue_number"] = "1"
    data["configuration"]["description"] = "name@#$%name"

    response_status, response_data = execute_request(
        q_profile_entry_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The allowed characters are' in response_data

def case_q_profile_entry_patch():
    data = [{"op": "add", "path": "/description", "value": "d1"}]

    response_status, response_data = execute_request(
        q_profile_entry_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

def case_q_profile_entry_patch_validate_profile_applied_cannot_be_a_or_d():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    ops1(format('apply qos queue-profile profile1 schedule-profile profile1'))

    data = [{"op": "add", "path": "/description", "value": "d1"}]

    response_status, response_data = execute_request(
        q_profile_entry_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_q_profile_entry_patch_validate_hw_default_cannot_be_a_or_d():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/description", "value": "d1"}]
    q_profile_entry_url = "/rest/v1/system/q_profiles/" + \
        "factory-default/q_profile_entries/1"

    response_status, response_data = execute_request(
        q_profile_entry_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_q_profile_entry_patch_validate_profile_entry_name_valid_chars():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/description", "value": "d1%$#@d1"}]

    response_status, response_data = execute_request(
        q_profile_entry_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The allowed characters are' in response_data

def case_q_profile_entry_put():
    data = deepcopy(q_profile_entry_data)

    response_status, response_data = execute_request(
        q_profile_entry_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.OK
    assert response_data is ''

def case_q_profile_entry_put_validate_profile_applied_cannot_be_a_or_d():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('profile1', 'profile1')

    data = deepcopy(q_profile_entry_data)

    response_status, response_data = execute_request(
        q_profile_entry_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('default', 'default')

def case_q_profile_entry_put_validate_profile_hw_default_cannot_be_a_or_d():
    data = deepcopy(q_profile_entry_data)
    q_profile_entry_url = "/rest/v1/system/q_profiles/" + \
        "factory-default/q_profile_entries/1"

    response_status, response_data = execute_request(
        q_profile_entry_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_q_profile_entry_put_validate_profile_entry_name_valid_chars():
    data = deepcopy(q_profile_entry_data)
    data["configuration"]["description"] = "name@#$%name"

    response_status, response_data = execute_request(
        q_profile_entry_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The allowed characters are' in response_data

def case_q_profile_entry_delete():
    case_q_profile_entry_put()

    response_status, response_data = execute_request(
        q_profile_entry_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

    with ops1.libs.vtysh.ConfigQueueProfile('profile1') as ctx:
        ctx.map_queue_local_priority('1', '6')

def case_q_profile_entry_delete_validate_profile_applied_cannot_be_a_or_d():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('profile1', 'profile1')

    response_status, response_data = execute_request(
        q_profile_entry_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_q_profile_entry_delete_validate_profile_hw_def_cannot_be_a_or_d():
    data = deepcopy(q_profile_entry_data)
    q_profile_entry_url = "/rest/v1/system/q_profiles/" + \
        "factory-default/q_profile_entries/1"

    response_status, response_data = execute_request(
        q_profile_entry_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_q_profile_post():
    data = deepcopy(q_profile_data)
    data["configuration"]["name"] = "n1"

    response_status, response_data = execute_request(
        q_profile_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.CREATED
    assert response_data is ''

def case_q_profile_post_validate_profile_name_contains_valid_chars():
    data = deepcopy(q_profile_data)
    data["configuration"]["name"] = "name@#$%name"

    response_status, response_data = execute_request(
        q_profile_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The allowed characters are' in response_data

def case_q_profile_post_validate_profile_name_cannot_be_strict():
    data = deepcopy(q_profile_data)
    data["configuration"]["name"] = "strict"

    response_status, response_data = execute_request(
        q_profile_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The profile name cannot be \'strict\'.' in response_data

def case_q_profile_patch():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('default', 'default')

    data = [{"op": "add", "path": "/q_profile_entries", "value": {}}]

    response_status, response_data = execute_request(
        q_profile_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

def case_q_profile_patch_validate_profile_applied_cannot_be_a_or_d():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    ops1(format('apply qos queue-profile profile1 schedule-profile profile1'))

    data = [{"op": "add", "path": "/q_profile_entries", "value": {}}]

    response_status, response_data = execute_request(
        q_profile_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_q_profile_patch_validate_profile_hw_default_cannot_be_a_or_d():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/q_profile_entries", "value": {}}]
    q_profile_url = "/rest/v1/system/q_profiles/factory-default"

    response_status, response_data = execute_request(
        q_profile_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_q_profile_put():
    data = deepcopy(q_profile_data)

    response_status, response_data = execute_request(
        q_profile_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.OK
    assert response_data is ''

def case_q_profile_put_validate_profile_applied_cannot_be_a_or_d():
    with ops1.libs.vtysh.ConfigQueueProfile('profile1') as ctx:
        ctx.map_queue_local_priority('4', '3')
        ctx.map_queue_local_priority('5', '2')
        ctx.map_queue_local_priority('6', '1')
        ctx.map_queue_local_priority('7', '0')
        ctx.map_queue_local_priority('0', '7')
        ctx.map_queue_local_priority('1', '6')
        ctx.map_queue_local_priority('2', '5')
        ctx.map_queue_local_priority('3', '4')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('profile1', 'profile1')

    data = deepcopy(q_profile_data)

    response_status, response_data = execute_request(
        q_profile_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_q_profile_put_validate_profile_hw_default_cannot_be_a_or_d():
    data = deepcopy(q_profile_data)
    data["configuration"]["name"] = "factory-default"

    q_profile_url = "/rest/v1/system/q_profiles/factory-default"

    response_status, response_data = execute_request(
        q_profile_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_q_profile_delete():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('default', 'default')

    case_q_profile_put()

    response_status, response_data = execute_request(
        q_profile_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.NO_CONTENT or \
        response_status == http.client.OK
    assert response_data is ''

    with ops1.libs.vtysh.ConfigQueueProfile('profile1') as ctx:
        ctx.map_queue_local_priority('4', '3')
        ctx.map_queue_local_priority('5', '2')
        ctx.map_queue_local_priority('6', '1')
        ctx.map_queue_local_priority('7', '0')
        ctx.map_queue_local_priority('0', '7')
        ctx.map_queue_local_priority('1', '6')
        ctx.map_queue_local_priority('2', '5')
        ctx.map_queue_local_priority('3', '4')

def case_q_profile_delete_validate_profile_applied_cannot_be_a_or_d():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('profile1', 'profile1')

    response_status, response_data = execute_request(
        q_profile_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_q_profile_delete_validate_profile_hw_default_cannot_be_a_or_d():
    data = deepcopy(q_profile_data)
    q_profile_url = "/rest/v1/system/q_profiles/factory-default"

    response_status, response_data = execute_request(
        q_profile_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_q_profile_delete_validate_profile_default_cannot_be_deleted():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('profile1', 'profile1')

    data = deepcopy(q_profile_data)
    q_profile_url = "/rest/v1/system/q_profiles/default"

    response_status, response_data = execute_request(
        q_profile_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The default profile cannot be deleted.' in response_data

def case_qos_cos_map_entry_post():
    data = deepcopy(qos_cos_map_entry_data)

    response_status, response_data = execute_request(
        qos_cos_map_entry_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'COS Map Entries cannot be created' in response_data

def case_qos_cos_map_entry_patch():
    data = [{"op": "add", "path": "/description", "value": "d1"}]

    response_status, response_data = execute_request(
        qos_cos_map_entry_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

def case_qos_cos_map_entry_patch_validate_cos_map_desc_has_valid_chars():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/description", "value": "d1%$#@d1"}]

    response_status, response_data = execute_request(
        qos_cos_map_entry_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The allowed characters are' in response_data

def case_qos_cos_map_entry_put():
    data = deepcopy(qos_cos_map_entry_data)

    response_status, response_data = execute_request(
        qos_cos_map_entry_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.OK
    assert response_data is ''

def case_qos_cos_map_entry_put_validate_cos_map_desc_has_valid_chars():
    data = deepcopy(qos_cos_map_entry_data)
    data["configuration"]["description"] = "name@#$%name"

    response_status, response_data = execute_request(
        qos_cos_map_entry_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The allowed characters are' in response_data

def case_qos_cos_map_entry_delete():
    response_status, response_data = execute_request(
        qos_cos_map_entry_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'COS Map Entries cannot be deleted.' in response_data

def case_qos_dscp_map_entry_post():
    data = deepcopy(qos_dscp_map_entry_data)

    response_status, response_data = execute_request(
        qos_dscp_map_entry_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'DSCP Map Entries cannot be created' in response_data

def case_qos_dscp_map_entry_patch():
    data = [{"op": "add", "path": "/description", "value": "d1"}]

    response_status, response_data = execute_request(
        qos_dscp_map_entry_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

def case_qos_dscp_map_entry_patch_validate_dscp_map_desc_has_valid_chars():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/description", "value": "d1%$#@d1"}]

    response_status, response_data = execute_request(
        qos_dscp_map_entry_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The allowed characters are' in response_data

def case_qos_dscp_map_entry_patch_validate_pcp_is_empty():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/priority_code_point",
             "value": "1"}]

    response_status, response_data = execute_request(
        qos_dscp_map_entry_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'not supported.' in response_data

def case_qos_dscp_map_entry_put():
    data = deepcopy(qos_dscp_map_entry_data)

    response_status, response_data = execute_request(
        qos_dscp_map_entry_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.OK
    assert response_data is ''

def case_qos_dscp_map_entry_put_validate_dscp_map_desc_has_valid_chars():
    data = deepcopy(qos_dscp_map_entry_data)
    data["configuration"]["description"] = "name@#$%name"

    response_status, response_data = execute_request(
        qos_dscp_map_entry_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The allowed characters are' in response_data

def case_qos_dscp_map_entry_put_validate_pcp_is_empty():
    data = deepcopy(qos_dscp_map_entry_data)
    data["configuration"]["priority_code_point"] = 1

    response_status, response_data = execute_request(
        qos_dscp_map_entry_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'not currently supported' in response_data

def case_qos_dscp_map_entry_delete():
    response_status, response_data = execute_request(
        qos_dscp_map_entry_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'DSCP Map Entries cannot be deleted.' in response_data

def case_qos_post():
    data = deepcopy(qos_data)
    data["configuration"]["name"] = "n1"

    response_status, response_data = execute_request(
        qos_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.CREATED
    assert response_data is ''

def case_qos_post_validate_profile_name_contains_valid_chars():
    data = deepcopy(qos_data)
    data["configuration"]["name"] = "name@#$%name"

    response_status, response_data = execute_request(
        qos_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The allowed characters are' in response_data

def case_qos_post_validate_profile_name_cannot_be_strict():
    data = deepcopy(qos_data)
    data["configuration"]["name"] = "strict"

    response_status, response_data = execute_request(
        qos_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The profile name cannot be \'strict\'.' in response_data

def case_qos_patch():
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_apply_qos_schedule_profile()
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('default', 'default')

    data = [{"op": "add", "path": "/queues", "value": {}}]

    response_status, response_data = execute_request(
        qos_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

def case_qos_patch_validate_profile_applied_cannot_be_a_or_d():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    ops1(format('apply qos queue-profile profile1 schedule-profile profile1'))

    data = [{"op": "add", "path": "/queues", "value": {}}]

    response_status, response_data = execute_request(
        qos_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_qos_patch_validate_profile_hw_default_cannot_be_a_or_d():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/queues", "value": {}}]
    qos_url = "/rest/v1/system/qoss/factory-default"

    response_status, response_data = execute_request(
        qos_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_qos_put():
    data = deepcopy(qos_data)

    response_status, response_data = execute_request(
        qos_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.OK
    assert response_data is ''

def case_qos_put_validate_profile_applied_cannot_be_a_or_d():
    with ops1.libs.vtysh.ConfigScheduleProfile('profile1') as ctx:
        ctx.dwrr_queue_weight('4', '40')
        ctx.dwrr_queue_weight('5', '50')
        ctx.dwrr_queue_weight('6', '60')
        ctx.dwrr_queue_weight('7', '70')
        ctx.dwrr_queue_weight('0', '1')
        ctx.dwrr_queue_weight('1', '10')
        ctx.dwrr_queue_weight('2', '20')
        ctx.dwrr_queue_weight('3', '30')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('profile1', 'profile1')

    data = deepcopy(qos_data)

    response_status, response_data = execute_request(
        qos_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_qos_put_validate_profile_hw_default_cannot_be_a_or_d():
    data = deepcopy(qos_data)
    data["configuration"]["name"] = "factory-default"

    qos_url = "/rest/v1/system/qoss/factory-default"

    response_status, response_data = execute_request(
        qos_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_qos_delete():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('default', 'default')

    case_qos_put()

    response_status, response_data = execute_request(
        qos_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.NO_CONTENT or \
        response_status == http.client.OK
    assert response_data is ''

    with ops1.libs.vtysh.ConfigScheduleProfile('profile1') as ctx:
        ctx.dwrr_queue_weight('4', '40')
        ctx.dwrr_queue_weight('5', '50')
        ctx.dwrr_queue_weight('6', '60')
        ctx.dwrr_queue_weight('7', '70')
        ctx.dwrr_queue_weight('0', '1')
        ctx.dwrr_queue_weight('1', '10')
        ctx.dwrr_queue_weight('2', '20')
        ctx.dwrr_queue_weight('3', '30')

def case_qos_delete_validate_profile_applied_cannot_be_a_or_d():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('profile1', 'profile1')

    response_status, response_data = execute_request(
        qos_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_qos_delete_validate_profile_hw_default_cannot_be_a_or_d():
    data = deepcopy(qos_data)
    qos_url = "/rest/v1/system/qoss/factory-default"

    response_status, response_data = execute_request(
        qos_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_qos_delete_validate_profile_default_cannot_be_deleted():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('profile1', 'profile1')

    data = deepcopy(qos_data)
    qos_url = "/rest/v1/system/qoss/default"

    response_status, response_data = execute_request(
        qos_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The default profile cannot be deleted.' in response_data

def case_queue_post():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('default', 'default')

    data = deepcopy(queue_data)
    data["configuration"]["queue_number"] = "1"

    response_status, response_data = execute_request(
        queue_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.CREATED
    assert response_data is ''

def case_queue_post_validate_profile_applied_cannot_be_a_or_d():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('profile1', 'profile1')

    data = deepcopy(queue_data)
    data["configuration"]["queue_number"] = "1"

    response_status, response_data = execute_request(
        queue_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_queue_post_validate_profile_hw_default_cannot_be_a_or_d():
    data = deepcopy(queue_data)
    data["configuration"]["queue_number"] = "1"
    queue_post_url = "/rest/v1/system/qoss/factory-default/queues"

    response_status, response_data = execute_request(
        queue_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_queue_post_validate_profile_entry_with_dwrr_has_w_less_than_max_w():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('default', 'default')

    data = deepcopy(queue_data)
    data["configuration"]["queue_number"] = "1"
    data["configuration"]["weight"] = 1024

    response_status, response_data = execute_request(
        queue_post_url, "POST",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The weight cannot be larger than' in response_data

def case_queue_patch():
    data = [{"op": "add", "path": "/weight", "value": 1}]

    response_status, response_data = execute_request(
        queue_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

def case_queue_patch_validate_profile_applied_cannot_be_a_or_d():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    ops1(format('apply qos queue-profile profile1 schedule-profile profile1'))

    data = [{"op": "add", "path": "/weight", "value": 1}]

    response_status, response_data = execute_request(
        queue_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_queue_patch_validate_profile_hw_default_cannot_be_a_or_d():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/weight", "value": 1}]
    queue_url = "/rest/v1/system/qoss/factory-default/queues"

    response_status, response_data = execute_request(
        queue_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_queue_patch_validate_profile_entry_with_dwrr_has_w_less_than_max_w():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/weight", "value": 1024}]

    response_status, response_data = execute_request(
        queue_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The weight cannot be larger than' in response_data

def case_queue_put():
    data = deepcopy(queue_data)

    response_status, response_data = execute_request(
        queue_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.OK
    assert response_data is ''

def case_queue_put_validate_profile_applied_cannot_be_a_or_d():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('profile1', 'profile1')

    data = deepcopy(queue_data)

    response_status, response_data = execute_request(
        queue_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_queue_put_validate_profile_hw_default_cannot_be_a_or_d():
    data = deepcopy(queue_data)
    queue_url = "/rest/v1/system/qoss/factory-default/queues/1"

    response_status, response_data = execute_request(
        queue_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_queue_put_validate_profile_entry_with_dwrr_has_w_less_than_max_w():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('default', 'default')

    data = deepcopy(queue_data)
    data["configuration"]["weight"] = 1024

    response_status, response_data = execute_request(
        queue_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The weight cannot be larger than' in response_data

def case_queue_delete():
    case_queue_put()

    response_status, response_data = execute_request(
        queue_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

    with ops1.libs.vtysh.ConfigScheduleProfile('profile1') as ctx:
        ctx.dwrr_queue_weight('1', '10')

def case_queue_delete_validate_profile_applied_cannot_be_a_or_d():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('profile1', 'profile1')

    response_status, response_data = execute_request(
        queue_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'An applied profile cannot' in response_data

def case_queue_delete_validate_profile_hw_default_cannot_be_a_or_d():
    data = deepcopy(queue_data)
    queue_url = "/rest/v1/system/qoss/factory-default/queues/1"

    response_status, response_data = execute_request(
        queue_url, "DELETE",
        None, switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'A hardware default profile cannot' in response_data

def case_system_qos_patch():
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('default', 'default')

    data = [{"op": "add", "path": "/qos_config",
             "value": {"qos_trust": "dscp"}}]

    response_status, response_data = execute_request(
        system_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.NO_CONTENT
    assert response_data is ''

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_patch_validate_trust_global_is_not_empty():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    data = [{"op": "add", "path": "/qos_config",
             "value": {}}]

    response_status, response_data = execute_request(
        system_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The qos trust value cannot be empty.' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_patch_validate_apply_global_q_p_has_all_local_p():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    ops1(format('no qos queue-profile profile2'))
    ops1(format('qos queue-profile profile2'))
    ops1(format('map queue 4 local-priority 4'))
    ops1(format('map queue 5 local-priority 5'))
    ops1(format('map queue 6 local-priority 6'))
    ops1(format('map queue 7 local-priority 7'))
    ops1(format('map queue 0 local-priority 0'))
    ops1(format('map queue 1 local-priority 1'))
    ops1(format('map queue 2 local-priority 2'))
    ops1(format('name queue 3 n1'))
    ops1(format('exit'))

    data = [{"op": "add", "path": "/q_profile",
             "value": "/rest/v1/system/q_profiles/profile2"}]

    response_status, response_data = execute_request(
        system_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The queue profile is missing local priority' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_patch_validate_apply_global_q_p_has_no_dup_local_p():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    ops1(format('no qos queue-profile profile2'))
    ops1(format('qos queue-profile profile2'))
    ops1(format('map queue 4 local-priority 4'))
    ops1(format('map queue 5 local-priority 5'))
    ops1(format('map queue 6 local-priority 6'))
    ops1(format('map queue 7 local-priority 7'))
    ops1(format('map queue 0 local-priority 0'))
    ops1(format('map queue 1 local-priority 1'))
    ops1(format('map queue 2 local-priority 2'))
    ops1(format('map queue 3 local-priority 3'))
    ops1(format('map queue 3 local-priority 4'))
    ops1(format('exit'))

    data = [{"op": "add", "path": "/q_profile",
             "value": "/rest/v1/system/q_profiles/profile2"}]

    response_status, response_data = execute_request(
        system_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'assigned more than once' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_patch_validate_apply_global_s_p_has_all_same_alg():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    ops1(format('no qos schedule-profile profile2'))
    ops1(format('qos schedule-profile profile2'))
    ops1(format('strict queue 4'))
    ops1(format('strict queue 5'))
    ops1(format('strict queue 6'))
    ops1(format('strict queue 7'))
    ops1(format('dwrr queue 0 weight 1'))
    ops1(format('dwrr queue 1 weight 10'))
    ops1(format('dwrr queue 2 weight 20'))
    ops1(format('dwrr queue 3 weight 30'))
    ops1(format('exit'))

    data = [{"op": "add", "path": "/qos",
             "value": "/rest/v1/system/qoss/profile2"}]

    response_status, response_data = execute_request(
        system_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'must have the same algorithm on all queues.' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_patch_validate_apply_global_profiles_have_same_queues():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    ops1(format('no qos schedule-profile profile2'))
    ops1(format('qos schedule-profile profile2'))
    ops1(format('strict queue 5'))
    ops1(format('exit'))

    data = [{"op": "add", "path": "/qos",
             "value": "/rest/v1/system/qoss/profile2"}]

    response_status, response_data = execute_request(
        system_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'must contain all of the' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_patch_validate_apply_port_profiles_have_same_queues():
    # Once custom validators support PATCH (taiga 661), enable this test.
    return
    # Create profiles with just one queue.
    ops1(format('no qos queue-profile profile2'))
    ops1(format('qos queue-profile profile2'))
    ops1(format('map queue 0 local-priority 0'))
    ops1(format('map queue 0 local-priority 1'))
    ops1(format('map queue 0 local-priority 2'))
    ops1(format('map queue 0 local-priority 3'))
    ops1(format('map queue 0 local-priority 4'))
    ops1(format('map queue 0 local-priority 5'))
    ops1(format('map queue 0 local-priority 6'))
    ops1(format('map queue 0 local-priority 7'))
    ops1(format('exit'))

    ops1(format('no qos schedule-profile profile2'))
    ops1(format('qos schedule-profile profile2'))
    ops1(format('strict queue 0'))
    ops1(format('exit'))

    # Apply the one-queue profiles to system and port.
    ops1(format('apply qos queue-profile profile2 schedule-profile profile2'))
    ops1(format('interface {p1}'))
    ops1(format('apply qos schedule-profile profile2'))
    ops1(format('exit'))

    # Globally applying the default profiles should fail, since they
    # have 8 queues rather than 1 queue.
    data = [{"op": "add", "path": "/q_profile",
             "value": "/rest/v1/system/q_profiles/default"}]

    response_status, response_data = execute_request(
        system_url, "PATCH",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'must contain all of the' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_put():
    data = deepcopy(system_data)

    response_status, response_data = execute_request(
        system_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.OK
    assert response_data is ''

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_put_validate_trust_global_is_not_empty():
    data = deepcopy(system_data)
    data["configuration"]["qos_config"] = {}

    response_status, response_data = execute_request(
        system_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The qos trust value cannot be empty.' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_put_validate_apply_global_q_p_has_all_local_p():
    with ops1.libs.vtysh.ConfigQueueProfile(
            'MissingLocalPriority') as ctx:
        ctx.map_queue_local_priority('4', '3')
        ctx.map_queue_local_priority('5', '2')
        ctx.map_queue_local_priority('6', '1')
        ctx.name_queue('7', 'MyName')
        ctx.map_queue_local_priority('0', '7')
        ctx.map_queue_local_priority('1', '6')
        ctx.map_queue_local_priority('2', '5')
        ctx.map_queue_local_priority('3', '4')

    data = deepcopy(system_data)
    data["configuration"]["q_profile"] = \
        "/rest/v1/system/q_profiles/MissingLocalPriority"

    response_status, response_data = execute_request(
        system_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'The queue profile is missing local priority' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_put_validate_apply_global_q_p_has_no_dup_local_p():
    with ops1.libs.vtysh.ConfigQueueProfile(
            'DuplicateLocalPriority') as ctx:
        ctx.map_queue_local_priority('4', '3')
        ctx.map_queue_local_priority('5', '2')
        ctx.map_queue_local_priority('6', '1')
        ctx.map_queue_local_priority('7', '0')
        ctx.map_queue_local_priority('0', '7,6')
        ctx.map_queue_local_priority('1', '6')
        ctx.map_queue_local_priority('2', '5')
        ctx.map_queue_local_priority('3', '4')

    data = deepcopy(system_data)
    data["configuration"]["q_profile"] = \
        "/rest/v1/system/q_profiles/DuplicateLocalPriority"

    response_status, response_data = execute_request(
        system_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'assigned more than once' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_put_validate_apply_global_s_p_has_all_same_algorithms():
    data = deepcopy(system_data)
    data["configuration"]["qos"] = "/rest/v1/system/qoss/HigherStrictLowerWrr"

    response_status, response_data = execute_request(
        system_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'must have the same algorithm on all queues.' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_put_validate_apply_global_profiles_have_same_queues():
    data = deepcopy(system_data)
    data["configuration"]["qos"] = "/rest/v1/system/qoss/SingleQ"

    response_status, response_data = execute_request(
        system_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'must contain all of the' in response_data

    check_system_qos_status_has("\"queue_profile\": \"default\"")
    check_system_qos_status_has("\"schedule_profile\": \"default\"")

def case_system_qos_put_validate_apply_port_profiles_have_same_queues():
    # Apply the one-queue profiles to system and port.
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('SingleQ', 'SingleQ')
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.apply_qos_schedule_profile('SingleQ')

    # Globally applying the default profiles should fail, since they
    # have 8 queues rather than 1 queue.
    data = deepcopy(system_data)

    response_status, response_data = execute_request(
        system_url, "PUT",
        json.dumps(data), switch_ip)

    assert response_status == http.client.BAD_REQUEST
    assert 'must contain all of the' in response_data

    # TODO: Investigate why these commands fail some of the time when the
    # system is under stress.
#     check_system_qos_status_has("\"queue_profile\": \"profile2\"")
#     check_system_qos_status_has("\"schedule_profile\": \"profile2\"")

    # Un-apply the one-queue profiles.
    with ops1.libs.vtysh.ConfigInterface('1') as ctx:
        ctx.no_apply_qos_schedule_profile()
    with ops1.libs.vtysh.Configure() as ctx:
        ctx.apply_qos_queue_profile_schedule_profile('default', 'default')

@mark.gate
def test_qos_ct_rest_custom_validators(topology, setup):
    setUp_qosApplyGlobal()

    case_port_qos_patch()
    case_port_qos_patch_validate_port_cos_has_port_trust_mode_none()
    case_port_qos_patch_validate_port_dscp_has_port_trust_mode_none()
    case_port_qos_patch_validate_apply_port_queue_profile_is_null()
    case_port_qos_patch_validate_apply_port_s_p_has_same_algorithms()
    case_port_qos_patch_validate_apply_port_profiles_have_same_queues()
    case_port_qos_put()
    case_port_qos_put_validate_port_cos_has_trust_mode_none()
    case_port_qos_put_port_dscp_with_sys_trust_none_port_trust_dscp()
    case_port_qos_put_port_dscp_with_sys_trust_none_port_trust_null()
    case_port_qos_put_port_dscp_with_sys_trust_dscp_port_trust_none()
    case_port_qos_put_port_dscp_with_sys_trust_dscp_port_trust_null()
    case_port_qos_put_validate_apply_port_queue_profile_is_null()
    case_port_qos_put_validate_apply_port_s_p_has_same_algorithms()
    case_port_qos_put_validate_apply_port_profiles_have_same_queues()

    case_q_profile_entry_post()
    case_q_profile_entry_post_validate_profile_applied_cannot_be_a_or_d()
    case_q_profile_entry_post_validate_profile_hw_default_cannot_be_a_or_d()
    case_q_profile_entry_post_validate_profile_entry_name_valid_chars()
    case_q_profile_entry_patch()
    case_q_profile_entry_patch_validate_profile_applied_cannot_be_a_or_d()
    case_q_profile_entry_patch_validate_hw_default_cannot_be_a_or_d()
    case_q_profile_entry_patch_validate_profile_entry_name_valid_chars()
    case_q_profile_entry_put()
    case_q_profile_entry_put_validate_profile_applied_cannot_be_a_or_d()
    case_q_profile_entry_put_validate_profile_hw_default_cannot_be_a_or_d()
    case_q_profile_entry_put_validate_profile_entry_name_valid_chars()
    case_q_profile_entry_delete()
    case_q_profile_entry_delete_validate_profile_applied_cannot_be_a_or_d()
    case_q_profile_entry_delete_validate_profile_hw_def_cannot_be_a_or_d()

    case_q_profile_post()
    case_q_profile_post_validate_profile_name_contains_valid_chars()
    case_q_profile_post_validate_profile_name_cannot_be_strict()
    case_q_profile_patch()
    case_q_profile_patch_validate_profile_applied_cannot_be_a_or_d()
    case_q_profile_patch_validate_profile_hw_default_cannot_be_a_or_d()
    case_q_profile_put()
    case_q_profile_put_validate_profile_applied_cannot_be_a_or_d()
    case_q_profile_put_validate_profile_hw_default_cannot_be_a_or_d()
    case_q_profile_delete()
    case_q_profile_delete_validate_profile_applied_cannot_be_a_or_d()
    case_q_profile_delete_validate_profile_hw_default_cannot_be_a_or_d()
    case_q_profile_delete_validate_profile_default_cannot_be_deleted()

    case_qos_cos_map_entry_post()
    case_qos_cos_map_entry_patch()
    case_qos_cos_map_entry_patch_validate_cos_map_desc_has_valid_chars()
    case_qos_cos_map_entry_put()
    case_qos_cos_map_entry_put_validate_cos_map_desc_has_valid_chars()
    case_qos_cos_map_entry_delete()

    case_qos_dscp_map_entry_post()
    case_qos_dscp_map_entry_patch()
    case_qos_dscp_map_entry_patch_validate_dscp_map_desc_has_valid_chars()
    case_qos_dscp_map_entry_patch_validate_pcp_is_empty()
    case_qos_dscp_map_entry_put()
    case_qos_dscp_map_entry_put_validate_dscp_map_desc_has_valid_chars()
    case_qos_dscp_map_entry_put_validate_pcp_is_empty()
    case_qos_dscp_map_entry_delete()

    case_qos_post()
    case_qos_post_validate_profile_name_contains_valid_chars()
    case_qos_post_validate_profile_name_cannot_be_strict()
    case_qos_patch()
    case_qos_patch_validate_profile_applied_cannot_be_a_or_d()
    case_qos_patch_validate_profile_hw_default_cannot_be_a_or_d()
    case_qos_put()
    case_qos_put_validate_profile_applied_cannot_be_a_or_d()
    case_qos_put_validate_profile_hw_default_cannot_be_a_or_d()
    case_qos_delete()
    case_qos_delete_validate_profile_applied_cannot_be_a_or_d()
    case_qos_delete_validate_profile_hw_default_cannot_be_a_or_d()
    case_qos_delete_validate_profile_default_cannot_be_deleted()

    case_queue_post()
    case_queue_post_validate_profile_applied_cannot_be_a_or_d()
    case_queue_post_validate_profile_hw_default_cannot_be_a_or_d()
    case_queue_post_validate_profile_entry_with_dwrr_has_w_less_than_max_w()
    case_queue_patch()
    case_queue_patch_validate_profile_applied_cannot_be_a_or_d()
    case_queue_patch_validate_profile_hw_default_cannot_be_a_or_d()
    case_queue_patch_validate_profile_entry_with_dwrr_has_w_less_than_max_w()
    case_queue_put()
    case_queue_put_validate_profile_applied_cannot_be_a_or_d()
    case_queue_put_validate_profile_hw_default_cannot_be_a_or_d()
    case_queue_put_validate_profile_entry_with_dwrr_has_w_less_than_max_w()
    case_queue_delete()
    case_queue_delete_validate_profile_applied_cannot_be_a_or_d()
    case_queue_delete_validate_profile_hw_default_cannot_be_a_or_d()

    case_system_qos_patch()
    case_system_qos_patch_validate_trust_global_is_not_empty()
    case_system_qos_patch_validate_apply_global_q_p_has_all_local_p()
    case_system_qos_patch_validate_apply_global_q_p_has_no_dup_local_p()
    case_system_qos_patch_validate_apply_global_s_p_has_all_same_alg()
    case_system_qos_patch_validate_apply_global_profiles_have_same_queues()
    case_system_qos_patch_validate_apply_port_profiles_have_same_queues()
    case_system_qos_put()
    case_system_qos_put_validate_trust_global_is_not_empty()
    case_system_qos_put_validate_apply_global_q_p_has_all_local_p()
    case_system_qos_put_validate_apply_global_q_p_has_no_dup_local_p()
    case_system_qos_put_validate_apply_global_s_p_has_all_same_algorithms()
    case_system_qos_put_validate_apply_global_profiles_have_same_queues()
    case_system_qos_put_validate_apply_port_profiles_have_same_queues()
