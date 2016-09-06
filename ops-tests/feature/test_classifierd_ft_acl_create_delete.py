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
OpenSwitch Test for acl create, delete configuration.
"""

from pytest import mark, raises
from topology_lib_vtysh import exceptions

TOPOLOGY = """
# +--------+
# |  ops1  |
# +--------+

# Nodes
[type=openswitch name="OpenSwitch 1"] ops1

# Links
"""


@mark.gate
@mark.test_id(10401)
def test_acl_create_delete(topology, step):
    """
    Test the creation and deletion of access control list.

    Build a topology of one switch. Tested the ability to properly add ACL,
    delete ACL.
    """
    ops1 = topology.get('ops1')

    assert ops1 is not None

    step('################ T0 Make sure there are no ACLs defined ###########')
    out = ops1.libs.vtysh.show_access_list_commands('')
    for acl_type in out['access-list']:
        for acl_name in out['access-list'][acl_type]:
            print("Cleaning: " + acl_type + " " + acl_name)
            with ops1.libs.vtysh.Configure() as ctx:
                ctx.no_access_list(type=acl_type, access_list=acl_name)

    step('################ T1 access-list create ACL ###########')
    step('################ with one number ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', '1')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('1' in out['access-list']['ip'])

    step('################ T2 access-list create ACL ###########')
    step('################ with apostrophe ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', '1\'s')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('1\'s' in out['access-list']['ip'])

    step('################ T3 access-list create ACL ###########')
    step('################ with quotation ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', '1\"s')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('1\"s' in out['access-list']['ip'])

    step('################ T4 access-list create ACL ###########')
    step('################ with @ sign ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', '1@s')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('1@s' in out['access-list']['ip'])

    step('################ T5 access-list create ACL ###########')
    step('################ with 1 char ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'z')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('z' in out['access-list']['ip'])

    step('################ T6 access-list create ACL ###########')
    step('################ with grave accent ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v`v')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v`v' in out['access-list']['ip'])

    step('################ T7 access-list create ACL ###########')
    step('################ with number sign ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v+v')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v+v' in out['access-list']['ip'])

    step('################ T8 access-list create ACL ###########')
    step('################ with percent sign ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v%v')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v%v' in out['access-list']['ip'])

    step('################ T9 access-list create ACL ###########')
    step('################ with greater sign ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v>v')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v>v' in out['access-list']['ip'])

    step('################ T10 access-list create ACL ###########')
    step('################ with lesser sign ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v<v')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v<v' in out['access-list']['ip'])

    step('################ T11 access-list create ACL ###########')
    step('################ with exclamation sign ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v!v')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v!v' in out['access-list']['ip'])

    step('################ T12 access-list create ACL ###########')
    step('################ with period sign ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v.v')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v.v' in out['access-list']['ip'])

    step('################ T13 access-list create ACL ###########')
    step('################ with brackets ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v(v)')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v(v)' in out['access-list']['ip'])

    step('################ T14 access-list create ACL ###########')
    step('################ with asterisk sign ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v*v')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v*v' in out['access-list']['ip'])

    step('################ T15 access-list create ACL ###########')
    step('################ with dollar sign ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v$v')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v$v' in out['access-list']['ip'])

    step('################ T16 access-list create ACL ###########')
    step('################ with semicolon sign ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v;v')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v;v' in out['access-list']['ip'])

    step('################ T17 access-list create ACL ###########')
    step('################ with colon sign ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v:v')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v:v' in out['access-list']['ip'])

    step('################ T18 access-list create ACL ###########')
    step('################ with caret ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v^v')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v^v' in out['access-list']['ip'])

    step('################ T19 access-list create ACL ###########')
    step('################ with braces ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v{v}')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v{v}' in out['access-list']['ip'])

    step('################ T20 access-list create ACL ###########')
    step('################ with hyphen  ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v-v')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v-v' in out['access-list']['ip'])

    step('################ T21 access-list create ACL ###########')
    step('################ with equal  ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v=v')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v=v' in out['access-list']['ip'])

    step('################ T22 access-list create ACL ###########')
    step('################ with tilde  ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v~v')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v~v' in out['access-list']['ip'])

    step('################ T23 access-list create ACL ###########')
    step('################ with slash  ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v/v')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v/v' in out['access-list']['ip'])

    step('################ T24 access-list create ACL ###########')
    step('################ with backslash  ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v\\v')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v\\v' in out['access-list']['ip'])

    step('################ T25 access-list create ACL ###########')
    step('################ with pipe  ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v|v')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v|v' in out['access-list']['ip'])

    step('################ T26 access-list create ACL ###########')
    step('################ with ampersand  ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v&v')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v&v' in out['access-list']['ip'])

    step('################ T26 access-list create ACL ###########')
    step('################ with dash  ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v-v')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v-v' in out['access-list']['ip'])

    step('################ T27 access-list create ACL ###########')
    step('################ with underscore  ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'v_v')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('v_v' in out['access-list']['ip'])

    step('################ T28 access-list create ACL ###########')
    step('################ with Capitalization 1  ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'VIvTest')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('VIvTest' in out['access-list']['ip'])

    step('################ T29 access-list create ACL ###########')
    step('################ with Capitalization 2  ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'viVtEST')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('viVtEST' in out['access-list']['ip'])

    step('################ T30 access-list create ACL ###############')
    step('################ with valid name ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'test1')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('test1' in out['access-list']['ip'])

    step('#################### access-list create ACL ####################')
    step('################ with name contains invalid char ###############')

    with raises(exceptions.UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.access_list('ip', 'te st!$')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('te st!$' not in out['access-list']['ip'])

    step('################ access-list create ACL ###############')
    step('with valid name  and non-alphanumeric')
    step(' characters  ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'goodtest$!')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('goodtest$!' in out['access-list']['ip'])

    step('################ access-list create ACL ###############')
    step('################ with no name ###############')

    with raises(
            exceptions.IncompleteCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.access_list('ip', ' ')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert(' ' not in out['access-list']['ip'])

    step('################ with name > 64 chars ###############')
    longstr = (
                'creationofaccesscontrollisttestwith'
                'namegreaterthanmaximumallowedlengthshallberejected'
              )

    with raises(exceptions.UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.access_list('ip', '%s' % longstr)
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert(longstr not in out['access-list']['ip'])

    step('################ access-list delete ACL ###############')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'test2')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('test2' in out['access-list']['ip'])

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.no_access_list('ip', 'test2')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('test2' not in out['access-list']['ip'])

    step('################ modify ACL ###############')
    step('################# with valid resequence number ##################')

    with ops1.libs.vtysh.Configure() as ctx:
        ctx.access_list('ip', 'test1')
    out = ops1.libs.vtysh.show_access_list_commands('ip')
    assert('test1' in out['access-list']['ip'])

    with raises(exceptions.AclEmptyException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.access_list_resequence('ip', 'test1', 1, 10)

    step('##################### Modify empty ACL ####################')
    step('############# with invalid resequence number ##############')

    with raises(exceptions.UnknownCommandException):
        with ops1.libs.vtysh.Configure() as ctx:
            ctx.access_list_resequence('ip', 'test1', 0, 10)
