/*
 * Copyright (C) 2015, 2016 Hewlett Packard Enterprise Development LP
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA.
 */

/************************************************************************//**
 * @ingroup ops-access-list
 *
 * @file
 * Implementation of Access Control List (ACL) CLI for "show running-config".
 ***************************************************************************/

#include <vswitch-idl.h>

#include <vty.h>
#include <command.h>
#include <vtysh.h>
#include <vtysh_ovsdb_config.h>

#include <acl_parse.h>

#include "access_list_vty_util.h"
#include "access_list_vty_ovsdb_util.h"

/** Utilize OVSDB interface code generated from schema */
extern struct ovsdb_idl *idl;

vtysh_ret_val
show_run_access_list_callback(void *p_private)
{
    vtysh_ovsdb_cbmsg_ptr p_msg = (vtysh_ovsdb_cbmsg *) p_private;
    const struct ovsrec_system *ovs;
    const struct ovsrec_acl *acl_row;
    const char *acl_log_timer_value;
    char *ace_str;
    int i;

    /* Get System table */
    ovs = ovsrec_system_first(idl);
    if (!ovs) {
        assert(0);
        return CMD_OVSDB_FAILURE;
    }

    /* Iterate over each ACL table entry */
    OVSREC_ACL_FOR_EACH(acl_row, p_msg->idl) {
        if (acl_row) {
            vtysh_ovsdb_cli_print(p_msg,
                                  "%s %s %s",
                                  "access-list",
                                  "ip",
                                  acl_row->name);
            /* Print each ACL entry as a single line (ala CLI input) */
            for (i = 0; i < acl_row->n_cur_aces; i ++) {
                /* If entry has or is a comment, print as its own line */
                if (acl_row->value_cur_aces[i]->comment) {
                    vtysh_ovsdb_cli_print(p_msg,
                                          "    %" PRId64 " comment %s",
                                          acl_row->key_cur_aces[i],
                                          acl_row->value_cur_aces[i]->comment);
                }
                if (acl_row->value_cur_aces[i]->action) {
                    ace_str = acl_entry_config_to_string(acl_row->key_cur_aces[i],
                                                         acl_row->value_cur_aces[i]);
                    vtysh_ovsdb_cli_print(p_msg, "    %s", ace_str);
                    free(ace_str);
                }
            }
        }
    }

    /* Print log timer configuration (if not default) */
    acl_log_timer_value = smap_get(&ovs->other_config, ACL_LOG_TIMER_STR);
    if (acl_log_timer_value) {
        vtysh_ovsdb_cli_print(p_msg, "access-list log-timer %s", acl_log_timer_value);
    }
    return e_vtysh_ok;
}

vtysh_ret_val
show_run_access_list_subcontext_callback(void *p_private)
{
    vtysh_ovsdb_cbmsg_ptr p_msg = (vtysh_ovsdb_cbmsg *) p_private;
    const struct ovsrec_vlan *vlan_row = NULL;
    const struct ovsrec_interface *interface_row = NULL;
    const struct ovsrec_port *port_row = NULL;

    /* Determine context type and subtype we were called for */
    if (p_msg->contextid == e_vtysh_vlan_context &&
        p_msg->clientid == e_vtysh_vlan_context_access_list) {
        vlan_row = (struct ovsrec_vlan *) p_msg->feature_row;
    } else if (p_msg->contextid == e_vtysh_interface_context &&
               p_msg->clientid == e_vtysh_interface_context_access_list) {
        interface_row = (struct ovsrec_interface *) p_msg->feature_row;
    }

    /* Print VLAN ACL, if any */
    if (vlan_row && vlan_row->aclv4_in_applied) {
        vtysh_ovsdb_cli_print(p_msg, "    apply access-list ip %s in",
                              vlan_row->aclv4_in_applied->name);
    }
    /* Print port ACL, if any (LAGs won't have interface name == port name) */
    if (interface_row) {
        port_row = get_port_by_name(interface_row->name);
        if (port_row && port_row->aclv4_in_applied) {
            vtysh_ovsdb_cli_print(p_msg, "    apply access-list ip %s in",
                                  port_row->aclv4_in_applied->name);
        }
    }
    return e_vtysh_ok;
}
