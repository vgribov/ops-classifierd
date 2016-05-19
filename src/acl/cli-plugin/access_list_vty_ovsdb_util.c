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
 * Implementation of Access Control List (ACL) CLI OVSDB utility functions,
 * including printing and manipulating OVSDB IDL data structures.
 ***************************************************************************/

#include <vswitch-idl.h>
#include <ovsdb-idl.h>

#include <openvswitch/vlog.h>
#include <dynamic-string.h>
#include <latch.h>

#include <vty.h>
#include <command.h>
#include <vtysh.h>
#include <vty_utils.h>

#include <acl_parse.h>
#include <ops-cls-asic-plugin.h>
#include <ops_cls_status_msgs.h>

#include "access_list_vty_util.h"

/** Create logging module */
VLOG_DEFINE_THIS_MODULE(vtysh_access_list_cli_ovsdb_util);

/** Utilize OVSDB interface code generated from schema */
extern struct ovsdb_idl *idl;

const struct ovsrec_acl *
get_acl_by_type_name(const char *acl_type, const char *acl_name)
{
    const struct ovsrec_acl acl = {.list_type = (char *) acl_type,
                                   .name      = (char *) acl_name};
    struct ovsdb_idl_index_cursor cursor;
    ovsdb_idl_initialize_cursor(idl, &ovsrec_table_acl, "by_ACL_list_type_and_name", &cursor);
    return ovsrec_acl_index_find(&cursor, &acl);
}

const struct ovsrec_port *
get_port_by_name(const char *name)
{
    const struct ovsrec_port port = {.name = (char *) name};
    struct ovsdb_idl_index_cursor cursor;
    ovsdb_idl_initialize_cursor(idl, &ovsrec_table_port, "by_Port_name", &cursor);
    return ovsrec_port_index_find(&cursor, &port);
}

const struct ovsrec_vlan *
get_vlan_by_id_str(const char *id_str)
{
    const struct ovsrec_vlan vlan = {.id = strtoul(id_str, NULL, 0)};
    struct ovsdb_idl_index_cursor cursor;
    ovsdb_idl_initialize_cursor(idl, &ovsrec_table_vlan, "by_VLAN_id", &cursor);
    return ovsrec_vlan_index_find(&cursor, &vlan);
}

/**
 * @todo This could/should be generated as part of IDL.
 */
const struct ovsrec_acl_entry*
ovsrec_acl_cur_aces_getvalue(const struct ovsrec_acl *acl_row,
                             const int64_t key)
{
    int i;
    for (i = 0; i < acl_row->n_cur_aces; i ++) {
        if (acl_row->key_cur_aces[i] == key) {
            return acl_row->value_cur_aces[i];
        }
    }
    return NULL;
}

/**
 * @todo This could/should be generated as part of IDL.
 */
const int64_t
ovsrec_vlan_aclv4_in_statistics_getvalue(const struct ovsrec_vlan *vlan_row,
                                         const int64_t key)
{
    int i;
    for (i = 0; i < vlan_row->n_aclv4_in_statistics; i ++) {
        if (vlan_row->key_aclv4_in_statistics[i] == key) {
            return vlan_row->value_aclv4_in_statistics[i];
        }
    }
    return 0;
}

int
check_ace_capacity (const struct ovsrec_acl *acl_row,
                    const struct ovsrec_acl_entry *ace_row)
{
    const struct ovsrec_system *ovs;
    const char* max_aces_str;
    const char* max_aces_per_acl_str;
    int64_t max_aces, max_aces_per_acl;
    const struct ovsdb_idl_row *ace_header;
    size_t ace_entries;

    /* Get System table */
    ovs = ovsrec_system_first(idl);
    if (!ovs) {
        VLOG_ERR("Unable to acquire system table.");
        assert(0);
        return CMD_OVSDB_FAILURE;
    }

    /* Get max ACEs and max ACEs per acl from system table, other config */
    max_aces_str = smap_get(&ovs->other_info, "max_aces");
    max_aces_per_acl_str = smap_get(&ovs->other_info, "max_aces_per_acl");

    if (max_aces_str && max_aces_per_acl_str) {
        max_aces = strtol(max_aces_str, NULL, 0);
        max_aces_per_acl = strtol(max_aces_per_acl_str, NULL, 0);
    } else {
        VLOG_ERR("Unable to acquire ACE hardware limits.");
        return CMD_OVSDB_FAILURE;
    }

    /* Get number of ACEs in database from table header */
    ace_header = &ace_row->header_;
    ace_entries = hmap_count(&ace_header->table->rows);

    /* Updating an ACE always (except comments) creates a new row in ACE table.
     * n_cfg_aces doesn't increment until finish updating ACL table.
     * Abort if ACEs limits are reached */
    if (ace_entries > max_aces) {
        vty_out(vty, "%% Unable to create ACL entry. "
                "The maximum allowed number of ACL entries has been reached%s", VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
    } else if (acl_row->n_cfg_aces >= max_aces_per_acl) {
        vty_out(vty, "%% Unable to create ACL entry. "
                "The maximum allowed number of entries per acl has been reached%s", VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
    } else {
        return CMD_SUCCESS;
    }
}

void
print_acl_config(const struct ovsrec_acl *acl_row)
{
    char *ace_str;
    int i;

    /* Print ACL command, type, name */
    vty_out(vty,
            "%s %s %s%s",
            "access-list",
            "ip",
            acl_row->name,
            VTY_NEWLINE);

    /* Print each ACL entry as a single line (ala CLI input) */
    for (i = 0; i < acl_row->n_cur_aces; i ++) {
        /* If entry has or is a comment, print as its own line */
        if (acl_row->value_cur_aces[i]->comment) {
            vty_out(vty,
                    "    %" PRId64 " comment %s%s",
                    acl_row->key_cur_aces[i],
                    acl_row->value_cur_aces[i]->comment,
                    VTY_NEWLINE);
        }
        if (acl_row->value_cur_aces[i]->action) {
            ace_str = acl_entry_config_to_string(acl_row->key_cur_aces[i],
                                                 acl_row->value_cur_aces[i]);
            vty_out(vty, "    %s%s", ace_str, VTY_NEWLINE);
            free(ace_str);
        }
    }
}

void
print_acl_tabular(const struct ovsrec_acl *acl_row)
{
    int i;

    /* Print ACL type and name */
    if (!strcmp(acl_row->list_type, "ipv4")) {
        vty_out(vty, "%-10s ", "IPv4");
    }
    vty_out(vty, "%s%s", acl_row->name, VTY_NEWLINE);

    /* Print each ACL entry as a single line (ala CLI input) */
    for (i = 0; i < acl_row->n_cur_aces; i ++) {
        /* Entry sequence number, action, and protocol (if any) */
        vty_out(vty, "%10" PRId64 " ", acl_row->key_cur_aces[i]);
        /* No action was specified (comment-only entry) */
        if (acl_row->value_cur_aces[i]->comment && !acl_row->value_cur_aces[i]->action) {
            vty_out(vty, "%s", acl_row->value_cur_aces[i]->comment);
            vty_out(vty, "%s", VTY_NEWLINE);
        } else {
            /* If comment specified in addition to action */
            if (acl_row->value_cur_aces[i]->comment) {
                vty_out(vty, "%s", acl_row->value_cur_aces[i]->comment);
                vty_out(vty, "%s", VTY_NEWLINE);
                /* Adjust spacing */
                vty_out(vty, "%-10s ", "");
            }
            vty_out(vty, "%-31s ", acl_row->value_cur_aces[i]->action);
            if (acl_row->value_cur_aces[i]->n_protocol != 0) {
                vty_out(vty, "%s ", acl_parse_protocol_get_name_from_number(acl_row->value_cur_aces[i]->protocol[0]));
            } else {
                vty_out(vty, "%s ", "any ");
            }
            vty_out(vty, "%s", VTY_NEWLINE);
            /* Source IP, port information */
            vty_out(vty, "%-10s ", "");
            print_ace_pretty_ip_address("%-31s ", acl_row->value_cur_aces[i]->src_ip);
            if (acl_row->value_cur_aces[i]->n_src_l4_port_min &&
                    acl_row->value_cur_aces[i]->n_src_l4_port_max) {
                print_ace_pretty_l4_ports(
                        acl_row->value_cur_aces[i]->src_l4_port_min[0],
                        acl_row->value_cur_aces[i]->src_l4_port_max[0],
                        acl_row->value_cur_aces[i]->n_src_l4_port_range_reverse);
            }
            vty_out(vty, "%s", VTY_NEWLINE);
            /* Destination IP, port information */
            vty_out(vty, "%-10s ", "");
            print_ace_pretty_ip_address("%-31s ", acl_row->value_cur_aces[i]->dst_ip);
            if (acl_row->value_cur_aces[i]->n_dst_l4_port_min &&
                    acl_row->value_cur_aces[i]->n_dst_l4_port_max) {
                print_ace_pretty_l4_ports(
                        acl_row->value_cur_aces[i]->dst_l4_port_min[0],
                        acl_row->value_cur_aces[i]->dst_l4_port_max[0],
                        acl_row->value_cur_aces[i]->n_dst_l4_port_range_reverse);
            }
            vty_out(vty, "%s", VTY_NEWLINE);
            /* Additional parameters, each on their own line */
            if (acl_row->value_cur_aces[i]->n_log) {
                vty_out(vty, "%-10s Logging: enabled %s", "", VTY_NEWLINE);
            }
            if (acl_row->value_cur_aces[i]->n_count) {
                vty_out(vty, "%-10s Hit-counts: enabled %s", "", VTY_NEWLINE);
            }
        }
    }
}

void
print_port_aclv4_in_statistics(const struct ovsrec_port *port_row)
{
    int64_t hit_count;
    char *ace_str;
    int i;

    vty_out(vty, "Interface %s (in):%s", port_row->name, VTY_NEWLINE);
    vty_out(vty, "%20s  %s%s", "Hit Count", "Configuration", VTY_NEWLINE);

    /* Print each ACL entry as a single line (ala CLI input) */
    for (i = 0; i < port_row->aclv4_in_applied->n_cur_aces; i ++) {
        /* If entry has or is a comment, print as its own line */
        if (port_row->aclv4_in_applied->value_cur_aces[i]->comment) {
            vty_out(vty,
                    "%20s  %" PRId64 " comment %s%s",
                    "",
                    port_row->aclv4_in_applied->key_cur_aces[i],
                    port_row->aclv4_in_applied->value_cur_aces[i]->comment,
                    VTY_NEWLINE);
        }
        if (port_row->aclv4_in_applied->value_cur_aces[i]->action) {
            if (port_row->aclv4_in_applied->value_cur_aces[i]->n_count) {
                hit_count = ovsrec_port_aclv4_in_statistics_getvalue(
                                    port_row, port_row->aclv4_in_applied->key_cur_aces[i]);
                vty_out(vty, "%20" PRId64, hit_count);
            } else {
                vty_out(vty, "%20s", "-");
            }
            ace_str = acl_entry_config_to_string(port_row->aclv4_in_applied->key_cur_aces[i],
                                                 port_row->aclv4_in_applied->value_cur_aces[i]);
            vty_out(vty, "  %s%s", ace_str, VTY_NEWLINE);
            free(ace_str);
        }
    }
}

void
print_vlan_aclv4_in_statistics(const struct ovsrec_vlan *vlan_row)
{
    int64_t hit_count;
    char *ace_str;
    int i;

    vty_out(vty,"VLAN %" PRId64 " (in):%s", vlan_row->id, VTY_NEWLINE);
    vty_out(vty, "%20s  %s%s", "Hit Count", "Configuration", VTY_NEWLINE);

    /* Print each ACL entry as a single line (ala CLI input) */
    for (i = 0; i < vlan_row->aclv4_in_applied->n_cur_aces; i ++) {
        /* If entry has or is a comment, print as its own line */
        if (vlan_row->aclv4_in_applied->value_cur_aces[i]->comment) {
            vty_out(vty,
                    "%20s  %" PRId64 " comment %s%s",
                    "",
                    vlan_row->aclv4_in_applied->key_cur_aces[i],
                    vlan_row->aclv4_in_applied->value_cur_aces[i]->comment,
                    VTY_NEWLINE);
        }
        if (vlan_row->aclv4_in_applied->value_cur_aces[i]->action) {
            if (vlan_row->aclv4_in_applied->value_cur_aces[i]->n_count) {
                hit_count = ovsrec_vlan_aclv4_in_statistics_getvalue(
                                    vlan_row, vlan_row->aclv4_in_applied->key_cur_aces[i]);
                vty_out(vty, "%20" PRId64, hit_count);
            } else {
                vty_out(vty, "%20s", "-");
            }
            ace_str = acl_entry_config_to_string(vlan_row->aclv4_in_applied->key_cur_aces[i],
                                                 vlan_row->aclv4_in_applied->value_cur_aces[i]);
            vty_out(vty, "  %s%s", ace_str, VTY_NEWLINE);
            free(ace_str);
        }
    }
}

bool
ovsrec_acl_set_cfg_aces_from_cur_aces(const struct ovsrec_acl *acl_row,
                                      const int64_t key,
                                      struct ovsrec_acl_entry *value)
{
    /* Assume we may add an entry until we find out this is an update or delete */
    int entries_changed = 1;
    /* malloc one extra entry key-value pair in case we insert */
    int64_t *key_list = xmalloc(sizeof(int64_t) * (acl_row->n_cur_aces + entries_changed));
    struct ovsrec_acl_entry **value_list = xmalloc(sizeof *acl_row->value_cur_aces * (acl_row->n_cur_aces + entries_changed));
    int cur_idx, cfg_idx;

    for (cur_idx = 0, cfg_idx = 0; cur_idx < acl_row->n_cur_aces; cur_idx++) {
        if (key == acl_row->key_cur_aces[cur_idx]) {
            /* For update, use provided value instead of cur_aces value */
            if (value != NULL) {
                key_list[cfg_idx] = key;
                value_list[cfg_idx] = value;
                entries_changed = 0;
                cfg_idx++;
            /* For delete operation, don't copy into cfg_aces or bump cfg_idx*/
            } else {
                entries_changed = -1;
            }
        } else {
            /* For all other entries, copy cur_aces to cfg_aces */
            key_list[cfg_idx] = acl_row->key_cur_aces[cur_idx];
            value_list[cfg_idx] = acl_row->value_cur_aces[cur_idx];
            cfg_idx++;
        }
    }
    /* If matching entry key was not found */
    if (entries_changed > 0) {
        /* Check if it was a delete where the value wasn't found */
        if (!value) {
            free(key_list);
            free(value_list);
            return false;
        }
        /* Not an update or delete, so it's an insert. Append entry to list
           (will be sorted by key automatically). */
        key_list[acl_row->n_cur_aces] = key;
        value_list[acl_row->n_cur_aces] = value;
    }
    ovsrec_acl_set_cfg_aces(acl_row, key_list, value_list, acl_row->n_cur_aces + entries_changed);
    free(key_list);
    free(value_list);
    return true;
}

int
wait_for_ace_update_status(const char *acl_type,
                           const char *acl_name,
                           const int64_t pending_cfg_version)
{
    const struct ovsrec_acl *acl_row;
    int64_t status_version;
    const char *status_version_str;
    const char *status_state_str;
    const char *status_message_str;
    const char *status_code_str;

    /* Loop can be halted by Ctrl-C (SIGINT) */
    while (!vty_interrupted_flag_get()) {
        /* Let OVSDB IDL update thread run */
        VTYSH_OVSDB_UNLOCK;
        /* Set latch to wake up OVSDB thread and get new status */
        latch_set(&ovsdb_latch);
        /* Take lock so we can safely operate on IDL again */
        VTYSH_OVSDB_LOCK;
        /* We purposely return with OVSDB lock held below because execute_command unlocks */
        acl_row = get_acl_by_type_name(acl_type, acl_name);
        status_version_str = smap_get(&acl_row->status, OPS_CLS_STATUS_VERSION_STR);
        if (status_version_str) {
            status_version = strtoull(status_version_str, NULL, 0);
            /* We got a status for the version we configured */
            if (status_version == pending_cfg_version) {
                status_state_str = smap_get(&acl_row->status, OPS_CLS_STATUS_STATE_STR);
                if (!strcmp(status_state_str, OPS_CLS_STATE_APPLIED_STR)) {
                    return CMD_SUCCESS;
                } else {
                    status_message_str = smap_get(&acl_row->status, OPS_CLS_STATUS_MSG_STR);
                    status_code_str = smap_get(&acl_row->status, OPS_CLS_STATUS_CODE_STR);
                    vty_out(vty, "%% Configuration %s: %s (code %s)%s",
                            status_state_str ? status_state_str : "(no state)",
                            status_message_str ? status_message_str : "(no message)",
                            status_code_str ? status_code_str : "none",
                            VTY_NEWLINE);
                    return CMD_WARNING;
                }
            /* We got a status for a later configuration version */
            } else if (status_version > pending_cfg_version) {
                vty_out(vty, "%% Other changes may have occurred while this change was being processed%s", VTY_NEWLINE);
                return CMD_WARNING;
            }
        }
    }
    vty_out(vty, "%s%% Command interrupted; not all changes may have been processed%s", VTY_NEWLINE, VTY_NEWLINE);
    return CMD_WARNING;
}

int
wait_for_acl_apply_status(const char *interface_type,
                          const char *interface_id,
                          const char *acl_type,
                          const char *direction,
                          const int64_t pending_cfg_version)
{
    const struct ovsrec_port *port_row;
    const struct smap *status_map;
    int64_t status_version;
    const char *status_version_str;
    const char *status_state_str;
    const char *status_message_str;
    const char *status_code_str;

    /* Loop can be halted by Ctrl-C (SIGINT) */
    while (!vty_interrupted_flag_get()) {
        /* Let OVSDB IDL update thread run */
        VTYSH_OVSDB_UNLOCK;
        /* Set latch to wake up OVSDB thread and get new status */
        latch_set(&ovsdb_latch);
        /* Take lock so we can safely operate on IDL again */
        VTYSH_OVSDB_LOCK;
        /* We purposely return with OVSDB lock held below because execute_command unlocks */
        /* Port (unfortunately called "interface" in the CLI) */
        if (!strcmp(interface_type, "interface")) {
            port_row = get_port_by_name(interface_id);
            if (!strcmp(acl_type, "ipv4") && !strcmp(direction, "in")) {
                status_map = &port_row->aclv4_in_status;
                status_version_str = smap_get(status_map, OPS_CLS_STATUS_VERSION_STR);
            } else {
                vty_out(vty, "%% Unsupported ACL type or direction%s", VTY_NEWLINE);
                return CMD_WARNING;
            }
        } else if (!strcmp(interface_type, "vlan")) {
            /** @todo Remove once classifier feature plug-in supports VLAN apply. */
            vty_out(vty, "%% warning: VLAN ACLs presently unsupported by classifier feature plug-in%s", VTY_NEWLINE);
            VLOG_WARN("VLAN ACLs presently unsupported by classifier feature plug-in");
            /* Return now because ops-switchd won't update VLAN ACL status
               and we'll wait for no reason until it supports VLAN ACLs. */
            return CMD_WARNING;
        } else {
            vty_out(vty, "%% Unsupported interface type%s", VTY_NEWLINE);
            return CMD_WARNING;
        }
        if (status_version_str) {
            status_version = strtoull(status_version_str, NULL, 0);
            /* We got a status for the version we configured */
            if (status_version == pending_cfg_version) {
                status_state_str = smap_get(status_map, OPS_CLS_STATUS_STATE_STR);
                if (!strcmp(status_state_str, OPS_CLS_STATE_APPLIED_STR)) {
                    return CMD_SUCCESS;
                } else {
                    status_message_str = smap_get(status_map, OPS_CLS_STATUS_MSG_STR);
                    status_code_str = smap_get(status_map, OPS_CLS_STATUS_CODE_STR);
                    vty_out(vty, "%% Configuration %s: %s (code %s)%s",
                            status_state_str ? status_state_str : "(no state)",
                            status_message_str ? status_message_str : "(no message)",
                            status_code_str ? status_code_str : "none",
                            VTY_NEWLINE);
                    return CMD_WARNING;
                }
            /* We got a status for a later configuration version */
            } else if (status_version > pending_cfg_version) {
                vty_out(vty, "%% Other changes may have occurred while this change was being processed%s", VTY_NEWLINE);
                return CMD_WARNING;
            }
        }
    }
    vty_out(vty, "%s%% Command interrupted; not all changes may have been processed%s", VTY_NEWLINE, VTY_NEWLINE);
    return CMD_WARNING;
}
