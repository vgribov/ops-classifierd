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
#include <acl_db_util.h>
#include <ops-cls-asic-plugin.h>
#include <ops_cls_status_msgs.h>

#include "access_list_vty_util.h"
#include "access_list_vty_ovsdb_util.h"

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
ovsrec_acl_cfg_aces_getvalue(const struct ovsrec_acl *acl_row,
                             const int64_t key)
{
    int i;
    for (i = 0; i < acl_row->n_cfg_aces; i ++) {
        if (acl_row->key_cfg_aces[i] == key) {
            return acl_row->value_cfg_aces[i];
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
check_ace_capacity(const struct ovsrec_acl *acl_row,
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
print_acl_commands(const struct ovsrec_acl *acl_row,
                   const char *configuration)
{
    char *ace_str;
    int i;
    int64_t *key_aces;
    struct ovsrec_acl_entry **value_aces;
    size_t n_aces;

    if (!configuration) {
        key_aces = acl_row->key_cur_aces;
        value_aces = acl_row->value_cur_aces;
        n_aces = acl_row->n_cur_aces;
    } else {
        key_aces = acl_row->key_cfg_aces;
        value_aces = acl_row->value_cfg_aces;
        n_aces = acl_row->n_cfg_aces;
    }

    /* Print ACL command, type, name */
    vty_out(vty,
            "%s %s %s%s",
            "access-list",
            "ip",
            acl_row->name,
            VTY_NEWLINE);

    /* Print each ACL entry as a single line (ala CLI input) */
    for (i = 0; i < n_aces; i ++) {
        /* If entry has or is a comment, print as its own line */
        if (value_aces[i]->comment) {
            vty_out(vty,
                    "    %" PRId64 " comment %s%s",
                    key_aces[i],
                    value_aces[i]->comment,
                    VTY_NEWLINE);
        }
        if (value_aces[i]->action) {
            ace_str = acl_entry_config_to_string(key_aces[i], value_aces[i]);
            vty_out(vty, "    %s%s", ace_str, VTY_NEWLINE);
            free(ace_str);
        }
    }
}

void
print_acl_apply_commands(const char *interface_type,
                         const char *interface_id,
                         const char *direction,
                         const struct ovsrec_acl *acl_row)
{
    const char ip_str[] = "ip";
    const char *list_type_str;

    if (acl_row->list_type && !strcmp(acl_row->list_type, "ipv4")) {
        list_type_str = ip_str;
    } else {
        list_type_str = acl_row->list_type;
    }

    vty_out(vty, "%s %s%s", interface_type, interface_id, VTY_NEWLINE);
    vty_out(vty, "    apply access-list %s %s %s%s",
            list_type_str, acl_row->name, direction, VTY_NEWLINE);
}

void
print_acl_tabular(const struct ovsrec_acl *acl_row,
                  const char *configuration)
{
    int i;
    int64_t *key_aces;
    struct ovsrec_acl_entry **value_aces;
    size_t n_aces;

    if (!configuration) {
        key_aces = acl_row->key_cur_aces;
        value_aces = acl_row->value_cur_aces;
        n_aces = acl_row->n_cur_aces;
    } else {
        key_aces = acl_row->key_cfg_aces;
        value_aces = acl_row->value_cfg_aces;
        n_aces = acl_row->n_cfg_aces;
    }

    /* Print ACL type and name */
    if (!strcmp(acl_row->list_type, "ipv4")) {
        vty_out(vty, "%-10s ", "IPv4");
    }
    vty_out(vty, "%s%s", acl_row->name, VTY_NEWLINE);

    /* Print each ACL entry as a single line (ala CLI input) */
    for (i = 0; i < n_aces; i ++) {
        /* Entry sequence number, action, and protocol (if any) */
        vty_out(vty, "%10" PRId64 " ", key_aces[i]);
        /* No action was specified (comment-only entry) */
        if (value_aces[i]->comment && !value_aces[i]->action) {
            vty_out(vty, "%s", value_aces[i]->comment);
            vty_out(vty, "%s", VTY_NEWLINE);
        } else {
            /* If comment specified in addition to action */
            if (value_aces[i]->comment) {
                vty_out(vty, "%s", value_aces[i]->comment);
                vty_out(vty, "%s", VTY_NEWLINE);
                /* Adjust spacing */
                vty_out(vty, "%-10s ", "");
            }
            vty_out(vty, "%-31s ", value_aces[i]->action);
            if (value_aces[i]->n_protocol != 0) {
                vty_out(vty, "%s ", acl_parse_protocol_get_name_from_number(value_aces[i]->protocol[0]));
            } else {
                vty_out(vty, "%s ", "any ");
            }
            vty_out(vty, "%s", VTY_NEWLINE);
            /* Source IP, port information */
            vty_out(vty, "%-10s ", "");
            print_ace_pretty_ip_address("%-31s ", value_aces[i]->src_ip);
            if (value_aces[i]->n_src_l4_port_min &&
                    value_aces[i]->n_src_l4_port_max) {
                print_ace_pretty_l4_ports(
                        value_aces[i]->src_l4_port_min[0],
                        value_aces[i]->src_l4_port_max[0],
                        value_aces[i]->n_src_l4_port_range_reverse);
            }
            vty_out(vty, "%s", VTY_NEWLINE);
            /* Destination IP, port information */
            vty_out(vty, "%-10s ", "");
            print_ace_pretty_ip_address("%-31s ", value_aces[i]->dst_ip);
            if (value_aces[i]->n_dst_l4_port_min &&
                    value_aces[i]->n_dst_l4_port_max) {
                print_ace_pretty_l4_ports(
                        value_aces[i]->dst_l4_port_min[0],
                        value_aces[i]->dst_l4_port_max[0],
                        value_aces[i]->n_dst_l4_port_range_reverse);
            }
            vty_out(vty, "%s", VTY_NEWLINE);
            /* Additional parameters, each on their own line */
            if (value_aces[i]->n_log) {
                vty_out(vty, "%-10s Logging: enabled %s", "", VTY_NEWLINE);
            }
            if (value_aces[i]->n_count) {
                vty_out(vty, "%-10s Hit-counts: enabled %s", "", VTY_NEWLINE);
            }
        }
    }
}

void
print_port_aclv4_statistics(const struct acl_db_util *acl_db,
                              const struct ovsrec_port *port_row)
{
    int64_t hit_count;
    char *ace_str;
    int i;
    const struct ovsrec_acl* acl_applied = acl_db_util_get_applied(acl_db, port_row);

    vty_out(vty, "Interface %s (%s):%s", port_row->name, acl_db->direction_str, VTY_NEWLINE);
    vty_out(vty, "%20s  %s%s", "Hit Count", "Configuration", VTY_NEWLINE);

    /* Print each ACL entry as a single line (ala CLI input) */
    for (i = 0; i < acl_applied->n_cur_aces; i++) {
        /* If entry has or is a comment, print as its own line */
        if (acl_applied->value_cur_aces[i]->comment) {
            vty_out(vty,
                    "%20s  %" PRId64 " comment %s%s",
                    "",
                    acl_applied->key_cur_aces[i],
                    acl_applied->value_cur_aces[i]->comment,
                    VTY_NEWLINE);
        }
        if (acl_applied->value_cur_aces[i]->action) {
            if (acl_applied->value_cur_aces[i]->n_count) {
                hit_count = ovsrec_port_aclv4_statistics_getvalue(acl_db, port_row,
                              acl_applied->key_cur_aces[i]);
                vty_out(vty, "%20" PRId64, hit_count);
            } else {
                vty_out(vty, "%20s", "-");
            }
            ace_str = acl_entry_config_to_string(acl_applied->key_cur_aces[i],
                                                 acl_applied->value_cur_aces[i]);
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

void
print_acl_mismatch_warning(const char *acl_name, const char *commands)
{
    if (commands) {
        vty_out(vty,
                "! access-list %s %s%s"
                "! %s%s",
                acl_name,
                ACL_MISMATCH_WARNING,
                VTY_NEWLINE,
                ACL_MISMATCH_HINT_RESET,
                VTY_NEWLINE);
    } else {
        vty_out(vty,
                "%% Warning: %s %s%s",
                acl_name, ACL_MISMATCH_WARNING, VTY_NEWLINE);
        vty_out(vty,
                "%%          %s%s",
                ACL_MISMATCH_HINT_RESET, VTY_NEWLINE);
    }
}

bool
aces_cur_cfg_equal(const struct ovsrec_acl *acl_row)
{
    /* Compare number of entries */
    if (acl_row->n_cur_aces != acl_row->n_cfg_aces) {
        return false;
    }
    /* Compare entry pointers; entry rows aren't modified so this is enough */
    if (memcmp(acl_row->value_cfg_aces,
               acl_row->value_cur_aces,
               acl_row->n_cfg_aces * sizeof(struct ovsrec_acl_entry *))) {
        return false;
    }
    return true;
}

void acl_mismatch_check_and_print(const struct ovsrec_acl *acl_applied_row,
                                  const struct ovsrec_acl *acl_cfg_row,
                                  const char *configuration,
                                  const char *commands)
{
    const char *acl_name;

    if (acl_applied_row != acl_cfg_row) {
        if (configuration == NULL) {
            if (acl_applied_row != NULL) {
                acl_name = acl_applied_row->name;
            } else {
                acl_name = acl_cfg_row->name;
            }
        } else {
            if (acl_cfg_row != NULL) {
                acl_name = acl_cfg_row->name;
            } else {
                acl_name = acl_applied_row->name;
            }
        }
        print_acl_mismatch_warning(acl_name, commands);
    } else {
        /* acl_applied_row is equal to acl_cfg_row so the param
         * "configuration" is irrelevant here. */
        if(acl_applied_row != NULL) {
            if (!aces_cur_cfg_equal(acl_applied_row)) {
                print_acl_mismatch_warning(acl_applied_row->name, commands);
            }
        }
    }
}
