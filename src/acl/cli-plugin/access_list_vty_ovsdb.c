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
 * Implementation of Access Control List (ACL) CLI OVSDB interactions.
 ***************************************************************************/

#include <ovsdb-idl.h>
#include <vswitch-idl.h>

#include <openvswitch/vlog.h>

#include <vty.h>
#include <command.h>
#include <vtysh.h>
#include <vtysh_ovsdb_config.h>

#include <acl_parse.h>
#include <acl_db_util.h>

#include "access_list_vty.h"
#include "access_list_vty_util.h"
#include "access_list_vty_ovsdb_util.h"

/** Create logging module */
VLOG_DEFINE_THIS_MODULE(vtysh_access_list_cli_ovsdb);

/** Utilize OVSDB interface code generated from schema */
extern struct ovsdb_idl *idl;

int
cli_print_acls(const char *acl_type, const char *acl_name, const char *config)
{
    const struct ovsrec_system *ovs;
    const struct ovsrec_acl *acl_row;

    /* Get System table */
    ovs = ovsrec_system_first(idl);
    if (!ovs) {
        assert(0);
        return CMD_OVSDB_FAILURE;
    }

    /* ACL specified, print just one */
    if (acl_type && acl_name) {
        acl_row = get_acl_by_type_name(acl_type, acl_name);
        if (!acl_row) {
            vty_out(vty, "%% ACL does not exist%s", VTY_NEWLINE);
            return CMD_ERR_NOTHING_TODO;
        }
        if (!config) {
            print_acl_tabular_header();
            print_acl_horizontal_rule();
            print_acl_tabular(acl_row);
        } else {
            print_acl_config(acl_row);
        }
    /* Print all ACLs */
    } else {
        if (!config && ovs->n_acls) {
            print_acl_tabular_header();
            OVSREC_ACL_FOR_EACH(acl_row, idl) {
                print_acl_horizontal_rule();
                print_acl_tabular(acl_row);
            }
            print_acl_horizontal_rule();
        } else {
            OVSREC_ACL_FOR_EACH(acl_row, idl) {
                print_acl_config(acl_row);
            }
        }
    }

    return CMD_SUCCESS;
}

int
cli_create_acl_if_needed(const char *acl_type, const char *acl_name)
{
    struct ovsdb_idl_txn *transaction;
    enum ovsdb_idl_txn_status txn_status;
    const struct ovsrec_system *ovs;
    const struct ovsrec_acl *acl_row;
    const struct ovsrec_acl **acl_info;
    int i;

    /* Start transaction */
    transaction = cli_do_config_start();
    if (!transaction) {
        VLOG_ERR("Unable to acquire transaction");
        return CMD_OVSDB_FAILURE;
    }

    /* Get System table */
    ovs = ovsrec_system_first(idl);
    if (!ovs) {
        cli_do_config_abort(transaction);
        assert(0);
        return CMD_OVSDB_FAILURE;
    }

    /* Get ACL row */
    acl_row = get_acl_by_type_name(acl_type, acl_name);

    /* Create */
    if (!acl_row) {
        const char* max_acls_str;
        int64_t max_acls;
        int64_t pending_cfg_version = 0;

        /* Get max ACLs from system table, other config */
        max_acls_str = smap_get(&ovs->other_info, "max_acls");

        if (max_acls_str) {
            max_acls = strtol(max_acls_str, NULL, 0);
        } else {
            cli_do_config_abort(transaction);
            VLOG_ERR("Unable to acquire ACL hardware limits.");
            return CMD_OVSDB_FAILURE;
        }

        /* Abort if hardware limit is reached */
        if (ovs->n_acls >= max_acls) {
            vty_out(vty, "%% Unable to create ACL. "
                    "The maximum allowed number of ACLs has been reached%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_SUCCESS;
        }
        VLOG_DBG("Creating ACL type=%s name=%s", acl_type, acl_name);

        /* Create, populate new ACL table row */
        acl_row = ovsrec_acl_insert(transaction);
        ovsrec_acl_set_list_type(acl_row, acl_type);
        ovsrec_acl_set_name(acl_row, acl_name);
        ovsrec_acl_set_cfg_version(acl_row, &pending_cfg_version, 1);

        /* Update System (parent) table */
        acl_info = xmalloc(sizeof *ovs->acls * (ovs->n_acls + 1));
        for (i = 0; i < ovs->n_acls; i++) {
            acl_info[i] = ovs->acls[i];
        }
        acl_info[i] = acl_row;
        ovsrec_system_set_acls(ovs, (struct ovsrec_acl **) acl_info, i + 1);
        free(acl_info);
    }
    /* Update */
    else {
        VLOG_DBG("Updating ACL type=%s name=%s", acl_type, acl_name);

        /* Don't actually have to take any action */
    }

    /* Complete transaction */
    txn_status = cli_do_config_finish(transaction);
    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED) {
        return CMD_SUCCESS;
    } else {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }
}

int
cli_delete_acl(const char *acl_type, const char *acl_name)
{
    struct ovsdb_idl_txn *transaction;
    enum ovsdb_idl_txn_status txn_status;
    const struct ovsrec_system *ovs;
    const struct ovsrec_acl *acl_row;
    const struct ovsrec_acl **acl_info;
    int i, n;

    /* Start transaction */
    transaction = cli_do_config_start();
    if (!transaction) {
        VLOG_ERR("Unable to acquire transaction");
        return CMD_OVSDB_FAILURE;
    }

    /* Get System table */
    ovs = ovsrec_system_first(idl);
    if (!ovs) {
        cli_do_config_abort(transaction);
        assert(0);
        return CMD_OVSDB_FAILURE;
    }

    /* Get ACL row */
    acl_row = get_acl_by_type_name(acl_type, acl_name);

    /* ACL exists, delete it */
    if (acl_row) {
        VLOG_DBG("Deleting ACL type=%s name=%s", acl_type, acl_name);

        /* Remove ACL row */
        ovsrec_acl_delete(acl_row);

        /* Update System table */
        acl_info = xmalloc(sizeof *ovs->acls * (ovs->n_acls - 1));
        for (i = n = 0; i < ovs->n_acls; i++) {
            if (ovs->acls[i] != acl_row) {
                acl_info[n++] = ovs->acls[i];
            }
        }
        ovsrec_system_set_acls(ovs, (struct ovsrec_acl **) acl_info, n);
        free(acl_info);
    }
    /* No such ACL exists */
    else {
        vty_out(vty, "%% ACL does not exist%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_ERR_NOTHING_TODO;
    }

    /* Complete transaction */
    txn_status = cli_do_config_finish(transaction);
    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED) {
        return CMD_SUCCESS;
    } else {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }
}

int
cli_create_update_ace (const char *acl_type,
                       const char *acl_name,
                       const char *ace_sequence_number_str,
                       const char *ace_action,
                       const char *ace_ip_protocol,
                       const char *ace_source_ip_address,
                       const char *ace_source_port_operator,
                       const char *ace_source_port,
                       const char *ace_source_port_max,
                       const char *ace_destination_ip_address,
                       const char *ace_destination_port_operator,
                       const char *ace_destination_port,
                       const char *ace_destination_port_max,
                       const char *ace_log_enabled,
                       const char *ace_count_enabled,
                             char *ace_comment)
{
    struct ovsdb_idl_txn *transaction;
    enum ovsdb_idl_txn_status txn_status;
    const struct ovsrec_acl *acl_row;
    const struct ovsrec_acl_entry *old_ace_row, *ace_row;
    int64_t ace_sequence_number;
    int64_t protocol_num, min_num, max_num;
    char addr_str[INET_ADDRSTRLEN*2];
    bool flag;
    int64_t pending_cfg_version;

    VLOG_DBG("Create/Update");

    /* Start transaction */
    transaction = cli_do_config_start();
    if (!transaction) {
        VLOG_ERR("Unable to acquire transaction");
        return CMD_OVSDB_FAILURE;
    }

    /* Get parent ACL row */
    acl_row = get_acl_by_type_name(acl_type, acl_name);
    if (!acl_row) {
        /* Should not be possible; context should have created if needed */
        vty_out(vty, "%% ACL does not exist%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_ERR_NOTHING_TODO;
    }

    /* If a sequence number is specified, use it */
    if (ace_sequence_number_str) {
        ace_sequence_number = strtoll(ace_sequence_number_str, NULL, 0);
    /* Otherwise set sequence number to the current highest + auto-increment */
    } else {
        int64_t highest_ace_seq = 0;
        if (acl_row->n_cur_aces > 0) {
            /* ACEs are stored sorted, so just get the last one */
            highest_ace_seq = acl_row->key_cur_aces[acl_row->n_cur_aces - 1];
        }
        if (highest_ace_seq + ACE_SEQ_AUTO_INCR > ACE_SEQ_MAX) {
            vty_out(vty, "%% Unable to automatically set sequence number%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }
        ace_sequence_number = highest_ace_seq + ACE_SEQ_AUTO_INCR;
    }

    /* Create new, empty ACE table row (garbage collected if unused) */
    ace_row = ovsrec_acl_entry_insert(transaction);
    if (!ace_row)
    {
        vty_out(vty, "%% Unable to add ACL entry%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_OVSDB_FAILURE;
    }

    /* Updating an ACE always (except comments) creates a new row.
       If the old ACE is no longer referenced it will be garbage-collected. */
    old_ace_row = ovsrec_acl_cur_aces_getvalue(acl_row, ace_sequence_number);
    if (old_ace_row) {
        VLOG_DBG("Updating ACE seq=%" PRId64, ace_sequence_number);

        /* Comment applied to existing entry */
        if (!strcmp(ace_action, "comment")) {
            /* May set to NULL if action is comment and text is empty (remove) */
            ovsrec_acl_entry_set_comment(old_ace_row, ace_comment);
            if (ace_comment) {
                free(ace_comment);
            }
            /* Complete transaction */
            txn_status = cli_do_config_finish(transaction);
            if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED) {
                return CMD_SUCCESS;
            } else {
                VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
                return CMD_OVSDB_FAILURE;
            }
        /* Copy comment (if any) from old entry  */
        } else {
            ovsrec_acl_entry_set_comment(ace_row, old_ace_row->comment);
        }
    } else {
        int result;
        /* Check ACEs capacity */
        result = check_ace_capacity(acl_row, ace_row);
        if (CMD_SUCCESS != result) {
          cli_do_config_abort(transaction);
          /* Error message is logged in check_ace_capacity */
          return result;
        }
        VLOG_DBG("Creating ACE seq=%" PRId64, ace_sequence_number);
    }

    /* Set any updated columns */
    if (ace_action) {
        if (!strcmp(ace_action, "permit") || !strcmp(ace_action, "deny")) {
            ovsrec_acl_entry_set_action(ace_row, ace_action);
        }
    }
    /* Check that protocol is present and not "any" */
    if (ace_ip_protocol && strcmp(ace_ip_protocol, "any")) {
        protocol_num = acl_parse_protocol_get_number_from_name(ace_ip_protocol);
        if (protocol_num != ACL_PROTOCOL_INVALID) {
            ovsrec_acl_entry_set_protocol(ace_row, &protocol_num, 1);
        } else {
            vty_out(vty, "%% Invalid protocol%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }
    }
    /* Check that source IP is present and not "any" */
    if (ace_source_ip_address && strcmp(ace_source_ip_address, "any")) {
        if (acl_ipv4_address_user_to_normalized(ace_source_ip_address, addr_str)) {
            ovsrec_acl_entry_set_src_ip(ace_row, addr_str);
        } else {
            vty_out(vty, "%% Invalid source IP address%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }
    }
    if (ace_source_port_operator) {
        if (!strcmp(ace_source_port_operator, "eq")) {
            min_num = strtoll(ace_source_port, NULL, 0);
            ovsrec_acl_entry_set_src_l4_port_min(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_src_l4_port_max(ace_row, &min_num, 1);
        } else if (!strcmp(ace_source_port_operator, "neq")) {
            flag = true;
            min_num = strtoll(ace_source_port, NULL, 0);
            ovsrec_acl_entry_set_src_l4_port_min(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_src_l4_port_max(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_src_l4_port_range_reverse(ace_row, &flag, 1);
        } else if (!strcmp(ace_source_port_operator, "gt")) {
            min_num = strtoll(ace_source_port, NULL, 0) + 1;
            max_num = 65535;
            if (min_num > max_num) {
                vty_out(vty, "%% Invalid L4 source port%s", VTY_NEWLINE);
                cli_do_config_abort(transaction);
                return CMD_ERR_NOTHING_TODO;
            }
            ovsrec_acl_entry_set_src_l4_port_min(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_src_l4_port_max(ace_row, &max_num, 1);
        } else if (!strcmp(ace_source_port_operator, "lt")) {
            min_num = 0;
            max_num = strtoll(ace_source_port, NULL, 0) - 1;
            if (min_num > max_num) {
                vty_out(vty, "%% Invalid L4 source port%s", VTY_NEWLINE);
                cli_do_config_abort(transaction);
                return CMD_ERR_NOTHING_TODO;
            }
            ovsrec_acl_entry_set_src_l4_port_min(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_src_l4_port_max(ace_row, &max_num, 1);
        } else if (!strcmp(ace_source_port_operator, "range")) {
            min_num = strtoll(ace_source_port, NULL, 0);
            max_num = strtoll(ace_source_port_max, NULL, 0);
            if (min_num > max_num) {
                vty_out(vty, "%% Invalid L4 source port range%s", VTY_NEWLINE);
                cli_do_config_abort(transaction);
                return CMD_ERR_NOTHING_TODO;
            }
            ovsrec_acl_entry_set_src_l4_port_min(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_src_l4_port_max(ace_row, &max_num, 1);
        }
    }
    /* Check that destination IP is present and not "any" */
    if (ace_destination_ip_address && strcmp(ace_destination_ip_address, "any")) {
        if (acl_ipv4_address_user_to_normalized(ace_destination_ip_address, addr_str)) {
            ovsrec_acl_entry_set_dst_ip(ace_row, addr_str);
        } else {
            vty_out(vty, "%% Invalid destination IP address%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }
    }
    if (ace_destination_port_operator) {
        if (!strcmp(ace_destination_port_operator, "eq")) {
            min_num = strtoll(ace_destination_port, NULL, 0);
            ovsrec_acl_entry_set_dst_l4_port_min(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_dst_l4_port_max(ace_row, &min_num, 1);
        } else if (!strcmp(ace_destination_port_operator, "neq")) {
            flag = true;
            min_num = strtoll(ace_destination_port, NULL, 0);
            ovsrec_acl_entry_set_dst_l4_port_min(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_dst_l4_port_max(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_dst_l4_port_range_reverse(ace_row, &flag, 1);
        } else if (!strcmp(ace_destination_port_operator, "gt")) {
            min_num = strtoll(ace_destination_port, NULL, 0) + 1;
            max_num = 65535;
            if (min_num > max_num) {
                vty_out(vty, "%% Invalid L4 destination port%s", VTY_NEWLINE);
                cli_do_config_abort(transaction);
                return CMD_ERR_NOTHING_TODO;
            }
            ovsrec_acl_entry_set_dst_l4_port_min(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_dst_l4_port_max(ace_row, &max_num, 1);
        } else if (!strcmp(ace_destination_port_operator, "lt")) {
            min_num = 0;
            max_num = strtoll(ace_destination_port, NULL, 0) - 1;
            if (min_num > max_num) {
                vty_out(vty, "%% Invalid L4 destination port%s", VTY_NEWLINE);
                cli_do_config_abort(transaction);
                return CMD_ERR_NOTHING_TODO;
            }
            ovsrec_acl_entry_set_dst_l4_port_min(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_dst_l4_port_max(ace_row, &max_num, 1);
        } else if (!strcmp(ace_destination_port_operator, "range")) {
            min_num = strtoll(ace_destination_port, NULL, 0);
            max_num = strtoll(ace_destination_port_max, NULL, 0);
            if (min_num > max_num) {
                vty_out(vty, "%% Invalid L4 destination port range%s", VTY_NEWLINE);
                cli_do_config_abort(transaction);
                return CMD_ERR_NOTHING_TODO;
            }
            ovsrec_acl_entry_set_dst_l4_port_min(ace_row, &min_num, 1);
            ovsrec_acl_entry_set_dst_l4_port_max(ace_row, &max_num, 1);
        }
    }
    if (ace_log_enabled) {
        flag = true;
        ovsrec_acl_entry_set_log(ace_row, &flag, 1);
        /* Enabling log implies enabling hit counts */
        ovsrec_acl_entry_set_count(ace_row, &flag, 1);
    }
    if (ace_count_enabled) {
        flag = true;
        ovsrec_acl_entry_set_count(ace_row, &flag, 1);
    }
    /* New entry with only a comment */
    if (ace_comment) {
        ovsrec_acl_entry_set_comment(ace_row, ace_comment);
        free(ace_comment);
    }

    /* Update ACL (parent) table */
    ovsrec_acl_set_cfg_aces_from_cur_aces(acl_row, ace_sequence_number, (struct ovsrec_acl_entry *) ace_row);
    pending_cfg_version = acl_row->cfg_version[0] + 1;
    ovsrec_acl_set_cfg_version(acl_row, &pending_cfg_version, 1);

    /* Complete transaction */
    txn_status = cli_do_config_finish(transaction);
    if (txn_status != TXN_SUCCESS && txn_status != TXN_UNCHANGED) {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    /* Wait until ACE update either succeeds or fails and report to user */
    return wait_for_ace_update_status(acl_type, acl_name, pending_cfg_version);
}

int
cli_delete_ace (const char *acl_type,
                const char *acl_name,
                const char *ace_sequence_number_str)
{
    struct ovsdb_idl_txn *transaction;
    enum ovsdb_idl_txn_status txn_status;
    const struct ovsrec_acl *acl_row;
    int64_t ace_sequence_number;
    int64_t pending_cfg_version;

    /* Start transaction */
    transaction = cli_do_config_start();
    if (!transaction) {
        VLOG_ERR("Unable to acquire transaction");
        return CMD_OVSDB_FAILURE;
    }

    /* Get parent ACL row */
    acl_row = get_acl_by_type_name(acl_type, acl_name);
    if (!acl_row) {
        /* Should not be possible; context should have created */
        vty_out(vty, "%% ACL does not exist%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_ERR_NOTHING_TODO;
    }

    /* Should already be guarded against by parser */
    if (!ace_sequence_number_str) {
        vty_out(vty, "%% Invalid sequence number%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_ERR_NOTHING_TODO;
    }
    ace_sequence_number = strtoll(ace_sequence_number_str, NULL, 0);

    /* Check to make sure ACE is present in ACL */

    VLOG_DBG("Deleting ACE seq=%" PRId64, ace_sequence_number);
    if (!ovsrec_acl_set_cfg_aces_from_cur_aces(acl_row, ace_sequence_number, NULL)) {
        vty_out(vty, "%% ACL entry does not exist%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_ERR_NOTHING_TODO;
    }
    pending_cfg_version = acl_row->cfg_version[0] + 1;
    ovsrec_acl_set_cfg_version(acl_row, &pending_cfg_version, 1);
    /* If ACE is no longer referenced it will be garbage-collected */

    /* Complete transaction */
    txn_status = cli_do_config_finish(transaction);
    if (txn_status != TXN_SUCCESS && txn_status != TXN_UNCHANGED) {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    /* Wait until ACE update either succeeds or fails and report to user */
    return wait_for_ace_update_status(acl_type, acl_name, pending_cfg_version);
}

int
cli_resequence_acl (const char *acl_type,
                    const char *acl_name,
                    const char *start,
                    const char *increment)
{
    struct ovsdb_idl_txn *transaction;
    enum ovsdb_idl_txn_status txn_status;
    const struct ovsrec_acl *acl_row;
    unsigned long start_num, increment_num, current_num;
    int64_t *key_list;
    struct ovsrec_acl_entry **value_list;
    int i;
    int64_t pending_cfg_version;

    /* Start transaction */
    transaction = cli_do_config_start();
    if (!transaction) {
        VLOG_ERR("Unable to acquire transaction");
        return CMD_OVSDB_FAILURE;
    }

    /* Get ACL row */
    acl_row = get_acl_by_type_name(acl_type, acl_name);
    if (!acl_row) {
        vty_out(vty, "%% ACL does not exist%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_ERR_NOTHING_TODO;
    }

    /* Check for an empty list */
    if (!acl_row->n_cur_aces) {
        vty_out(vty, "%% ACL is empty%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_ERR_NOTHING_TODO;
    }

    /* Set numeric values */
    start_num = strtoul(start, NULL, 0);
    increment_num = strtoul(increment, NULL, 0);
    current_num = start_num;

    /* Check that sequence numbers will not exceed maximum a_n = a_0 + (n-1)d
     * Test that formula works for ACE_SEQ_MAX of 4294967295:
     *   use start = 3, increment = 1073741823 on 5-ACE list
     *   input should be accepted
     *   resequence should result in ACE #5 seq=4294967295
     */
    if (start_num + ((acl_row->n_cur_aces - 1) * increment_num) > ACE_SEQ_MAX) {
        vty_out(vty, "%% Sequence numbers would exceed maximum%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_ERR_NOTHING_TODO;
    }

    /* Initialize temporary data structures */
    key_list = xmalloc(sizeof(int64_t) * (acl_row->n_cur_aces));
    value_list = xmalloc(sizeof *acl_row->value_cur_aces * (acl_row->n_cur_aces));

    /* Walk through sorted list, resequencing by adding into new_aces */
    for (i = 0; i < acl_row->n_cur_aces; i++) {
        key_list[i] = current_num;
        value_list[i] = acl_row->value_cur_aces[i];
        current_num += increment_num;
    }

    /* Replace ACL's entries with resequenced ones */
    ovsrec_acl_set_cfg_aces(acl_row, key_list, value_list, acl_row->n_cur_aces);
    pending_cfg_version = acl_row->cfg_version[0] + 1;
    ovsrec_acl_set_cfg_version(acl_row, &pending_cfg_version, 1);

    /* Clean up temporary data structures */
    free(key_list);
    free(value_list);

    /* Complete transaction */
    txn_status = cli_do_config_finish(transaction);
    if (txn_status != TXN_SUCCESS && txn_status != TXN_UNCHANGED) {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    /* Wait until ACE update either succeeds or fails and report to user */
    return wait_for_ace_update_status(acl_type, acl_name, pending_cfg_version);
}

int
cli_print_applied_acls (const char *interface_type,
                        const char *interface_id,
                        const char *acl_type,
                        const char *direction,
                        const char *config)
{
    /* Port (unfortunately called "interface" in the CLI) */
    if (!strcmp(interface_type, "interface")) {
        const struct ovsrec_port *port_row;

        /* Get Port row */
        port_row = get_port_by_name(interface_id);
        if (!port_row) {
            vty_out(vty, "%% Port does not exist%s", VTY_NEWLINE);
            return CMD_ERR_NOTHING_TODO;
        }

        if (port_row->aclv4_in_applied) {
            VLOG_DBG("Found ACL application port=%s name=%s",
                     interface_id, port_row->aclv4_in_applied->name);
            if (config)
            {
                print_acl_config(port_row->aclv4_in_applied);
            } else {
                vty_out(vty, "%-10s %-31s%s", "Direction", "", VTY_NEWLINE);
                print_acl_tabular_header();
                print_acl_horizontal_rule();
                vty_out(vty, "%-10s %-31s%s", "Inbound", "", VTY_NEWLINE);
                print_acl_tabular(port_row->aclv4_in_applied);
                print_acl_horizontal_rule();
            }
        }

        /* Print application commands if printing config */
        if (config && port_row->aclv4_in_applied) {
            vty_out(vty, "%s %s\n    %s %s %s %s %s%s",
                    "interface", port_row->name,
                    "apply", "access-list", "ip",
                    port_row->aclv4_in_applied->name, "in",
                    VTY_NEWLINE);
        }
    } else if (!strcmp(interface_type, "vlan")) {
        const struct ovsrec_vlan *vlan_row;

        /* Get VLAN row */
        vlan_row = get_vlan_by_id_str(interface_id);
        if (!vlan_row) {
            vty_out(vty, "%% VLAN does not exist%s", VTY_NEWLINE);
            return CMD_ERR_NOTHING_TODO;
        }

        if (vlan_row->aclv4_in_applied) {
            VLOG_DBG("Found ACL application vlan=%s name=%s",
                     interface_id, vlan_row->aclv4_in_applied->name);
            if (config)
            {
                print_acl_config(vlan_row->aclv4_in_applied);
            } else {
                vty_out(vty, "%-10s %-31s%s", "Direction", "", VTY_NEWLINE);
                print_acl_tabular_header();
                print_acl_horizontal_rule();
                vty_out(vty, "%-10s %-31s%s", "Inbound", "", VTY_NEWLINE);
                print_acl_tabular(vlan_row->aclv4_in_applied);
                print_acl_horizontal_rule();
            }
        }

        /* Print application commands if printing config */
        if (config && vlan_row->aclv4_in_applied) {
            vty_out(vty, "%s %" PRId64 "\n    %s %s %s %s %s%s",
                    "vlan", vlan_row->id,
                    "apply", "access-list", "ip",
                    vlan_row->aclv4_in_applied->name, "in",
                    VTY_NEWLINE);
        }
    }

    return CMD_SUCCESS;
}

int
cli_apply_acl (const char *interface_type,
               const char *interface_id,
               const char *acl_type,
               const char *acl_name,
               const char *direction)
{
    struct ovsdb_idl_txn *transaction;
    enum ovsdb_idl_txn_status txn_status;
    const struct ovsrec_acl *acl_row;
    int64_t pending_cfg_version;

    VLOG_DBG("Apply");

    /* Start transaction */
    transaction = cli_do_config_start();
    if (!transaction) {
        VLOG_ERR("Unable to acquire transaction");
        return CMD_OVSDB_FAILURE;
    }

    /* Get ACL row */
    acl_row = get_acl_by_type_name(acl_type, acl_name);
    if (!acl_row) {
        vty_out(vty, "%% ACL does not exist%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_ERR_NOTHING_TODO;
    }

    /* Port (unfortunately called "interface" in the CLI) */
    if (!strcmp(interface_type, "interface")) {
        const struct ovsrec_port *port_row;
        /* Get Port row */
        port_row = get_port_by_name(interface_id);
        if (!port_row) {
            vty_out(vty, "%% Port does not exist%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }

        if (!strcmp(acl_type, "ipv4") && !strcmp(direction, "in")) {
            /* Check if we're replacing an already-applied ACL */
            if (port_row->aclv4_in_applied) {
                VLOG_DBG("Old ACL application port=%s acl_name=%s",
                         interface_id, port_row->aclv4_in_applied->name);
            }
            /* Apply the requested ACL to the Port */
            VLOG_DBG("New ACL application port=%s acl_name=%s", interface_id, acl_name);
            ovsrec_port_set_aclv4_in_cfg(port_row, acl_row);
            if (port_row->n_aclv4_in_cfg_version) {
                pending_cfg_version = port_row->aclv4_in_cfg_version[0] + 1;
            } else {
                pending_cfg_version = 0;
            }
            ovsrec_port_set_aclv4_in_cfg_version(port_row, &pending_cfg_version, 1);
        } else {
            vty_out(vty, "%% Unsupported ACL type or direction%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }

    } else if (!strcmp(interface_type, "vlan")) {

        const struct ovsrec_vlan *vlan_row;
        /* Get VLAN row */
        vlan_row = get_vlan_by_id_str(interface_id);
        if (!vlan_row) {
            vty_out(vty, "%% VLAN does not exist%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }

        if (!strcmp(acl_type, "ipv4") && !strcmp(direction, "in")) {
            /* Check if we're replacing an already-applied ACL */
            if (vlan_row->aclv4_in_applied) {
                VLOG_DBG("Old ACL application vlan=%s acl_name=%s",
                         interface_id, vlan_row->aclv4_in_applied->name);
            }

            /* Apply the requested ACL to the VLAN */
            VLOG_DBG("New ACL application vlan=%s acl_name=%s", interface_id, acl_name);
            ovsrec_vlan_set_aclv4_in_cfg(vlan_row, acl_row);
            if (vlan_row->n_aclv4_in_cfg_version) {
                pending_cfg_version = vlan_row->aclv4_in_cfg_version[0] + 1;
            } else {
                pending_cfg_version = 0;
            }
            ovsrec_vlan_set_aclv4_in_cfg_version(vlan_row, &pending_cfg_version, 1);
        } else {
            vty_out(vty, "%% Unsupported ACL type or direction%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }
    }

    /* Complete transaction */
    txn_status = cli_do_config_finish(transaction);
    if (txn_status != TXN_SUCCESS && txn_status != TXN_UNCHANGED) {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    /* Wait until ACL apply either succeeds or fails and report to user */
    return wait_for_acl_apply_status(interface_type, interface_id,
                                     acl_type, direction,
                                     pending_cfg_version);
}

int
cli_unapply_acl (const char *interface_type,
                 const char *interface_id,
                 const char *acl_type,
                 const char *acl_name,
                 const char *direction)
{
    struct ovsdb_idl_txn *transaction;
    enum ovsdb_idl_txn_status txn_status;
    const struct ovsrec_acl *acl_row;
    int64_t pending_cfg_version;

    /* Start transaction */
    transaction = cli_do_config_start();
    if (!transaction) {
        VLOG_ERR("Unable to acquire transaction");
        return CMD_OVSDB_FAILURE;
    }

    /* Get ACL row */
    acl_row = get_acl_by_type_name(acl_type, acl_name);
    if (!acl_row) {
        vty_out(vty, "%% ACL does not exist%s", VTY_NEWLINE);
        cli_do_config_abort(transaction);
        return CMD_ERR_NOTHING_TODO;
    }

    /* Port (unfortunately called "interface" in the CLI) */
    if (!strcmp(interface_type, "interface")) {
        const struct ovsrec_port *port_row;
        /* Get Port row */
        port_row = get_port_by_name(interface_id);
        if (!port_row) {
            vty_out(vty, "%% Port does not exist%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }

        if (!strcmp(acl_type, "ipv4") && !strcmp(direction, "in")) {
            /* Check that any ACL is currently applied to the port */
            if (!port_row->aclv4_in_applied) {
                vty_out(vty, "%% No ACL is applied to port %s", VTY_NEWLINE);
                cli_do_config_abort(transaction);
                return CMD_ERR_NOTHING_TODO;
            }

            /* Check that the requested ACL to remove is the one applied to port */
            if (strcmp(acl_name, port_row->aclv4_in_applied->name)) {
                vty_out(vty, "%% ACL %s is applied to port %s, not %s%s",
                        port_row->aclv4_in_applied->name,
                        port_row->name, acl_name, VTY_NEWLINE);
                cli_do_config_abort(transaction);
                return CMD_ERR_NOTHING_TODO;
            }

            /* Un-apply the requested ACL application from the Port */
            VLOG_DBG("Removing ACL application port=%s acl_name=%s", interface_id, acl_name);
            ovsrec_port_set_aclv4_in_cfg(port_row, NULL);
            if (port_row->n_aclv4_in_cfg_version) {
                pending_cfg_version = port_row->aclv4_in_cfg_version[0] + 1;
            } else {
                pending_cfg_version = 0;
            }
            ovsrec_port_set_aclv4_in_cfg_version(port_row, &pending_cfg_version, 1);
        } else {
            vty_out(vty, "%% Unsupported ACL type or direction%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }

    } else if (!strcmp(interface_type, "vlan")) {

        const struct ovsrec_vlan *vlan_row;
        /* Get VLAN row */
        vlan_row = get_vlan_by_id_str(interface_id);
        if (!vlan_row) {
            vty_out(vty, "%% VLAN does not exist%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }

        if (!strcmp(acl_type, "ipv4") && !strcmp(direction, "in")) {
            /* Check that any ACL is currently applied to the VLAN */
            if (!vlan_row->aclv4_in_applied) {
                vty_out(vty, "%% No ACL is applied to VLAN %s", VTY_NEWLINE);
                cli_do_config_abort(transaction);
                return CMD_ERR_NOTHING_TODO;
            }

            /* Check that the requested ACL to remove is the one applied to vlan */
            if (strcmp(acl_name, vlan_row->aclv4_in_applied->name)) {
                vty_out(vty, "%% ACL %s is applied to VLAN %" PRId64 ", not %s%s",
                        vlan_row->aclv4_in_applied->name,
                        vlan_row->id, acl_name, VTY_NEWLINE);
                cli_do_config_abort(transaction);
                return CMD_ERR_NOTHING_TODO;
            }

            /* Un-apply the requested ACL application from the VLAN */
            VLOG_DBG("Removing ACL application vlan=%s acl_name=%s", interface_id, acl_name);
            ovsrec_vlan_set_aclv4_in_cfg(vlan_row, NULL);
            if (vlan_row->n_aclv4_in_cfg_version) {
                pending_cfg_version = vlan_row->aclv4_in_cfg_version[0] + 1;
            } else {
                pending_cfg_version = 0;
            }
            ovsrec_vlan_set_aclv4_in_cfg_version(vlan_row, &pending_cfg_version, 1);
        } else {
            vty_out(vty, "%% Unsupported ACL type or direction%s", VTY_NEWLINE);
            cli_do_config_abort(transaction);
            return CMD_ERR_NOTHING_TODO;
        }
    }

    /* Complete transaction */
    txn_status = cli_do_config_finish(transaction);
    if (txn_status != TXN_SUCCESS && txn_status != TXN_UNCHANGED) {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    /* Wait until ACL un-apply either succeeds or fails and report to user */
    return wait_for_acl_apply_status(interface_type, interface_id,
                                     acl_type, direction,
                                     pending_cfg_version);
}

int
cli_print_acl_statistics (const char *acl_type,
                          const char *acl_name,
                          const char *interface_type,
                          const char *interface_id,
                          const char *direction)
{
    const struct ovsrec_port *port_row;
    const struct ovsrec_vlan *vlan_row;
    const struct ovsrec_acl *acl_row;

    VLOG_DBG("Showing statistics for %s ACL %s %s=%s direction=%s",
            acl_type, acl_name, interface_type, interface_id, direction);

    acl_row = get_acl_by_type_name(acl_type, acl_name);
    if (!acl_row) {
        vty_out(vty, "%% ACL %s does not exist%s", acl_name, VTY_NEWLINE);
        return CMD_ERR_NOTHING_TODO;
    }

    /* No interface specified (implicit "all" interface type/id/direction) */
    if (!interface_type) {
        vty_out(vty, "Statistics for ACL %s (%s):%s", acl_row->name, acl_row->list_type, VTY_NEWLINE);
        OVSREC_PORT_FOR_EACH(port_row, idl) {
            if (port_row->aclv4_in_applied && (port_row->aclv4_in_applied == acl_row)) {
                print_port_aclv4_in_statistics(port_row);
            }
        }
        OVSREC_VLAN_FOR_EACH(vlan_row, idl) {
            if (vlan_row->aclv4_in_applied && (vlan_row->aclv4_in_applied == acl_row)) {
                print_vlan_aclv4_in_statistics(vlan_row);
            }
        }
    /* Port (unfortunately called "interface" in the CLI) */
    } else if (interface_type && !strcmp(interface_type, "interface")) {
        /* Get Port row */
        port_row = get_port_by_name(interface_id);
        if (!port_row) {
            vty_out(vty, "%% Port %s does not exist%s", interface_id, VTY_NEWLINE);
            return CMD_ERR_NOTHING_TODO;
        }
        if (port_row->aclv4_in_applied && (port_row->aclv4_in_applied == acl_row)) {
            vty_out(vty, "Statistics for ACL %s (%s):%s", acl_row->name, acl_row->list_type, VTY_NEWLINE);
            print_port_aclv4_in_statistics(port_row);
        } else {
            vty_out(vty, "%% Specified ACL not applied to interface%s", VTY_NEWLINE);
            return CMD_ERR_NOTHING_TODO;
        }
    /* VLAN */
    } else if (interface_type && !strcmp(interface_type, "vlan")) {
        /* Get VLAN row */
        vlan_row = get_vlan_by_id_str(interface_id);
        if (!vlan_row) {
            vty_out(vty, "%% VLAN %s does not exist%s", interface_id, VTY_NEWLINE);
            return CMD_ERR_NOTHING_TODO;
        }
        if (vlan_row->aclv4_in_applied && (vlan_row->aclv4_in_applied == acl_row)) {
            vty_out(vty, "Statistics for ACL %s (%s):%s", acl_row->name, acl_row->list_type, VTY_NEWLINE);
            print_vlan_aclv4_in_statistics(vlan_row);
        } else {
            vty_out(vty, "%% Specified ACL not applied to VLAN%s", VTY_NEWLINE);
            return CMD_ERR_NOTHING_TODO;
        }
    }
    return CMD_SUCCESS;
}

int
cli_clear_acl_statistics (const char *acl_type,
                          const char *acl_name,
                          const char *interface_type,
                          const char *interface_id,
                          const char *direction)
{
    struct ovsdb_idl_txn *transaction;
    enum ovsdb_idl_txn_status txn_status;
    const struct ovsrec_port *port_row;
    const struct ovsrec_vlan *vlan_row;
    const struct ovsrec_acl *acl_row;
    int64_t clear_stats_req_id;
    struct acl_db_util *acl_db_util;

    VLOG_DBG("Clearing statistics for %s ACL %s %s=%s direction=%s",
            acl_type, acl_name, interface_type, interface_id, direction);

    /* Start transaction */
    transaction = cli_do_config_start();
    if (!transaction) {
        VLOG_ERR("Unable to acquire transaction");
        return CMD_OVSDB_FAILURE;
    }

    /* retrieve acl_db_accessor */
    acl_db_util = acl_db_util_accessor_get(OPS_CLS_ACL_V4, OPS_CLS_DIRECTION_IN);
    if (!acl_db_util) {
        VLOG_ERR("Unable to acquire acl_db_util accessor");
        return CMD_OVSDB_FAILURE;
    }
    /* No ACL specified (implicit "all" applied ACLs) */
    if (!acl_name) {
        OVSREC_PORT_FOR_EACH(port_row, idl) {

            if (port_row->aclv4_in_applied) {
                VLOG_DBG("Clearing ACL statistics port=%s", port_row->name);
                /* retrieve current clear requested id and increment by 1 for
                 * this clear request
                 */
                clear_stats_req_id = acl_db_util_get_clear_statistics_requested(
                                        acl_db_util, port_row) + 1;

                acl_db_util_set_clear_statistics_requested(acl_db_util,
                                        port_row, clear_stats_req_id);
            }
        }

        OVSREC_VLAN_FOR_EACH(vlan_row, idl) {
            VLOG_DBG("Not supported: Clearing ACL statistics vlan=%" PRId64 "",
                        vlan_row->id);
        }
    /* ACL specified */
    } else {
        acl_row = get_acl_by_type_name(acl_type, acl_name);
        if (!acl_row) {
            vty_out(vty, "%% ACL %s does not exist%s", acl_name, VTY_NEWLINE);
            return CMD_ERR_NOTHING_TODO;
        }
        /* No interface specified (implicit "all" interface type/id/direction) */
        if (!interface_type) {
            OVSREC_PORT_FOR_EACH(port_row, idl) {
                if (port_row->aclv4_in_applied &&
                    (port_row->aclv4_in_applied == acl_row)) {
                    /* retrieve current clear requested id and increment by 1 for
                     * this clear request
                     */
                    clear_stats_req_id = acl_db_util_get_clear_statistics_requested(
                                            acl_db_util, port_row) + 1;

                    acl_db_util_set_clear_statistics_requested(acl_db_util,
                                            port_row, clear_stats_req_id);
                }

            }
            OVSREC_VLAN_FOR_EACH(vlan_row, idl) {
                if (vlan_row->aclv4_in_applied && (vlan_row->aclv4_in_applied == acl_row)) {
                    VLOG_DBG("Not supported: Clearing ACL statistics vlan=%" PRId64 " acl_name=%s",
                                vlan_row->id, acl_name);
                }
            }
        /* Port (unfortunately called "interface" in the CLI) */
        } else if (!strcmp(interface_type, "interface")) {
            /* Get Port row */
            port_row = get_port_by_name(interface_id);
            if (!port_row) {
                vty_out(vty, "%% Port %s does not exist%s", interface_id, VTY_NEWLINE);
                return CMD_ERR_NOTHING_TODO;
            }
            if (port_row->aclv4_in_applied && (port_row->aclv4_in_applied == acl_row)) {
                VLOG_DBG("Clearing ACL statistics port=%s acl_name=%s",
                            port_row->name, acl_name);
                /* retrieve current clear requested id and increment by 1 for
                 * this clear request
                 */
                clear_stats_req_id = acl_db_util_get_clear_statistics_requested(
                                        acl_db_util, port_row) + 1;
                acl_db_util_set_clear_statistics_requested(acl_db_util,
                                        port_row, clear_stats_req_id);

            } else {
                vty_out(vty, "%% Specified ACL not applied to interface%s", VTY_NEWLINE);
                return CMD_ERR_NOTHING_TODO;
            }
        /* VLAN */
        } else if (!strcmp(interface_type, "vlan")) {
            /* Get VLAN row */
            vlan_row = get_vlan_by_id_str(interface_id);
            if (!vlan_row) {
                vty_out(vty, "%% VLAN %s does not exist%s", interface_id, VTY_NEWLINE);
                return CMD_ERR_NOTHING_TODO;
            }
            if (vlan_row->aclv4_in_applied && (vlan_row->aclv4_in_applied == acl_row)) {
                VLOG_DBG("Not supported: Clearing ACL statistics vlan=%" PRId64 " acl_name=%s", vlan_row->id, acl_name);
            } else {
                vty_out(vty, "%% Specified ACL not applied to VLAN%s", VTY_NEWLINE);
                return CMD_ERR_NOTHING_TODO;
            }
        }
    }

    /* Complete transaction */
    txn_status = cli_do_config_finish(transaction);
    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED) {
        return CMD_SUCCESS;
    } else {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }
}

int
cli_set_acl_log_timer(const char* timer_value)
{
    struct ovsdb_idl_txn *transaction;
    enum ovsdb_idl_txn_status txn_status;
    const struct ovsrec_system *ovs;
    struct smap other_config;

    VLOG_DBG("Setting ACL log timer to %s", timer_value);

    /* Start transaction */
    transaction = cli_do_config_start();
    if (!transaction) {
        VLOG_ERR("Unable to acquire transaction");
        return CMD_OVSDB_FAILURE;
    }

    /* Get System table */
    ovs = ovsrec_system_first(idl);
    if (!ovs) {
        cli_do_config_abort(transaction);
        assert(0);
        return CMD_OVSDB_FAILURE;
    }

    /* Copy current "other_config" column from System table */
    smap_clone(&other_config, &ovs->other_config);

    /* Remove any existing value (smap_add doesn't replace) */
    smap_remove(&other_config, ACL_LOG_TIMER_STR);

    /* Only set "other_config" record for non-default value */
    if (strcmp(timer_value, ACL_LOG_TIMER_DEFAULT_STR))
    {
        smap_add(&other_config, ACL_LOG_TIMER_STR, timer_value);
    }

    /* Set new "other_config" column in System table */
    ovsrec_system_set_other_config(ovs, &other_config);

    /* Complete transaction */
    txn_status = cli_do_config_finish(transaction);
    if (txn_status == TXN_SUCCESS || txn_status == TXN_UNCHANGED) {
        return CMD_SUCCESS;
    } else {
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }
}

void
access_list_ovsdb_init(void)
{
    /* System table, columns */
    ovsdb_idl_add_table(idl, &ovsrec_table_system);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_acls);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_other_config);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_other_info);

    /* ACL table, columns */
    ovsdb_idl_add_table(idl, &ovsrec_table_acl);
    ovsdb_idl_add_column(idl, &ovsrec_acl_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_acl_col_list_type);
    ovsdb_idl_add_column(idl, &ovsrec_acl_col_cfg_aces);
    ovsdb_idl_add_column(idl, &ovsrec_acl_col_cfg_version);
    ovsdb_idl_add_column(idl, &ovsrec_acl_col_cur_aces);
    ovsdb_idl_add_column(idl, &ovsrec_acl_col_in_progress_aces);
    ovsdb_idl_add_column(idl, &ovsrec_acl_col_status);

    /* ACL_Entry table, columns */
    ovsdb_idl_add_table(idl, &ovsrec_table_acl_entry);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_action);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_protocol);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_src_ip);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_src_l4_port_min);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_src_l4_port_max);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_src_l4_port_range_reverse);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_dst_ip);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_dst_l4_port_min);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_dst_l4_port_max);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_dst_l4_port_range_reverse);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_log);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_count);
    ovsdb_idl_add_column(idl, &ovsrec_acl_entry_col_comment);

    /* ACL columns in Port table */
    ovsdb_idl_add_table(idl, &ovsrec_table_port);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_aclv4_in_applied);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_aclv4_in_cfg);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_aclv4_in_cfg_version);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_aclv4_in_statistics);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_aclv4_in_status);
    ovsdb_idl_add_column(idl,
                    &ovsrec_port_col_aclv4_in_statistics_clear_requested);

    /* ACL columns in VLAN table */
    ovsdb_idl_add_table(idl, &ovsrec_table_vlan);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_id);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_aclv4_in_applied);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_aclv4_in_cfg);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_aclv4_in_cfg_version);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_aclv4_in_statistics);
    ovsdb_idl_add_column(idl, &ovsrec_vlan_col_aclv4_in_status);

    /* Initialize ACL DB Util array */
    acl_db_util_init();
}
