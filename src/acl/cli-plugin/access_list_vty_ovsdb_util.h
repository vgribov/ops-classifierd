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
 * Definition of Access Control List (ACL) CLI OVSDB utility functions,
 * including printing and manipulating OVSDB IDL data structures.
 ***************************************************************************/

#ifndef _ACCESS_LIST_VTY_OVSDB_UTIL_H
#define _ACCESS_LIST_VTY_OVSDB_UTIL_H

/**
 * Look up an ACL by type + name
 *
 * @param  acl_type ACL type string
 * @param  acl_name ACL name string
 *
 * @return          Pointer to ovsrec_acl structure object
 */
const struct ovsrec_acl *get_acl_by_type_name(const char *acl_type,
                                              const char *acl_name);

/**
 * Look up a Port by name
 *
 * @param  name     Port name string
 *
 * @return          Pointer to ovsrec_port structure object
 */
const struct ovsrec_port * get_port_by_name(const char *name);

/**
 * Look up a VLAN by ID (in string form)
 *
 * @param  id_str   VLAN ID string
 *
 * @return          Pointer to ovsrec_vlan structure object
 */
const struct ovsrec_vlan *get_vlan_by_id_str(const char *id_str);

/**
 * Look up an ACE by key (sequence number) in current ACEs
 *
 * @param  acl_row         ACL row pointer
 * @param  sequence_number ACE sequence number
 *
 * @return                 Pointer to ovsrec_acl_entry structure object
 */
const struct ovsrec_acl_entry *ovsrec_acl_cur_aces_getvalue(const struct ovsrec_acl *acl_row,
                                                            const int64_t key);

/**
 * Look up an ACE by key (sequence number) in ACE statistics
 *
 * @param  port_row        Port row pointer
 * @param  sequence_number ACE sequence number
 *
 * @return                 Hit count for ACE, 0 on failure
 */
const int64_t ovsrec_port_aclv4_in_statistics_getvalue(const struct ovsrec_port *port_row,
                                                       const int64_t key);

/**
 * Look up an ACE by key (sequence number) in ACE statistics
 *
 * @param  vlan_row        VLAN row pointer
 * @param  sequence_number ACE sequence number
 *
 * @return                 Hit count for ACE, 0 on failure
 */
const int64_t ovsrec_vlan_aclv4_in_statistics_getvalue(const struct ovsrec_vlan *vlan_row,
                                                       const int64_t key);

/**
 * Creates a string with an ACL Entry config as if it were entered into the CLI
 *
 * @param sequence_num  ACL Entry Sequence number
 * @param ace_row       Pointer to ACL_Entry row
 *
 * @return              ACL Entry string, caller-freed, not newline-terminated
 */
char *acl_entry_config_to_string(const int64_t sequence_num,
                                 const struct ovsrec_acl_entry *ace_row);

/**
 * Check ACL entry capacity for any given ACL and in database table
 *
 * @param acl_row Pointer to ACL row
 * @param ace_row Pointer to ACE row
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on ACE capacity failure
 */
int check_ace_capacity (const struct ovsrec_acl *acl_row,
                        const struct ovsrec_acl_entry *ace_row);

/**
 * Print an ACL's configuration as if it were entered into the CLI
 *
 * @param acl_row Pointer to ACL row
 *
 * @sa show_run_access_list_callback A similar function that uses a different
 *                                   print method
 */
void print_acl_config(const struct ovsrec_acl *acl_row);

/**
 * Print an ACL's configuration in a tabular format
 *
 * This function isn't pretty, but this is the only place this formatting style
 * is used, so there's not a lot of re-use to be gained by breaking it up now.
 *
 * @param acl_row Pointer to ACL to print
 */
void print_acl_tabular(const struct ovsrec_acl *acl_row);

/**
 * Print inbound IPv4 statistics for any ACLs applied to a given Port
 *
 * @param port_row Pointer to Port row
 */
void print_port_aclv4_in_statistics(const struct ovsrec_port *port_row);

/**
 * Print inbound IPv4 statistics for any ACLs applied to a given VLAN
 *
 * @param vlan_row Pointer to VLAN row
 */
void print_vlan_aclv4_in_statistics(const struct ovsrec_vlan *vlan_row);

/**
 * Take ACL Entries from an ACL's cur_aces, copy them into cfg_aces, and update
 * the provided entry with a new value.
 *
 * @param acl_row ACL row pointer
 * @param key     numeric key (entry sequence number)
 * @param value   ACL Entry row pointer (NULL indicates delete)
 *
 * @return        false if attempting to delete a non-existent entry,
 *                true otherwise
 */
bool ovsrec_acl_set_cfg_aces_from_cur_aces(const struct ovsrec_acl *acl_row,
                                           const int64_t key,
                                           struct ovsrec_acl_entry *value);

/**
 * Wait for an ACL matching the given type and name to have a status for the
 * given configuration version.
 *
 * @param  acl_type             Type string
 * @param  acl_name             Name string
 * @param  pending_cfg_version  Configuration version to wait for status on
 *
 * @retval CMD_SUCCESS on success
 * @retval CMD_WARNING if the operation may not have succeeded
 */
int wait_for_ace_update_status(const char *acl_type,
                               const char *acl_name,
                               const int64_t pending_cfg_version);

/**
 * Wait for an inteface (e.g. port or VLAN) matching the given type and ID and
 * ACL type and direction to have a status for the given configuration version.
 *
 * @param  interface_type       Interface (Port/VLAN) type string
 * @param  interface_id         Interface (Port/VLAN) identifier string
 * @param  acl_type             ACL type string
 * @param  direction            Direction of traffic ACL is applied to
 * @param  pending_cfg_version  Configuration version to wait for status on
 */
int wait_for_acl_apply_status(const char *interface_type,
                              const char *interface_id,
                              const char *acl_type,
                              const char *direction,
                              const int64_t pending_cfg_version);

#endif /* _ACCESS_LIST_VTY_OVSDB_UTIL_H */
