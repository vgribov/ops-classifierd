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
 * Definition of Access Control List (ACL) CLI OVSDB interactions.
 ***************************************************************************/

#ifndef _ACCESS_LIST_VTY_OVSDB_H
#define _ACCESS_LIST_VTY_OVSDB_H

/**
 * Create an ACL if it does not exist
 *
 * @param  acl_type  ACL type string
 * @param  acl_name  ACL name string
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 */
int cli_create_acl_if_needed (const char *acl_type,
                              const char *acl_name);

/**
 * Delete an ACL
 *
 * @param  acl_type  ACL type string
 * @param  acl_name  ACL name string
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 *
 */
int cli_delete_acl (const char *acl_type,
                    const char *acl_name);

/**
 * Create/Update an ACE
 *
 * @param  acl_type                       Type string
 * @param  acl_name                       Name string
 * @param  ace_sequence_number_str        Sequence number string (NULL = auto)
 * @param  ace_action                     Action string
 * @param  ace_ip_protocol                IP protocol string
 * @param  ace_source_ip_address          Source IP address string
 * @param  ace_source_port_operator       Operator for source port(s)
 * @param  ace_source_port                First source port
 * @param  ace_source_port_max            Second source port (range only)
 * @param  ace_destination_ip_address     Destination IP address string
 * @param  ace_destination_port_operator  Operator for destination port(s)
 * @param  ace_destination_port           First destination port
 * @param  ace_destination_port_max       Second destination port (range only)
 * @param  ace_log_enabled                Is logging enabled on this entry?
 * @param  ace_count_enabled              Is counting enabled on this entry?
 * @param  ace_comment                    Text comment string (must be freed)
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 */
int cli_create_update_ace (const char *acl_type,
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
                                 char *ace_comment);

/**
 * Delete an ACE
 *
 * @param  acl_type                 ACL type string
 * @param  acl_name                 ACL name string
 * @param  ace_sequence_number_str  ACE parameter string
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 *
 */
int cli_delete_ace (const char *acl_type,
                    const char *acl_name,
                    const char *ace_sequence_number_str);

/**
 * Resequence entries in an ACL
 *
 * @param  acl_type   ACL type string
 * @param  acl_name   ACL string name to apply
 * @param  start      Starting entry sequence number
 * @param  increment  Increment to increase each entry's sequence number by
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 */
int cli_resequence_acl (const char *acl_type,
                        const char *acl_name,
                        const char *start,
                        const char *increment);

/**
 * Display ACL(s) applied to the specified interface in the given direction
 *
 * @param  interface_type  Interface (Port/VLAN) type string
 * @param  interface_id    Interface (Port/VLAN) identifier string
 * @param  acl_type        ACL type string
 * @param  acl_name        ACL name string
 * @param  direction       Direction of traffic ACL is applied to
 * @param  commands        Print ACL configuration as CLI commands
 * @param  configuration   Print user-specified configuration
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 */
int cli_print_acls (const char *interface_type,
                    const char *interface_id,
                    const char *acl_type,
                    const char *acl_name,
                    const char *direction,
                    const char *commands,
                    const char *configuration);

/**
 * Reset user-specified ACL configuration to active configuration.
 * Includes ACL entries and applications of ACLs.
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 */
int cli_reset_acls_all(void);

/**
 * Apply an ACL to an interface in a specified direction
 *
 * @param  interface_type  Interface (Port/VLAN) type string
 * @param  interface_id    Interface (Port/VLAN) identifier string
 * @param  acl_type        ACL type string
 * @param  acl_name        ACL string name to apply
 * @param  direction       Direction of traffic ACL is applied to
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 */
int cli_apply_acl (const char *interface_type,
                   const char *interface_id,
                   const char *acl_type,
                   const char *acl_name,
                   const char *direction);

/**
 * Un-apply an ACL from an interface in a specified direction
 *
 * @param  interface_type  Interface (Port/VLAN) type string
 * @param  interface_id    Interface (Port/VLAN) identifier string
 * @param  acl_type        ACL type string
 * @param  acl_name        ACL name string
 * @param  direction       Direction of traffic ACL is applied to
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 */
int cli_unapply_acl (const char *interface_type,
                     const char *interface_id,
                     const char *acl_type,
                     const char *acl_name,
                     const char *direction);

/**
 * Print statistics for a specified ACL (optionally for a specified interface
 * and/or direction)
 *
 * @param  acl_type        ACL type string
 * @param  acl_name        ACL name string
 * @param  interface_type  Interface (Port/VLAN) type string
 * @param  interface_id    Interface (Port/VLAN) identifier string
 * @param  direction       Direction of traffic ACL is applied to
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 */
int cli_print_acl_statistics (const char *acl_type,
                              const char *acl_name,
                              const char *interface_type,
                              const char *interface_id,
                              const char *direction);

/**
 * Clear ACL statistics (optionally for a specific ACL, interface, direction)
 *
 * @param  acl_type        ACL type string
 * @param  acl_name        ACL name string
 * @param  interface_type  Interface (Port/VLAN) type string
 * @param  interface_id    Interface (Port/VLAN) identifier string
 * @param  direction       Direction of traffic ACL is applied to
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 * @retval CMD_ERR_NOTHING_TODO  on bad parameter/value
 */
int cli_clear_acl_statistics (const char *acl_type,
                              const char *acl_name,
                              const char *interface_type,
                              const char *interface_id,
                              const char *direction);

/**
 * Set the ACL logging timer to a specified value (in seconds)
 *
 * @param  timer_value ACL log timer frequency (in seconds)
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 */
int cli_set_acl_log_timer(const char* timer_value);

/**
 * Print the configured ACL logging timer value (or "default")
 *
 * @retval CMD_SUCCESS           on success
 * @retval CMD_OVSDB_FAILURE     on database/transaction failure
 */
int cli_print_acl_log_timer(void);

/**
 * Initialize ACL OVSDB tables, columns
 */
void access_list_ovsdb_init(void);

#endif /* _ACCESS_LIST_VTY_OVSDB_H */
