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
 * Definition of Access Control List (ACL) CLI for "show running-config".
 ***************************************************************************/

/**
 * Callback routine for access-list (ACL) show running-config handler
 *
 * @param  p_private Void pointer for holding address of vtysh_ovsdb_cbmsg_ptr
 *                   structure object
 *
 * @return           e_vtysh_ok on success
 *
 * @sa print_acl_commands A similar function that uses a different print method
 * @sa print_acl_mismatch_warning Another function for config mismatch warnings
 */
vtysh_ret_val show_run_access_list_callback(void *p_private);

/**
 * Callback routine for access-list show running-config subcontext handler
 *
 * @param  p_private Void pointer for holding address of vtysh_ovsdb_cbmsg_ptr
 *                   structure object
 *
 * @return           e_vtysh_ok on success
 *
 * @sa print_acl_mismatch_warning Another function for config mismatch warnings
 */
vtysh_ret_val show_run_access_list_subcontext_callback(void *p_private);
