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
 * Definition of Access Control List (ACL) CLI utility functions,
 * including print and string-handling functions.
 ***************************************************************************/

#ifndef _ACCESS_LIST_VTY_UTIL_H
#define _ACCESS_LIST_VTY_UTIL_H

/**
 * Print header for ACL(s) to be printed in a tabular format
 */
void print_acl_tabular_header(void);

/**
 * Print horizontal rule line to separate tabular output
 */
void print_acl_horizontal_rule(void);

/**
 * Print human-readable IP Address string
 *
 * The database stores only in dotted-slash notation, but this should be
 * translated to other CLI-style keywords/formats to improve readability.
 *
 * @param format       Format string (e.g. "%s" for simple usage)
 * @param address_str  Pointer to IP address string
 */
void print_ace_pretty_ip_address(const char *format, char *address_str);

/**
 * Print human-readable L4 ports string
 *
 * @param min      First port number
 * @param max      Last port number
 * @param reverse  Whether range is reversed
 */
void print_ace_pretty_l4_ports(int64_t min, int64_t max, bool reverse);

#endif /* _ACCESS_LIST_VTY_UTIL_H */
