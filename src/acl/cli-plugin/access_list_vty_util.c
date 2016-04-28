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
 * Implementation of Access Control List (ACL) CLI utility functions,
 * including print and string-handling functions.
 ***************************************************************************/

#include <dynamic-string.h>

#include <vty.h>
#include <command.h>
#include <vtysh.h>

#include <acl_parse.h>
#include <ops-cls-asic-plugin.h>
#include <ops_cls_status_msgs.h>

void
print_acl_tabular_header(void)
{
    vty_out(vty,
            "%-10s %-31s %-18s\n"
             "%10s %-31s %-18s\n"
             "%10s %-31s %-18s\n"
             "%10s %-31s %-18s\n"
             "%10s %-31s %-18s\n"
             "%10s %-31s %-18s%s",
            "Type", "Name", "",
            "Sequence", "Comment", "",
            "", "Action", "L3 Protocol",
            "", "Source IP Address", "Source L4 Port(s)",
            "", "Destination IP Address", "Destination L4 Port(s)",
            "", "Additional Parameters", "", VTY_NEWLINE);
}

void
print_acl_horizontal_rule(void)
{
    vty_out(vty, "%s%s",
        "-------------------------------------------------------------------------------",
        VTY_NEWLINE);
}

void
print_ace_pretty_ip_address(const char *format, char *address_str)
{
    char user_str[INET_ADDRSTRLEN*2];
    if (acl_ipv4_address_normalized_to_user(address_str, user_str))
    {
        vty_out(vty, format, user_str);
    }
}

void
print_ace_pretty_l4_ports(int64_t min, int64_t max, bool reverse)
{
    if (min == max) {
        if (reverse) {
            vty_out(vty, "%s %5" PRId64, "!=", min);
        } else {
            vty_out(vty, "%s %5" PRId64, " =", min);
        }
    } else if (min == 0 && max < 65535) {
        vty_out(vty, "%s %5" PRId64, " <", max + 1);
    } else if (min > 0 && max == 65535) {
        vty_out(vty, "%s %5" PRId64, " >", min - 1);
    } else {
        vty_out(vty, "%s %5" PRId64 " %s %5" PRId64, "  ", min, "-", max);
    }
}
