/*
 * Copyright (C) 1997, 98 Kunihiro Ishiguro
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
 * Implementation of Access Control List (ACL) CLI command definitions.
 ***************************************************************************/

#include <openvswitch/vlog.h>
#include <util.h>

#include <vty.h>
#include <command.h>
#include <vtysh_ovsdb_config.h>
#include <vtysh.h>

#include <acl_parse.h>

#include "access_list_vty.h"
#include "access_list_vty_ovsdb.h"
#include "vtysh_ovsdb_access_list_context.h"

/** Create logging module */
VLOG_DEFINE_THIS_MODULE(vtysh_access_list_cli);

/**
 * Action routine for creating/updating an ACL (entering context)
 */
DEFUN (cli_access_list,
       cli_access_list_cmd,
       "access-list ip NAME",
       ACL_STR
       ACL_IP_STR
       ACL_NAME_STR
      )
{
    /* static buffers because CLI context persists past this function */
    static char acl_ip_version[IP_VER_STR_LEN];
    static char acl_name[MAX_ACL_NAME_LENGTH];

    if ((strnlen(argv[0], MAX_ACL_NAME_LENGTH) < MAX_ACL_NAME_LENGTH)) {
        strncpy(acl_ip_version, "ipv4", IP_VER_STR_LEN);
        strncpy(acl_name, argv[0], MAX_ACL_NAME_LENGTH);
    } else {
        return CMD_ERR_NO_MATCH;
    }

    /* Same name can be used with different IP versions; consider name sub-index */
    vty->index = acl_ip_version;
    vty->index_sub = acl_name;
    vty->node = ACCESS_LIST_NODE;

    return cli_create_acl_if_needed(CONST_CAST(char*,vty->index),      /* Type */
                                    CONST_CAST(char*,vty->index_sub)); /* Name */
}

/**
 * Action routine for deleting an ACL
 */
DEFUN (cli_no_access_list,
       cli_no_access_list_cmd,
       "no access-list ip NAME",
       NO_STR
       ACL_STR
       ACL_IP_STR
       ACL_NAME_STR
      )
{
    return cli_delete_acl("ipv4",
                          CONST_CAST(char*,argv[0]));
}

/**
 * Action routine for showing all ACLs
 */
DEFUN (cli_show_access_list,
       cli_show_access_list_cmd,
       "show access-list { commands | configuration }",
       SHOW_STR
       ACL_STR
       ACL_CLI_CMD_STR
       ACL_CFG_STR
      )
{
    return cli_print_acls(NULL,                       /* interface_type */
                          NULL,                       /* interface_id */
                          NULL,                       /* acl_type */
                          NULL,                       /* acl_name */
                          NULL,                       /* direction */
                          CONST_CAST(char*,argv[0]),  /* commands */
                          CONST_CAST(char*,argv[1])); /* configuration */
}

/**
 * Action routine for a single ACL type
 */
DEFUN (cli_show_access_list_type,
       cli_show_access_list_type_cmd,
       "show access-list (ip) { commands | configuration }",
       SHOW_STR
       ACL_STR
       ACL_IP_STR
       ACL_CLI_CMD_STR
       ACL_CFG_STR
      )
{
    const char ipv4_str[] = "ipv4";
    const char *type_str;
    if (argv[0] && !strcmp(argv[0], "ip")) {
        type_str = ipv4_str;
    } else {
        type_str = argv[0];
    }
    return cli_print_acls(NULL,                       /* interface_type */
                          NULL,                       /* interface_id */
                          type_str,                   /* acl_type */
                          NULL,                       /* acl_name */
                          NULL,                       /* direction */
                          CONST_CAST(char*,argv[1]),  /* commands */
                          CONST_CAST(char*,argv[2])); /* configuration */
}

/**
 * Action routine for a single ACL specified by type and name
 */
DEFUN (cli_show_access_list_type_name,
       cli_show_access_list_type_name_cmd,
       "show access-list (ip) NAME { commands | configuration }",
       SHOW_STR
       ACL_STR
       ACL_IP_STR
       ACL_NAME_STR
       ACL_CLI_CMD_STR
       ACL_CFG_STR
      )
{
    const char ipv4_str[] = "ipv4";
    const char *type_str;
    if (argv[0] && !strcmp(argv[0], "ip")) {
        type_str = ipv4_str;
    } else {
        type_str = argv[0];
    }
    return cli_print_acls(NULL,                       /* interface_type */
                          NULL,                       /* interface_id */
                          type_str,                   /* acl_type */
                          CONST_CAST(char*,argv[1]),  /* acl_name */
                          NULL,                       /* direction */
                          CONST_CAST(char*,argv[2]),  /* commands */
                          CONST_CAST(char*,argv[3])); /* configuration */
}

/**
 * Action routine for resetting all ACLs to active configuration
 */
DEFUN (cli_reset_access_list_all,
       cli_reset_access_list_all_cmd,
       "reset access-list all",
       ACL_RESET_STR
       ACL_STR
       ACL_ALL_STR
       )
{
    return cli_reset_acls(NULL,  /* acl_type */
                          NULL); /* acl_name */
}

/**
 * Action routine for resetting specified ACL to active configuration
 */
DEFUN (cli_reset_access_list,
       cli_reset_access_list_cmd,
       "reset access-list (ip) NAME",
       ACL_RESET_STR
       ACL_STR
       ACL_IP_STR
       ACL_NAME_STR
       )
{
    const char ipv4_str[] = "ipv4";
    const char *type_str;
    if (argv[0] && !strcmp(argv[0], "ip")) {
        type_str = ipv4_str;
    } else {
        type_str = argv[0];
    }
    return cli_reset_acls(type_str,                   /* acl_type */
                          CONST_CAST(char*,argv[1])); /* acl_name */
}

/**
 * Action routine for resequencing an ACL
 */
DEFUN (cli_access_list_resequence,
       cli_access_list_resequence_cmd,
       "access-list ip NAME resequence " ACE_SEQ_CMDSTR " " ACE_SEQ_CMDSTR,
       ACL_STR
       ACL_IP_STR
       ACL_NAME_STR
       "Re-number entries\n"
       "Starting sequence number\n"
       "Re-sequence increment\n"
      )
{
    return cli_resequence_acl("ipv4",
                              CONST_CAST(char*,argv[0]),
                              CONST_CAST(char*,argv[1]),
                              CONST_CAST(char*,argv[2]));
}

/* ACE create/update command functions.
 * These are PAINFUL to express due to vtysh's lack of handling for optional
 * tokens or sequences in the middle of a command. The relevant combinations
 * are below and result in 18 combinations (and therefore "DEFUN" calls)
 *
 * - With or without sequence number
 * - Layer 4 source port options (3)
 *   - None
 *   - Operation and port specified
 *   - Range and min+max ports specified
 * - Layer 4 destination port options (3)
 *   - None
 *   - Operation and port specified
 *   - Range and min+max ports specified
 *
 * Adding another optional parameter mid-command will double this number again.
 */

/**
 * Action routine for setting an ACE
 */
DEFUN (cli_access_list_entry,
       cli_access_list_entry_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_SEQ_CMDSTR
       ACE_ACTION_CMDSTR
       ACE_ALL_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_SEQ_HELPSTR
       ACE_ACTION_HELPSTR
       ACE_ALL_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 CONST_CAST(char*,argv[2]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[3]),        /* Source IP */
                                 NULL,                             /* Source Port Operator */
                                 NULL,                             /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[4]),        /* Destination IP */
                                 NULL,                             /* Destination Port Operator */
                                 NULL,                             /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[5]),        /* Log */
                                 CONST_CAST(char*,argv[6]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with a source port operator specified
 */
DEFUN (cli_access_list_entry_src_port_op,
       cli_access_list_entry_src_port_op_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_SEQ_CMDSTR
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_SEQ_HELPSTR
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_OPER_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 CONST_CAST(char*,argv[2]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[3]),        /* Source IP */
                                 CONST_CAST(char*,argv[4]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[5]),        /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[6]),        /* Destination IP */
                                 NULL,                             /* Destination Port Operator */
                                 NULL,                             /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[7]),        /* Log */
                                 CONST_CAST(char*,argv[8]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with a source port range specified
 */
DEFUN (cli_access_list_entry_src_port_range,
       cli_access_list_entry_src_port_range_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_SEQ_CMDSTR
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_SEQ_HELPSTR
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_RANGE_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 CONST_CAST(char*,argv[2]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[3]),        /* Source IP */
                                 CONST_CAST(char*,argv[4]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[5]),        /* Source Port 1 */
                                 CONST_CAST(char*,argv[6]),        /* Source Port 2 */
                                 CONST_CAST(char*,argv[7]),        /* Destination IP */
                                 NULL,                             /* Destination Port Operator */
                                 NULL,                             /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[8]),        /* Log */
                                 CONST_CAST(char*,argv[9]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with a destination port operator specified
 */
DEFUN (cli_access_list_entry_dst_port_op,
       cli_access_list_entry_dst_port_op_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_SEQ_CMDSTR
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_SEQ_HELPSTR
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_OPER_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 CONST_CAST(char*,argv[2]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[3]),        /* Source IP */
                                 NULL,                             /* Source Port Operator */
                                 NULL,                             /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[4]),        /* Destination IP */
                                 CONST_CAST(char*,argv[5]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[6]),        /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[7]),        /* Log */
                                 CONST_CAST(char*,argv[8]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with a destination port range specified
 */
DEFUN (cli_access_list_entry_dst_port_range,
       cli_access_list_entry_dst_port_range_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_SEQ_CMDSTR
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_SEQ_HELPSTR
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_RANGE_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 CONST_CAST(char*,argv[2]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[3]),        /* Source IP */
                                 NULL,                             /* Source Port Operator */
                                 NULL,                             /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[4]),        /* Destination IP */
                                 CONST_CAST(char*,argv[5]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[6]),        /* Destination Port 1 */
                                 CONST_CAST(char*,argv[7]),        /* Destination Port 2 */
                                 CONST_CAST(char*,argv[8]),        /* Log */
                                 CONST_CAST(char*,argv[9]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with both source and destination port
 * operators specified
 */
DEFUN (cli_access_list_entry_src_port_op_dst_port_op,
       cli_access_list_entry_src_port_op_dst_port_op_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_SEQ_CMDSTR
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_SEQ_HELPSTR
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_OPER_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_OPER_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 CONST_CAST(char*,argv[2]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[3]),        /* Source IP */
                                 CONST_CAST(char*,argv[4]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[5]),        /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[6]),        /* Destination IP */
                                 CONST_CAST(char*,argv[7]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[8]),        /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[9]),        /* Log */
                                 CONST_CAST(char*,argv[10]),       /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with both source and destination port
 * ranges specified
 */
DEFUN (cli_access_list_entry_src_port_range_dst_port_range,
       cli_access_list_entry_src_port_range_dst_port_range_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_SEQ_CMDSTR
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_SEQ_HELPSTR
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_RANGE_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_RANGE_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 CONST_CAST(char*,argv[2]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[3]),        /* Source IP */
                                 CONST_CAST(char*,argv[4]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[5]),        /* Source Port 1 */
                                 CONST_CAST(char*,argv[6]),        /* Source Port 2 */
                                 CONST_CAST(char*,argv[7]),        /* Destination IP */
                                 CONST_CAST(char*,argv[8]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[9]),        /* Destination Port 1 */
                                 CONST_CAST(char*,argv[10]),       /* Destination Port 2 */
                                 CONST_CAST(char*,argv[11]),       /* Log */
                                 CONST_CAST(char*,argv[12]),       /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with source port operator and destination
 * port range specified
 */
DEFUN (cli_access_list_entry_src_port_op_dst_port_range,
       cli_access_list_entry_src_port_op_dst_port_range_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_SEQ_CMDSTR
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_SEQ_HELPSTR
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_OPER_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_RANGE_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 CONST_CAST(char*,argv[2]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[3]),        /* Source IP */
                                 CONST_CAST(char*,argv[4]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[5]),        /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[6]),        /* Destination IP */
                                 CONST_CAST(char*,argv[7]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[8]),        /* Destination Port 1 */
                                 CONST_CAST(char*,argv[9]),        /* Destination Port 2 */
                                 CONST_CAST(char*,argv[10]),       /* Log */
                                 CONST_CAST(char*,argv[11]),       /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with source port range and destination
 * port operator specified
 */
DEFUN (cli_access_list_entry_src_port_range_dst_port_op,
       cli_access_list_entry_src_port_range_dst_port_op_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_SEQ_CMDSTR
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_SEQ_HELPSTR
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_RANGE_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_OPER_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 CONST_CAST(char*,argv[2]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[3]),        /* Source IP */
                                 CONST_CAST(char*,argv[4]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[5]),        /* Source Port 1 */
                                 CONST_CAST(char*,argv[6]),        /* Source Port 2 */
                                 CONST_CAST(char*,argv[7]),        /* Destination IP */
                                 CONST_CAST(char*,argv[8]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[9]),        /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[10]),       /* Log */
                                 CONST_CAST(char*,argv[11]),       /* Count */
                                 NULL);                            /* Comment */
}

/* ACE commands omitting sequence number */

/**
 * Action routine for setting an ACE without a sequence number
 */
DEFUN (cli_access_list_entry_no_seq,
       cli_access_list_entry_no_seq_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_ACTION_CMDSTR
       ACE_ALL_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_ACTION_HELPSTR
       ACE_ALL_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 NULL,                             /* Sequence number */
                                 CONST_CAST(char*,argv[0]),        /* Action */
                                 CONST_CAST(char*,argv[1]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[2]),        /* Source IP */
                                 NULL,                             /* Source Port Operator */
                                 NULL,                             /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[3]),        /* Destination IP */
                                 NULL,                             /* Destination Port Operator */
                                 NULL,                             /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[4]),        /* Log */
                                 CONST_CAST(char*,argv[5]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with a source port operator specified
 * without a sequence number
 */
DEFUN (cli_access_list_entry_src_port_op_no_seq,
       cli_access_list_entry_src_port_op_no_seq_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_OPER_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 NULL,                             /* Sequence number */
                                 CONST_CAST(char*,argv[0]),        /* Action */
                                 CONST_CAST(char*,argv[1]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[2]),        /* Source IP */
                                 CONST_CAST(char*,argv[3]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[4]),        /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[5]),        /* Destination IP */
                                 NULL,                             /* Destination Port Operator */
                                 NULL,                             /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[6]),        /* Log */
                                 CONST_CAST(char*,argv[7]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with a source port range specified
 * without a sequence number
 */
DEFUN (cli_access_list_entry_src_port_range_no_seq,
       cli_access_list_entry_src_port_range_no_seq_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_RANGE_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 NULL,                             /* Sequence number */
                                 CONST_CAST(char*,argv[0]),        /* Action */
                                 CONST_CAST(char*,argv[1]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[2]),        /* Source IP */
                                 CONST_CAST(char*,argv[3]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[4]),        /* Source Port 1 */
                                 CONST_CAST(char*,argv[5]),        /* Source Port 2 */
                                 CONST_CAST(char*,argv[6]),        /* Destination IP */
                                 NULL,                             /* Destination Port Operator */
                                 NULL,                             /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[7]),        /* Log */
                                 CONST_CAST(char*,argv[8]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with a destination port operator specified
 * without a sequence number
 */
DEFUN (cli_access_list_entry_dst_port_op_no_seq,
       cli_access_list_entry_dst_port_op_no_seq_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_OPER_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 NULL,                             /* Sequence number */
                                 CONST_CAST(char*,argv[0]),        /* Action */
                                 CONST_CAST(char*,argv[1]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[2]),        /* Source IP */
                                 NULL,                             /* Source Port Operator */
                                 NULL,                             /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[3]),        /* Destination IP */
                                 CONST_CAST(char*,argv[4]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[5]),        /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[6]),        /* Log */
                                 CONST_CAST(char*,argv[7]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with a destination port range specified
 * without a sequence number
 */
DEFUN (cli_access_list_entry_dst_port_range_no_seq,
       cli_access_list_entry_dst_port_range_no_seq_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_RANGE_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 NULL,                             /* Sequence number */
                                 CONST_CAST(char*,argv[0]),        /* Action */
                                 CONST_CAST(char*,argv[1]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[2]),        /* Source IP */
                                 NULL,                             /* Source Port Operator */
                                 NULL,                             /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[3]),        /* Destination IP */
                                 CONST_CAST(char*,argv[4]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[5]),        /* Destination Port 1 */
                                 CONST_CAST(char*,argv[6]),        /* Destination Port 2 */
                                 CONST_CAST(char*,argv[7]),        /* Log */
                                 CONST_CAST(char*,argv[8]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with both source and destination port
 * operators specified without a sequence number
 */
DEFUN (cli_access_list_entry_src_port_op_dst_port_op_no_seq,
       cli_access_list_entry_src_port_op_dst_port_op_no_seq_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_OPER_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_OPER_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 NULL,                             /* Sequence number */
                                 CONST_CAST(char*,argv[0]),        /* Action */
                                 CONST_CAST(char*,argv[1]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[2]),        /* Source IP */
                                 CONST_CAST(char*,argv[3]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[4]),        /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[5]),        /* Destination IP */
                                 CONST_CAST(char*,argv[6]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[7]),        /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[8]),        /* Log */
                                 CONST_CAST(char*,argv[9]),        /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with both source and destination port
 * ranges specified without a sequence number
 */
DEFUN (cli_access_list_entry_src_port_range_dst_port_range_no_seq,
       cli_access_list_entry_src_port_range_dst_port_range_no_seq_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_RANGE_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_RANGE_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 NULL,                             /* Sequence number */
                                 CONST_CAST(char*,argv[0]),        /* Action */
                                 CONST_CAST(char*,argv[1]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[2]),        /* Source IP */
                                 CONST_CAST(char*,argv[3]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[4]),        /* Source Port 1 */
                                 CONST_CAST(char*,argv[5]),        /* Source Port 2 */
                                 CONST_CAST(char*,argv[6]),        /* Destination IP */
                                 CONST_CAST(char*,argv[7]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[8]),        /* Destination Port 1 */
                                 CONST_CAST(char*,argv[9]),        /* Destination Port 2 */
                                 CONST_CAST(char*,argv[10]),       /* Log */
                                 CONST_CAST(char*,argv[11]),       /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with source port operator and destination
 * port range specified without a sequence number
 */
DEFUN (cli_access_list_entry_src_port_op_dst_port_range_no_seq,
       cli_access_list_entry_src_port_op_dst_port_range_no_seq_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_OPER_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_RANGE_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 NULL,                             /* Sequence number */
                                 CONST_CAST(char*,argv[0]),        /* Action */
                                 CONST_CAST(char*,argv[1]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[2]),        /* Source IP */
                                 CONST_CAST(char*,argv[3]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[4]),        /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 CONST_CAST(char*,argv[5]),        /* Destination IP */
                                 CONST_CAST(char*,argv[6]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[7]),        /* Destination Port 1 */
                                 CONST_CAST(char*,argv[8]),        /* Destination Port 2 */
                                 CONST_CAST(char*,argv[9]),        /* Log */
                                 CONST_CAST(char*,argv[10]),       /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE with source port range and destination
 * port operator specified without a sequence number
 */
DEFUN (cli_access_list_entry_src_port_range_dst_port_op_no_seq,
       cli_access_list_entry_src_port_range_dst_port_op_no_seq_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_ACTION_CMDSTR
       ACE_PORT_PROTOCOLS_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_RANGE_CMDSTR
       ACE_IP_ADDRESS_CMDSTR
       ACE_PORT_OPER_CMDSTR
       ACE_ADDITIONAL_OPTIONS_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_ACTION_HELPSTR
       ACE_PORT_PROTOCOLS_HELPSTR
       ACE_SRC_IP_ADDRESS_HELPSTR
       ACE_SRC_PORT_RANGE_HELPSTR
       ACE_DST_IP_ADDRESS_HELPSTR
       ACE_DST_PORT_OPER_HELPSTR
       ACE_ADDITIONAL_OPTIONS_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 NULL,                             /* Sequence number */
                                 CONST_CAST(char*,argv[0]),        /* Action */
                                 CONST_CAST(char*,argv[1]),        /* IP Protocol */
                                 CONST_CAST(char*,argv[2]),        /* Source IP */
                                 CONST_CAST(char*,argv[3]),        /* Source Port Operator */
                                 CONST_CAST(char*,argv[4]),        /* Source Port 1 */
                                 CONST_CAST(char*,argv[5]),        /* Source Port 2 */
                                 CONST_CAST(char*,argv[6]),        /* Destination IP */
                                 CONST_CAST(char*,argv[7]),        /* Destination Port Operator */
                                 CONST_CAST(char*,argv[8]),        /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 CONST_CAST(char*,argv[9]),        /* Log */
                                 CONST_CAST(char*,argv[10]),       /* Count */
                                 NULL);                            /* Comment */
}

/**
 * Action routine for setting an ACE comment
 */
DEFUN (cli_access_list_entry_comment,
       cli_access_list_entry_comment_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_SEQ_CMDSTR
       ACE_COMMENT_CMDSTR
       ACE_COMMENT_TEXT_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_SEQ_HELPSTR
       ACE_COMMENT_HELPSTR
       ACE_COMMENT_TEXT_HELPSTR
      )
{
    /* To be freed after use */
    char *comment_text = argv_concat(argv, argc, 2);

    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 NULL,                             /* IP Protocol */
                                 NULL,                             /* Source IP */
                                 NULL,                             /* Source Port Operator */
                                 NULL,                             /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 NULL,                             /* Destination IP */
                                 NULL,                             /* Destination Port Operator */
                                 NULL,                             /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 NULL,                             /* Log */
                                 NULL,                             /* Count */
                                 comment_text);                    /* Comment */
}

/**
 * Action routine for setting an ACE comment without a sequence number
 */
DEFUN (cli_access_list_entry_comment_no_seq,
       cli_access_list_entry_comment_no_seq_cmd,
       /* start of cmdstr, broken up to help readability */
       ACE_COMMENT_CMDSTR
       ACE_COMMENT_TEXT_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       ACE_COMMENT_HELPSTR
       ACE_COMMENT_TEXT_HELPSTR
      )
{
    /* To be freed after use */
    char *comment_text = argv_concat(argv, argc, 1);

    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 NULL,                             /* Sequence number */
                                 CONST_CAST(char*,argv[0]),        /* Action */
                                 NULL,                             /* IP Protocol */
                                 NULL,                             /* Source IP */
                                 NULL,                             /* Source Port Operator */
                                 NULL,                             /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 NULL,                             /* Destination IP */
                                 NULL,                             /* Destination Port Operator */
                                 NULL,                             /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 NULL,                             /* Log */
                                 NULL,                             /* Count */
                                 comment_text);                    /* Comment */
}

/**
 * Action routine for deleting an ACE comment
 */
DEFUN (cli_no_access_list_entry_comment,
       cli_no_access_list_entry_comment_cmd,
       /* start of cmdstr, broken up to help readability */
       "no "
       ACE_SEQ_CMDSTR
       ACE_COMMENT_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       NO_STR
       ACE_SEQ_HELPSTR
       ACE_COMMENT_HELPSTR
      )
{
    return cli_create_update_ace(CONST_CAST(char*,vty->index),     /* Type */
                                 CONST_CAST(char*,vty->index_sub), /* Name */
                                 CONST_CAST(char*,argv[0]),        /* Sequence number */
                                 CONST_CAST(char*,argv[1]),        /* Action */
                                 NULL,                             /* IP Protocol */
                                 NULL,                             /* Source IP */
                                 NULL,                             /* Source Port Operator */
                                 NULL,                             /* Source Port 1 */
                                 NULL,                             /* Source Port 2 */
                                 NULL,                             /* Destination IP */
                                 NULL,                             /* Destination Port Operator */
                                 NULL,                             /* Destination Port 1 */
                                 NULL,                             /* Destination Port 2 */
                                 NULL,                             /* Log */
                                 NULL,                             /* Count */
                                 NULL);                            /* Comment */
}

/* Can't delete an ACE comment without a sequence number, so no DEFUN for it */

/**
 * Alternate form that ignores additional tokens when deleting an ACE comment
 */
ALIAS (cli_no_access_list_entry_comment,
       cli_no_access_list_entry_comment_etc_cmd,
       "no "
       ACE_SEQ_CMDSTR
       ACE_COMMENT_CMDSTR
       ACE_ETC_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       NO_STR
       ACE_SEQ_HELPSTR
       ACE_COMMENT_HELPSTR
       ACE_ETC_HELPSTR
      )

/**
 * Action routine for deleting an ACE
 */
DEFUN (cli_no_access_list_entry,
       cli_no_access_list_entry_cmd,
       "no " ACE_SEQ_CMDSTR,
       NO_STR
       ACE_SEQ_HELPSTR
      )
{
    return cli_delete_ace(CONST_CAST(char*,vty->index),     /* Type */
                          CONST_CAST(char*,vty->index_sub), /* Name */
                          CONST_CAST(char*,argv[0]));       /* Sequence number */
}

/**
 * Alternate form that ignores additional tokens when deleting an ACE
 */
ALIAS (cli_no_access_list_entry,
       cli_no_access_list_entry_etc_cmd,
       "no "
       ACE_SEQ_CMDSTR
       ACE_ETC_CMDSTR
       , /* end of cmdstr, comment to avoid accidental comma loss */

       /* helpstr, newline delimited */
       NO_STR
       ACE_SEQ_HELPSTR
       ACE_ETC_HELPSTR
      )

/**
 * Action routine for showing specific applications of ACLs
 */
DEFUN (cli_show_access_list_applied, cli_show_access_list_applied_cmd,
       "show access-list (interface|vlan) ID { ip | in | commands | configuration }",
       SHOW_STR
       ACL_STR
       ACL_INTERFACE_STR
       ACL_VLAN_STR
       ACL_INTERFACE_ID_STR
       ACL_IP_STR
       ACL_IN_STR
       ACL_CLI_CMD_STR
       ACL_CFG_STR
      )
{
    const char ipv4_str[] = "ipv4";
    const char *type_str;
    if (argv[2] && !strcmp(argv[2], "ip")) {
        type_str = ipv4_str;
    } else {
        type_str = argv[2];
    }
    return cli_print_acls(CONST_CAST(char*,argv[0]),  /* interface type */
                          CONST_CAST(char*,argv[1]),  /* interface id */
                          CONST_CAST(char*,type_str), /* acl_type */
                          NULL,                       /* acl_name */
                          CONST_CAST(char*,argv[3]),  /* direction */
                          CONST_CAST(char*,argv[4]),  /* commands */
                          CONST_CAST(char*,argv[5])); /* configuration */
}

/**
 * Action routine for applying an ACL to an interface
 */
DEFUN (cli_apply_access_list, cli_apply_access_list_cmd,
       "apply access-list (ip) NAME (in)",
       ACL_APPLY_STR
       ACL_STR
       ACL_IP_STR
       ACL_NAME_STR
       ACL_IN_STR
      )
{
    const char vlan_str[] = "vlan";
    const char interface_str[] = "interface";
    const char *interface_type_str;
    const char ipv4_str[] = "ipv4";
    const char *type_str;

    if (vty->node == VLAN_NODE) {
        interface_type_str = vlan_str;
    } else if (vty->node == INTERFACE_NODE) {
        interface_type_str = interface_str;
    } else {
        interface_type_str = NULL;
    }
    if (argv[0] && !strcmp(argv[0], "ip")) {
        type_str = ipv4_str;
    } else {
        type_str = argv[0];
    }

    return cli_apply_acl(interface_type_str,           /* interface type */
                         CONST_CAST(char*,vty->index), /* interface id */
                         type_str,                     /* type */
                         CONST_CAST(char*,argv[1]),    /* name */
                         CONST_CAST(char*,argv[2]));   /* direction */
}

/**
 * Action routine for un-applying an ACL from an interface
 */
DEFUN (cli_no_apply_access_list, cli_no_apply_access_list_cmd,
       "no apply access-list (ip) NAME (in)",
       NO_STR
       ACL_APPLY_STR
       ACL_STR
       ACL_IP_STR
       ACL_NAME_STR
       ACL_IN_STR
      )
{
    const char vlan_str[] = "vlan";
    const char interface_str[] = "interface";
    const char *interface_type_str;
    const char ipv4_str[] = "ipv4";
    const char *type_str;

    if (vty->node == VLAN_NODE) {
        interface_type_str = vlan_str;
    } else if (vty->node == INTERFACE_NODE) {
        interface_type_str = interface_str;
    } else {
        interface_type_str = NULL;
    }
    if (argv[0] && !strcmp(argv[0], "ip")) {
        type_str = ipv4_str;
    } else {
        type_str = argv[0];
    }

    return cli_unapply_acl(interface_type_str,           /* interface type */
                           CONST_CAST(char*,vty->index), /* interface id */
                           type_str,                     /* type */
                           CONST_CAST(char*,argv[1]),    /* name */
                           CONST_CAST(char*,argv[2]));   /* direction */
}

/**
 * Action routine for resetting all ACLs applied in active configuration
 */
DEFUN (cli_reset_access_list_applied_all,
       cli_reset_access_list_applied_all_cmd,
       "reset access-list applied all",
       ACL_RESET_STR
       ACL_STR
       ACL_APPLIED_STR
       ACL_ALL_STR
       )
{
    return cli_reset_applied_acls(NULL,  /* interface type */
                                  NULL,  /* interface id */
                                  NULL,  /* type */
                                  NULL); /* direction */
}

/**
 * Action routine for resetting specified ACLs applied in active configuration
 */
DEFUN (cli_reset_access_list_applied,
       cli_reset_access_list_applied_cmd,
       "reset access-list applied (interface|vlan) ID { ip | in }",
       ACL_RESET_STR
       ACL_STR
       ACL_APPLIED_STR
       ACL_INTERFACE_STR
       ACL_VLAN_STR
       ACL_INTERFACE_ID_STR
       ACL_IP_STR
       ACL_IN_STR
       )
{
    const char ipv4_str[] = "ipv4";
    const char *type_str;

    if (argv[2] && !strcmp(argv[2], "ip")) {
        type_str = ipv4_str;
    } else {
        type_str = argv[0];
    }

    return cli_reset_applied_acls(CONST_CAST(char*,argv[0]),  /* interface type */
                                  CONST_CAST(char*,argv[1]),  /* interface id */
                                  type_str,                   /* type */
                                  CONST_CAST(char*,argv[3])); /* direction */
}

/**
 * Action routine for showing ACL statistics on a specified interface
 */
DEFUN (cli_show_access_list_hitcounts,
       cli_show_access_list_hitcounts_cmd,
       "show access-list hitcounts (ip) NAME (interface|vlan) ID { in }",
       SHOW_STR
       ACL_STR
       ACL_HITCOUNTS_STR
       ACL_IP_STR
       ACL_NAME_STR
       ACL_INTERFACE_STR
       ACL_VLAN_STR
       ACL_INTERFACE_ID_STR
       ACL_IN_STR
      )
{
    const char ipv4_str[] = "ipv4";
    const char *type_str;
    if (argv[0] && !strcmp(argv[0], "ip")) {
        type_str = ipv4_str;
    } else {
        type_str = argv[0];
    }
    return cli_print_acl_statistics(CONST_CAST(char*,type_str), /* type */
                                    CONST_CAST(char*,argv[1]),  /* name */
                                    CONST_CAST(char*,argv[2]),  /* interface type */
                                    CONST_CAST(char*,argv[3]),  /* interface id */
                                    CONST_CAST(char*,argv[4])); /* direction */
}

/**
 * Action routine for showing ACL statistics on all applied interfaces
 */
DEFUN (cli_show_access_list_hitcounts_all,
       cli_show_access_list_hitcounts_all_cmd,
       "show access-list hitcounts (ip) NAME",
       SHOW_STR
       ACL_STR
       ACL_HITCOUNTS_STR
       ACL_IP_STR
       ACL_NAME_STR
      )
{
    const char ipv4_str[] = "ipv4";
    const char *type_str;
    if (argv[0] && !strcmp(argv[0], "ip")) {
        type_str = ipv4_str;
    } else {
        type_str = argv[0];
    }
    return cli_print_acl_statistics(CONST_CAST(char*,type_str), /* type */
                                    CONST_CAST(char*,argv[1]),  /* name */
                                    NULL,                       /* interface type */
                                    NULL,                       /* interface id */
                                    NULL);                      /* direction */
}

/**
 * Action routine for clearing ACL statistics on a specified interface
 */
DEFUN (cli_clear_access_list_hitcounts,
       cli_clear_access_list_hitcounts_cmd,
       "clear access-list hitcounts (ip) NAME (interface|vlan) ID { in }",
       SHOW_STR
       ACL_STR
       ACL_HITCOUNTS_STR
       ACL_IP_STR
       ACL_NAME_STR
       ACL_INTERFACE_STR
       ACL_VLAN_STR
       ACL_INTERFACE_ID_STR
       ACL_IN_STR
      )
{
    const char ipv4_str[] = "ipv4";
    const char *type_str;

    if (argv[0] && !strcmp(argv[0], "ip")) {
        type_str = ipv4_str;
    } else {
        type_str = argv[0];
    }

    return cli_clear_acl_statistics(CONST_CAST(char*,type_str), /* type */
                                    CONST_CAST(char*,argv[1]),  /* name */
                                    CONST_CAST(char*,argv[2]),  /* interface type */
                                    CONST_CAST(char*,argv[3]),  /* interface id */
                                    CONST_CAST(char*,argv[4])); /* direction */
}

/**
 * Action routine for clearing all ACL statistics on all interfaces
 */
DEFUN (cli_clear_access_list_hitcounts_all,
       cli_clear_access_list_hitcounts_all_cmd,
       "clear access-list hitcounts all { in }",
       CLEAR_STR
       ACL_STR
       ACL_HITCOUNTS_STR
       ACL_ALL_STR
       ACL_IN_STR
      )
{
    return cli_clear_acl_statistics(NULL,                       /* type */
                                    NULL,                       /* name */
                                    NULL,                       /* interface type */
                                    NULL,                       /* interface id */
                                    CONST_CAST(char*,argv[0])); /* direction */
}

/**
 * Action routine for setting ACL log timer to a specified value (or default)
 */
DEFUN (cli_access_list_log_timer, cli_access_list_log_timer_cmd,
       "access-list log-timer (" ACL_LOG_TIMER_DEFAULT_STR "|<" ACL_LOG_TIMER_MIN "-" ACL_LOG_TIMER_MAX ">)",
       ACL_STR
       "Set " ACL_LOG_TIMER_NAME_STR "\n"
       "Default value (" ACL_LOG_TIMER_DEFAULT " seconds)\n"
       "Specify value (in seconds)\n"
      )
{
    return cli_set_acl_log_timer(CONST_CAST(char*,argv[0])); /* timer_value */
}

/**
 * Action routine for displaying ACL log timer
 */
DEFUN (cli_show_access_list_log_timer, cli_show_access_list_log_timer_cmd,
       "show access-list log-timer",
       SHOW_STR
       ACL_STR
       "Display " ACL_LOG_TIMER_NAME_STR "\n"
      )
{
    return cli_print_acl_log_timer();
}

/**
 * Prompt string when in access-list context
 */
static struct cmd_node access_list_node = {
    ACCESS_LIST_NODE,
    "%s(config-acl)# "
};

/**
 * Install the CLI action routines for ACL
 */
static void
access_list_vty_init(void)
{
    install_element(CONFIG_NODE, &cli_access_list_cmd);
    install_element(CONFIG_NODE, &cli_no_access_list_cmd);
    install_element(CONFIG_NODE, &cli_access_list_resequence_cmd);
    install_element(CONFIG_NODE, &cli_reset_access_list_all_cmd);
    install_element(CONFIG_NODE, &cli_reset_access_list_cmd);
    install_element(CONFIG_NODE, &cli_reset_access_list_applied_all_cmd);
    install_element(CONFIG_NODE, &cli_reset_access_list_applied_cmd);

    install_element(ENABLE_NODE, &cli_show_access_list_cmd);
    install_element(ENABLE_NODE, &cli_show_access_list_type_cmd);
    install_element(ENABLE_NODE, &cli_show_access_list_type_name_cmd);
    install_element(VIEW_NODE, &cli_show_access_list_cmd);
    install_element(VIEW_NODE, &cli_show_access_list_type_cmd);
    install_element(VIEW_NODE, &cli_show_access_list_type_name_cmd);

    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_op_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_range_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_dst_port_op_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_dst_port_range_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_op_dst_port_op_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_range_dst_port_range_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_op_dst_port_range_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_range_dst_port_op_cmd);

    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_no_seq_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_op_no_seq_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_range_no_seq_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_dst_port_op_no_seq_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_dst_port_range_no_seq_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_op_dst_port_op_no_seq_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_range_dst_port_range_no_seq_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_op_dst_port_range_no_seq_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_src_port_range_dst_port_op_no_seq_cmd);

    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_comment_cmd);
    install_element(ACCESS_LIST_NODE, &cli_access_list_entry_comment_no_seq_cmd);
    install_element(ACCESS_LIST_NODE, &cli_no_access_list_entry_comment_cmd);
    install_element(ACCESS_LIST_NODE, &cli_no_access_list_entry_comment_etc_cmd);

    install_element(ACCESS_LIST_NODE, &cli_no_access_list_entry_cmd);
    install_element(ACCESS_LIST_NODE, &cli_no_access_list_entry_etc_cmd);

    install_element(ENABLE_NODE, &cli_show_access_list_applied_cmd);
    install_element(VIEW_NODE, &cli_show_access_list_applied_cmd);

    install_element(INTERFACE_NODE, &cli_apply_access_list_cmd);
    install_element(INTERFACE_NODE, &cli_no_apply_access_list_cmd);
    install_element(VLAN_NODE, &cli_apply_access_list_cmd);
    install_element(VLAN_NODE, &cli_no_apply_access_list_cmd);

    install_element(ENABLE_NODE, &cli_show_access_list_hitcounts_cmd);
    install_element(ENABLE_NODE, &cli_show_access_list_hitcounts_all_cmd);
    install_element(VIEW_NODE, &cli_show_access_list_hitcounts_cmd);
    install_element(VIEW_NODE, &cli_show_access_list_hitcounts_all_cmd);
    install_element(ENABLE_NODE, &cli_clear_access_list_hitcounts_cmd);
    install_element(ENABLE_NODE, &cli_clear_access_list_hitcounts_all_cmd);

    install_element(CONFIG_NODE, &cli_access_list_log_timer_cmd);
    install_element(ENABLE_NODE, &cli_show_access_list_log_timer_cmd);
    install_element(VIEW_NODE, &cli_show_access_list_log_timer_cmd);

    install_element(ACCESS_LIST_NODE, &config_exit_cmd);
    install_element(ACCESS_LIST_NODE, &config_quit_cmd);
    install_element(ACCESS_LIST_NODE, &config_end_cmd);
}

/**
 * Initialize context and database infrastructure for access-list
 */
void
cli_pre_init (void)
{
    install_node(&access_list_node, NULL);
    vtysh_install_default(ACCESS_LIST_NODE);

    access_list_ovsdb_init();
}

/**
 * Initialize access-list and related "show" vty commands
 */
void
cli_post_init (void)
{
    vtysh_ret_val retval;

    /* Register access-list and related commands */
    access_list_vty_init();

    /* Register show running-configuration callback */
    retval = install_show_run_config_context(
                    e_vtysh_access_list_context,
                    &show_run_access_list_callback,
                    NULL, NULL);
    if (e_vtysh_ok != retval) {
        vtysh_ovsdb_config_logmsg(VTYSH_OVSDB_CONFIG_ERR,
                    "unable to add access-list show running callback");
        assert(0);
        return;
    }

    /* Register port context show running-configuration command */
    retval = install_show_run_config_subcontext(
                    e_vtysh_interface_context,
                    e_vtysh_interface_context_access_list,
                    &show_run_access_list_subcontext_callback,
                    NULL, NULL);
    if (e_vtysh_ok != retval) {
        vtysh_ovsdb_config_logmsg(VTYSH_OVSDB_CONFIG_ERR,
                    "unable to add port access-list show running callback");
        assert(0);
        return;
    }

    /* Register vlan context show running-configuration command */
    retval = install_show_run_config_subcontext(
                    e_vtysh_vlan_context,
                    e_vtysh_vlan_context_access_list,
                    &show_run_access_list_subcontext_callback,
                    NULL, NULL);
    if (e_vtysh_ok != retval) {
        vtysh_ovsdb_config_logmsg(VTYSH_OVSDB_CONFIG_ERR,
                    "unable to add vlan access-list show running callback");
        assert(0);
        return;
    }
}
