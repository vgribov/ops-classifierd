/*
 * (c) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
/************************************************************************//**
 * @ingroup acl_daemon_init
 *
 * @file
 * Source for ACL feature initialization required in classifier daemon
 *
 ***************************************************************************/
#include <openvswitch/vlog.h>
#include <vswitch-idl.h>
#include "acl_db_util.h"

VLOG_DEFINE_THIS_MODULE(acl_daemon_init);

/* Initializes OVSDB tables and columns to cache for ACL feature */
void
acl_ovsdb_init(struct ovsdb_idl *idl)
{
    VLOG_DBG("Initializing IDL cache for ACL feature\n");
    /* Choose some OVSDB tables and columns to cache. */
    ovsdb_idl_add_table(idl, &ovsrec_table_interface);
    ovsdb_idl_add_table(idl, &ovsrec_table_port);
    ovsdb_idl_add_table(idl, &ovsrec_table_acl);

    /* Monitor the following columns, marking them read-only. */
    ovsdb_idl_add_column(idl, &ovsrec_port_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_aclv4_in_status);
    ovsdb_idl_add_column(idl, &ovsrec_port_col_aclv4_out_status);
    /* @todo: we may need a column to monitor per interface ACL
     * applied status, especially for LAGs
     */
    ovsdb_idl_add_column(idl, &ovsrec_port_col_interfaces);
    ovsdb_idl_add_column(idl, &ovsrec_acl_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_acl_col_cfg_aces);

    /* Mark the following columns write-only. */
    ovsdb_idl_add_column(idl, &ovsrec_acl_col_in_progress_aces);
    ovsdb_idl_add_column(idl, &ovsrec_acl_col_in_progress_version);
    ovsdb_idl_add_column(idl, &ovsrec_acl_col_status);
    ovsdb_idl_add_column(idl, &ovsrec_acl_col_cfg_version);
    ovsdb_idl_add_column(idl, &ovsrec_interface_col_hw_status);

    /* Omit alerts for the columns we are writing. */
    ovsdb_idl_omit_alert(idl, &ovsrec_acl_col_in_progress_aces);
    ovsdb_idl_omit_alert(idl, &ovsrec_acl_col_in_progress_version);
    ovsdb_idl_omit_alert(idl, &ovsrec_interface_col_hw_status);

    acl_db_util_init();
} /* acl_ovsdb_init */


/** @} end of group acl_daemon_init */
