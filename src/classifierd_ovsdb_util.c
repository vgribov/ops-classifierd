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
 * @ingroup classifierd_ovsdb_if
 *
 * @file
 * Source for classifierd OVSDB access interface.
 *
 ***************************************************************************/

#include <errno.h>
#include <getopt.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <ctype.h>

#include <config.h>
#include <command-line.h>
#include <compiler.h>
#include <daemon.h>
#include <dirs.h>
#include <dynamic-string.h>
#include <fatal-signal.h>
#include <ovsdb-idl.h>
#include <poll-loop.h>
#include <unixctl.h>
#include <util.h>
#include <openvswitch/vconn.h>
#include <openvswitch/vlog.h>
#include <vswitch-idl.h>
#include <openswitch-idl.h>
#include <hash.h>
#include <shash.h>
#include <acl_daemon.h>

#include "classifierd.h"



VLOG_DEFINE_THIS_MODULE(classifierd_ovsdb_if);

/** @ingroup classifierd_ovsdb_if
 * @{ */
static struct ovsdb_idl *idl;

static unsigned int idl_seqno;

static bool system_configured = false;


void
classifierd_debug_dump_port_acl_info(struct ds *ds,
                                     const struct ovsrec_port *port_row)
{
    struct ovsrec_acl *acl;

    if(port_row)
    {
        acl = port_row->aclv4_in_applied;
        if(acl) {
            ds_put_cstr(ds, "aclv4_in: ");
            ds_put_format(ds, "name=%s",acl->name);
            ds_put_cstr(ds,"\n");
        }
    }
}


void
classifierd_debug_dump_interface_info(struct ds *ds,
                                      struct ovsrec_interface *interface)
{
    if(interface == NULL) {
        VLOG_ERR("%s: NULL interface\n",__FUNCTION__);
        return;
    }

    ds_put_cstr(ds, "interface: ");
    ds_put_format(ds, "name=%s ",interface->name);

    /* @todo this needs to be updated to print hw_ready_state once
     * updated schema is available after port state pecking order
     * changes.
     */
    if(interface->admin_state) {
        ds_put_format(ds, "admin_state=%s ", interface->admin_state);
    }
    ds_put_cstr(ds,"\n");
}


void
classifierd_debug_dump(struct ds *ds, int argc, const char *argv[])

{
    bool list_all_ports = true;
    const char *port_name;
    const struct ovsrec_port *port_row = NULL;
    unsigned int iface_idx;
    struct ovsrec_interface *interface;


    if (argc > 1) {
        list_all_ports = false;
        port_name = argv[1];
    }

    OVSREC_PORT_FOR_EACH (port_row, idl) {
        if (list_all_ports
            || (!strcmp(port_name, port_row->name))) {

            if(port_row->n_interfaces == 0) {
                VLOG_DBG("No interfaces assigned yet..\n");
                continue;
            }

            if(port_row->n_interfaces == 1) {
                VLOG_DBG("single interface assigned to port..\n");
                interface = port_row->interfaces[0];
                ds_put_format(ds, "Port: name=%s\n", port_row->name);
                classifierd_debug_dump_port_acl_info(ds,port_row);
                classifierd_debug_dump_interface_info(ds, interface);
                ds_put_format(ds,"\n");
            } else {   /* LAG */
                VLOG_DBG("LAG interfaces ..\n");
                ds_put_format(ds, "LAG name=%s\n", port_row->name);
                classifierd_debug_dump_port_acl_info(ds,port_row);
                for(iface_idx = 0;
                        iface_idx < port_row->n_interfaces;iface_idx++) {
                    interface = port_row->interfaces[iface_idx];
                    classifierd_debug_dump_interface_info(ds, interface);
                } /* end for loop */
            } /* LAG */

            /* line between port row entries */
            ds_put_cstr(ds,"\n");
        } /* if list_all_ports or matching name */
    } /* for each ROW */

} /* classifierd_debug_dump */



/* Create a connection to the OVSDB at db_path and create a dB cache
 * for this daemon. */
void
classifierd_ovsdb_init(const char *db_path)
{
    VLOG_DBG("%s: db_path = %s\n",__FUNCTION__,db_path);
    /* Initialize IDL through a new connection to the dB. */
    idl = ovsdb_idl_create(db_path, &ovsrec_idl_class, false, true);
    idl_seqno = ovsdb_idl_get_seqno(idl);
    ovsdb_idl_set_lock(idl, "ops_classifierd");

    /* Reject writes to columns which are not marked write-only using
     * ovsdb_idl_omit_alert().
     */
    ovsdb_idl_verify_write_only(idl);

    /* Choose some OVSDB tables and columns to cache. */
    ovsdb_idl_add_table(idl, &ovsrec_table_system);
    ovsdb_idl_add_table(idl, &ovsrec_table_subsystem);

    /* Monitor the following columns, marking them read-only. */
    ovsdb_idl_add_column(idl, &ovsrec_system_col_cur_cfg);

    /* Initialize ovsdb interfaces for ACL */
    acl_ovsdb_init(idl);

} /* classifierd_ovsdb_init */

void
classifierd_ovsdb_exit(void)
{
    ovsdb_idl_destroy(idl);
} /* classifierd_ovsdb_exit */



static int
classifierd_reconfigure(void)
{
    int rc = 0;
    unsigned int new_idl_seqno = 0;
    const struct ovsrec_port *port_row = NULL;
    const struct ovsrec_acl  *acl_row = NULL;

    new_idl_seqno = ovsdb_idl_get_seqno(idl);
    if (new_idl_seqno == idl_seqno) {
        VLOG_DBG("%s: no change in the db\n",__FUNCTION__);
        /* There was no change in the dB. */
        return 0;
    }

    /* get first port row from IDL cache */
    port_row = ovsrec_port_first(idl);
    if(port_row) {
        /* if port table is not changed then do not go ahead */
        if ( (!OVSREC_IDL_ANY_TABLE_ROWS_MODIFIED(port_row, idl_seqno)) &&
                (!OVSREC_IDL_ANY_TABLE_ROWS_INSERTED(port_row, idl_seqno)) &&
                (!OVSREC_IDL_ANY_TABLE_ROWS_DELETED(port_row, idl_seqno)) ) {
            VLOG_DBG("%s: not a port row change\n",__FUNCTION__);
        } else {
            /* Perform ports reconfigure event for ACL */
            rc = acl_ports_reconfigure(idl,idl_seqno);
        }
    }



    /* get first acl row from IDL cache */
    acl_row = ovsrec_acl_first(idl);
    if(acl_row) {
        /* if port table is not changed then do not go ahead */
        if ( (!OVSREC_IDL_ANY_TABLE_ROWS_MODIFIED(acl_row, idl_seqno)) &&
                (!OVSREC_IDL_ANY_TABLE_ROWS_INSERTED(acl_row, idl_seqno)) &&
                (!OVSREC_IDL_ANY_TABLE_ROWS_DELETED(acl_row, idl_seqno)) ) {
            VLOG_DBG("%s: not a acl row change\n",__FUNCTION__);
        } else {
            /* Perform acl_list_reconfigure event for ACL */
            rc = acl_reconfigure(idl,idl_seqno);
        }
    }


    /* Update idl_seqno after handling all OVSDB updates. */
    idl_seqno = new_idl_seqno;


    return rc;
} /* classifierd_reconfigure */

static inline bool
classifierd_system_is_configured(void)
{
    const struct ovsrec_system *sysrow = NULL;

    if (system_configured) {
        return true;
    }

    sysrow = ovsrec_system_first(idl);
    if (sysrow && sysrow->cur_cfg > INT64_C(0)) {
        VLOG_DBG("System now configured (cur_cfg=%" PRId64 ").",
                 sysrow->cur_cfg);
        return (system_configured = true);
    }

    return false;
} /* classifierd_system_is_configured */

void
classifierd_run(void)
{
    struct ovsdb_idl_txn *txn;

    /* Process a batch of messages from OVSDB. */
    ovsdb_idl_run(idl);

    if (ovsdb_idl_is_lock_contended(idl)) {
        static struct vlog_rate_limit rl = VLOG_RATE_LIMIT_INIT(1, 1);

        VLOG_ERR_RL(&rl, "Another classifierd process is running, "
                    "disabling this process until it goes away");
        return;
    } else if (!ovsdb_idl_has_lock(idl)) {
        return;
    }

    /* Nothing to do until system has been configured, i.e. cur_cfg > 0. */
    if (!classifierd_system_is_configured()) {
        return;
    }

    /* Update the local configuration and push any changes to the dB. */
    txn = ovsdb_idl_txn_create(idl);
    if (classifierd_reconfigure()) {
        VLOG_DBG("%s: Committing changes\n",__FUNCTION__);
        /* Some OVSDB write needs to happen. */
        ovsdb_idl_txn_commit_block(txn);
    }
    ovsdb_idl_txn_destroy(txn);

    return;
} /* classifierd_run */

void
classifierd_wait(void)
{
    ovsdb_idl_wait(idl);
} /* classifierd_wait */

/** @} end of group classifierd_ovsdb_if */
