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
 * @ingroup acl_daemon_ports
 *
 * @file
 * Source for port related processing required by ACL feature in classifier
 * daemon.
 *
 ***************************************************************************/
#include <openvswitch/vlog.h>
#include <assert.h>
#include <vswitch-idl.h>
#include <acl_daemon.h>
#include "ops-cls-asic-plugin.h"
#include "ops_cls_status_msgs.h"

VLOG_DEFINE_THIS_MODULE(acl_daemon_ports);

/* This function determines if hw_ready_state can be set for the interface
 * associated with the port_row.
 */
static bool
acl_ports_is_hw_ready(const struct ovsrec_port *port_row)
{
    int hw_ready_state = false;
    const char *status = NULL;

    ovs_assert(port_row);

    /* set hw_ready_state to true for following conditions,
     * - If ACL is NOT configured for this port
     * - If ACL is configured and applied status is success
     */
    /* @todo: need to handle multiple acls to the port
     */
    if(!port_row->aclv4_in_applied) {
        VLOG_DBG("port %s: ACL not configured \n", port_row->name);
        /* set hw_ready_state on the interface */
        hw_ready_state = true;
    } else {
        /* ACL is configured on this port so verify if
         * ACL is applied successfully in hw or not
         */
        status =
            smap_get((const struct smap *)&port_row->aclv4_in_status,
                     OPS_CLS_STATUS_CODE_STR);
        VLOG_DBG("port %s: ACL %s configured, apply status %s \n",
                  port_row->name, port_row->aclv4_in_applied->name,
                  status);
        if(strtoul(status,NULL,10) == OPS_CLS_STATUS_SUCCESS) {
            /* set hw_ready_state  */
            hw_ready_state = true;
        }
    } /* end if !aclv4_in_applied */

    return hw_ready_state;
}

/**
 * Processes single port to determine if hw_ready_state
 * for the interface associated with this port to be set to true or false
 */
static int
acl_single_port_reconfigure(const struct ovsrec_port *port_row)
{
    int  rc = 0;
    bool hw_ready_state = false;

    ovs_assert(port_row);
    ovs_assert(port_row->n_interfaces == 1);

    if(port_row->interfaces[0] == NULL) {
        VLOG_WARN("Port %s: linked to NULL interface.\n",port_row->name);
        return rc;
    }

    VLOG_DBG("Port %s:  linked to interface %s\n",
              port_row->name,port_row->interfaces[0]->name);

    /* @todo: update following block once hw_ready_state is
     * available.
     */
#if HW_READY_STATE
    if(port_row->interfaces[0]->hw_ready_state == false) {
#else
    if(1) {
#endif
        hw_ready_state = acl_ports_is_hw_ready(port_row);

    }

    if(hw_ready_state) {
    /* @todo: update following block once hw_ready_state is
     * available.
     */
#if HW_READY_STATE
        /* set interface hw_ready_state in db */
        ovsrec_interface_set_hw_ready_state(
                                      port_row->interfaces[0],
                                      hw_ready_state);
#endif
        /* increment rc to indicate db update */
        rc++;
    }

    return rc;
}

/**
 * Processes LAG port row to determine if hw_ready_state
 * for each interface of the LAG needs to be set to true or false
 */
static int
acl_lag_port_reconfigure(const struct ovsrec_port *port_row)
{
    int rc = 0;
#if HW_READY_STATE
    bool hw_ready_state;
    unsigned int intf_idx;
#endif

    ovs_assert(port_row);
    ovs_assert(port_row->n_interfaces > 1);

    VLOG_DBG("%s: lag port name: %s\n",__FUNCTION__,port_row->name);

    if(port_row->aclv4_in_applied) {
        VLOG_ERR("ACLs are not supported on LAG port,"
                 "port name:  %s, ACL name: %s\n",
                  port_row->name, port_row->aclv4_in_applied->name);
        return rc;
    }

#if HW_READY_STATE
    hw_ready_state = true;
    for(intf_idx = 0; intf_idx < port_row->n_interfaces; intf_idx++) {
        /* @todo: update following block once hw_ready_state is
         * available.
         */

        if(port_row->interfaces[intf_idx]->hw_ready_state == false) {
            VLOG_DBG("port %s: setting hw_ready_state to true on "
                     "interface %s\n",port_row->name,
                      port_row->interfaces[interface_idx]->name);


            ovsrec_interface_set_hw_ready_state(
                                            port_row->interfaces[intf_idx],
                                            hw_ready_state);

            /* increment rc to indicate db update */
            rc++;

        }
    } /* end for loop */
#endif
    return rc;
}

/**
 * Process port table changes to determine if interface hw_ready_state
 * needs to be set to true or false for each port row entry
 */
int
acl_ports_reconfigure(struct ovsdb_idl *idl, unsigned int idl_seqno)
{
    int rc = 0;
    const struct ovsrec_port *port_row = NULL;

    VLOG_DBG("%s: idl_seqno %d\n",__FUNCTION__,idl_seqno);
    ovs_assert(idl);

    OVSREC_PORT_FOR_EACH (port_row, idl) {
        if(port_row->n_interfaces == 0) {
            VLOG_DBG("Port %s: No interfaces assigned yet.\n",port_row->name);
            continue;
        }

        if(port_row->n_interfaces == 1) {
            rc = acl_single_port_reconfigure(port_row);
        } else {   /* LAG */
            rc = acl_lag_port_reconfigure(port_row);
        } /* end if n_interfaces */

    } /* for each port ROW */

    VLOG_DBG("%s: number of updates back to db: %d",__FUNCTION__,rc);

    return rc;
} /* acl_ports_reconfigure */


/** @} end of group acl_daemon_ports */
