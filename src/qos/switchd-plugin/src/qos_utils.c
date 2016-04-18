/****************************************************************************
 * (c) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 *
 ***************************************************************************/
#include <config.h>

#include "qos_utils.h"

#include "qos_map.h"
#include "qos_profile.h"
#include "qos_trust.h"

#include "bridge.h"
#include "openswitch-idl.h"
#include "ovsdb-idl.h"
#include "reconfigure-blocks.h"
#include "smap.h"
#include "vswitch-idl.h"
#include "vrf.h"
#include "openvswitch/vlog.h"

VLOG_DEFINE_THIS_MODULE(qos_utils);


/**
 * Configure all global QOS parameters:
 *  COS & DSCP maps
 *  queue- & schedule-profiles
 *
 *  NOTE: trust not programmed globally, only per-port
 */
static
void qos_configure_globals(struct ofproto *ofproto,
                           struct ovsdb_idl *idl, unsigned int idl_seqno)
{
    qos_configure_global_cos_map(ofproto, idl, idl_seqno);

    qos_configure_global_dscp_map(ofproto, idl, idl_seqno);

    qos_configure_global_profiles(ofproto, idl, idl_seqno);
}

/**
 * check all ports in a bridge or VRF, configuring trust and/or profiles
 * as needed.
 */
static void
qos_set_globals_per_port_if_needed(struct blk_params *blk_params,
                                   struct hmap *ports)
{
    struct port     *port;

    /* loop through all ports */
    HMAP_FOR_EACH(port, hmap_node, ports) {
#ifdef DEBUG
        VLOG_DBG("%s: port %s", __FUNCTION__, port->cfg->name);
#endif

        /* Set QOS trust if global changed (and no override). */
        qos_trust_send_change(blk_params->ofproto,
                              port, port->cfg,
                              blk_params->idl_seqno);

        /* Set queue- and/or schedule-profile if global changed
         * (and no override). */
        qos_configure_port_profiles(blk_params->ofproto,
                                    port, port->cfg,
                                    blk_params->idl, blk_params->idl_seqno,
                                    false);
    }
}

/**
 * bridge_reconfigure BLK_INIT_RECONFIGURE callback handler
 *
 * called at the start of bridge_reconfigure, before anything has been
 * added, deleted or updated.
 *
 * First time only -- set global trust & profiles, so they exist prior
 * to any port being configured.
 */
void qos_callback_init_reconfigure(struct blk_params *blk_params)
{

    /* Check for global qos-trust change. */
    qos_check_if_global_trust_changed(blk_params->idl, blk_params->idl_seqno);

    /* Configure any global QOS parameters. */
    qos_configure_globals(blk_params->ofproto,
                          blk_params->idl, blk_params->idl_seqno);

#ifdef DEBUG
    VLOG_DBG("%s: params@ %p idl@ %p  seqno=%d ofproto@ %p",
             __FUNCTION__, blk_params,
             blk_params->idl, blk_params->idl_seqno, blk_params->ofproto);
#endif
}

/**
 * bridge_reconfigure BLK_BR_PORT_UPDATE callback
 *
 * called after port_configure on a single bridge port
 */
void
qos_callback_bridge_port_update(struct blk_params *blk_params)
{
    VLOG_DBG("%s: params@ %p idl@ %p  seqno=%d ofproto@ %p br@ %p port@ %p (%s)",
             __FUNCTION__, blk_params, blk_params->idl, blk_params->idl_seqno,
             blk_params->ofproto, blk_params->br,
             blk_params->port, blk_params->port->name);
    qos_trust_send_change(blk_params->ofproto,
                          blk_params->port,
                          blk_params->port->cfg,
                          blk_params->idl_seqno);

    qos_configure_port_profiles(blk_params->ofproto,
                                blk_params->port,
                                blk_params->port->cfg,
                                blk_params->idl, blk_params->idl_seqno,
                                true);
}

/**
 * bridge_reconfigure BLK_VRF_PORT_UPDATE callback
 *
 * called after port_configure on a single VRF port
 */
void
qos_callback_vrf_port_update(struct blk_params *blk_params)
{
    VLOG_DBG("%s: params@ %p idl@ %p  seqno=%d ofproto@ %p vrf@ %p port@ %p (%s)",
             __FUNCTION__, blk_params, blk_params->idl, blk_params->idl_seqno,
             blk_params->ofproto, blk_params->vrf,
             blk_params->port, blk_params->port->name);
    qos_trust_send_change(blk_params->ofproto,
                          blk_params->port,
                          blk_params->port->cfg,
                          blk_params->idl_seqno);

    qos_configure_port_profiles(blk_params->ofproto,
                                blk_params->port,
                                blk_params->port->cfg,
                                blk_params->idl, blk_params->idl_seqno,
                                true);
}

/**
 * bridge_reconfigure BLK_BR_FEATURE_RECONFIG callback
 *
 * called after everything for a bridge has been add/deleted/updated
 */
void
qos_callback_bridge_feature_reconfig(struct blk_params *blk_params)
{
    /* Do global QoS changes only after all ports on the bridge
     * have been reconfigured.  Only change those ports that don't have
     * either:
     *  1. a locally-configured override configured by the port-update
     *      callback, or
     *  2. had the global default configured in the port-update callback.
     *      In this case, the Port row's qos_status will show that the
     *      global-default has already been configured.
     */

#ifdef DEBUG
    VLOG_DBG("%s: params@ %p idl@ %p  seqno=%d ofproto@ %p vrf@ %p ports@ %p",
             __FUNCTION__, blk_params, blk_params->idl, blk_params->idl_seqno,
             blk_params->ofproto, blk_params->br, &blk_params->br->ports);
#endif

    qos_set_globals_per_port_if_needed(blk_params, &blk_params->br->ports);
}

/**
 * bridge_reconfigure BLK_RECONFIGURE_NEIGHBORS callback
 *
 * called after everything for a VRF has been add/deleted/updated
 */
void
qos_callback_reconfigure_neighbors(struct blk_params *blk_params)
{
    /* Do global QoS changes only after all ports on the bridge
     * have been reconfigured.  Only change those ports that don't have
     * either:
     *  1. a locally-configured override configured by the port-update
     *      callback, or
     *  2. had the global default configured in the port-update callback.
     *      In this case, the Port row's qos_status will show that the
     *      global-default has already been configured.
     */

#ifdef DEBUG
    VLOG_DBG("%s: params@ %p idl@ %p  seqno=%d ofproto@ %p vrf@ %p ports@ %p",
             __FUNCTION__, blk_params, blk_params->idl, blk_params->idl_seqno,
             blk_params->ofproto, blk_params->vrf, &blk_params->vrf->up->ports);
#endif
    qos_set_globals_per_port_if_needed(blk_params, &blk_params->vrf->up->ports);
}

/**
 * bridge_reconfigure BLK_BRIDGE_INIT callback handler
 */
void qos_callback_bridge_init(struct blk_params *blk_params)
{
    /* Enable writes into various QoS columns. */
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_port_col_qos_status);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_system_col_qos_status);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_system_col_status);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_interface_col_queue_tx_bytes);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_interface_col_queue_tx_packets);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_interface_col_queue_tx_errors);
}
