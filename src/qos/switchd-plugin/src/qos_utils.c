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
 * Configure QOS maps & profiles for a particular bridge.
 */
void qos_configure(struct ofproto *ofproto,
                   struct ovsdb_idl *idl, unsigned int idl_seqno)
{
    qos_configure_cos_map(ofproto, idl, idl_seqno);

    qos_configure_dscp_map(ofproto, idl, idl_seqno);

    qos_configure_global_profiles(ofproto, idl, idl_seqno);
}

/**
 * bridge_reconfigure BLK_INIT_RECONFIGURE callback handler
 */
void qos_callback_reconfigure_init(struct blk_params *blk_params)
{

    /* check for global qos-trust change. */
    qos_configure_trust(blk_params->idl, blk_params->idl_seqno);

    /* do the global profiles */
    qos_configure(blk_params->ofproto, blk_params->idl, blk_params->idl_seqno);

    VLOG_DBG("%s: params@ %p idl@ %p  seqno=%d opfproto@ %p",
             __FUNCTION__,
             blk_params, blk_params->idl, blk_params->idl_seqno, blk_params->ofproto);
}

/**
 * bridge_reconfigure BLK_BR_xxx and BLK_VRF_xxx callback handler
 *
 * handles all Bridge- and VRF- post add/delete reconfigure-type callbacks
 * from bridge_reconfigure.
 */
void qos_callback_reconfigure(struct blk_params *blk_params, struct hmap *ports)
{
    struct port     *port;

    /* loop through all ports */
    HMAP_FOR_EACH(port, hmap_node, ports) {
        VLOG_DBG("%s: port %s", __FUNCTION__, port->cfg->name);

        qos_trust_send_change(blk_params->ofproto,
                              port, port->cfg,
                              blk_params->idl_seqno);

        qos_configure_port_profiles(blk_params->ofproto,
                                    port->cfg, port,
                                    blk_params->idl, blk_params->idl_seqno);
    }
}

/**
 * bridge_reconfigure BLK_BR_RECONFIGURE_PORTS callback
 *
 * handles all Bridge post add/delete reconfigure event
 */
void qos_callback_reconfigure_bridge(struct blk_params *blk_params)
{
    VLOG_DBG("%s: params@ %p idl@ %p  seqno=%d opfproto@ %p bridge@ %p",
             __FUNCTION__, blk_params, blk_params->idl, blk_params->idl_seqno,
             blk_params->ofproto, blk_params->br);

    qos_callback_reconfigure(blk_params, &blk_params->br->ports);
}

/**
 * bridge_reconfigure BLK_VRF_RECONFIGURE_PORTS callback
 *
 * handles all VRF post add/delete reconfigure event
 */
void qos_callback_reconfigure_vrf(struct blk_params *blk_params)
{
    VLOG_DBG("%s: params@ %p idl@ %p  seqno=%d opfproto@ %p vrf@ %p",
             __FUNCTION__, blk_params, blk_params->idl, blk_params->idl_seqno,
             blk_params->ofproto, blk_params->vrf);

    qos_callback_reconfigure(blk_params, &blk_params->vrf->up->ports);
}

/**
 * bridge_reconfigure BLK_BRIDGE_INIT callback handler
 */
void qos_callback_init(struct blk_params *blk_params)
{
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_port_col_qos_status);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_system_col_qos_status);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_system_col_status);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_interface_col_queue_tx_bytes);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_interface_col_queue_tx_packets);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_interface_col_queue_tx_errors);
}
