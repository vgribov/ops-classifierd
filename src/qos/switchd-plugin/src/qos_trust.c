/****************************************************************************
 * (c) Copyright 2016 Hewlett Packard Enterprise Development LP
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
 * Handle QoS trust callbacks from bridge_reconfigure
 ***************************************************************************/

#include <config.h>

#include "qos_trust.h"

#include "openvswitch/vlog.h"
#include "qos-asic-provider.h"
#include "qos_plugin.h"
#include "qos_utils.h"


VLOG_DEFINE_THIS_MODULE(qos_trust);

/* Global QOS trust state. */
static enum qos_trust global_qos_trust = QOS_TRUST_NONE;
static bool global_trust_changed = false;


/**
 * Configure global QOS trust setting.
 *   Keeps track of global QOS trust value.
 *
 *   Called from bridge reconfigure at the start of its processing.
 *
 * @param idl       - pointer to IDL
 * @param idl_seqno - current transaction sequence number
 */
void
qos_configure_trust(struct ovsdb_idl *idl, unsigned int idl_seqno)
{
    enum qos_trust qos_trust;
    const struct ovsrec_system *ovs_row = NULL;


    /* Clear global trust changed indicator. */
    global_trust_changed = false;

    /* nothing to do if System row is unchanged. */
    ovs_row = ovsrec_system_first(idl);
    if (OVSREC_IDL_IS_ROW_MODIFIED(ovs_row, idl_seqno) &&
        OVSREC_IDL_IS_COLUMN_MODIFIED(ovsrec_system_col_qos_config, idl_seqno))
    {
        qos_trust = get_qos_trust_value(&ovs_row->qos_config);

        /* only change saved QoS trust if default is valid */
        if (qos_trust != QOS_TRUST_MAX) {
            if (qos_trust != global_qos_trust)
            {
                /* Indicate trust change to rest of the world. */
                global_trust_changed = true;
                global_qos_trust = qos_trust;
            }
        }
    }

    return;
}

/**
 * programs qos trust for a port
 *      called from bridge reconfigure after all ports in a bridge or VRF
 *      have been configured.
 *
 * @param ofproto   - pointer to bridge or VRF descriptor
 * @param aux       - opaque pointer passed through to provider layer,
 *                    is a bridge_reconfigure "struct port" pointer
 * @param port_cfg  - Port row in IDL
 * @param idl_seqno - current transaction sequence number
 */
void
qos_trust_send_change(struct ofproto *ofproto,
                      void *aux,
                      const struct ovsrec_port *port_cfg,
                      unsigned int idl_seqno)
{
    bool send_trust_change = false;

    if (global_trust_changed) {
        if (smap_get(&port_cfg->qos_config, "qos_trust") == NULL) {
            send_trust_change = true;
        }
    }
    if (send_trust_change ||
        OVSREC_IDL_IS_ROW_MODIFIED(port_cfg, idl_seqno)) {

        VLOG_DBG("%s: port %s TRUST change", __FUNCTION__, port_cfg->name);
        ofproto_set_port_qos_cfg(ofproto,
                                 aux,
                                 global_qos_trust,
                                 &port_cfg->qos_config,
                                 &port_cfg->other_config);
    }
}
