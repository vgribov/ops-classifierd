/**************************************************************************//**
 * @file acl_plugin.c
 *
 * (c) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 *****************************************************************************/
#include "openvswitch/vlog.h"
#include "plugin-extensions.h"
#include "acl.h"
#include "acl_log.h"
#include "acl_plugin.h"
#include "acl_port.h"
#include "vswitch-idl.h"
#include "ops_cls_status_msgs.h"
#include "stats-blocks.h"

VLOG_DEFINE_THIS_MODULE(acl_switchd_plugin);

/*************************************************************************//**
 * ACL plugin for switchd. This file contains plugin functions that register
 * callbacks into reconfigure blocks.
 ****************************************************************************/
int init (int phase_id)
{
    /* Register callbacks */
    VLOG_INFO("[%s] - Registering BLK_BRIDGE_INIT", ACL_PLUGIN_NAME);
    register_reconfigure_callback(&acl_callback_bridge_init, BLK_BRIDGE_INIT,
                                  NO_PRIORITY);
    VLOG_INFO("[%s] - Registering BLK_INIT_RECONFIGURE", ACL_PLUGIN_NAME);
    register_reconfigure_callback(&acl_reconfigure_init, BLK_INIT_RECONFIGURE,
                                  NO_PRIORITY);
    VLOG_INFO("[%s] - Registering BLK_INIT_RECONFIGURE to handle LAG shut", ACL_PLUGIN_NAME);
    register_reconfigure_callback(&acl_port_lag_ifaces_shutdown, BLK_INIT_RECONFIGURE,
                                  NO_PRIORITY);
    VLOG_INFO("[%s] - Registering BLK_BR_DELETE_PORTS", ACL_PLUGIN_NAME);
    register_reconfigure_callback(&acl_callback_port_delete,
                                  BLK_BR_DELETE_PORTS, NO_PRIORITY);
    VLOG_INFO("[%s] - Registering BLK_VRF_DELETE_PORTS", ACL_PLUGIN_NAME);
    register_reconfigure_callback(&acl_callback_port_delete,
                                  BLK_VRF_DELETE_PORTS, NO_PRIORITY);
    VLOG_INFO("[%s] - Registering BLK_BR_RECONFIGURE_PORTS", ACL_PLUGIN_NAME);
    register_reconfigure_callback(&acl_callback_port_reconfigure,
                                  BLK_BR_RECONFIGURE_PORTS, NO_PRIORITY);
    VLOG_INFO("[%s] - Registering BLK_VRF_RECONFIGURE_PORTS", ACL_PLUGIN_NAME);
    register_reconfigure_callback(&acl_callback_port_reconfigure,
                                  BLK_VRF_RECONFIGURE_PORTS, NO_PRIORITY);
    VLOG_INFO("[%s] - Registering BLK_BR_PORT_UPDATE", ACL_PLUGIN_NAME);
    register_reconfigure_callback(&acl_callback_port_update,
                                  BLK_BR_PORT_UPDATE, NO_PRIORITY);
    VLOG_INFO("[%s] - Registering BLK_VRF_PORT_UPDATE", ACL_PLUGIN_NAME);
    register_reconfigure_callback(&acl_callback_port_update,
                                  BLK_VRF_PORT_UPDATE, NO_PRIORITY);
    VLOG_INFO("[%s] - Registering STATS_PER_BRIDGE_PORT", ACL_PLUGIN_NAME);
    register_stats_callback(&acl_callback_port_stats_get,
                            STATS_PER_BRIDGE_PORT, NO_PRIORITY);
    VLOG_INFO("[%s] - Registering STATS_PER_VRF_PORT", ACL_PLUGIN_NAME);
    register_stats_callback(&acl_callback_port_stats_get,
                            STATS_PER_VRF_PORT, NO_PRIORITY);

    VLOG_INFO("[%s] - Registering BLK_RUN_COMPLETE", ACL_PLUGIN_NAME);
    register_run_callback(&acl_log_run, BLK_RUN_COMPLETE, NO_PRIORITY);

    VLOG_INFO("[%s] - Registering BLK_WAIT_COMPLETE", ACL_PLUGIN_NAME);
    register_run_callback(&acl_log_wait, BLK_WAIT_COMPLETE, NO_PRIORITY);

    /* initialize ACL logging code */
    acl_log_init();

    /* Initialize debugging commands for ACL */
    acl_debug_init();

    return 0;
}

int run(void)
{
    return 0;
}

int wait(void)
{
    return 0;
}

int destroy(void)
{
    unregister_plugin_extension("ACL_PLUGIN");
    VLOG_INFO("[%s] was destroyed", ACL_PLUGIN_NAME);
    return 0;
}

void
acl_callback_bridge_init(struct blk_params *blk_params)
{
    /* Add omit alerts for ACL and port tables */
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_port_col_aclv4_in_applied);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_port_col_aclv4_in_status);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_port_col_aclv4_in_statistics);
    ovsdb_idl_omit_alert(blk_params->idl,
                         &ovsrec_port_col_aclv4_in_statistics_clear_performed);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_port_col_aclv4_out_applied);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_port_col_aclv4_out_status);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_port_col_aclv4_out_statistics);
    ovsdb_idl_omit_alert(blk_params->idl,
                         &ovsrec_port_col_aclv4_out_statistics_clear_performed);
    ovsdb_idl_omit(blk_params->idl, &ovsrec_acl_col_other_config);
    ovsdb_idl_omit(blk_params->idl, &ovsrec_acl_col_external_ids);
    ovsdb_idl_omit(blk_params->idl, &ovsrec_acl_col_cfg_aces);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_acl_col_cur_aces);
    ovsdb_idl_omit_alert(blk_params->idl, &ovsrec_acl_col_status);


    /* Initialize ACL DB Util array */
    acl_db_util_init();
    /* Populate the global cls status table for cls status messages
     * @todo Ideally this should be populated from the classifier
     * plugin init callback instead of acl plugin callback, but we
     * don't have such callback as of now. please move this call to
     * classifier plugin init callback once that infra is available
     */
     ops_cls_status_msgs_populate();

    /* Find and initialize the asic plugin */
    acl_ofproto_init();
}

void
acl_debug_init() {
    /* Debug acl_port */
    acl_port_debug_init();
}
