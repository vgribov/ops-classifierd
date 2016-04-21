/****************************************************************************
 * (c) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 *    Licensed under the Apache License, Version 2.0 (the "License"); you may
 *    not use this file except in compliance with the License. You may obtain
 *    a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 *    Unless required by applicable law or agreed to in writing, software
 *    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *    License for the specific language governing permissions and limitations
 *    under the License.
 *
 * switchd plugin framework interactions
 ***************************************************************************/

#include <config.h>

#include "qos_plugin.h"

#include <errno.h>
#include <string.h>

#include "ofproto/ofproto-provider.h"
#include "openvswitch/vlog.h"
#include "plugin-extensions.h"
#include "qos-asic-provider.h"
#include "qos_statistics.h"
#include "qos_utils.h"
#include "reconfigure-blocks.h"
#include "shash.h"
#include "smap.h"
#include "stats-blocks.h"
#include "vswitch-idl.h"
#ifdef QOS_DEBUG
#include "bridge.h"
#endif

VLOG_DEFINE_THIS_MODULE(qos_plugin);

static struct plugin_extension_interface *extension = NULL;
static struct qos_asic_plugin_interface *plugin = NULL;


/* converts enum in qos_trust SMAP into enum value */
enum qos_trust get_qos_trust_value(const struct smap *cfg) {
    enum qos_trust rv = QOS_TRUST_MAX;
    const char *qos_trust_name = smap_get(cfg, "qos_trust");

    if (qos_trust_name == NULL) {
        return rv;
    }

    if (strcmp(qos_trust_name, "dscp") == 0) {
        rv = QOS_TRUST_DSCP;
    } else if (strcmp(qos_trust_name, "cos") == 0) {
        rv = QOS_TRUST_COS;
    } else if (strcmp(qos_trust_name, "none") == 0) {
        rv = QOS_TRUST_NONE;
    }

    return rv;
}

/* sets qos (and any other qos parameter) for a port in an ofproto.
   aux is pointer to struct port */
int ofproto_set_port_qos_cfg(struct ofproto *ofproto, void *aux,
                             const enum qos_trust global_qos_trust,
                             const struct smap *qos_config,
                             const struct smap *other_config) {
    struct qos_port_settings settings = {0};
    const char *cos_override_str;
    const char *dscp_override_str;
    int rv = 0;

    if (plugin == NULL) {
        return EOPNOTSUPP;
    }
    if (plugin->set_port_qos_cfg == NULL) {
        return EOPNOTSUPP;
    }

    VLOG_DBG("%s: aux @ %p, qos_trust %d, qos_cfg smap@ %p",
             __FUNCTION__, aux, global_qos_trust, qos_config);

    /* Set port qos trust.  If port has no setting, use global default */
    settings.qos_trust = get_qos_trust_value(qos_config);
    if (settings.qos_trust == QOS_TRUST_MAX) {
       settings.qos_trust = global_qos_trust;
    }
    if (settings.qos_trust == QOS_TRUST_MAX) {
        return EOPNOTSUPP;
    }

    /* check for COS or DSCP overrides */
    cos_override_str = smap_get(qos_config, QOS_COS_OVERRIDE_KEY);
    if (cos_override_str != NULL) {
        settings.cos_override_enable = true;
        settings.cos_override_value = strtoul(cos_override_str, NULL, 0);
    }
    dscp_override_str = smap_get(qos_config, QOS_DSCP_OVERRIDE_KEY);
    if (dscp_override_str != NULL) {
        settings.dscp_override_enable = true;
        settings.dscp_override_value = strtoul(dscp_override_str, NULL, 0);
    }

    settings.other_config = other_config;
    VLOG_DBG("... qos trust %d, override cos:%c%d dscp:%c%d, other_cfg smap@ %p",
             settings.qos_trust,
             (settings.cos_override_enable) ? 'T' : 'F',
             settings.cos_override_value,
             (settings.dscp_override_enable) ? 'T' : 'F',
             settings.dscp_override_value,
             other_config);

    rv = plugin->set_port_qos_cfg(ofproto, aux, &settings);

    return rv;
}

/* sets COS map in an ofproto.  aux currently unused */
int ofproto_set_cos_map(struct ofproto *ofproto, void *aux,
                        const struct cos_map_settings *settings) {
    int rv = 0;

    if (plugin == NULL) {
        return EOPNOTSUPP;
    }
    if (plugin->set_cos_map == NULL) {
        return EOPNOTSUPP;
    }

    VLOG_DBG("%s: aux @ %p, settings@ %p (%d entry(s))",
             __FUNCTION__, aux, settings, settings->n_entries);

    rv = plugin->set_cos_map(ofproto, aux, settings);

    return rv;
}

/* sets DSCP map in an ofproto.  aux currently unused */
int ofproto_set_dscp_map(struct ofproto *ofproto, void *aux,
                         const struct dscp_map_settings *settings) {
    int rv = 0;

    if (plugin == NULL) {
        return EOPNOTSUPP;
    }
    if (plugin->set_dscp_map == NULL) {
        return EOPNOTSUPP;
    }

    VLOG_DBG("%s: aux @ %p, settings@ %p (%d entry(s)",
             __FUNCTION__, aux, settings, settings->n_entries);

    rv = plugin->set_dscp_map(ofproto, aux, settings);

    return rv;
}

/* Set queue- and schedule- profiles globally or for a single Port. */
int ofproto_apply_qos_profile(struct ofproto *ofproto,
                              void *aux,
                              const struct schedule_profile_settings *s_settings,
                              const struct queue_profile_settings *q_settings) {
    int rv = 0;

#ifndef QOS_DEBUG
    VLOG_DBG("%s aux=%p settings=%p,%p", __FUNCTION__, aux,
             s_settings, q_settings);
#else
    VLOG_DBG("%s aux=%p (%s) settings=%p,%p", __FUNCTION__, aux,
             (aux) ? ((struct port *)aux)->name : "global",
             s_settings, q_settings);
#endif

    if (plugin == NULL) {
        return EOPNOTSUPP;
    }
    if (plugin->apply_qos_profile == NULL) {
        return EOPNOTSUPP;
    }

    rv = plugin->apply_qos_profile(ofproto,
                                   aux,
                                   s_settings,
                                   q_settings);

    VLOG_DBG("%s rv=%d", __FUNCTION__, rv);

    return rv;
}

/* Initialization (called once) - register for callbacks. */
int init(int phase_id)
{
    int ret = 0;

    /**
     * Initialize the QOS API -- it will find its ASIC provider APIs.
     *
     * Must run after ASIC provider plugin initializes
     * Plugin load order is configured in plugins.yaml file
     * in ops-hw-config platform-dependent directory.
     */
    ret = find_plugin_extension(QOS_ASIC_PLUGIN_INTERFACE_NAME,
                                QOS_ASIC_PLUGIN_INTERFACE_MAJOR,
                                QOS_ASIC_PLUGIN_INTERFACE_MINOR,
                                &extension);
    if (ret == 0) {
        VLOG_INFO("Found [%s] plugin extension...", QOS_PLUGIN_NAME);
        plugin = (struct qos_asic_plugin_interface *)extension->plugin_interface;
    }
    else {
        VLOG_WARN("%s (v%d.%d) not found", QOS_ASIC_PLUGIN_INTERFACE_NAME,
                  QOS_ASIC_PLUGIN_INTERFACE_MAJOR,
                  QOS_ASIC_PLUGIN_INTERFACE_MINOR);
    }

    VLOG_DBG("[%s] Registering BLK_BRIDGE_INIT", QOS_PLUGIN_NAME);
    register_reconfigure_callback(&qos_callback_bridge_init,
                                  BLK_BRIDGE_INIT, QOS_PRIORITY);

    VLOG_DBG("[%s] Registering in BLK_INIT_RECONFIGURE", QOS_PLUGIN_NAME);
    register_reconfigure_callback(&qos_callback_init_reconfigure,
                                  BLK_INIT_RECONFIGURE, QOS_PRIORITY);

    VLOG_DBG("[%s] Registering in BLK_BR_PORT_UPDATE", QOS_PLUGIN_NAME);
    register_reconfigure_callback(&qos_callback_bridge_port_update,
                                  BLK_BR_PORT_UPDATE, QOS_PRIORITY);

    VLOG_DBG("[%s] Registering in BLK_VRF_PORT_UPDATE", QOS_PLUGIN_NAME);
    register_reconfigure_callback(&qos_callback_vrf_port_update,
                                  BLK_VRF_PORT_UPDATE, QOS_PRIORITY);

    VLOG_DBG("[%s] Registering in BLK_BR_FEATURE_RECONFIG", QOS_PLUGIN_NAME);
    register_reconfigure_callback(&qos_callback_bridge_feature_reconfig,
                                  BLK_BR_FEATURE_RECONFIG, QOS_PRIORITY);

    VLOG_DBG("[%s] Registering in BLK_RECONFIGURE_NEIGHBORS", QOS_PLUGIN_NAME);
    register_reconfigure_callback(&qos_callback_reconfigure_neighbors,
                                  BLK_RECONFIGURE_NEIGHBORS, QOS_PRIORITY);

    for (int blk_id = 0; blk_id < (int)MAX_STATS_BLOCKS_NUM; blk_id++) {
        switch (blk_id) {
        case STATS_PER_BRIDGE_NETDEV:
        case STATS_PER_VRF_NETDEV:
        case STATS_PER_SUBSYSTEM_NETDEV:
            VLOG_DBG("[%s] Registering STATS_PER_xxx_NETDEV", QOS_PLUGIN_NAME);
            register_stats_callback(&qos_callback_statistics_netdev,
                                    blk_id, QOS_PRIORITY);
            break;
        case STATS_BRIDGE_CREATE_NETDEV:
        case STATS_SUBSYSTEM_CREATE_NETDEV:
            VLOG_DBG("[%s] Registering STATS_xxx_CREATE_NETDEV", QOS_PLUGIN_NAME);
            register_stats_callback(&qos_callback_statistics_create_netdev,
                                    blk_id, QOS_PRIORITY);
            break;

        default:
#ifdef QOS_STATS_DEBUG
            VLOG_DBG("[%s] Registering STATS block %d", QOS_PLUGIN_NAME, blk_id);
            register_stats_callback(&qos_callback_statistics_default, blk_id, QOS_PRIORITY);
#endif
            break;
        }
    }

    return ret;
}

/* bridge_run-related operations go here. */
int run(void)
{
    /* Nothing to do. */
    return 0;
}

/* bridge_wait-related operations go here. */
int wait(void)
{
    /* Nothing to do. */
    return 0;
}

/* Handle plugin unload. */
int destroy(void)
{
    unregister_plugin_extension(QOS_PLUGIN_NAME);
    VLOG_DBG("[%s] was destroyed...", QOS_PLUGIN_NAME);
    return 0;
}
