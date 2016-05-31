/*
 * Copyright (C) 2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "acl_ofproto.h"
#include <errno.h>
#include <config.h>
#include "plugin-extensions.h"
#include "ops-cls-asic-plugin.h"
#include "ofproto/ofproto-provider.h"
#include "openvswitch/vlog.h"
#include "acl.h"
#include "acl_plugin.h"
#include "acl_log.h"

VLOG_DEFINE_THIS_MODULE(acl_switchd_plugin_ofproto);

static struct plugin_extension_interface *extension = NULL;
static struct ops_cls_plugin_interface *plugin = NULL;

const char * const ops_cls_type_strings[] = {
    "INVALID",
    "ACL_V4",
    "ACL_V6"
};

const char * const ops_cls_direction_strings[] = {
    "INVALID",
    "IN",
    "OUT"
};

struct ops_cls_list*
ops_cls_list_new(void)
{
    struct ops_cls_list *list = xzalloc(sizeof *list);
    return list;
}

void
ops_cls_list_delete(struct ops_cls_list *list)
{
    if (list) {
        free(CONST_CAST(char*, list->list_name));
        free(list->entries);
        free(list);
    }
}

int
call_ofproto_ops_cls_apply(struct acl                     *acl,
                           struct port                    *bridgec_port,
                           struct ofproto                 *ofproto,
                           struct ops_cls_interface_info  *interface_info,
                           enum ops_cls_direction         direction,
                           struct ops_cls_pd_status       *pd_status)
{
    int rc = 0;
    if (plugin && plugin->ofproto_ops_cls_apply) {
        rc = plugin->ofproto_ops_cls_apply(acl->cfg_pi, ofproto, bridgec_port,
                                           interface_info, direction,
                                           pd_status);
    }

    VLOG_DBG("%s rc (%d)", __func__, rc);
    return rc;
}

int
call_ofproto_ops_cls_remove(struct acl                       *acl,
                            struct port                      *bridgec_port,
                            struct ofproto                   *ofproto,
                            struct ops_cls_interface_info    *interface_info,
                            enum ops_cls_direction           direction,
                            struct ops_cls_pd_status         *pd_status)
{
    int rc = 0;
    if (plugin && plugin->ofproto_ops_cls_remove) {
        rc = plugin->ofproto_ops_cls_remove(&acl->uuid, acl->name,
                                            acl->type, ofproto,
                                            bridgec_port, interface_info,
                                            direction, pd_status);
    }
    VLOG_DBG("%s rc (%d)", __func__, rc);
    return rc;
}

int
call_ofproto_ops_cls_replace(struct acl                      *orig_acl,
                             struct acl                      *new_acl,
                             struct port                     *bridgec_port,
                             struct ofproto                  *ofproto,
                             struct ops_cls_interface_info   *interface_info,
                             enum ops_cls_direction          direction,
                             struct ops_cls_pd_status        *pd_status)
{
    int rc = 0;
    if (plugin && plugin->ofproto_ops_cls_replace) {
        rc = plugin->ofproto_ops_cls_replace(&orig_acl->uuid, orig_acl->name,
                                             new_acl->cfg_pi, ofproto,
                                             bridgec_port, interface_info,
                                             direction, pd_status);
    }
    VLOG_DBG("%s rc (%d)", __func__, rc);
    return rc;
}

int
call_ofproto_cls_lag_update(struct acl                     *acl,
                            struct port                    *bridge_port,
                            struct ofproto                 *ofproto,
                            ofp_port_t                      ofp_port,
                            enum ops_cls_lag_update_action  action,
                            struct ops_cls_interface_info  *interface_info,
                            enum ops_cls_direction          direction,
                            struct ops_cls_pd_status       *pd_status)
{
    int rc = 0;

    if (plugin && plugin->ofproto_ops_cls_lag_update) {
        rc = plugin->ofproto_ops_cls_lag_update(acl->cfg_pi,
                                                ofproto,
                                                bridge_port, ofp_port,
                                                action,
                                                interface_info,
                                                direction, pd_status);
    }
    VLOG_DBG("%s rc (%d)", __func__, rc);
    return rc;
}

int
call_ofproto_ops_cls_list_update(struct acl                     *acl,
                                 struct ops_cls_pd_list_status  *status)
{
    int rc = 0;
    if (plugin && plugin->ofproto_ops_cls_list_update) {
        rc = plugin->ofproto_ops_cls_list_update(acl->cfg_pi, status);
    }
    VLOG_DBG("%s rc (%d)", __func__, rc);
    return rc;
}

int
call_ofproto_ops_cls_statistics_get(struct acl       *acl,
                      struct port                    *bridgec_port,
                      struct ofproto                 *ofproto,
                      struct ops_cls_interface_info  *interface_info,
                      enum ops_cls_direction         direction,
                      struct ops_cls_statistics      *statistics,
                      int                            num_entries,
                      struct ops_cls_pd_list_status  *status)
{
    int rc = 0;
    if (plugin && plugin->ofproto_ops_cls_statistics_get) {
        rc = plugin->ofproto_ops_cls_statistics_get(&acl->uuid, acl->name,
                                                    acl->type, ofproto,
                                                    bridgec_port,
                                                    interface_info,
                                                    direction, statistics,
                                                    num_entries, status);
    }
    VLOG_DBG("%s rc (%d)", __func__, rc);
    return rc;
}

int
call_ofproto_ops_cls_statistics_clear(struct acl      *acl,
                      struct port                     *bridgec_port,
                      struct ofproto                  *ofproto,
                      struct ops_cls_interface_info   *interface_info,
                      enum ops_cls_direction          direction,
                      struct ops_cls_pd_list_status   *status)
{
    int rc = 0;
    if (plugin && plugin->ofproto_ops_cls_statistics_clear) {
        rc = plugin->ofproto_ops_cls_statistics_clear(&acl->uuid, acl->name,
                                                      acl->type, ofproto,
                                                      bridgec_port,
                                                      interface_info,
                                                      direction,
                                                      status);
    }
    VLOG_DBG("%s rc (%d)", __func__, rc);
    return rc;
}

int
call_ofproto_ops_cls_statistics_clear_all(
                               struct ops_cls_pd_list_status    *status)
{
    int rc = 0;
    if (plugin && plugin->ofproto_ops_cls_statistics_clear_all) {
        rc = plugin->ofproto_ops_cls_statistics_clear_all(status);
    }
    VLOG_DBG("%s rc (%d)", __func__, rc);
    return rc;
}

void
acl_ofproto_init()
{
    int rc;

    rc = find_plugin_extension(OPS_CLS_ASIC_PLUGIN_INTERFACE_NAME,
                               OPS_CLS_ASIC_PLUGIN_INTERFACE_MAJOR,
                               OPS_CLS_ASIC_PLUGIN_INTERFACE_MINOR,
                               &extension);
    if (rc == 0) {
        plugin = (struct ops_cls_plugin_interface *)
                  extension->plugin_interface;
        /* Initialize ACL logging */
        if (plugin && plugin->ofproto_ops_cls_acl_log_pkt_register_cb) {
            plugin->ofproto_ops_cls_acl_log_pkt_register_cb(
                                                        &acl_log_pkt_data_set);
        }
    }
}
