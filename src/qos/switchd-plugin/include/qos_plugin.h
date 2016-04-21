/*
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
 */

#ifndef __QOS_PLUGIN_H__
#define __QOS_PLUGIN_H__


#include "qos-asic-provider.h"
#include "ofproto/ofproto-provider.h"
#include "reconfigure-blocks.h"

#define QOS_PLUGIN_NAME    "QOS" //Do not change this name


#define QOS_PRIORITY        NO_PRIORITY

/* bridge_reconfigure callback functions (registered by qos_plugin:init) */
void qos_callback_bridge_init(struct blk_params *);
void qos_callback_init_reconfigure(struct blk_params *);
void qos_callback_bridge_port_update(struct blk_params *);
void qos_callback_bridge_feature_reconfig(struct blk_params *);
void qos_callback_vrf_port_update(struct blk_params *);
void qos_callback_reconfigure_neighbors(struct blk_params *);

/* Configuration of QOS tables. */
enum qos_trust get_qos_trust_value(const struct smap *);
int ofproto_set_port_qos_cfg(struct ofproto *, void *,
                             const enum qos_trust,
                             const struct smap *,
                             const struct smap *);
int ofproto_set_cos_map(struct ofproto *, void *,
                        const struct cos_map_settings *);
int ofproto_set_dscp_map(struct ofproto *, void *,
                         const struct dscp_map_settings *);
int ofproto_apply_qos_profile(struct ofproto *, void *,
                              const struct schedule_profile_settings *,
                              const struct queue_profile_settings *);

#endif //__QOS_PLUGIN_H__
