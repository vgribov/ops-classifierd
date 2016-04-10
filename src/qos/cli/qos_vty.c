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

#include "qos_vty.h"

#include <libaudit.h>

#include "memory.h"
#include "ovsdb-idl.h"
#include "qos_apply_global_vty.h"
#include "qos_apply_port_vty.h"
#include "qos_cos_map_vty.h"
#include "qos_cos_port_vty.h"
#include "qos_dscp_map_vty.h"
#include "qos_dscp_port_vty.h"
#include "qos_queue_profile_vty.h"
#include "qos_schedule_profile_vty.h"
#include "qos_trust_global_vty.h"
#include "qos_trust_port_vty.h"
#include "qos_utils.h"
#include "qos_utils_vty.h"
#include "smap.h"
#include "openvswitch/vlog.h"
#include "openswitch-idl.h"
#include "vswitch-idl.h"
#include "vtysh/command.h"
#include "vtysh/vtysh.h"
#include "vtysh/vtysh_ovsdb_config.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_user.h"

/**
 * Initialize cli.
 */
void
cli_pre_init(void)
{
    qos_apply_global_ovsdb_init();
    qos_apply_port_ovsdb_init();
    qos_cos_map_ovsdb_init();
    qos_cos_port_ovsdb_init();
    qos_dscp_map_ovsdb_init();
    qos_dscp_port_ovsdb_init();
    qos_queue_profile_ovsdb_init();
    qos_schedule_profile_ovsdb_init();
    qos_trust_global_ovsdb_init();
    qos_trust_port_ovsdb_init();
}

/**
 * Initialize cli.
 */
void
cli_post_init(void)
{
    qos_apply_global_vty_init();
    qos_apply_port_vty_init();
    qos_cos_map_vty_init();
    qos_cos_port_vty_init();
    qos_dscp_map_vty_init();
    qos_dscp_port_vty_init();
    qos_queue_profile_vty_init();
    qos_schedule_profile_vty_init();
    qos_trust_global_vty_init();
    qos_trust_port_vty_init();

    qos_apply_global_show_running_config();
    qos_cos_map_show_running_config();
    qos_dscp_map_show_running_config();
    qos_trust_global_show_running_config();

    qos_audit_init();
}
