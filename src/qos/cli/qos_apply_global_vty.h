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

#ifndef _QOS_APPLY_GLOBAL_VTY_H_
#define _QOS_APPLY_GLOBAL_VTY_H_

#include <stdbool.h>

#include "vswitch-idl.h"

/**
 * Returns true if the queue profile and the schedule profile contain the
 * same queues.
 */
bool qos_profiles_contain_same_queues(
        struct ovsrec_q_profile * queue_profile_row,
        struct ovsrec_qos *schedule_profile_row);

/**
 * Shows the running config for global qos apply.
 */
void qos_apply_global_show_running_config(void);

/**
 * Initializes vty functions for global qos apply.
 */
void qos_apply_global_vty_init(void);

/**
 * Initializes ovsdb functions for global qos apply.
 */
void qos_apply_global_ovsdb_init(void);

#endif /* _QOS_APPLY_GLOBAL_VTY_H_ */
