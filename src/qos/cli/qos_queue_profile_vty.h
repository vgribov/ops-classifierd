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

#ifndef _QOS_QUEUE_PROFILE_VTY_H_
#define _QOS_QUEUE_PROFILE_VTY_H_

#include <stdbool.h>
#include <stdint.h>

#include "vswitch-idl.h"

/**
 * Shows the running config for queue_profile. Returns true if the applied
 * profile differs from the default profile.
 */
bool qos_queue_profile_show_running_config(void);

/**
 * Returns true if the queue profile has the queue_num.
 */
bool qos_queue_profile_has_queue_num(struct ovsrec_q_profile *profile_row,
        int64_t queue_num);

/**
 * Returns true if the queue profile is complete.
 */
bool qos_queue_profile_is_complete(struct ovsrec_q_profile *profile_row,
        bool print_error);

/**
 * Retrieves the queue profile row.
 */
struct ovsrec_q_profile *qos_get_queue_profile_row(
        const char *profile_name);

/**
 * Initializes vty functions for qos queue profile.
 */
void qos_queue_profile_vty_init(void);

/**
 * Initializes ovsdb functions for qos queue profile.
 */
void qos_queue_profile_ovsdb_init(void);

#endif /* _QOS_QUEUE_PROFILE_VTY_H_ */
