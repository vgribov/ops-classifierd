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
 ***************************************************************************/

#ifndef _QOS_STATISTICS_H_
#define _QOS_STATISTICS_H_

#include "stats-blocks.h"

#include "netdev.h"

void populate_bridge_queue_stats_callback (unsigned int queue_id,
                                           struct netdev_queue_stats* stats,
                                           void *aux);
void qos_callback_statistics_netdev(struct stats_blk_params *, enum stats_block_id);
void qos_callback_statistics_create_netdev(struct stats_blk_params *sblk,
                                           enum stats_block_id blk_id);
#ifdef QOS_STATS_DEBUG
void qos_callback_statistics_default(struct stats_blk_params *, enum stats_block_id);
#endif

#endif /* _QOS_STATISTICS_H_ */
