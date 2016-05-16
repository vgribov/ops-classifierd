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
 * Handle QoS statistics callbacks from subsystem.c and bridge.c
 ***************************************************************************/

#include <config.h>

#include "qos_statistics.h"

#include "bridge.h"
#include "netdev.h"
#include "qos_plugin.h"
#include "openvswitch/vlog.h"


VLOG_DEFINE_THIS_MODULE(qos_statistics);

#define NUM_QUEUES 8

/*
 * callback from netdev interface layer
 * netdev_queue_stats has statistics for a single QOS queue
 */
void
populate_bridge_queue_stats_callback (unsigned int queue_id,
                                      struct netdev_queue_stats* stats,
                                      void *aux)
{
    struct netdev_queue_stats *qstats = NULL;

    /* 'stats' is a single queue_stats struct ptr containing the 'hw' data for
     * the current queue.
     * 'aux' carries a ptr to our queue_stats array from iface_refresh_queue_stats
     */
    if (stats == NULL) {
        return;
    }
    if (aux == NULL) {
        return;
    }
    if (queue_id >= NUM_QUEUES) {
        return;
    }

    qstats = (struct netdev_queue_stats *)aux;

    qstats[queue_id].tx_bytes   = stats->tx_bytes;
    qstats[queue_id].tx_packets = stats->tx_packets;
    qstats[queue_id].tx_errors  = stats->tx_errors;
}

#ifdef QOS_STATS_DEBUG
static int stats_counts[MAX_STATS_BLOCKS_NUM];

void
qos_callback_statistics_default(struct stats_blk_params *sblk,
                                enum stats_block_id blk_id)
{
    int ii;
    int jj;
    char buff[120];

    stats_counts[blk_id]++;
    switch (blk_id) {
    case STATS_BEGIN:
    case STATS_END:
    case STATS_SUBSYSTEM_BEGIN:
    case STATS_SUBSYSTEM_END:
        jj = 0;
        for (ii = 0; ii < MAX_STATS_BLOCKS_NUM; ii++) {
            jj += snprintf(&buff[jj], 120-jj, " %6d", stats_counts[ii]);
        }
        VLOG_INFO("%2d :%s", blk_id, buff);
        break;
    default:
        break;
    }
}
#endif

/*
 * request queue statistics for a netdev interface
 * write the stats into the Interface row
 */
void
qos_callback_statistics_netdev(struct stats_blk_params *sblk,
                               enum stats_block_id blk_id)
{
    struct netdev *netdev = sblk->netdev;
    const struct ovsrec_interface *cfg = sblk->cfg;

#ifdef QOS_STATS_DEBUG
    stats_counts[blk_id]++;
    VLOG_DBG("%s %d %s", __FUNCTION__, blk_id, sblk->cfg->name);
#endif

#define IFACE_QUEUE_STATS                             \
    IFACE_QUEUE_STAT(tx_bytes,        "tx_bytes")     \
    IFACE_QUEUE_STAT(tx_packets,      "tx_packets")   \
    IFACE_QUEUE_STAT(tx_errors,       "tx_errors")

#define IFACE_QUEUE_STAT(MEMBER, NAME) + 1
    enum { N_IFACE_QUEUE_STATS = IFACE_QUEUE_STATS };
#undef IFACE_QUEUE_STAT
    int64_t keys[NUM_QUEUES];
    int64_t values[NUM_QUEUES];
    int i,j = 0;

    struct netdev_queue_stats qstats[NUM_QUEUES];

    /* Initialize queue statistic structures */
    for (i = 0; i < NUM_QUEUES; i++) {
        qstats[i].tx_bytes = UINT64_MAX;
        qstats[i].tx_packets = UINT64_MAX;
        qstats[i].tx_errors = UINT64_MAX;
        qstats[i].created = LLONG_MIN;
    }
    /* Dump all queues statistics */
    netdev_dump_queue_stats(netdev,
                            populate_bridge_queue_stats_callback,
                            (void *)qstats);

    /* Copy statistics into keys[] and values[]. */
#define IFACE_QUEUE_STAT(MEMBER, NAME)        \
    j = 0;                                    \
    for (i = 0; i < NUM_QUEUES; i++) {        \
        if (qstats[i].MEMBER != UINT64_MAX) { \
            keys[j] = i;                      \
            values[j] = qstats[i].MEMBER;     \
            j++;                              \
        }                                     \
    }                                         \
    ovs_assert(j <= NUM_QUEUES);              \
                                              \
    ovsrec_interface_set_queue_##MEMBER(cfg, keys, values, j);
    IFACE_QUEUE_STATS;

#undef IFACE_QUEUE_STAT
#undef IFACE_QUEUE_STATS

}

/* Iface creation. */
void
qos_callback_statistics_create_netdev(struct stats_blk_params *sblk,
                                      enum stats_block_id blk_id)
{
    VLOG_DBG("%s %d %s", __FUNCTION__, blk_id, sblk->cfg->name);
}
