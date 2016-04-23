/*
 * Copyright (c) 2016 Hewlett-Packard Enterprise Development, LP
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


#include <stdlib.h>
#include <errno.h>
#include "list.h"
#include "openvswitch/vlog.h"
#include "vswitch-idl.h"
#include "reconfigure-blocks.h"
#include "stats-blocks.h"
#include "plugin-extensions.h"
#include "copp-asic-provider.h"
#include "vswitch-idl.h"
#include "copp-temp-keys.h"


#define COPP_PLUGIN_PRIORITY NO_PRIORITY


VLOG_DEFINE_THIS_MODULE(stats_copp_plugin);

/* Globals */
struct plugin_extension_interface g_copp_asic_plugin;
static bool g_copp_initialized;

typedef struct copp_stats_errors_logged {
   bool no_supp     : 1;
   bool inval       : 1;
} copp_stats_errors_logged_t;

typedef struct copp_stauts_errors_logged {
   bool no_supp     : 1;
   bool no_spc      : 1;
   bool io          : 1;
   bool inval       : 1;
} copp_stauts_errors_logged_t;

copp_stats_errors_logged_t  g_copp_stats_log_info[COPP_NUM_CLASSES];
copp_stauts_errors_logged_t g_copp_status_log_info[COPP_NUM_CLASSES];


void copp_stats_cb(struct stats_blk_params *sblk, enum stats_block_id blk_id);
void copp_stats_brinit_cb(struct blk_params* cblk);


/* IMPLEMENTATION NOTE:
 * init()
 * Trust the magic... this function really is called. Here's how it works:
 * ops-switchd:main calls plugins_init(path) just prior to bridge_init()
 * plugins_init() takes a path as an arg and calls plugins_initializaton(path)
 * plugins_initializaton(path) searches for any library files in path, dynamically
 * loads them and invokes each of their init() functions.
 *
 * The end effect is that a plugin can get loaded by ensuring two things
 *  1. it provides an init() fuction
 *  2. the make system installs it's library into the same path that plugins_init searches
 *
 * At the time of this writting, that special path was intended to be
 *    /usr/lib/openvswitch/plugins
 */
void init(void) {
    int i, rc;
    struct plugin_extension_interface* asic_intf;

    /* find the previously registered asic copp plugin */
    g_copp_initialized = false;
    rc = find_plugin_extension(COPP_ASIC_PLUGIN_INTERFACE_NAME,
        COPP_ASIC_PLUGIN_INTERFACE_MAJOR,
        COPP_ASIC_PLUGIN_INTERFACE_MINOR,
        &asic_intf);
    if (rc) {
        VLOG_INFO("%s (v%d.%d) not found", COPP_ASIC_PLUGIN_INTERFACE_NAME,
            COPP_ASIC_PLUGIN_INTERFACE_MAJOR,
            COPP_ASIC_PLUGIN_INTERFACE_MINOR);
        return;
    }

    /* register our callback on BLK_BRIDGE_INIT. */
    rc = register_reconfigure_callback(copp_stats_brinit_cb, BLK_BRIDGE_INIT, COPP_PLUGIN_PRIORITY);
    if (rc) {
        VLOG_INFO("Failed to register for switchd bridge configure_init plugin");
        g_copp_asic_plugin.plugin_interface = NULL;
        g_copp_initialized = false;
        return;
    }

    /* register our callback on STATS_PER_BRIDGE. */
    rc = register_stats_callback(copp_stats_cb, STATS_PER_BRIDGE, COPP_PLUGIN_PRIORITY);
    if (rc) {
        VLOG_INFO("Failed to register for switchd stats plugin");
        g_copp_asic_plugin.plugin_interface = NULL;
        g_copp_initialized = false;
        return;
    }

    for (i=0; i < COPP_NUM_CLASSES; i++) {
        g_copp_stats_log_info[i].no_supp = false;
        g_copp_stats_log_info[i].inval= false;

        g_copp_status_log_info[i].no_supp = false;
        g_copp_status_log_info[i].no_spc= false;
        g_copp_status_log_info[i].io = false;
        g_copp_status_log_info[i].inval= false;
    }
    g_copp_asic_plugin.plugin_interface = asic_intf->plugin_interface;

    /* done */
    VLOG_INFO("%s (v%d.%d) registered", COPP_ASIC_PLUGIN_INTERFACE_NAME,
            COPP_ASIC_PLUGIN_INTERFACE_MAJOR,
            COPP_ASIC_PLUGIN_INTERFACE_MINOR);

}


/* The copp stats system has no need of employing run, wait, or destroy
 * functions. However, the plugin system dynamic lyncing demands that
 * these functions be present in our library or the plugin will not load.
 */
void run() {
}
void wait() {
}
void destroy() {
}


void
copp_stats_brinit_cb(struct blk_params* cblk) {

    /* config the DB for our copp stats column... we want 'write_only' */
     if (cblk->idl) {
        ovsdb_idl_omit_alert(cblk->idl, &ovsrec_system_col_copp_statistics);

        VLOG_INFO("callback copp_stats_cb() sucessfully initialized");
        g_copp_initialized = true;
     }
     else
         VLOG_INFO("failed to initialize copp_stats_cb()");
}


/* copp_stats_cb
 * This gathers COPP stats from a PD layer and publishes them to the ovsdb via
 * the IDL.
 * We loop through every class in copp_protocol_class and ask the PD layer for
 * its view of each one of them. We build up an smap of all the answers. Then
 * we tack on some totals rows into the smap. Then publish it.
 *
 * If a PD layer returns an error for any call, we do not publish any data into
 * the DB (even deleting the row if necessary) and send a WARN log the first
 * time we encounter that error.
 *
 * It's also fair for an PD layer to tell us -1, which we will faithfully
 * publish to the DB without logging anything.
 *
 * Each time we query a PD layer for stats, we are seeking four stats. If the
 * PD layer partially supports them, it should send us real values for those it
 * supports, -1s for those it does not, and return a non-error status (0).
 *
 * Each time we query a PD layer for status, we are seeking three stats. PD
 * layer must support all three of these or return an error status.
 */
/* IMPLEMENTATION NOTE:
 * At the time an execute_stats_block() is called from swithcd, there is
 * already an idl transaction in flight. We assume that transaction is live/
 * valid and tack on our column rows to it. We also assume that switchd will
 * soon commit that transaction.
 */
void
copp_stats_cb(struct stats_blk_params *sblk, enum stats_block_id blk_id) {

    int class, rc, len=0;
    const struct copp_asic_plugin_interface* asic_intf =
        (struct copp_asic_plugin_interface*)g_copp_asic_plugin.plugin_interface;
    struct copp_protocol_stats  copp_stats;
    struct copp_hw_status  hw_status;
    const struct ovsrec_open_vswitch *cfg;
    struct smap copp_smap;
    uint64_t copp_stats_totals[COPP_STATS_TOTAL_MAX] = {0,0,0,0};

#define NUM_STATS_PER_CLASS 7
#define NUM_CHARS_UINT_64 21
#define NUM_COMMAS_AND_SUCH 8
#define STATS_BUF_SIZE ((NUM_STATS_PER_CLASS*NUM_CHARS_UINT_64) + NUM_COMMAS_AND_SUCH)
    char stats_buf[STATS_BUF_SIZE];

    /* sanity checking */
    if (!asic_intf)
        return;
    if(!asic_intf->copp_stats_get)
        return;
    if(!asic_intf->copp_hw_status_get)
        return;
    if (!g_copp_initialized) {
        return;
    }

    if (sblk->idl)
       cfg = ovsrec_open_vswitch_first(sblk->idl);
    else {
        /* error case. log something */
        return;
    }

    /* starting */
    smap_init(&copp_smap);

    for (class=0; class < COPP_NUM_CLASSES; class++) {

        if (g_copp_stats_log_info[class].no_supp == true)
            continue;

        /* collect from asic */
        rc = asic_intf->copp_stats_get(0, class, &copp_stats);
        if (rc) {
            switch(rc) {
                case EOPNOTSUPP :
                    if (g_copp_stats_log_info[class].no_supp == false ) {
                        VLOG_INFO("copp_stats_get for class %d returned %d %s",
                            class, rc, strerror(rc));

                        /* The first time we encounter NOTSUPP, we remove this
                         * row from the smap. Doing it once the first time,
                         * will be a percistent decision and this row will
                         * never get published. Most likely, this row never
                         * made it into smap anyway and smap_removing it is
                         * a null-op.
                         */
                        g_copp_stats_log_info[class].no_supp = true;
                    }
                    break;
                case EINVAL :
                    if (g_copp_stats_log_info[class].inval == false ) {
                        VLOG_INFO("copp_stats_get for class %d returned %d %s",
                            class, rc, strerror(rc));
                        g_copp_stats_log_info[class].inval= true;
                    }
                    break;
                default:
                    VLOG_INFO("copp_stats_get for class %d returned"
                        "unrecognized %d %s", class, rc, strerror(rc));
            }

            /* give up on both stats and status for this class */
            continue;
        }

        rc = asic_intf->copp_hw_status_get(0, class, &hw_status);
        if (rc) {
            hw_status.rate =
            hw_status.burst =
            hw_status.local_priority = ULLONG_MAX;
            switch(rc) {
                case EOPNOTSUPP:
                    if (g_copp_status_log_info[class].no_supp == false ) {
                        /* It would be very strange to arrive here. asic must
                         * have given us stats and then subsequently claimed
                         * that it was not supported to have configured
                         * collecing those stats. Could happen on first pass
                         * I suppose.
                         */
                        VLOG_INFO("copp_hw_status_get for class %d returned"
                        " %d %s", class, rc, strerror(rc));
                        g_copp_status_log_info[class].no_supp = true;

                        /* give up on both stats and status for this class */
                        smap_remove(&copp_smap, temp_copp_keys[class]);
                        continue;
                    }
                    break;
                case ENOSPC:
                    if (g_copp_status_log_info[class].no_spc== false ) {
                        VLOG_INFO("copp_hw_status_get for class %d returned "
                            "%d %s", class, rc, strerror(rc));
                        g_copp_status_log_info[class].no_spc= true;
                        /* ok to publish class into db row in this case */
                    }
                    break;
                case EIO:
                    if (g_copp_status_log_info[class].io == false ) {
                        VLOG_INFO("copp_hw_status_get for class %d returned "
                            "%d %s", class, rc, strerror(rc));
                        g_copp_status_log_info[class].io = true;
                        /* ok to publish class into db row in this case */
                    }
                    break;
                case EINVAL:
                    if (g_copp_status_log_info[class].inval == false ) {
                        VLOG_INFO("copp_hw_status_get for class %d returned "
                            "%d %s", class, rc, strerror(rc));
                        g_copp_status_log_info[class].inval= true;
                        /* give up on both stats and status for this class */
                        smap_remove(&copp_smap, temp_copp_keys[class]);
                        continue;
                    }
                    break;
                default:
                    VLOG_INFO("copp_hw_status_get() for class %d returned "
                        "unrecognized %d %s", class, rc, strerror(rc));
            }
        }

        len = snprintf(stats_buf, STATS_BUF_SIZE,
            TEMP_COPP_STATS_BUF_FMT,
            TEMP_COPP_STATS_VARS(hw_status, copp_stats));
        if (len < 0) {
            VLOG_WARN("could not convert stats to string. Not reporting class "
                "%d", class);
            goto out;
        }
        if (len > STATS_BUF_SIZE) {
            VLOG_WARN("could not convert stats to string. Not reporting class "
                " %d", class);
            goto out;
        }

        /* Looks good.  Publish to db */
        smap_add(&copp_smap, temp_copp_keys[class], stats_buf);

        /* keep running track of totals */
        if ( copp_stats.bytes_dropped != UINT64_MAX )
            copp_stats_totals[COPP_STATS_TOTAL_BYTES_DROPPED] +=
                copp_stats.bytes_dropped;
        if ( copp_stats.bytes_passed != UINT64_MAX )
            copp_stats_totals[COPP_STATS_TOTAL_BYTES_PASSED] +=
                copp_stats.bytes_passed;
        if ( copp_stats.packets_dropped != UINT64_MAX )
            copp_stats_totals[COPP_STATS_TOTAL_PKTS_DROPPED] +=
                copp_stats.packets_dropped;
        if ( copp_stats.packets_passed != UINT64_MAX )
            copp_stats_totals[COPP_STATS_TOTAL_PKTS_PASSED] +=
                copp_stats.packets_passed;

    }

    for (int tots=0; tots<COPP_STATS_TOTAL_MAX; tots++) {

        len = snprintf(stats_buf, STATS_BUF_SIZE,
            "%lu", copp_stats_totals[tots]);
        if (len < 0) {
            VLOG_WARN("could not convert totals to text; not reporting total"
                " [%d]", tots);
            goto out;
        }
        if (len > STATS_BUF_SIZE) {
             VLOG_WARN("could not convert total to text; not reporting total"
             " [%d]", tots);
            goto out;
        }

        /* publish to db */
        smap_replace(&copp_smap, temp_copp_totals_keys[tots], stats_buf);

    }


    if (cfg) {
        /* IMPLEMENTATION NOTE:
        * The call to ovsrec_system_set_copp_statistics() depends upon changes
        * in ops-switchd/src/bridge.c:bridge_init() to omit_alert on the copp
        * stats column.  (search ovsrec_system_col_copp_statistics)
        * We might be able to omit_alert here in this plugin's init() fucnciton
        * if the loader would pass either cfg or idl or stats_blk to us.
        */
        ovsrec_system_set_copp_statistics(cfg, &copp_smap);
    }
out:
    smap_destroy(&copp_smap);

}
