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
 * Handle QoS COS- and DSCP-map callbacks from bridge_reconfigure
 ***************************************************************************/

#include <config.h>

#include "qos_map.h"

#include <stdlib.h>
#include <string.h>

#include "openvswitch/vlog.h"
#include "qos_plugin.h"
#include "qos-asic-provider.h"


VLOG_DEFINE_THIS_MODULE(qos_map);

/* Convert COS color text into enum value. */
static enum cos_color
qos_get_color(const char *color_text)
{
    /* if all else fails, return GREEN! */
    enum cos_color color = COS_COLOR_GREEN;

    if (!color_text) {
        color = COS_COLOR_GREEN;
    }
    else if (!strncmp(OVSREC_QOS_COS_MAP_ENTRY_COLOR_GREEN, color_text, 8)) {
        color = COS_COLOR_GREEN;
    }
    else if (!strncmp(OVSREC_QOS_COS_MAP_ENTRY_COLOR_YELLOW, color_text, 8)) {
        color = COS_COLOR_YELLOW;
    }
    else if (!strncmp(OVSREC_QOS_COS_MAP_ENTRY_COLOR_RED, color_text, 8)) {
        color = COS_COLOR_RED;
    }
    return color;
}

/* Configure QOS COS maps for a particular bridge. */
void
qos_configure_global_cos_map(struct ofproto *ofproto,
                             struct ovsdb_idl *idl, unsigned int idl_seqno)
{
    int n_modified;
    const struct ovsrec_qos_cos_map_entry *ovsrec_cos_map_entry;
    struct cos_map_settings cos_map_settings;

    /* How many rows in the COS map are modified? */
    cos_map_settings.n_entries = 0;
    OVSREC_QOS_COS_MAP_ENTRY_FOR_EACH(ovsrec_cos_map_entry, idl) {
        if (OVSREC_IDL_IS_ROW_MODIFIED(ovsrec_cos_map_entry, idl_seqno) ||
            OVSREC_IDL_IS_ROW_INSERTED(ovsrec_cos_map_entry, idl_seqno)) {

            VLOG_DBG("%s: MODIFIED %s %d", __FUNCTION__,
                     ovsrec_cos_map_entry->description,
                     (int)ovsrec_cos_map_entry->code_point);
            cos_map_settings.n_entries++;
        }
    }
    if (cos_map_settings.n_entries > 0) {
        /* build the settings struct, call provider API */
        cos_map_settings.entries = malloc(sizeof(struct cos_map_entry) *
                                          cos_map_settings.n_entries);
        n_modified = 0;
        OVSREC_QOS_COS_MAP_ENTRY_FOR_EACH(ovsrec_cos_map_entry, idl) {
            if (OVSREC_IDL_IS_ROW_MODIFIED(ovsrec_cos_map_entry, idl_seqno) ||
                OVSREC_IDL_IS_ROW_INSERTED(ovsrec_cos_map_entry, idl_seqno))
            {
                cos_map_settings.entries[n_modified].color =
                                    qos_get_color(ovsrec_cos_map_entry->color);
                cos_map_settings.entries[n_modified].codepoint =
                                    ovsrec_cos_map_entry->code_point;
                cos_map_settings.entries[n_modified].local_priority =
                                    ovsrec_cos_map_entry->local_priority;
                n_modified++;
            }
        }
        if (n_modified != cos_map_settings.n_entries) {
            VLOG_WARN("%s: mismatched cos_map request rows_chgd=%d != modified=%d",
                      __FUNCTION__, cos_map_settings.n_entries, n_modified);
        }
        ofproto_set_cos_map(ofproto, NULL, &cos_map_settings);
        free(cos_map_settings.entries);
    }
}

/* Configure QOS DSCP maps for a particular bridge. */
void
qos_configure_global_dscp_map(struct ofproto *ofproto,
                              struct ovsdb_idl *idl, unsigned int idl_seqno)
{
    int n_modified;
    const struct ovsrec_qos_dscp_map_entry *ovsrec_dscp_map_entry;
    struct dscp_map_settings dscp_map_settings;

    /* how many rows in the DSCP map are modified? */
    dscp_map_settings.n_entries = 0;
    OVSREC_QOS_DSCP_MAP_ENTRY_FOR_EACH(ovsrec_dscp_map_entry, idl) {
        if (OVSREC_IDL_IS_ROW_MODIFIED(ovsrec_dscp_map_entry, idl_seqno) ||
            OVSREC_IDL_IS_ROW_INSERTED(ovsrec_dscp_map_entry, idl_seqno)) {
            dscp_map_settings.n_entries++;
            VLOG_DBG("%s: MODIFIED %s %ld", __FUNCTION__,
                     ovsrec_dscp_map_entry->description,
                     ovsrec_dscp_map_entry->code_point);
        }
    }
    if (dscp_map_settings.n_entries) {
        /* build the settings struct, call provider API */
        dscp_map_settings.entries = malloc(sizeof(struct dscp_map_entry) *
                                           dscp_map_settings.n_entries);
        n_modified = 0;
        OVSREC_QOS_DSCP_MAP_ENTRY_FOR_EACH(ovsrec_dscp_map_entry, idl) {
            if (OVSREC_IDL_IS_ROW_MODIFIED(ovsrec_dscp_map_entry, idl_seqno) ||
                OVSREC_IDL_IS_ROW_INSERTED(ovsrec_dscp_map_entry, idl_seqno))
            {
                dscp_map_settings.entries[n_modified].color =
                    qos_get_color(ovsrec_dscp_map_entry->color);
                dscp_map_settings.entries[n_modified].codepoint =
                    ovsrec_dscp_map_entry->code_point;
                dscp_map_settings.entries[n_modified].cos =
                    ovsrec_dscp_map_entry->n_priority_code_point;
                dscp_map_settings.entries[n_modified].local_priority =
                    ovsrec_dscp_map_entry->local_priority;
                n_modified++;
            }
        }
        if (n_modified != dscp_map_settings.n_entries) {
            VLOG_WARN("%s: mismatched dscp_map request rows_chgd=%d != modified=%d",
                      __FUNCTION__, dscp_map_settings.n_entries, n_modified);
        }
        ofproto_set_dscp_map(ofproto, NULL, &dscp_map_settings);
        free(dscp_map_settings.entries);
    }
}
