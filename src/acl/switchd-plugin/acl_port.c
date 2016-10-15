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

#include "bridge.h"
#include "vrf.h"
#include "acl_port.h"
#include "vswitch-idl.h"
#include "dynamic-string.h"
#include "unixctl.h"
#include "openvswitch/vlog.h"
#include "reconfigure-blocks.h"
#include "stats-blocks.h"
#include "acl_plugin.h"
#include "acl_ofproto.h"
#include "acl_log.h"
#include "ops_cls_status_msgs.h"
#include "ops-cls-asic-plugin.h"
#include "acl_db_util.h"
#include "acl_parse.h"
#include "acl_port_lag_utils.h"


VLOG_DEFINE_THIS_MODULE(acl_switchd_plugin_port);

static void
acl_port_map_stats_get(struct acl_port_map *acl_port_map,
                       struct ofproto *ofproto);

/**************************************************************************//**
 * struct ops_cls_interface_info helper routine
 * Sets the interface_info structure
 *
 * @param[out] interface_info - Pointer to @see struct ops_cls_interface_info
 * @param[in]  acl_port       - Pointer to @see struct acl_port
 * @param[in]  port           - Pointer to @see struct port
 *****************************************************************************/
static void
ops_cls_interface_info_construct(struct ops_cls_interface_info *interface_info,
                                 const struct acl_port *acl_port,
                                 const struct port* port OVS_UNUSED)
{
    memset(interface_info, 0, sizeof *interface_info);

    /* TODO: handle more interface types when we know how to */
    interface_info->interface = OPS_CLS_INTERFACE_PORT;
    interface_info->flags |= acl_port->interface_flags;
}

/******************************************************************************
 * struct acl_port_map helper routines
 *****************************************************************************/

 /*************************************************************************//**
 * Sets the hw_acl field in the acl_port_map. This function is called after
 * an ACL has been successfully applied in hw to a port config
 * type (type, direction)
 *
 * @param[in] acl_port_map - Pointer to the port_map containing port info
 *                           for a given cfg (type, direction)
 * @param[in] acl          - Pointer to acl that was successfully applied
 *****************************************************************************/
void
acl_port_map_set_hw_acl(struct acl_port_map *acl_port_map, struct acl *acl)
{
    /* Only do something if the hw_acl is really changing */
    if (acl_port_map->hw_acl != acl) {
        if (acl_port_map->hw_acl) {
            /* remove myself from the old one */
            list_remove(&acl_port_map->acl_node);
            /* Reset myself */
            list_init(&acl_port_map->acl_node);
        }
        acl_port_map->hw_acl = acl;
        if (acl_port_map->hw_acl) {
            /* add myself to the new one */
            list_push_back(&acl_port_map->hw_acl->acl_port_map, &acl_port_map->acl_node);
        }
    }
}

/**************************************************************************//**
 * Construct an acl_port_map for a given configuration (type, direction).
 * This function is called once when the port is seen by ACL plugin for the
 * first time.
 *
 * @param[in] acl_port_map - acl_port_map to construct
 * @param[in] acl_port     - Pointer to the acl_port structure
 * @param[in] index        - Index of the global array holding the relevant
 *                           configuration.
 *****************************************************************************/
static void
acl_port_map_construct(struct acl_port_map *acl_port_map,
                       struct acl_port *acl_port, off_t index)
{
    /* no allocation here. acl_port_map structs are stored in an array
       inside acl_port structs */
    acl_port_map->parent = acl_port;
    acl_port_map->acl_db = &acl_db_accessor[index];
    acl_port_map->hw_acl = NULL;
    list_init(&acl_port_map->acl_node);
}

/**************************************************************************//**
 * Destruct an acl_port_map for a given configuration (type, direction). This
 * function is called when a port delete request is received.
 *
 * @param[in] acl_port_map - acl_port_map to destruct
 * @param[in] acl_port     - Pointer to the acl_port structure
 * @param[in] index        - Index of the global array holding the relevant
 *                           configuration.
 *****************************************************************************/
static void
acl_port_map_destruct(struct acl_port_map *acl_port_map)
{
    /* If we eventually hook into a polite shutdown mechanism, we'll
     * need to replace these asserts with a call to
     * acl_port_map_set_hw_acl(acl_port_map, NULL). If we ever do that, we should
     * also make sure that we teardown acl_ports (and therefore these
     * acl_port_map records) before we teardown the acl records.
     *
     * Only during a polite shutdown should we be doing low-level
     * teardown on PI records that are still interconnected.
     *
     * Until the day we support polite shutdown I prefer these asserts
     * to catch code that's doing bad things.
     */
    ovs_assert(!acl_port_map->hw_acl);
    ovs_assert(list_is_empty(&acl_port_map->acl_node));

    /* no deallocation here. acl_port_map structs are stored in an array
       inside acl_port structs */
}

/**************************************************************************//**
 * Construct and set the cfg_status column of a given port row. This function
 * is called after a call to the classifier asic plugin. The status
 * is recorded and uploaded to OVSDB.
 *
 * @param[in] acl_port_map - Pointer to the acl_port_map to get relevant
 *                           database access calls.
 * @param[in] row          - Pointer to the IDL port row
 * @param[in] state        - State string for the status code
 * @param[in] code         - Status code
 * @param[in] details      - detailed message explaining the status of an
 *                           acl port operation
 *****************************************************************************/
static void
acl_port_map_set_cfg_status(struct acl_port_map *acl_port_map,
                            const struct ovsrec_port *row,
                            char *state, unsigned int code, char *details)
{
    char code_str[OPS_CLS_CODE_STR_MAX_LEN];
    char version[OPS_CLS_VERSION_STR_MAX_LEN];

    snprintf(version, OPS_CLS_VERSION_STR_MAX_LEN,
             "%" PRId64"", acl_db_util_get_cfg_version(acl_port_map->acl_db, row)[0]);
    acl_db_util_status_setkey(acl_port_map->acl_db, row,
                                OPS_CLS_STATUS_VERSION_STR, version);
    acl_db_util_status_setkey(acl_port_map->acl_db, row,
                                OPS_CLS_STATUS_STATE_STR, state);
    snprintf(code_str, OPS_CLS_CODE_STR_MAX_LEN, "%u", code);
    acl_db_util_status_setkey(acl_port_map->acl_db, row,
                                OPS_CLS_STATUS_CODE_STR, code_str);
    acl_db_util_status_setkey(acl_port_map->acl_db, row,
                                OPS_CLS_STATUS_MSG_STR, details);
}

/**************************************************************************//**
 * This function calls asic plugin API calls for a requested acl port
 * operation. Apply, Remove, Replace are currently supported actions.
 *
 * @param[in] acl_port_map - Pointer to the acl_port_map
 * @param[in] port         - Pointer to @see struct port
 * @param[in] ofproto      - Pointer to @see struct ofproto
 *****************************************************************************/
static void
acl_port_map_update_cfg_internal(struct acl_port_map *acl_port_map,
                                 struct port *port, struct ofproto *ofproto)
{
    struct ops_cls_pd_status status;
    struct ops_cls_pd_list_status list_status;

    memset(&status, 0, sizeof status);
    memset(&list_status, 0, sizeof list_status);
    struct ops_cls_interface_info interface_info;
    ops_cls_interface_info_construct(&interface_info,
                                     acl_port_map->parent, port);
    int rc;
    const char *method_called = NULL;
    /* status_str used to store status description in db */
    char status_str[OPS_CLS_STATUS_MSG_MAX_LEN] = {0};
    unsigned int sequence_number = 0;
    int64_t clear_req_id = 0;
    int64_t clear_performed_id = 0;

    struct acl* acl;
    const struct ovsrec_acl *ovsdb_acl =
        acl_db_util_get_cfg(acl_port_map->acl_db, acl_port_map->parent->ovsdb_row);
    if (!ovsdb_acl) {
        /* The cfg being null means that acl_port_cfg_delete should have been
         * called instead of this function.
         */
        ovs_assert(0);
    }

    acl = acl_lookup_by_uuid(&ovsdb_acl->header_.uuid);
    if (!acl) {
        /* This shouldn't happen because we currently process ACL
         * row changes before Port row changes. But once the
         * Change system is in place this really becomes
         * impossible. Changes will have dependencies and can
         * be reordered.
         */
         ovs_assert(0);
    }

    if (acl_port_map->hw_acl == acl) {

        /* Perform clear statistics if clear requested id and clear
         * performed id are different
         */
         clear_req_id = acl_db_util_get_clear_statistics_requested(
                                        acl_port_map->acl_db,
                                        acl_port_map->parent->ovsdb_row);
         clear_performed_id = acl_db_util_get_clear_statistics_performed(
                                        acl_port_map->acl_db,
                                        acl_port_map->parent->ovsdb_row);
        if (clear_req_id != clear_performed_id) {
            /* Call ASIC layer to clear statistics.
             * This field is set from UI when clear stats is requested.
             * We call ASIC layer to clear statistics and mark the
             * operation done by setting
             * aclv4_in_statistics_clear_performed column regardless of
             * result of the call.The UI is expected to look at this
             * column and reset the aclv4_in_statistics_clear_requested
             * column. We will then detect that the flag is reset and
             * reset our flag marking completion of the request/response
             * cycle
             */
            VLOG_DBG("ACL_PORT_MAP %s:%s:%s clearing statistics\n",
                     acl_port_map->parent->port->name,
                     ops_cls_type_strings[acl_port_map->acl_db->type],
                     ops_cls_direction_strings[
                                        acl_port_map->acl_db->direction]);
            rc = call_ofproto_ops_cls_statistics_clear(
                                                acl_port_map->hw_acl,
                                                acl_port_map->parent->port,
                                                ofproto,
                                                &interface_info,
                                                acl_port_map->acl_db->direction,
                                                &list_status);
            acl_log_handle_clear_stats(ovsdb_acl);
            acl_port_map_stats_get(acl_port_map, ofproto);
            method_called = OPS_CLS_STATUS_MSG_OP_CLEAR_STR;
        }
    } else if (!acl_port_map->hw_acl) {
        /* Call PD apply for non-LAG ports in any state but for LAG ports only
         * when all the members are active
         */
        if (!ACL_PORT_IS_LAG(acl_port_map->parent->port) ||
            acl_port_map->parent->lag_members_active) {
            VLOG_DBG("ACL_PORT_MAP %s:%s:%s applying %s",
                 acl_port_map->parent->port->name,
                 ops_cls_type_strings[acl_port_map->acl_db->type],
                 ops_cls_direction_strings[acl_port_map->acl_db->direction],
                 acl->name);
            rc = call_ofproto_ops_cls_apply(acl,
                                            port,
                                            ofproto,
                                            &interface_info,
                                            acl_port_map->acl_db->direction,
                                            &status);
            method_called = OPS_CLS_STATUS_MSG_OP_APPLY_STR;
        }
    } else {
        /* Call PD replace for non-LAG ports in any state but for LAG ports only
         * when all the members are active
         */
        if (!ACL_PORT_IS_LAG(acl_port_map->parent->port) ||
            acl_port_map->parent->lag_members_active) {
            VLOG_DBG("ACL_PORT_MAP %s:%s:%s replacing %s with %s",
                     acl_port_map->parent->port->name,
                     ops_cls_type_strings[acl_port_map->acl_db->type],
                     ops_cls_direction_strings[acl_port_map->acl_db->direction],
                     acl_port_map->hw_acl->name,
                     acl->name);
            rc = call_ofproto_ops_cls_replace(acl_port_map->hw_acl,
                                                  acl,
                                                  port,
                                                  ofproto,
                                                  &interface_info,
                                                  acl_port_map->acl_db->direction,
                                                  &status);
            method_called = OPS_CLS_STATUS_MSG_OP_REPLACE_STR;
        }
    }

    if (method_called == NULL) {
        VLOG_DBG("ACL_PORT_MAP %s:%s:%s no PD call needed",
                 acl_port_map->parent->port->name,
                 ops_cls_type_strings[acl_port_map->acl_db->type],
                 ops_cls_direction_strings[acl_port_map->acl_db->direction]);
    } else if (!strcmp(method_called, OPS_CLS_STATUS_MSG_OP_CLEAR_STR)) {
        /* Set the clear statistics performed column to match clear
         * statistics requested column
         */
        acl_db_util_set_clear_statistics_performed(acl_port_map->acl_db,
                                                   port->cfg,
                                                   clear_req_id);
        /* Print debug messages to note success or failure */
        if (rc == 0) {
             VLOG_DBG("ACL_PORT_MAP %s:%s:%s -- PD %s succeeded",
                  acl_port_map->parent->port->name,
                  ops_cls_type_strings[acl_port_map->acl_db->type],
                  ops_cls_direction_strings[acl_port_map->acl_db->direction],
                  method_called);
        } else {
             VLOG_DBG("ACL_PORT_MAP %s:%s:%s -- PD %s failed",
                  acl_port_map->parent->port->name,
                  ops_cls_type_strings[acl_port_map->acl_db->type],
                  ops_cls_direction_strings[acl_port_map->acl_db->direction],
                  method_called);
        }
    } else if (rc == 0) {
        /* success */
        VLOG_DBG("ACL_PORT_MAP %s:%s:%s -- PD %s succeeded",
                 acl_port_map->parent->port->name,
                 ops_cls_type_strings[acl_port_map->acl_db->type],
                 ops_cls_direction_strings[acl_port_map->acl_db->direction],
                 method_called);
        acl_port_map_set_hw_acl(acl_port_map, acl);
        acl_db_util_set_applied(acl_port_map->acl_db, port->cfg,
                                acl->ovsdb_row);
        /* status_str will be empty string ("") on success */
        acl_port_map_set_cfg_status(acl_port_map, port->cfg,
                                    OPS_CLS_STATE_APPLIED_STR,
                                    status.status_code, status_str);
    } else {
        /* failure */

        /* convert entry_id to sequence_number using cur_aces */
        if(status.entry_id < acl->ovsdb_row->n_cur_aces) {
            sequence_number = acl->ovsdb_row->key_cur_aces[status.entry_id];
        }
        ops_cls_status_msgs_get(status.status_code,
                                method_called,
                                OPS_CLS_STATUS_MSG_FEATURE_ACL_STR,
                                OPS_CLS_STATUS_MSG_IFACE_PORT_STR,
                                acl_port_map->parent->port->name,
                                sequence_number,
                                OPS_CLS_STATUS_MSG_MAX_LEN,
                                status_str);
        VLOG_DBG("ACL_PORT_MAP %s:%s:%s -- PD %s failed",
                 acl_port_map->parent->port->name,
                 ops_cls_type_strings[acl_port_map->acl_db->type],
                 ops_cls_direction_strings[acl_port_map->acl_db->direction],
                 method_called);
        acl_port_map_set_cfg_status(acl_port_map, port->cfg,
                                    OPS_CLS_STATE_REJECTED_STR,
                                    status.status_code, status_str);
    }
}

/**************************************************************************//**
 * This function calls asic plugin API calls for a requested acl port
 * unapply operation. This function is called when a port is deleted.
 *
 * @param[in] acl_port_map - Pointer to the acl_port_map
 * @param[in] port         - Pointer to @see struct port
 * @param[in] ofproto      - Pointer to @see struct ofproto
 *****************************************************************************/
static void
acl_port_map_unapply_internal(struct acl_port_map* acl_port_map,
                              struct port *port, struct ofproto *ofproto)
{
    VLOG_DBG("ACL_PORT_MAP %s:%s:%s unapply",
             acl_port_map->parent->port->name,
             ops_cls_type_strings[acl_port_map->acl_db->type],
             ops_cls_direction_strings[acl_port_map->acl_db->direction]);

    ovs_assert(acl_port_map->hw_acl);

    /* Make the call down to the PD layer */
    struct ops_cls_pd_status status;
    memset(&status, 0, sizeof status);
    struct ops_cls_interface_info interface_info;
    ops_cls_interface_info_construct(&interface_info, acl_port_map->parent,
                                     port);

    int rc = call_ofproto_ops_cls_remove(acl_port_map->hw_acl,
                                         port,
                                         ofproto,
                                         &interface_info,
                                         acl_port_map->acl_db->direction,
                                         &status);
    VLOG_DBG("ACL_PORT_MAP %s:%s:%s -- PD remove %s",
             acl_port_map->parent->port->name,
             ops_cls_type_strings[acl_port_map->acl_db->type],
             ops_cls_direction_strings[acl_port_map->acl_db->direction],
             rc==0 ? "succeeded" : "failed");

    /* Unapply (like delete) often has to be assumed to have succeeded,
     * even if lower levels said it failed. This is because unapply
     * & delete are often called as a knee-jerk reaction to noticing that
     * something has already been deleted.
     *
     * So, ignore rc and clear out our record from the acl.
     */
    acl_port_map_set_hw_acl(acl_port_map, NULL);

    /* In case of a LAG port, the port row is already deleted if the
       the LAG is deleted
     */
    if (!ACL_PORT_IS_LAG(port)) {
        acl_db_util_set_applied(acl_port_map->acl_db, port->cfg, NULL);
        acl_port_map_set_cfg_status(acl_port_map, port->cfg,
                                    rc == 0 ? OPS_CLS_STATE_APPLIED_STR
                                            : OPS_CLS_STATE_REJECTED_STR,
                                    status.status_code, "");
    }
}

/**************************************************************************//**
 * This function applies an ACL to a given port with a given configuration.
 * This is the create call of PI CRUD API.
 *
 * @param[in] acl_port_map - Pointer to the @see struct acl_port_map
 * @param[in] port         - Pointer to @see struct port
 * @param[in] ofproto      - Pointer to @see struct ofproto
 *****************************************************************************/
static void
acl_port_map_cfg_create(struct acl_port_map *acl_port_map, struct port *port,
                        struct ofproto *ofproto)
{
    VLOG_DBG("ACL_PORT_MAP %s:%s:%s - containing port row created",
             acl_port_map->parent->port->name,
             ops_cls_type_strings[acl_port_map->acl_db->type],
             ops_cls_direction_strings[acl_port_map->acl_db->direction]);

    /* no new/alloc to perform. Lifetime of acl_port_map is controlled by
       its containing acl_port */

    acl_port_map_update_cfg_internal(acl_port_map, port, ofproto);
}

/**************************************************************************//**
 * This function updates/replaces an ACL to a given port with a given
 * configuration.
 * This is the update/replace call of PI CRUD API.
 *
 * @param[in] acl_port_map - Pointer to the @see struct acl_port_map
 * @param[in] port         - Pointer to @see struct port
 * @param[in] ofproto      - Pointer to @see struct ofproto
 ******************************************************************************/
void
acl_port_map_cfg_update(struct acl_port_map* acl_port_map, struct port *port,
                        struct ofproto *ofproto)
{
    VLOG_DBG("ACL_PORT_MAP %s:%s:%s - containing port row updated",
             acl_port_map->parent->port->name,
             ops_cls_type_strings[acl_port_map->acl_db->type],
             ops_cls_direction_strings[acl_port_map->acl_db->direction]);

    acl_port_map_update_cfg_internal(acl_port_map, port, ofproto);
}

/**************************************************************************//**
 * This function unapplies an ACL to a given port with a given
 * configuration.
 * This is the delete call of PI CRUD API.
 *
 * @param[in] acl_port_map - Pointer to the @see struct acl_port_map
 * @param[in] port         - Pointer to @see struct port
 * @param[in] ofproto      - Pointer to @see struct ofproto
 *****************************************************************************/
static void
acl_port_map_cfg_delete(struct acl_port_map* acl_port_map, struct port *port,
                        struct ofproto *ofproto)
{
    VLOG_DBG("ACL_PORT_MAP %s:%s:%s deleted",
             acl_port_map->parent->port->name,
             ops_cls_type_strings[acl_port_map->acl_db->type],
             ops_cls_direction_strings[acl_port_map->acl_db->direction]);

    if (acl_port_map->hw_acl) {
        acl_port_map_unapply_internal(acl_port_map, port, ofproto);
    } else {
        VLOG_DBG("ACL_PORT_MAP %s:%s:%s no PD call needed",
                 acl_port_map->parent->port->name,
                 ops_cls_type_strings[acl_port_map->acl_db->type],
                 ops_cls_direction_strings[acl_port_map->acl_db->direction]);
    }

    /* There's nothing to log to OVSDB for a ACL_PORT_MAP:D, the OVSDB row
     * is already gone. */

    /* We don't release/free the acl_port_map* here. It's owned/managed
       by the acl_port structure. */
}

/**************************************************************************//**
 * This function gets ACL statistics for a given port and sets
 * them in the OVSDB
 *
 * @param[in] acl_port_map - Pointer to the @see struct acl_port_map
 * @param[in] ofproto      - Pointer to @see struct ofproto
 *****************************************************************************/
static void
acl_port_map_stats_get(struct acl_port_map *acl_port_map,
                       struct ofproto *ofproto)
{
    struct ops_cls_interface_info interface_info;

    struct ops_cls_pd_list_status status;
    int num_entries;
    int rc;
    struct ops_cls_statistics *statistics;
    int64_t *key_stats;
    int64_t *val_stats;
    int     num_stat_entries = 0, entry_idx;
    char    status_str[OPS_CLS_STATUS_MSG_MAX_LEN];
    unsigned int sequence_number = 0;

    VLOG_DBG("%s: acl_port_map port: %s, type %u direction %u\n",__FUNCTION__,
              acl_port_map->parent->port->name, acl_port_map->acl_db->type,
              acl_port_map->acl_db->direction);


    /* Check if there is an ACL applied to this port map */
    if (!acl_port_map->hw_acl) {
        VLOG_DBG("No ACL applied for port %s, type %u, direction %u\n",
                 acl_port_map->parent->port->name, acl_port_map->acl_db->type,
                 acl_port_map->acl_db->direction);
        return;
    }

    /* Construct the interface info */
    ops_cls_interface_info_construct(&interface_info, acl_port_map->parent,
                                     acl_port_map->parent->port);
    /* Initialize statistics structure */
    num_entries = acl_port_map->hw_acl->ovsdb_row->n_cur_aces;
    statistics = xzalloc(num_entries *
                         sizeof(struct ops_cls_statistics));


    /* Get stats from ASIC layer */
    rc = call_ofproto_ops_cls_statistics_get(acl_port_map->hw_acl,
                                            acl_port_map->parent->port,
                                            ofproto,
                                            &interface_info,
                                            acl_port_map->acl_db->direction,
                                            statistics,
                                            num_entries,
                                            &status);
    if (rc == 0) {
        /* Initialize results for num_entries
         * although, stats enabled entries might be less than num_entries
         * it should be OK considering max num_entries are going to be 512
         * @todo: considering this function gets called every x seconds
         * we can evaluate if we should allocate these structures one time
         * and use them v/s alloc/free in this fucntion i.e. reserving
         * max required memory in advance v/s fragmentation caused by
         * frequent alloc/free.
         */
        key_stats = xzalloc(num_entries * sizeof(int64_t));
        val_stats = xzalloc(num_entries * sizeof(int64_t));

        /* collect stats */
        for(entry_idx = 0; entry_idx < num_entries; entry_idx++) {
            if(statistics[entry_idx].stats_enabled){
                ovs_assert(entry_idx < acl_port_map->hw_acl->ovsdb_row->n_cur_aces);
                key_stats[num_stat_entries] =
                    acl_port_map->hw_acl->ovsdb_row->key_cur_aces[entry_idx];
                val_stats[num_stat_entries] = statistics[entry_idx].hitcounts;
                num_stat_entries++;
            }
        }

        /* Upload stats to ovsdb */
        acl_db_util_set_statistics(acl_port_map->acl_db,
                                   acl_port_map->parent->ovsdb_row,
                                   key_stats, val_stats,
                                   num_stat_entries);

        /* release memory */
        free(key_stats);
        free(val_stats);

   } else {
        /* Error handling
         * Note: statistics operation error is not required to be logged into
         * db status column
         */

        /* convert entry_id to sequence_number using cur_aces */
        if(status.entry_id < acl_port_map->hw_acl->ovsdb_row->n_cur_aces) {
            sequence_number =
                acl_port_map->hw_acl->ovsdb_row->key_cur_aces[status.entry_id];
        }

        ops_cls_status_msgs_get(status.status_code,
            OPS_CLS_STATUS_MSG_OP_GET_STR,
            OPS_CLS_STATUS_MSG_FEATURE_ACL_STAT_STR,
            OPS_CLS_STATUS_MSG_IFACE_PORT_STR,
            acl_port_map->parent->port->name,
            sequence_number,
            OPS_CLS_STATUS_MSG_MAX_LEN,
            status_str);

        /* since this function gets called every x seconds, logging it as
         * a warning instead of error
         */
        VLOG_WARN(status_str);

    }

    /* free memory allocated for statistics */
    free(statistics);
}

/**************************************************************************//**
 * This function unapplies an ACL to a given port with a given
 * configuration when an ACL is deleted.
 *
 * @param[in] acl_port_map - Pointer to the @see struct acl_port_map
 *****************************************************************************/
static void
acl_port_map_unapply_for_acl_cfg_delete(struct acl_port_map* acl_port_map)
{
    VLOG_DBG("ACL_PORT_MAP %s:%s:%s unapply for ACL delete",
             acl_port_map->parent->port->name,
             ops_cls_type_strings[acl_port_map->acl_db->type],
             ops_cls_direction_strings[acl_port_map->acl_db->direction]);

    acl_port_map_cfg_delete(acl_port_map, acl_port_map->parent->port,
                            acl_port_map->parent->port->bridge->ofproto);
}

/**************************************************************************//**
 * Hash map containing all acl_ports
 *****************************************************************************/
static struct shash all_ports = SHASH_INITIALIZER(&all_ports);

struct acl_port *
acl_port_lookup(const char *name)
{
    return ((struct acl_port *)shash_find_data(&all_ports, name));
}

/**************************************************************************//**
 * This function shows all acl_ports in the hash map. Used for debugging.
 * @param[in] conn - Pointer to unixctl connection
 * @param[in] argc - Number of arguments in the command
 * @param[in] argv - Command arguments
 * @param[in] aux  - Aux pointer. Unused for now
 *****************************************************************************/
static void
acl_show_ports(struct unixctl_conn *conn, int argc, const char *argv[],
               void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;
    struct shash_node *node, *next;
    struct acl_port *acl_port;

    SHASH_FOR_EACH_SAFE(node, next, &all_ports) {
        int acl_type_iter;
        acl_port = (struct acl_port *)node->data;
        ds_put_format(&ds, "-----------------------------\n");
        ds_put_format(&ds, "Port name: %s\n", acl_port->port->name);
        for (acl_type_iter = ACL_CFG_MIN_PORT_TYPES;
                acl_type_iter <= ACL_CFG_MAX_PORT_TYPES; ++acl_type_iter) {
            if (acl_port->port_map[acl_type_iter].hw_acl) {
                ds_put_format(&ds, "Applied ACL name (%s): %s\n",
                    acl_db_accessor[acl_type_iter].direction_str,
                    acl_port->port_map[acl_type_iter].hw_acl->name);
            }
        }
    }

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
}

/**************************************************************************//**
 * This function returns the ACL cfg index for a given
 * classifier type and classifer application direction
 *
 * @param[in] type      - classifier type
 * @param[in] direction - direction
 *
 * @return              - An integer value for index
 *                        corresponding to ACL type and
 *                        direction
 *****************************************************************************/
static int
acl_port_map_get_acl_cfg_index(enum ops_cls_type type,
                               enum ops_cls_direction direction)
{
    switch (type) {
      case OPS_CLS_ACL_V4:
        if (direction == OPS_CLS_DIRECTION_IN) {
            return ACL_CFG_PORT_V4_IN;
        } else if (direction == OPS_CLS_DIRECTION_OUT) {
            return ACL_CFG_PORT_V4_OUT;
        }

      case OPS_CLS_ACL_V6:
      default:
        break;
    }

    return ACL_CFG_MAX_TYPES;
}


/**************************************************************************//**
 * This function removes the ACLs that are applied to LAG ifaces
 *
 * @param[in] port                   - Pointer to @see struct port
 * @param[in] acl_port               - Pointer to @see struct acl_port
 * @param[in] ofproto                - Pointer to @see struct ofproto
 * @param[in] port_number            - Open flow port number
 *****************************************************************************/
static void
acl_port_lag_ifaces_acl_remove(struct acl_port *acl_port,
                               struct port *port,
                               struct ofproto *ofproto,
                               ofp_port_t port_number)
{
    struct acl *acl = NULL;
    int rc = 0;
    struct ops_cls_pd_status status;
    struct ops_cls_interface_info interface_info;

    if ((acl_port == NULL) || (port == NULL) || (ofproto == NULL)) {
        return;
    }

    memset(&status, 0, sizeof status);

    ops_cls_interface_info_construct(&interface_info,
                                     acl_port, port);

    /* remove all the ACLs that were successfully applied on the
     * iface
     */
    for (int acl_type_iter = ACL_CFG_MIN_PORT_TYPES;
          acl_type_iter <= ACL_CFG_MAX_PORT_TYPES; acl_type_iter++) {
        const struct ovsrec_acl *ovsdb_acl =
                 acl_db_util_get_cfg(acl_port->port_map[acl_type_iter].acl_db,
                                     port->cfg);
        if (ovsdb_acl == NULL) {
            continue;
        }

        acl = acl_lookup_by_uuid(&ovsdb_acl->header_.uuid);
        if (acl == NULL) {
            continue;
        }

        if(acl_port->port_map[acl_type_iter].hw_acl == acl) {
            rc = call_ofproto_cls_lag_update(
                           acl,
                           port,
                           ofproto,
                           port_number,
                           OPS_CLS_LAG_MEMBER_INTF_DEL,
                           &interface_info,
                           acl_port->port_map[acl_type_iter].acl_db->direction,
                           &status);
            if (rc != 0) {
                VLOG_DBG("ACL remove failed for iface: %d",
                         port_number);
            }
        }
    }
}


/**************************************************************************//**
 * This function processes the LAG iface rollback. It unapplies
 * the ACLs that were successfully applied
 *
 * @param[in] acl_port_map        - Pointer to @see struct acl_port_map
 * @param[in] port                - Pointer to @see struct port
 * @param[in] ofproto             - Pointer to @see struct ofproto
 * @param[in] port_number         - Open flow port number
 *****************************************************************************/
static void
acl_port_lag_ifaces_process_rollback(struct acl_port_map *acl_port_map,
                                     struct port *port,
                                     struct ofproto *ofproto,
                                     ofp_port_t port_number)
{
    struct ops_cls_pd_status status;
    struct ops_cls_interface_info interface_info;
    struct acl_port *acl_port = NULL;
    struct acl *acl = NULL;
    int index = 0;
    int rc = 0;

    if ((acl_port_map == NULL) || (port == NULL) || (ofproto == NULL)) {
        return;
    }

    memset(&status, 0, sizeof status);

    /* Get the acl_port from acl_port_map */
    acl_port = acl_port_map->parent;
    if (acl_port == NULL) {
        return;
    }

    ops_cls_interface_info_construct(&interface_info,
                                     acl_port, port);

    index = acl_port_map_get_acl_cfg_index(acl_port_map->acl_db->type,
                                           acl_port_map->acl_db->direction);
    if(index == ACL_CFG_MAX_TYPES)
    {
        VLOG_DBG("Incorrect index %d for ACL config", index);
        return;
    }

    /* rollback all the ACLs that were successfully applied on this
     * iface
     */
    for (int acl_type_iter = ACL_CFG_MIN_PORT_TYPES;
          acl_type_iter < index; acl_type_iter++) {
        const struct ovsrec_acl *ovsdb_acl =
                acl_db_util_get_cfg(acl_port->port_map[acl_type_iter].acl_db,
                                    port->cfg);
        if (ovsdb_acl == NULL) {
            continue;
        }

        acl = acl_lookup_by_uuid(&ovsdb_acl->header_.uuid);
        if (acl == NULL) {
            continue;
        }

        if(acl_port->port_map[acl_type_iter].hw_acl) {
            rc = call_ofproto_cls_lag_update(
                           acl,
                           port,
                           ofproto,
                           port_number,
                           OPS_CLS_LAG_MEMBER_INTF_DEL,
                           &interface_info,
                           acl_port->port_map[acl_type_iter].acl_db->direction,
                           &status);
            if (rc == 0) {
                /* TODO: Update the DB status for this iface when the
                 * schema changes are available
                 */
            }
        }
    }
}


/**************************************************************************//**
 * This function updates (add or apply) ACLs that are applied to
 * the LAG, to new iface that became part of this LAG port
 *
 * @param[in] port        - Pointer to @see struct port
 * @param[in] acl_port    - Pointer to @see struct acl_port
 * @param[in] ofproto     - Pointer to @see struct ofproto
 * @param[in] port_number - Open flow port number that needs ACL
 *                          updates
 *****************************************************************************/
static void
acl_port_lag_acl_update_and_rollback_if_needed(
    struct acl_port *acl_port,
    struct port *port,
    struct ofproto *ofproto,
    ofp_port_t port_number)
{
    struct acl *acl = NULL;
    int rc = 0;
    struct ops_cls_pd_status status;
    struct ops_cls_interface_info interface_info;

    if ((acl_port == NULL) || (port == NULL) || (ofproto == NULL)) {
        return;
    }

    memset(&status, 0, sizeof status);

    ops_cls_interface_info_construct(&interface_info,
                                     acl_port, port);

    for (int acl_type_iter = ACL_CFG_MIN_PORT_TYPES;
             acl_type_iter <= ACL_CFG_MAX_PORT_TYPES; acl_type_iter++) {
        const struct ovsrec_acl *ovsdb_acl =
            acl_db_util_get_cfg(acl_port->port_map[acl_type_iter].acl_db, port->cfg);
        if (ovsdb_acl == NULL) {
            continue;
        }

        acl = acl_lookup_by_uuid(&ovsdb_acl->header_.uuid);
        if (acl == NULL) {
            continue;
        }

        if (acl_port->port_map[acl_type_iter].hw_acl == NULL) {
            /* Call PD apply for lag port */
            acl_port_map_update_cfg_internal(&acl_port->port_map[acl_type_iter],
                                             port,
                                             ofproto);
        } else if (acl_port->port_map[acl_type_iter].hw_acl == acl) {
            rc = call_ofproto_cls_lag_update(
                           acl,
                           port,
                           ofproto,
                           port_number,
                           OPS_CLS_LAG_MEMBER_INTF_ADD,
                           &interface_info,
                           acl_port->port_map[acl_type_iter].acl_db->direction,
                           &status);
            if (rc != 0) {
                /* Adding the ACL to a new lag member failed. So rollback
                 * if any ACLs were successfully applied
                 */
                acl_port_lag_ifaces_process_rollback(
                             &acl_port->port_map[acl_type_iter],
                             port,
                             ofproto,
                             port_number);
                break;
            }
        }
    }
}


/**************************************************************************//**
 * This function processes the LAG ifaces delete. It builds the
 * list of ifaces that need reconfiguration due to ifaces being
 * deleted from LAG. It calls the PD to remove the ACLs that are
 * applied to this LAG port
 *
 * @param[in] port         - Pointer to @see struct port
 * @param[in] acl_port     - Pointer to @see struct acl_port
 * @param[in] ofproto      - Pointer to @see struct ofproto
 *****************************************************************************/
static void
acl_port_lag_ifaces_process_delete(struct port *port,
                                   struct acl_port *acl_port,
                                   struct ofproto *ofproto)
{
    struct acl_port_interface *acl_port_iface = NULL;

    if ((port == NULL) || (acl_port == NULL) || (ofproto == NULL)) {
        return;
    }

    LIST_FOR_EACH(acl_port_iface, iface_node,
                  &acl_port->port_ifaces) {
        /* Remove ACLs for lag ifaces */
        acl_port_lag_ifaces_acl_remove(acl_port,
                                       port,
                                       ofproto,
                                       acl_port_iface->ofp_port);

        /* Delete the hw_status in interface table for this iface
         * as lag port is getting deleted
         */
        acl_port_lag_iface_delete_intfd_hw_status(acl_port_iface);
    }

    /* Unset the lag members state as lag is getting deleted */
    acl_port->lag_members_active = false;

    /* Unset the hw_acl as none of the lag ifaces are active */
    acl_port_lag_check_and_unset_hw_acl(acl_port);

    /* Unset the cfg_status as the lag is getting deleted */
    acl_port_lag_check_and_delete_cfg_status(acl_port, port);
}


/**************************************************************************//**
 * This function processes the LAG ifaces shutdown. It checks
 * the ifaces that transitioned to shutdown state and calls the
 * PD to remove the ACLs that are applied to this LAG port
 *
 * @param[in] port         - Pointer to @see struct port
 * @param[in] acl_port     - Pointer to @see struct acl_port
 * @param[in] ofproto      - Pointer to @see struct ofproto
 *****************************************************************************/
static void
acl_port_lag_ifaces_process_shutdown(struct port *port,
                                     struct acl_port *acl_port,
                                     struct ofproto *ofproto)
{
    struct iface *iface = NULL;

    if ((port == NULL) || (acl_port == NULL) || (ofproto == NULL)) {
        return;
    }

    if ((list_size(&acl_port->port_ifaces) == 0) &&
        (list_size(&port->ifaces) == 0)) {
        return;
    }

    /* Check if the iface hw_bond_config state transitioned
     * from true to false
     */
    LIST_FOR_EACH(iface, port_elem, &port->ifaces) {
        if(acl_port_lag_iface_changed_to_shutdown_state(iface, acl_port)) {
            acl_port_lag_check_and_set_members_active(acl_port);

            /* Remove ACLs for this lag iface as it is currently shut */
            acl_port_lag_ifaces_acl_remove(acl_port,
                                           port,
                                           ofproto,
                                           iface->ofp_port);
        }
    }

    /* Unset the hw_acl in case none of the lag ifaces are active */
    acl_port_lag_check_and_unset_hw_acl(acl_port);
}


/**************************************************************************//**
 * This function processes the LAG ifaces update. It builds the
 * list of ifaces that need updates as a result of becoming part
 * of LAG port or becoming active. It calls the PD to add or
 * apply the ACLs that are applied to this LAG port
 *
 * @param[in] port         - Pointer to @see struct port
 * @param[in] acl_port     - Pointer to @see struct acl_port
 * @param[in] ofproto      - Pointer to @see struct ofproto
 *****************************************************************************/
static void
acl_port_lag_ifaces_process_update(struct port *port,
                                   struct acl_port *acl_port,
                                   struct ofproto *ofproto)
{
    struct iface *iface = NULL;

    if ((port == NULL) || (acl_port == NULL) || (ofproto == NULL)) {
        return;
    }

    if ((list_size(&acl_port->port_ifaces) == 0) &&
        (list_size(&port->ifaces) == 0)) {
        return;
    }

    LIST_FOR_EACH(iface, port_elem, &port->ifaces) {
        /* Check if the iface hw_bond_config state transitioned
         * from false to true or is it a new iface which got added to lag
         */
        if((acl_port_lag_iface_changed_to_no_shutdown_state(iface, acl_port)) ||
           (acl_port_lag_iface_added(iface, acl_port))) {

            acl_port_lag_check_and_set_members_active(acl_port);

            if (acl_port_lag_iface_hw_bond_config_enabled(iface)) {
                acl_port_lag_acl_update_and_rollback_if_needed(
                                                acl_port,
                                                port,
                                                ofproto,
                                                iface->ofp_port);
            }
        }
    }
}


/**************************************************************************//**
 * This function processes the ifaces removal from a LAG. It
 * builds the list of ifaces that need reconfiguration as a
 * result of moving out of LAG port. It calls the PD to remove
 * the ACLs that are applied to this LAG port
 *
 * @param[in] port         - Pointer to @see struct port
 * @param[in] acl_port     - Pointer to @see struct acl_port
 * @param[in] ofproto      - Pointer to @see struct ofproto
 *****************************************************************************/
static void
acl_port_lag_ifaces_process_remove(struct port *port,
                                   struct acl_port *acl_port,
                                   struct ofproto *ofproto)
{
    struct acl_port_interface *acl_port_iface = NULL;

    if ((port == NULL) || (acl_port == NULL) || (ofproto == NULL)) {
        return;
    }

    if ((list_size(&acl_port->port_ifaces) == 0) &&
        (list_size(&port->ifaces) == 0)) {
        return;
    }

    /* check if any ifaces got removed from lag */
    LIST_FOR_EACH(acl_port_iface, iface_node, &acl_port->port_ifaces) {
        if (acl_port_lag_iface_removed(acl_port_iface, port)) {

            /* Remove ACLs for this lag iface as it is no longer
             * part of the lag port
             */
            if (acl_port_iface->rx_enable && acl_port_iface->tx_enable) {
                acl_port_lag_ifaces_acl_remove(acl_port,
                                               port,
                                               ofproto,
                                               acl_port_iface->ofp_port);
            }

            /* Delete the hw_status in interface table for this iface
             * as it moved out of lag
             */
            acl_port_lag_iface_delete_intfd_hw_status(acl_port_iface);

            /* An existing iface got removed from this lag port. So remove it
             * from the list of ifaces maintained in acl_port, corresponding
             * to the lag port
             */
            acl_port_lag_iface_list_element_remove(acl_port_iface);
        }
    }

    acl_port_lag_check_and_set_members_active(acl_port);

    /* Unset the hw_acl in case none of the lag ifaces are active */
    acl_port_lag_check_and_unset_hw_acl(acl_port);
}


/**************************************************************************//**
 * This function checks if any ifaces within a LAG port, are
 * modified. If yes, it processes the LAG port for shut
 *
 * @param[in] blk_params - Pointer to the block parameters structure
 * @param[in] br         - Pointer to @see struct bridge
 *****************************************************************************/
static void
acl_port_lag_ifaces_check_shutdown(struct blk_params *blk_params,
                                   struct bridge *br)
{
    struct port *port = NULL;
    struct acl_port *acl_port = NULL;
    struct iface *iface = NULL;
    bool port_iface_modified = false;

    if ((blk_params == NULL) || (br == NULL)) {
        return;
    }

    HMAP_FOR_EACH(port, hmap_node, &br->ports) {
        /* In case of a LAG port, need to check if any LAG iface
         * became inactive i.e. shut down. If the LAG port has ACLs
         * applied and one of the ifaces is shut, then ACLs
         * need to be unapplied to that particular iface
         */
        if (ACL_PORT_IS_LAG(port)) {
            acl_port = acl_port_lookup(port->name);
            if (acl_port == NULL) {
                continue;
            }
            LIST_FOR_EACH(iface, port_elem, &port->ifaces) {
                if (OVSREC_IDL_IS_ROW_MODIFIED(iface->cfg,
                                               blk_params->idl_seqno)) {
                    port_iface_modified = true;
                    break;
                }
            }

            /* If an interface table row is modified check and process
             * any LAG iface shut down
             */
            if (port_iface_modified) {
                acl_port_lag_ifaces_process_shutdown(port, acl_port,
                                                     br->ofproto);
            }
        }
    }
}


/**************************************************************************//**
 * This function processes LAG port reconfiguration in case a
 * LAG member with ACL is shutdown. This function is called,
 * when @see bridge_reconfigure() is called from switchd.
 *
 * @param[in] blk_params - Pointer to the block parameters structure
 *****************************************************************************/
void
acl_port_lag_ifaces_shutdown(struct blk_params *blk_params)
{
    struct bridge *br = NULL;
    struct vrf *vrf = NULL;

    if (blk_params == NULL) {
        return;
    }

    HMAP_FOR_EACH(br, node, blk_params->all_bridges) {
        if (br->ofproto == NULL) {
            continue;
        }
        acl_port_lag_ifaces_check_shutdown(blk_params, br);
    }

    HMAP_FOR_EACH(vrf, node, blk_params->all_vrfs) {
        if ((vrf->up == NULL) || (vrf->up->ofproto == NULL)) {
            continue;
        }
        acl_port_lag_ifaces_check_shutdown(blk_params, vrf->up);
    }
}

/**************************************************************************//**
 * This function creates an acl_port when the port is seen for the first time
 * by ACL feature plugin. This function sets up all possible acl-port
 * configuration types as defined in @see acl_db_accessor global array.
 * Also, it adds thew newly created acl_port into all_ports shash for
 * quick lookup.
 *
 * @param[in] port       - Pointer to @see struct port
 * @param[in] seqno      - idl_seqno of the current idl batch
 * @param[in] interface_flags - Interface flags to specify the type of port
 *
 * @returns Pointer to acl_port
 *****************************************************************************/
static struct acl_port*
acl_port_new(struct port *port, unsigned int seqno,
             unsigned int interface_flags)
{
    struct acl_port *acl_port = xzalloc(sizeof *acl_port);

    /* setup my port_map to know about me and which acl_port_map they represent */
    for (int acl_type_iter = ACL_CFG_MIN_PORT_TYPES;
            acl_type_iter <= ACL_CFG_MAX_PORT_TYPES; ++acl_type_iter) {
        acl_port_map_construct(&acl_port->port_map[acl_type_iter], acl_port,
                acl_type_iter);
    }

    acl_port->port = port;
    acl_port->interface_flags |= interface_flags;
    acl_port->ovsdb_row = port->cfg;
    acl_port->delete_seqno = seqno;
    acl_port->lag_members_active = false;

    list_init(&acl_port->port_ifaces);

    /* Create iface list for lag ports */
    if (list_size(&port->ifaces) > 0) {
        acl_port_lag_iface_list_create(acl_port);
    }

    shash_add_assert(&all_ports, port->name, acl_port);
    return acl_port;
}

/**************************************************************************//**
 * This function deletes an acl_port when a delete port is requested.
 * It frees up all memory consumed by the port and removes shash membership.
 *
 * @param[in] acl_port - Port to be deleted
 *****************************************************************************/
static void
acl_port_delete(const char *port_name)
{
    struct acl_port *port = shash_find_and_delete_assert(&all_ports,
                                                         port_name);

    /* cleanup my port_map */
    for (int acl_type_iter = ACL_CFG_MIN_PORT_TYPES;
            acl_type_iter <= ACL_CFG_MAX_PORT_TYPES; ++acl_type_iter) {
        acl_port_map_destruct(&port->port_map[acl_type_iter]);
    }

    /* cleanup port interfaces list */
    acl_port_lag_iface_list_delete(&port->port_ifaces);

    free(port);
}

void acl_callback_port_delete(struct blk_params *blk_params)
{
    /* Handle port deletes here */
    bool have_ports = !shash_is_empty(&all_ports);
    struct acl_port *acl_port;
    struct bridge *br;
    struct port *del_port, *next_del_port;
    struct ovsrec_port *port_cfg;

    if (!have_ports) {
        VLOG_DBG("[%s]No ports to delete", ACL_PLUGIN_NAME);
        return;
    }

    /* Find the list of ports to operate on. Only one out of bridge and vrf
     * is populated at any given point
     */
    if (blk_params->br) {
        br = blk_params->br;
    } else {
        br = blk_params->vrf->up;
    }

    /* Find and delete ACL cfg for the ports that are being deleted */
    HMAP_FOR_EACH_SAFE(del_port, next_del_port, hmap_node, &br->ports) {
        acl_port = acl_port_lookup(del_port->name);
        if (acl_port == NULL) {
            continue;
        }
        port_cfg = shash_find_data(&br->wanted_ports, del_port->name);
        if (port_cfg == NULL) {
            for (int acl_type_iter = ACL_CFG_MIN_PORT_TYPES;
                        acl_type_iter <= ACL_CFG_MAX_PORT_TYPES;
                        ++acl_type_iter) {
                VLOG_DBG("PORT %s deleted", del_port->name);
                acl_port_map_cfg_delete(&acl_port->port_map[acl_type_iter],
                                        del_port, blk_params->ofproto);
            }

            /* In case of a lag port need to unset the hw_status
             * in interface table here
             */
            if (ACL_PORT_IS_LAG(del_port)) {
                struct acl_port_interface *acl_port_iface = NULL;

                LIST_FOR_EACH(acl_port_iface, iface_node,
                  &acl_port->port_ifaces) {
                    /* Delete the hw_status in interface table for the iface
                     * as lag is being deleted
                     */
                    acl_port_lag_iface_delete_intfd_hw_status(acl_port_iface);
                }
            }
            acl_port_delete(del_port->name);
        }
        else {
            if ((ACL_PORT_IS_LAG(del_port)) &&
                (port_cfg->n_interfaces == 0))
            {
                /* This indicates that last interface in lag port
                 * is getting deleted. If the last of the lag port
                 * ifaces is deleted, the port itself will be destroyed.
                 * So in case an ACL is configured to this lag port, we
                 * remove it from h/w and also remove the corresponding
                 * internal hw_acl
                 */
                acl_port_lag_ifaces_process_delete(del_port,
                                                   acl_port,
                                                   blk_params->ofproto);
                acl_port_delete(del_port->name);
            }
        }
    }
}

void
acl_port_unapply_if_needed(struct acl *acl)
{
    struct acl_port_map *port, *next = NULL;

    if (list_is_empty(&acl->acl_port_map)) {
        return;
    }

    LIST_FOR_EACH_SAFE(port, next, acl_node, &acl->acl_port_map) {
        acl_port_map_unapply_for_acl_cfg_delete(port);
    }
}

void acl_callback_port_reconfigure(struct blk_params *blk_params)
{
    struct acl_port            *acl_port;
    struct port                *port = NULL;
    struct bridge              *br;

    /* Find the bridge to work with */
    if (blk_params->br) {
        br = blk_params->br;
    } else {
        br = blk_params->vrf->up;
    }

    /* Port modify routine */
    HMAP_FOR_EACH(port, hmap_node, &br->ports) {
        if (OVSREC_IDL_IS_ROW_MODIFIED(port->cfg, blk_params->idl_seqno)) {
            acl_port = acl_port_lookup(port->name);
            if (acl_port) {

                /* In case of a LAG port, need to check if any ifaces were
                 * moved out of it. If the LAG port has ACLs applied and one
                 * of the ifaces is no longer part of it, then ACLs
                 * need to be unapplied to that particular iface
                 */

                if (ACL_PORT_IS_LAG(port)) {
                    acl_port_lag_ifaces_process_remove(port, acl_port,
                                                       blk_params->ofproto);
                }
                for (int acl_type_iter = ACL_CFG_MIN_PORT_TYPES;
                        acl_type_iter <= ACL_CFG_MAX_PORT_TYPES;
                        ++acl_type_iter) {
                    if (acl_db_util_get_cfg(&acl_db_accessor[acl_type_iter],
                                            port->cfg)) {
                        /* Reconfigure ACL */
                        acl_port->ovsdb_row = port->cfg;
                        acl_port->delete_seqno = blk_params->idl_seqno;
                        VLOG_DBG("PORT %s changed", acl_port->port->name);
                        acl_port_map_cfg_update(
                            &acl_port->port_map[acl_type_iter],
                            port,
                            blk_params->ofproto);
                    } else {
                        /* If the port row modification was unapply ACL, then
                         * this case is hit.
                         */
                         acl_port_map_cfg_delete(
                             &acl_port->port_map[acl_type_iter],
                             port,
                             blk_params->ofproto);
                    }
                }
            }
        }
    }
}

void
acl_callback_port_update(struct blk_params *blk_params)
{
    struct acl_port *acl_port;
    unsigned int interface_flags = 0;

    VLOG_DBG("Port Update called for %s\n", blk_params->port->name);

    acl_port = acl_port_lookup(blk_params->port->name);

    if (!acl_port) {
        if (blk_params->vrf) {
            interface_flags |= OPS_CLS_INTERFACE_L3ONLY;
        }

        /* Create on the port.*/
        struct acl_port *acl_port = acl_port_new(blk_params->port,
                                                 blk_params->idl_seqno,
                                                 interface_flags);
        VLOG_DBG("PORT %s created", blk_params->port->cfg->name);

        /* Apply if ACL is configured on the port.*/
        for (int acl_type_iter = ACL_CFG_MIN_PORT_TYPES;
                acl_type_iter <= ACL_CFG_MAX_PORT_TYPES;
                ++acl_type_iter) {
            if (acl_db_util_get_cfg(&acl_db_accessor[acl_type_iter],
                                    blk_params->port->cfg)) {
                 acl_port_map_cfg_create(&acl_port->port_map[acl_type_iter],
                                          blk_params->port,
                                          blk_params->ofproto);
            }
        }
    }
    else {

        /* In case of a lag port, need to check if any new ifaces were
         * made part of it or existing iface in lag became active
         * (i.e. hw_bond_config is enabled). If the lag port has ACLs
         * applied and a new iface gets added or existing iface becomes
         * active, then ACLs need to be applied to that particular iface
         */
        if (ACL_PORT_IS_LAG(blk_params->port)) {
            acl_port_lag_ifaces_process_update(blk_params->port,
                                               acl_port,
                                               blk_params->ofproto);
        }
    }
}

void
acl_callback_port_stats_get(struct stats_blk_params *sblk,
                            enum stats_block_id blk_id)
{
    struct bridge *br;
    struct acl_port *acl_port;

    /* Get the bridge to work with */
    if (blk_id == STATS_PER_BRIDGE_PORT) {
        br = sblk->br;
    } else {
        br = sblk->vrf->up;
    }

    /* Get the ACL port based on given port */
    acl_port = acl_port_lookup(sblk->port->name);
    if (!acl_port) {
        VLOG_DBG("Stats get not needed for port %s\n", sblk->port->name);
        return;
    }
    /* Get statistics for this port if needed */
    for (int acl_type_iter = ACL_CFG_MIN_PORT_TYPES;
            acl_type_iter <= ACL_CFG_MAX_PORT_TYPES; ++acl_type_iter) {
        acl_port_map_stats_get(&acl_port->port_map[acl_type_iter], br->ofproto);
    }
}

void
acl_port_debug_init()
{
    /* Dump acl_port shash */
    unixctl_command_register("acl_plugin/show_port", NULL, 0, 1,
                             acl_show_ports, NULL);
}
