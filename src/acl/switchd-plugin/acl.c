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

#include "acl.h"
#include "smap.h"
#include "vswitch-idl.h"
#include "openvswitch/vlog.h"
#include "ofproto/ofproto-provider.h"
#include "ops-cls-asic-plugin.h"
#include "acl_parse.h"
#include "acl_ofproto.h"
#include "reconfigure-blocks.h"
#include "acl_plugin.h"
#include "acl_port.h"
#include "ops_cls_status_msgs.h"
#include "ops_cls_status_table.h"
#include "acl_db_util.h"
#include "bridge.h"
#include "vrf.h"

VLOG_DEFINE_THIS_MODULE(acl_switchd_plugin_global);

/**************************************************************************//**
 * This function parses and validates the ipv4 address
 *
 * @param[in]   in_address - Pointer to string containig ipv4
 *                           address
 * @param[in]   flag       - Indicates valid src or dest ipv4
 *                           address
 * @param[out]  flags      - Contains valid src or dest ipv4
 *                           address
 * @param[in]   v4_addr    - Pointer to @see struct in_addr
 * @param[in]   v4_mask    - Pointer to @see struct in_addr
 * @param[out]  family     - Pointer to @see enum
 *                           ops_cls_addr_family
 *
 * @return      true       - If the ipv4 address is valid
                false      - If the address is not valid
 *****************************************************************************/
static bool
acl_parse_ipv4_address(const char *in_address,
                       uint32_t flag,
                       uint32_t *flags,
                       struct in_addr *v4_addr,
                       struct in_addr *v4_mask,
                       enum ops_cls_addr_family *family)
{
    char tmp_str[INET_ADDRSTRLEN*2]; /* Fits address, '/', mask, and NULL */
    char *slash_ptr;
    char *mask_substr = NULL;

    /* NULL address taken to mean "any"; return without setting flags */
    if (!in_address) {
        return true;
    }

    *flags |= flag;
    *family = OPS_CLS_AF_INET;

    /* Get a copy of the string we can do destructive things to */
    strncpy(tmp_str, in_address, INET_ADDRSTRLEN*2);

    /* Find the slash character (if any) in input */
    slash_ptr = strchr(tmp_str, '/');
    if (slash_ptr) {
        slash_ptr[0] = '\0'; /* Replace slash with NULL to split strings */
        mask_substr = &slash_ptr[1]; /* Point to mask string for parsing */
    } else {
        VLOG_ERR("Invalid IPv4 address string %s: expected 'A.B.C.D/W.X.Y.Z'", tmp_str);
        return false;
    }

    if (!inet_pton(AF_INET, tmp_str, v4_addr)) {
        VLOG_ERR("Invalid IPv4 address %s in DB", tmp_str);
        return false;
    }

    if (!inet_pton(AF_INET, mask_substr, v4_mask)) {
        VLOG_ERR("Invalid IPv4 mask %s in DB", mask_substr);
        return false;
    }

    return true;
}

/**************************************************************************//**
 * This function parses the actions and populates the action
 * flags in the classifier acl list
 *
 * @param[in]   acl_entry  - Pointer to @see struct
 *                           ovsrec_acl_entry
 * @param[in]   actions    - Pointer to @see struct
 *                           ops_cls_list_entry_actions
 *
 * @return      true       - If the action is valid
 *****************************************************************************/
static bool
acl_parse_actions(const struct ovsrec_acl_entry *acl_entry,
                  struct ops_cls_list_entry_actions *actions)
{
    if (acl_entry->action) {
        if (strstr(acl_entry->action, "permit")) {
            actions->action_flags |= OPS_CLS_ACTION_PERMIT;
        } else if (strstr(acl_entry->action, "deny")) {
            actions->action_flags |= OPS_CLS_ACTION_DENY;
        }
    }

    if (acl_entry->log) {
        actions->action_flags |= OPS_CLS_ACTION_LOG;
    }

    if (acl_entry->count) {
        actions->action_flags |= OPS_CLS_ACTION_COUNT;
    }

    return true;
}

/**************************************************************************//**
 * This function populates classifier ACL list entry from the
 * OVSDB acl entry data
 *
 * @param[in]   entry     - Pointer to @see struct
 *                          ops_cls_list_entry
 * @param[in]   acl_entry - Pointer to @see struct
 *                          ovsrec_acl_entry
 *
 * @return      true      - If source and destination ipv4
 *                          addresses are valid and action is
 *                          valid
 *              false     - In case of invalid addresses or
 *                          action
 *****************************************************************************/
static bool
populate_entry_from_acl_entry(struct ops_cls_list_entry *entry,
                              const struct ovsrec_acl_entry *acl_entry)
{
    bool valid = true;

    if (!acl_parse_ipv4_address
        (acl_entry->src_ip,
         OPS_CLS_SRC_IPADDR_VALID,
         &entry->entry_fields.entry_flags,
         &entry->entry_fields.src_ip_address.v4,
         &entry->entry_fields.src_ip_address_mask.v4,
         &entry->entry_fields.src_addr_family)) {
        VLOG_ERR("invalid source ip addr %s", acl_entry->src_ip);
        valid = false;
    }
    if (!acl_parse_ipv4_address
        (acl_entry->dst_ip,
         OPS_CLS_DEST_IPADDR_VALID,
         &entry->entry_fields.entry_flags,
         &entry->entry_fields.dst_ip_address.v4,
         &entry->entry_fields.dst_ip_address_mask.v4,
         &entry->entry_fields.dst_addr_family)) {
        VLOG_ERR("invalid destination ip addr %s", acl_entry->dst_ip);
        valid = false;
    }

    /* No protocol specified for IPv4 entry taken to mean "any" */
    if (acl_entry->n_protocol > 0)
    {
        entry->entry_fields.protocol = acl_entry->protocol[0];
        entry->entry_fields.entry_flags |= OPS_CLS_PROTOCOL_VALID;
    }

    if (!acl_parse_actions(acl_entry,
                           &entry->entry_actions)) {
        VLOG_ERR("invalid action %s", acl_entry->action);
        valid = false;
    }

    if (acl_entry->n_src_l4_port_min
            && acl_entry->src_l4_port_min)
    {
        entry->entry_fields.L4_src_port_op = OPS_CLS_L4_PORT_OP_EQ;
        entry->entry_fields.entry_flags |= OPS_CLS_L4_SRC_PORT_VALID;
        entry->entry_fields.L4_src_port_min = acl_entry->src_l4_port_min[0];
    }

    if (acl_entry->n_src_l4_port_max
            && acl_entry->src_l4_port_max
            && acl_entry->src_l4_port_min[0] != acl_entry->src_l4_port_max[0])
    {
        /* assumes port min was specified, so changes operator to range */
        entry->entry_fields.L4_src_port_op = OPS_CLS_L4_PORT_OP_RANGE;
        entry->entry_fields.entry_flags |= OPS_CLS_L4_SRC_PORT_VALID;
        entry->entry_fields.L4_src_port_max = acl_entry->src_l4_port_max[0];
    }

    if (acl_entry->n_src_l4_port_range_reverse
            && acl_entry->src_l4_port_range_reverse)
    {
        /* it assumes that CLI has validated port min and max are the same */
        entry->entry_fields.L4_src_port_op = OPS_CLS_L4_PORT_OP_NEQ;
    }


    if (acl_entry->n_dst_l4_port_min
            && acl_entry->dst_l4_port_min)
    {
        entry->entry_fields.L4_dst_port_op = OPS_CLS_L4_PORT_OP_EQ;
        entry->entry_fields.entry_flags |= OPS_CLS_L4_DEST_PORT_VALID;
        entry->entry_fields.L4_dst_port_min = acl_entry->dst_l4_port_min[0];
    }

    if (acl_entry->n_dst_l4_port_max
            && acl_entry->dst_l4_port_max
            && acl_entry->dst_l4_port_min[0] != acl_entry->dst_l4_port_max[0])
    {
        /* assumes port min was specified, so changes operator to range */
        entry->entry_fields.L4_dst_port_op = OPS_CLS_L4_PORT_OP_RANGE;
        entry->entry_fields.entry_flags |= OPS_CLS_L4_DEST_PORT_VALID;
        entry->entry_fields.L4_dst_port_max = acl_entry->dst_l4_port_max[0];
    }

    if (acl_entry->n_dst_l4_port_range_reverse
            && acl_entry->dst_l4_port_range_reverse)
    {
        /* it assumes that CLI has validated port min and max are the same */
        entry->entry_fields.L4_dst_port_op = OPS_CLS_L4_PORT_OP_NEQ;
    }

    return valid;
}

/**************************************************************************//**
 * This function builds a classifier ACL list from the PI ACL
 * data
 *
 * @param[in]   acl  - Pointer to @see struct acl
 *
 * @return             Pointer to struct ops_cls_list or NULL
 *****************************************************************************/
static struct ops_cls_list*
ops_cls_list_new_from_acl(struct acl *acl)
{
    const struct ovsrec_acl *acl_row = acl->ovsdb_row;
    bool valid = true;
    size_t n_aces = acl_row->n_in_progress_aces;

    struct ops_cls_list *list = ops_cls_list_new();
    if (!list) {
        VLOG_ERR("Failed to allocate new acl list in software for %s\n",
                    acl_row->name);
        return NULL;
    }

    list->list_id = acl->uuid;
    list->list_name = xstrdup(acl->name);
    list->list_type = acl->type;


    /* allocate our PI entries and convert from acl_entry idl cache */
    list->num_entries = n_aces + 1; /* +1 for implicit deny all */
    list->entries = xzalloc(list->num_entries * sizeof *list->entries);
    for (int i = 0; i < n_aces; ++i) {
        struct ops_cls_list_entry *entry = &list->entries[i];

        if (!populate_entry_from_acl_entry(entry,
                                   acl_row->value_in_progress_aces[i])) {
            /* VLOG_ERR already emitted */
            valid = false;
            break;
        }
    }

    /* add implicit deny all to end */
    list->entries[n_aces].entry_actions.action_flags =
                                               OPS_CLS_ACTION_DENY;

    if (!valid) {
        ops_cls_list_delete(list);
        list = NULL;
    }

    return list;
}

/*************************************************************
 * acl lookup routines
 *************************************************************/
static struct hmap all_acls_by_uuid = HMAP_INITIALIZER(&all_acls_by_uuid);

/**************************************************************************//**
 * This function looks up an ACL in the global hashmap based on
 * uuid
 *
 * @param[in]   uuid  - Pointer to @see struct uuid
 *
 * @return              Pointer to struct acl or NULL
 *****************************************************************************/
struct acl *
acl_lookup_by_uuid(const struct uuid* uuid)
{
    struct acl *acl;

    if (!uuid) {
        return NULL;
    }

    HMAP_FOR_EACH_WITH_HASH(acl, all_node_uuid, uuid_hash(uuid),
                            &all_acls_by_uuid) {
        if (uuid_equals(&acl->uuid, uuid)) {
            return acl;
        }
    }
    return NULL;
}

/**************************************************************************//**
 * This function returns ACL type for a given protocol string
 *
 * @param[in]   str  - Pointer to a string containing protocol
 *
 * @return      ops_cls_type
 *****************************************************************************/
static enum ops_cls_type
acl_type_from_string(const char *str)
{
    if (strcmp(str, "ipv4")==0) {
        return OPS_CLS_ACL_V4;
    } else if (strcmp(str, "ipv6")==0) {
        return OPS_CLS_ACL_V6;
    } else {
        return OPS_CLS_ACL_INVALID;
    }
}

/**************************************************************************//**
 * This function creates an ACL in PI data structures. It
 * doesn't make any PD call
 *
 * @param[in]   ovsdb_row    - Pointer to @see struct ovsrec_acl
 * @param[in]   seqno        - IDL batch sequence number
 *****************************************************************************/
static struct acl*
acl_create(const struct ovsrec_acl *ovsdb_row, unsigned int seqno)
{
    struct acl *acl = xzalloc(sizeof *acl);
    acl->uuid = ovsdb_row->header_.uuid;
    acl->name = xstrdup(ovsdb_row->name); /* we can outlive ovsdb row */
    acl->type = acl_type_from_string(ovsdb_row->list_type);

    acl->ovsdb_row = ovsdb_row;
    acl->delete_seqno = seqno;
    acl->in_progress_version = 0;

    list_init(&acl->acl_port_map);
    acl->cfg_pi = ops_cls_list_new_from_acl(acl);

    /* link myself into all the lists/maps I'm supposed to be in */
    hmap_insert(&all_acls_by_uuid, &acl->all_node_uuid, uuid_hash(&acl->uuid));

    return acl;
}

/**************************************************************************//**
 * This function deletes the ACL data from PI data structures.
 * It doesn't make any PD call
 *
 * @param[in]   acl      - Pointer to @see struct acl
 *****************************************************************************/
static void
acl_delete(struct acl* acl)
{
    /* Only during a polite shutdown (which doesn't exist yet)
     * should we be doing low-level teardown on PI records that
     * are still interconnected.
     *
     * And even in that case, we'll need to make sure we teardown
     * acl_ports (and their contained @see acl_port_map record) before we
     * teardown the ACL records.
     */
    ovs_assert(list_is_empty(&acl->acl_port_map));

    hmap_remove(&all_acls_by_uuid, &acl->all_node_uuid);

    /* free up my cached copy of the PI API struct */
    ops_cls_list_delete(acl->cfg_pi);

    free(CONST_CAST(char *, acl->name));
    free(acl);
}

/**************************************************************************//**
 * This function sets ACL configuration status in OVSDB
 *
 * @param[in]   row      - Pointer to @see struct ovsrec_acl
 * @param[in]   state    - State of the config status
 * @param[in]   code     - Code of the config status
 * @param[in]   details  - Buffer containing the config
 *                         status message
 *****************************************************************************/
static void
acl_set_cfg_status(const struct ovsrec_acl *row, char *state,
                   unsigned int code, char *details)
{
    char code_str[OPS_CLS_CODE_STR_MAX_LEN];
    char version[OPS_CLS_VERSION_STR_MAX_LEN];

    ovsrec_acl_update_status_setkey(row, OPS_CLS_STATUS_STR, state);
    snprintf(version, OPS_CLS_VERSION_STR_MAX_LEN,
             "%" PRId64"", row->in_progress_version[0]);
    ovsrec_acl_update_status_setkey(row, OPS_CLS_STATUS_VERSION_STR, version);
    ovsrec_acl_update_status_setkey(row, OPS_CLS_STATUS_STATE_STR, state);
    snprintf(code_str, OPS_CLS_CODE_STR_MAX_LEN, "%u", code);
    ovsrec_acl_update_status_setkey(row, OPS_CLS_STATUS_CODE_STR, code_str);
    ovsrec_acl_update_status_setkey(row, OPS_CLS_STATUS_MSG_STR, details);
}

/**************************************************************************//**
 * This function is called when there is an ACL config update.
 * It checks if there is a port in a bridge on which application
 * of this ACL was previously unsuccessful. If such a port is
 * found, it tries to reapply the acl, since the ACL has been
 * reconfigured.
 *
 * @param[in]   acl           - Pointer to @see struct acl
 * @param[in]   br            - Pointer to @see struct bridge
 * @param[in]   delete_seqno  - IDL batch sequence number
 *****************************************************************************/
static void
acl_cfg_check_ports_and_apply(struct acl *acl, struct bridge *br,
                              unsigned int delete_seqno)
{
    struct port *port = NULL;
    struct acl_port *acl_port = NULL;

    if ((acl == NULL) || (br == NULL)) {
        return;
    }

    HMAP_FOR_EACH(port, hmap_node, &br->ports) {
        acl_port = acl_port_lookup(port->name);
        if (acl_port == NULL) {
            continue;
        }
        for (int acl_type_iter = ACL_CFG_MIN_PORT_TYPES;
              acl_type_iter <= ACL_CFG_MAX_PORT_TYPES; acl_type_iter++) {
            const struct ovsrec_acl *acl_row = acl_db_util_get_cfg(
                                               &acl_db_accessor[acl_type_iter],
                                               port->cfg);
            if (acl_row == NULL) {
                continue;
            }

            /* check if the acl configured on the port matches the
             * acl that got updated
             */
            if ((strlen(acl->name) == strlen(acl_row->name)) &&
                (strncmp(acl->name, acl_row->name, strlen(acl->name)) == 0)) {
                const struct smap acl_status =
                    acl_db_util_get_cfg_status(&acl_db_accessor[acl_type_iter],
                                               port->cfg);
                const char *status_str = smap_get(&acl_status,
                                               OPS_CLS_STATUS_CODE_STR);

                /* check if the acl application status on the port
                 * was not successful
                 */
                if (status_str) {
                    if (strtoul(status_str, NULL, 10) !=
                            OPS_CLS_STATUS_SUCCESS) {
                        acl_port->ovsdb_row = port->cfg;
                        acl_port->delete_seqno = delete_seqno;

                        VLOG_DBG("ACL row corresponding to port %s updated",
                                 port->name);

                        acl_port_map_cfg_update(
                                &acl_port->port_map[acl_type_iter],
                                port,
                                br->ofproto);
                    }
                }
            }
        }
    }
}

/**************************************************************************//**
 * This function loops through all bridges and vrfs to check if
 * the ACL needs to be applied on any ports
 *
 * @param[in]   acl           - Pointer to @see struct acl
 * @param[in]   blk_params    - Pointer to @see struct blk_params
 *****************************************************************************/
static void
acl_cfg_apply_if_needed(struct acl *acl, struct blk_params *blk_params)
{
    struct bridge *br = NULL;
    struct vrf *vrf = NULL;

    if ((acl == NULL) || (blk_params == NULL)) {
        return;
    }

    HMAP_FOR_EACH(br, node, blk_params->all_bridges) {
        if (br->ofproto == NULL) {
            continue;
        }
        acl_cfg_check_ports_and_apply(acl, br, blk_params->idl_seqno);
    }

    HMAP_FOR_EACH(vrf, node, blk_params->all_vrfs) {
        if ((vrf->up == NULL) || (vrf->up->ofproto == NULL)) {
            continue;
        }
        acl_cfg_check_ports_and_apply(acl, vrf->up, blk_params->idl_seqno);
    }
}

/**************************************************************************//**
 * This function handles ACL config update by making PD API call
 * if there are ports on which this acl was either successfully
 * applied or rejected. It also updates ovsdb for the status
 *
 * @param[in]   acl           - Pointer to @see struct acl
 * @param[in]   blk_params    - Pointer to @see struct blk_params
 *****************************************************************************/
static void
acl_cfg_update(struct acl* acl, struct blk_params* blk_params)
{
    /* Always translate/validate user input, so we can fail early
     * on unsupported values */

    char details[256];
    char status_str[OPS_CLS_STATUS_MSG_MAX_LEN] = {0};
    unsigned int sequence_number = 0;
    struct ops_cls_list *saved_list = NULL;
    struct ops_cls_list *list = ops_cls_list_new_from_acl(acl);

    if (!list) {
        snprintf(status_str,OPS_CLS_STATUS_MSG_MAX_LEN,
                 ops_cls_status_table_get(OPS_CLS_STATUS_LIST_PARSE_ERR),
                 acl->name);
        VLOG_WARN(status_str);

        acl_set_cfg_status(acl->ovsdb_row, OPS_CLS_STATE_REJECTED_STR,
                           OPS_CLS_STATUS_LIST_PARSE_ERR, status_str);
        return;
    }

    /* save old PI cache of API obj, and remember new one */
    saved_list = acl->cfg_pi;
    acl->cfg_pi = list;

    if (!list_is_empty(&acl->acl_port_map)) {
        /* Make the call down to the PD layer so it can change the
         * application of this ACL on all related ports.
         */
        struct ops_cls_pd_list_status status;
        memset(&status, 0, sizeof status);
        int rc = call_ofproto_ops_cls_list_update(acl, &status);

        if (rc == 0) {
            snprintf(details, sizeof(details),
                    "ACL %s -- PD list_update succeeded", acl->name);
            VLOG_DBG(details);
            ovsrec_acl_set_cur_aces(acl->ovsdb_row,
                                    acl->ovsdb_row->key_in_progress_aces,
                                    acl->ovsdb_row->value_in_progress_aces,
                                    acl->ovsdb_row->n_in_progress_aces);
            /* status_str will be NULL on success */
            acl_set_cfg_status(acl->ovsdb_row, OPS_CLS_STATE_APPLIED_STR,
                               0, status_str);

            /* Apply the updated ACL on ports that are applicable */
            acl_cfg_apply_if_needed(acl, blk_params);

            ops_cls_list_delete(saved_list);

        } else {
            snprintf(details, sizeof(details),
                    "ACL %s -- PD list_update failed for"
                    " acl entry = %u", acl->name,
                     status.entry_id);
            VLOG_DBG(details);
            /* Convert entry_id to sequence_number using in_progress aces */
            if(status.entry_id < acl->ovsdb_row->n_in_progress_aces) {
                sequence_number =
                    acl->ovsdb_row->key_in_progress_aces[status.entry_id];
            }
            ops_cls_status_msgs_get(status.status_code,
                                    OPS_CLS_STATUS_MSG_OP_UPDATE_STR,
                                    OPS_CLS_STATUS_MSG_FEATURE_ACL_STR,
                                    OPS_CLS_STATUS_MSG_IFACE_PORT_STR,
                                    NULL,
                                    sequence_number,
                                    OPS_CLS_STATUS_MSG_MAX_LEN,status_str);
            acl_set_cfg_status(acl->ovsdb_row, OPS_CLS_STATE_REJECTED_STR,
                               status.status_code, status_str);

            ops_cls_list_delete(acl->cfg_pi);
            acl->cfg_pi = saved_list;
        }
    }
    else {
        acl_cfg_apply_if_needed(acl, blk_params);

        ovsrec_acl_set_cur_aces(acl->ovsdb_row,
                                acl->ovsdb_row->key_in_progress_aces,
                                acl->ovsdb_row->value_in_progress_aces,
                                acl->ovsdb_row->n_in_progress_aces);
        /* status_str will be NULL on success */
        acl_set_cfg_status(acl->ovsdb_row, OPS_CLS_STATE_APPLIED_STR,
                           0, status_str);
        ops_cls_list_delete(saved_list);
    }
}

/**************************************************************************//**
 * This function handles ACL config delete by calling
 * acl_delete, that deals with the PI data structures only
 *
 * @param[in]   acl   - Pointer to @see struct acl
 *****************************************************************************/
static void
acl_cfg_delete(struct acl* acl)
{
    VLOG_DBG("ACL %s deleted", acl->name);

    acl_port_unapply_if_needed(acl);
    acl_delete(acl);
}

/**************************************************************************//**
 * This function is the ACL feature plugin callback to handle
 * updates in the ACL table. It is registered with the switchd.
 *
 * @param[in]   blk_params   - Pointer to @see struct blk_params
 *****************************************************************************/
void
acl_reconfigure_init(struct blk_params *blk_params)
{
    /* Quick check for ACL table changes */
    bool acls_created;
    bool acls_updated;
    bool acls_deleted;
    struct ovsdb_idl *idl;
    unsigned int idl_seqno;
    bool have_acls = !hmap_is_empty(&all_acls_by_uuid);

    /* Get idl and idl_seqno to work with */
    idl = blk_params->idl;
    idl_seqno = blk_params->idl_seqno;

    const struct ovsrec_acl *acl_row = ovsrec_acl_first(idl);
    if (acl_row) {
        acls_created = OVSREC_IDL_ANY_TABLE_ROWS_INSERTED(acl_row, idl_seqno);
        acls_updated = OVSREC_IDL_ANY_TABLE_ROWS_MODIFIED(acl_row, idl_seqno);

        /* We only care about acls_deleted if we already have some acls. */
        acls_deleted = have_acls &&
            OVSREC_IDL_ANY_TABLE_ROWS_DELETED(acl_row, idl_seqno);
    } else {
        /* There are no ACL rows in OVSDB. */
        acls_created = false;
        acls_updated = false;
        acls_deleted = have_acls;
    }

    /* Check if we need to process any ACL:[CU]
     *   - ACL:C will show up as acls_created
     *   - ACL:U might not exist outside ACE:[CD]. Can an ACL's name or type
     *     be changed?
     * We also have to traverse if acls_deleted in order to mark/sweep.
     */
    if (acls_created || acls_updated || acls_deleted) {
        const struct ovsrec_acl *acl_row_next;
        bool row_changed;
        OVSREC_ACL_FOR_EACH_SAFE(acl_row, acl_row_next, idl) {
            struct acl *acl = acl_lookup_by_uuid(&acl_row->header_.uuid);
            if (!acl) {
                acl = acl_create(acl_row, idl_seqno);
                row_changed = true;
            } else {
                /* Always update these, even if nothing else has changed,
                 * The ovsdb_row may have changed out from under us.
                 * delete_seqno is use as mark/sweep to delete unused ACLs.
                 */
                acl->ovsdb_row = acl_row;
                acl->delete_seqno = idl_seqno;

                /* Check if this is an ACL:[CU] */
                row_changed =
                    (OVSREC_IDL_IS_ROW_MODIFIED(acl_row, idl_seqno) ||
                     OVSREC_IDL_IS_ROW_INSERTED(acl_row, idl_seqno));
            }
            if (row_changed && acl_row->n_in_progress_version > 0 &&
                acl_row->in_progress_version[0] >
                                   acl->in_progress_version) {
                acl_cfg_update(acl, blk_params);
                acl->in_progress_version = acl_row->in_progress_version[0];
            }
        }
    } else {
        VLOG_DBG("No changes in ACL table");
    }

    /* Detect any ACL:D by sweeping looking for old delete_seqno. */
    if (acls_deleted) {
        struct acl *acl, *next_acl;
        HMAP_FOR_EACH_SAFE (acl, next_acl, all_node_uuid, &all_acls_by_uuid) {
            if (acl->delete_seqno < idl_seqno) {
                acl_cfg_delete(acl);
            }
        }
    }
}
