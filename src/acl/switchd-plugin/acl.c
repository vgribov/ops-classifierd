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

VLOG_DEFINE_THIS_MODULE(acl_switchd_plugin_global);

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

static bool
acl_parse_actions(const struct ovsrec_acl_entry *acl_entry,
                  struct ops_cls_list_entry_actions *actions)
{
    if (acl_entry->action) {
        if (strstr(acl_entry->action, "permit")) {
            actions->action_flags |= OPS_CLS_ACTION_PERMIT;
        } else {
            if (strstr(acl_entry->action, "deny")) {
                actions->action_flags |= OPS_CLS_ACTION_DENY;
            }
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

struct acl *
acl_lookup_by_uuid(const struct uuid* uuid)
{
    struct acl *acl;

    HMAP_FOR_EACH_WITH_HASH(acl, all_node_uuid, uuid_hash(uuid),
                            &all_acls_by_uuid) {
        if (uuid_equals(&acl->uuid, uuid)) {
            return acl;
        }
    }
    return NULL;
}


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

/************************************************************
 * acl_create() and acl_delete() are low-level routines that deal with PI
 * acl data structures. They take care off all the memorary
 * management, hmap memberships, etc. They DO NOT make any PD calls.
 ************************************************************/
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

/************************************************************
 * This function handles acl config update by making PD API
 * call and then updating ovsdb for the status
 ************************************************************/
static void
acl_cfg_update(struct acl* acl)
{
    /* Always translate/validate user input, so we can fail early
     * on unsupported values */

    char details[256];
    char status_str[OPS_CLS_STATUS_MSG_MAX_LEN] = {0};
    unsigned int sequence_number = 0;
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

    /* delete old PI cache of API obj, and remember new one */
    ops_cls_list_delete(acl->cfg_pi);
    acl->cfg_pi = list;

    if (!list_is_empty(&acl->acl_port_map)) {
        /* Make the call down to the PD layer so it can change the
         * application of this ACL on all related ports.
         */
        struct ops_cls_pd_list_status status;
        memset(&status, 0, sizeof status);
        int rc = call_ofproto_ops_cls_list_update(acl, &status);

        if (rc == 0) {
            sprintf(details, "ACL %s -- PD list_update succeeded", acl->name);
            VLOG_DBG(details);
            ovsrec_acl_set_cur_aces(acl->ovsdb_row,
                                    acl->ovsdb_row->key_in_progress_aces,
                                    acl->ovsdb_row->value_in_progress_aces,
                                    acl->ovsdb_row->n_in_progress_aces);
            /* status_str will be NULL on success */
            acl_set_cfg_status(acl->ovsdb_row, OPS_CLS_STATE_APPLIED_STR,
                               0, status_str);
        } else {
            sprintf(details, "ACL %s -- PD list_update failed for"
                    " acl entry = %u and port = %s", acl->name,
                     status.entry_id, netdev_get_name(status.port->netdev));
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
                                    netdev_get_name(status.port->netdev),
                                    sequence_number,
                                    OPS_CLS_STATUS_MSG_MAX_LEN,status_str);
            acl_set_cfg_status(acl->ovsdb_row, OPS_CLS_STATE_REJECTED_STR,
                               status.status_code, status_str);
        }
    } else {
        sprintf(details, "ACL %s -- Not applied. No PD call necessary",
                acl->name);
        VLOG_DBG(details);
        ovsrec_acl_set_cur_aces(acl->ovsdb_row,
                                acl->ovsdb_row->key_in_progress_aces,
                                acl->ovsdb_row->value_in_progress_aces,
                                acl->ovsdb_row->n_in_progress_aces);
        /* status_str will be NULL on success */
        acl_set_cfg_status(acl->ovsdb_row, OPS_CLS_STATE_APPLIED_STR, 0, status_str);
    }
}

/************************************************************
 * This function handles acl config delete by calling
 * acl_delete  that deals with the PI data structures only.
 ************************************************************/
static void
acl_cfg_delete(struct acl* acl)
{
    VLOG_DBG("ACL %s deleted", acl->name);

    acl_port_unapply_if_needed(acl);
    acl_delete(acl);
}

/************************************************************
 * Top level routine to check if ACLs need to reconfigure
 ************************************************************/
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
            if (row_changed && acl_row->in_progress_version[0] >
                                   acl->in_progress_version) {
                acl_cfg_update(acl);
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
