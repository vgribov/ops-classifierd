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

#include <stddef.h>
#include "vswitch-idl.h"
#include "acl_db_util.h"

/**
 * Global array of groups of DB access routines. There will be one entry
 * in this array per (type, direction) pair of an ACL. This array is used
 * by the switchd plugin to access the quartet columns of ovsrec_port row
 * for a given (type, direction) type easily.
 */
struct acl_db_util acl_db_accessor[ACL_CFG_MAX_TYPES];

/**
 * Macro to populate the acl_db_accessor global array at switchd-plugin
 * init time.
 */
#define ASSIGN_ACL_DB_ACCESSOR(idx, type_arg, type_str_arg, direction_arg, direction_str_arg, table, interface_arg, base) \
    acl_db_accessor[idx].type = type_arg;                                 \
    acl_db_accessor[idx].type_str = type_str_arg;                         \
    acl_db_accessor[idx].direction = direction_arg;                       \
    acl_db_accessor[idx].direction_str = direction_str_arg;               \
    acl_db_accessor[idx].interface = interface_arg;                       \
    acl_db_accessor[idx].column_applied = \
                                    &ovsrec_##table##_col_##base##_applied;      \
    acl_db_accessor[idx].column_cfg = &ovsrec_##table##_col_##base##_cfg;    \
    acl_db_accessor[idx].column_cfg_version = \
                                  &ovsrec_##table##_col_##base##_cfg_version; \
    acl_db_accessor[idx].column_cfg_status =\
                                        &ovsrec_##table##_col_##base##_status; \
    acl_db_accessor[idx].offset_applied = \
                            offsetof(struct ovsrec_##table , base##_applied); \
    acl_db_accessor[idx].offset_cfg = \
                            offsetof(struct ovsrec_##table , base##_cfg); \
    acl_db_accessor[idx].offset_cfg_version = \
                        offsetof(struct ovsrec_##table , base##_cfg_version); \
    acl_db_accessor[idx].offset_n_cfg_version = \
                        offsetof(struct ovsrec_##table , n_##base##_cfg_version); \
    acl_db_accessor[idx].offset_cfg_status = \
                        offsetof(struct ovsrec_##table , base##_status); \
    acl_db_accessor[idx].offset_n_statistics = \
                        offsetof(struct ovsrec_##table , n_##base##_statistics); \
    acl_db_accessor[idx].offset_key_statistics = \
                        offsetof(struct ovsrec_##table , key_##base##_statistics); \
    acl_db_accessor[idx].offset_value_statistics = \
                        offsetof(struct ovsrec_##table , value_##base##_statistics); \
    acl_db_accessor[idx].set_applied = \
                                ovsrec_##table##_set_##base##_applied;      \
    acl_db_accessor[idx].set_cfg = ovsrec_##table##_set_##base##_cfg;        \
    acl_db_accessor[idx].set_cfg_version = \
                                   ovsrec_##table##_set_##base##_cfg_version; \
    acl_db_accessor[idx].set_cfg_status = ovsrec_##table##_set_##base##_status; \
    acl_db_accessor[idx].offset_statistics_clear_requested = \
                        offsetof(struct ovsrec_##table , \
                          base##_statistics_clear_requested); \
    acl_db_accessor[idx].offset_statistics_clear_performed = \
                        offsetof(struct ovsrec_##table , \
                          base##_statistics_clear_performed); \
    acl_db_accessor[idx].set_clear_statistics_requested = \
                          ovsrec_##table##_set_##base##_statistics_clear_requested; \
    acl_db_accessor[idx].set_clear_statistics_performed = \
                          ovsrec_##table##_set_##base##_statistics_clear_performed; \
    acl_db_accessor[idx].status_setkey = \
                          ovsrec_##table##_update_##base##_status_setkey; \
    acl_db_accessor[idx].set_statistics = \
                          ovsrec_##table##_set_##base##_statistics;


void
acl_db_util_init(void) {
    /* Create a global array entry for (aclv4, in) pair. */
    ASSIGN_ACL_DB_ACCESSOR((int)ACL_CFG_PORT_V4_IN, OPS_CLS_ACL_V4, "ip", OPS_CLS_DIRECTION_IN, "in", port, OPS_CLS_INTERFACE_PORT, aclv4_in);
    ASSIGN_ACL_DB_ACCESSOR((int)ACL_CFG_PORT_V4_OUT, OPS_CLS_ACL_V4, "ip", OPS_CLS_DIRECTION_OUT, "out", port, OPS_CLS_INTERFACE_PORT, aclv4_out);
}

struct acl_db_util *acl_db_util_accessor_get(enum ops_cls_type type,
                                             enum ops_cls_direction direction,
                                             enum ops_cls_interface interface)
{
    if (interface == OPS_CLS_INTERFACE_PORT) {
        if (type == OPS_CLS_ACL_V4) {
            if (direction == OPS_CLS_DIRECTION_IN) {
                return &acl_db_accessor[ACL_CFG_PORT_V4_IN];
            } else if (direction == OPS_CLS_DIRECTION_OUT) {
                return &acl_db_accessor[ACL_CFG_PORT_V4_OUT];
            }
        }
    }

    return NULL;
}


/***** Getters *****/
#define MEMBER_AT_OFFSET(objptr, offset, type) \
    *(type*)(CONST_CAST(char*, (const char *)(objptr) + (offset)))

const struct ovsrec_acl*
acl_db_util_get_applied(const struct acl_db_util *acl_db,
                        const struct ovsrec_port *port)
{
    return MEMBER_AT_OFFSET(port, acl_db->offset_applied,
                            const struct ovsrec_acl*);
}

const struct ovsrec_acl*
acl_db_util_get_cfg(const struct acl_db_util *acl_db,
                      const struct ovsrec_port *port)
{
    return MEMBER_AT_OFFSET(port, acl_db->offset_cfg,
                            const struct ovsrec_acl*);
}

const size_t
acl_db_util_get_n_cfg_version(const struct acl_db_util *acl_db,
                              const struct ovsrec_port *port)
{
    return MEMBER_AT_OFFSET(port, acl_db->offset_n_cfg_version, size_t);
}

const int64_t*
acl_db_util_get_cfg_version(const struct acl_db_util *acl_db,
                              const struct ovsrec_port *port)
{
    return MEMBER_AT_OFFSET(port, acl_db->offset_cfg_version, int64_t *);
}

const struct smap*
acl_db_util_get_cfg_status(const struct acl_db_util *acl_db,
                             const struct ovsrec_port *port)
{
    return MEMBER_AT_OFFSET(port, acl_db->offset_cfg_status,
                            const struct smap*);
}

int64_t
acl_db_util_get_clear_statistics_requested(const struct acl_db_util *acl_db,
                                           const struct ovsrec_port *port)
{
    const int64_t *clear_stats_requested;

    clear_stats_requested = MEMBER_AT_OFFSET(port,
                              acl_db->offset_statistics_clear_requested,
                              const int64_t*);
    if (clear_stats_requested) {
        return clear_stats_requested[0];
    } else {
        return 0;
    }
}

int64_t
acl_db_util_get_clear_statistics_performed(const struct acl_db_util *acl_db,
                                           const struct ovsrec_port *port)
{
    const int64_t *clear_stats_performed;

    clear_stats_performed = MEMBER_AT_OFFSET(port,
                              acl_db->offset_statistics_clear_performed,
                              const int64_t*);
    if (clear_stats_performed) {
        return clear_stats_performed[0];
    } else {
        return 0;
    }
}

const int64_t*
acl_db_util_get_value_statistics(const struct acl_db_util *acl_db,
                                   const struct ovsrec_port *port)
{
    return MEMBER_AT_OFFSET(port, acl_db->offset_value_statistics, int64_t *);
}

const int64_t*
acl_db_util_get_key_statistics(const struct acl_db_util *acl_db,
                                 const struct ovsrec_port *port)
{
    return MEMBER_AT_OFFSET(port, acl_db->offset_key_statistics, int64_t *);
}

const size_t
acl_db_util_get_n_statistics(const struct acl_db_util *acl_db,
                               const struct ovsrec_port *port)
{
    return MEMBER_AT_OFFSET(port, acl_db->offset_n_statistics, size_t);
}


/***** Setters *****/
void
acl_db_util_set_applied(const struct acl_db_util *acl_db,
                        const struct ovsrec_port *port,
                        const struct ovsrec_acl *cur)
{
    (*acl_db->set_applied)(port, cur);
}

void
acl_db_util_set_cfg(const struct acl_db_util *acl_db,
                      const struct ovsrec_port *port,
                      const struct ovsrec_acl *cfg)
{
    (*acl_db->set_cfg)(port, cfg);
}

void
acl_db_util_set_cfg_version(const struct acl_db_util *acl_db,
                             const struct ovsrec_port *port,
                             const int64_t *cfg_version)
{
    (*acl_db->set_cfg_version)(port, cfg_version, 1);
}

void
acl_db_util_set_cfg_status(const struct acl_db_util *acl_db,
                             const struct ovsrec_port *port,
                             const struct smap *cfg_status)
{
    (*acl_db->set_cfg_status)(port, cfg_status);
}

void
acl_db_util_set_clear_statistics_requested(const struct acl_db_util *acl_db,
                                            const struct ovsrec_port *port,
                                            const int64_t clear_stats_req_id)
{
    (*acl_db->set_clear_statistics_requested)(port, &clear_stats_req_id, 1);
}

void
acl_db_util_set_clear_statistics_performed(const struct acl_db_util *acl_db,
                                                 const struct ovsrec_port *port,
                                                 const int64_t clear_stats_performed_id)
{
    (*acl_db->set_clear_statistics_performed)(port, &clear_stats_performed_id, 1);
}

void
acl_db_util_status_setkey(const struct acl_db_util *acl_db,
                                            const struct ovsrec_port *port,
                                            char *status,
                                            char *detail)
{
    (*acl_db->status_setkey)(port, status, detail);
}

void
acl_db_util_set_statistics(const struct acl_db_util *acl_db,
                                            const struct ovsrec_port *port,
                                            const int64_t *key_statistics,
                                            const int64_t *value_statistics,
                                            size_t n_statistics)
{
    (*acl_db->set_statistics)(port, key_statistics, value_statistics, n_statistics);
}
