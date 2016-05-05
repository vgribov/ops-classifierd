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

#ifndef __ACL_DB_UTIL_H__
#define __ACL_DB_UTIL_H__ 1

#include <unistd.h>
#include "vswitch-idl.h"
#include "ops-cls-asic-plugin.h"
#include "smap.h"

/**************************************************************************//**
 * acl_db_util
 *
 * Data structure to ease access to the many acl_port_map field
 * "quartets" stored in the ovsrec_port table.
 *
 * For now, access to IDL generated fields cannot cleanly be
 * accomplished solely via row pointers and column pointers.
 * Access is only provided via direct access to individualy
 * named structure members and setter functions (e.g
 * ovsrec_port_set_aclv4_in_applied(). This means that
 * a function coded to work with the aclv4_in_applied field cannot
 * also be used to access the aclv4_out_applied field.
 *
 * This structure, and it's associated getters/setters solve that
 * problem. Functions coded to work with acl_db_util_get_applied()
 * and acl_db_util_set_applied() will be able to work with the _applied
 * field of any acl_port_map "quartet".
 *****************************************************************************/
struct acl_db_util {
    enum ops_cls_type type;
    enum ops_cls_direction direction;

    /* column pointer */
    struct ovsdb_idl_column *column_applied;
    struct ovsdb_idl_column *column_cfg;
    struct ovsdb_idl_column *column_cfg_version;
    struct ovsdb_idl_column *column_cfg_status;

    /* Offset to the fields inside IDL-generated 'struct ovsrec_port' */
    off_t offset_applied;
    off_t offset_cfg;
    off_t offset_cfg_version;
    off_t offset_cfg_status;
    off_t offset_statistics_clear_requested;
    off_t offset_statistics_clear_performed;

    /* pointers to IDL-generated setter functions */
    void (*set_applied)(const struct ovsrec_port *,
                    const struct ovsrec_acl *cur);
    void (*set_cfg)(const struct ovsrec_port *,
                     const struct ovsrec_acl *want);
    void (*set_cfg_version)(const struct ovsrec_port *,
                            const int64_t *cfg_version,
                            size_t n_cfg_version);
    void (*set_cfg_status)(const struct ovsrec_port *,
                            const struct smap *cfg_status);
    void(*set_clear_statistics_requested) (const struct ovsrec_port *,
                                   const int64_t *stats_clear_requested,
                                   size_t n_stats_clear_requested);
    void(*set_clear_statistics_performed) (const struct ovsrec_port *,
                                   const int64_t *stats_clear_performed,
                                   size_t n_stats_clear_performed);
};

enum acl_db_util_index {
    ACL_CFG_V4_IN = 0,
    ACL_CFG_MAX_TYPES
};

extern struct acl_db_util acl_db_accessor[ACL_CFG_MAX_TYPES];

/**
 * Initialize acl_db_accessor array. All possible configurations and their
 * db access routines are populated at the init time.
 */
void acl_db_util_init(void);

/**
 * Gets  the acl_db_accessor pointer that has db access routines populated at
 * the init time.
 *
 * @param[in] type - @see ops_cls_type
 * @param[in] direction   - @see ops_cls_direction
 *
 * @returns Pointer to the acl_db_util structure from acl_db_accessor array
 */
struct acl_db_util *acl_db_util_accessor_get(enum ops_cls_type type,
                                             enum ops_cls_direction direction);
/**
 * Gets the applied column of a given ovsrec_port
 *
 * @param[in] acl_db - Pointer to the @see acl_db_util structure
 * @param[in] port   - Pointer to the port row
 *
 * @returns Pointer to the ACL row that is applied on the port
 */
const struct ovsrec_acl* acl_db_util_get_applied(
    const struct acl_db_util *acl_db, const struct ovsrec_port *port);

/**
 * Gets the cfg column of a given ovsrec_port
 *
 * @param[in] acl_db - Pointer to the @see acl_db_util structure
 * @param[in] port   - Pointer to the port row
 *
 * @returns Pointer to the ACL row that is configured from UI on the port
 */
const struct ovsrec_acl* acl_db_util_get_cfg(
    const struct acl_db_util *acl_db, const struct ovsrec_port *port);

/**
 * Gets the cfg_version column of a given ovsrec_port
 *
 * @param[in] acl_db - Pointer to the @see acl_db_utl structure
 * @param[in] port   - Pointer to the port row
 *
 * @returns version number as configured into the db from UI
 */
int64_t acl_db_util_get_cfg_version(
    const struct acl_db_util *acl_db, const struct ovsrec_port *port);

/**
 * Gets the cfg_status column of a given ovsrec_port
 *
 * @param[in] acl_db - Pointer to the @see acl_db_util structure
 * @param[in] port   - Pointer to the port row
 *
 * @returns cfg_status map of this port row.
 */
const struct smap* acl_db_util_get_cfg_status(
    const struct acl_db_util *acl_db, const struct ovsrec_port *port);

/**
 * Sets the applied column of a given ovsrec_port
 *
 * @param[in] acl_db - Pointer to the @see acl_db_util structure
 * @param[in] port   - Pointer to the port row
 * @param[in] acl    - Pointer to ACL that has been applied to the port
 */
void acl_db_util_set_applied(const struct acl_db_util *acl_db,
                          const struct ovsrec_port *port,
                          const struct ovsrec_acl *acl);

/**
 * Sets the cfg_status column of a given ovsrec_port. This function
 * is called after the feature plugin has called the asic plugin API.
 * The status received from the asic plugin layer is populated into
 * OVSDB using this access function.
 *
 * @param[in] acl_db     - Pointer to the @see acl_db_util structure
 * @param[in] port       - Pointer to the port row
 * @param[in] cfg_status - Pointer to the cfg_status map. This map
 *                         is written into the cfg_status column in ovsdb
 */
void acl_db_util_set_cfg_status(const struct acl_db_util *acl_db,
                                  const struct ovsrec_port *port,
                                  const struct smap *cfg_status);

/**
 * Sets the clear statistics requested id in the port row.
 * @param[in] acl_db     - Pointer to the @see acl_db_util structure
 * @param[in] port       - Pointer to the port row
 * @param[in] clear_stats_requested_id - int64_t id to set in ovsdb
 */
void acl_db_util_set_clear_statistics_requested(
                                        const struct acl_db_util *acl_db,
                                        const struct ovsrec_port *port,
                                        const int64_t clear_stats_requested_id);
/**
 * Sets the clear statistics performed id in the port row.
 * @param[in] acl_db     - Pointer to the @see acl_db_util structure
 * @param[in] port       - Pointer to the port row
 * @param[in] clear_stats_performed_id - int64_t id to set in ovsdb
 */
 void acl_db_util_set_clear_statistics_performed(
                                        const struct acl_db_util *acl_db,
                                        const struct ovsrec_port *port,
                                        const int64_t clear_stats_performed_id);

/**
 * Gets the clear statistics requested column of a given ovsrec_port
 *
 * @param[in] acl_db - Pointer to the @see acl_db_utl structure
 * @param[in] port   - Pointer to the port row
 *
 * @returns int64_t id as configured into the db from UI
 */
int64_t
acl_db_util_get_clear_statistics_requested(const struct acl_db_util *acl_db,
                                           const struct ovsrec_port *port);

/**
 * Gets the clear statistics performed column of a given ovsrec_port
 *
 * @param[in] acl_db - Pointer to the @see acl_db_utl structure
 * @param[in] port   - Pointer to the port row
 *
 * @returns int64_t id as configured into the db from switchd
 */
int64_t
acl_db_util_get_clear_statistics_performed(const struct acl_db_util *acl_db,
                                           const struct ovsrec_port *port);
#endif  /* __ACL_DB_UTIL_H__ */
