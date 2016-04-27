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

#ifndef __SWITCHD__PLUGIN__ACL_H__
#define __SWITCHD__PLUGIN__ACL_H__ 1

#include <stdbool.h>
#include "hmap.h"
#include "uuid.h"
#include "list.h"
#include "ops-cls-asic-plugin.h"
#include "reconfigure-blocks.h"

struct classifier_list;
struct ops_cls_list;

/*************************************************************
 * acl structures
 *************************************************************/
struct acl {
    struct hmap_node   all_node_uuid;   /* In 'all_acls_by_uuid'. */

    /* members with information "about" me */
    struct uuid        uuid;
    const char        *name;
    enum ops_cls_type  type;

    /* members for working with OVSDB */
    const struct ovsrec_acl *ovsdb_row;
    unsigned int       delete_seqno; /* mark/sweep to identify deleted */

    /* members representing my cached PI state */
    struct ovs_list acl_port_map;    /* List of struct acl_port_map. */
    struct ops_cls_list *cfg_pi; /* List of acls user requested to
                                    configure but not yet processed */
};

/*************************************************************
 * acl lookup routines
 *************************************************************/
struct acl* acl_lookup_by_uuid(const struct uuid* uuid);

/************************************************************
 * Top level routine to check if ACL's need to reconfigure
 ************************************************************/
void acl_reconfigure_init(struct blk_params *blk_params);

#endif  /* __SWITCHD__PLUGIN__ACL_H__ */
