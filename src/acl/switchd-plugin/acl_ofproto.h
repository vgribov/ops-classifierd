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

#ifndef __SWITCHD__PLUGIN__ACL_OFPROTO_H__
#define __SWITCHD__PLUGIN__ACL_OFPROTO_H__ 1

#include "acl.h"

struct port;

/* string version of ofproto-ops-classifier enums */
extern const char * const ops_cls_type_strings[];
extern const char * const ops_cls_direction_strings[];

/* ops_cls_list member routines */
struct ops_cls_list* ops_cls_list_new(void);
void ops_cls_list_delete(struct ops_cls_list *list);




/* Routines to safely call down to PD layer
 * These routines look up the plugin function pointer and, if not null,
 * calls it with the appropriate arguments
 */
int call_ofproto_ops_cls_apply(
    struct acl                     *acl,
    struct port                    *bridgec_port,
    struct ofproto                 *ofproto,
    struct ops_cls_interface_info  *interface_info,
    enum ops_cls_direction         direction,
    struct ops_cls_pd_status       *pd_status);

int call_ofproto_ops_cls_remove(
    struct acl                       *acl,
    struct port                      *bridgec_port,
    struct ofproto                   *ofproto,
    struct ops_cls_interface_info    *interface_info,
    enum ops_cls_direction           direction,
    struct ops_cls_pd_status         *pd_status);

int call_ofproto_ops_cls_replace(
    struct acl                      *orig_acl,
    struct acl                      *new_acl,
    struct port                     *bridgec_port,
    struct ofproto                  *ofproto,
    struct ops_cls_interface_info   *interface_info,
    enum ops_cls_direction          direction,
    struct ops_cls_pd_status        *pd_status);

int call_ofproto_ops_cls_list_update(
    struct acl                       *acl,
    struct ops_cls_pd_list_status    *status);

int call_ofproto_ops_cls_statistics_get(
    struct acl                     *acl,
    struct port                    *bridgec_port,
    struct ofproto                 *ofproto,
    struct ops_cls_interface_info  *interface_info,
    enum ops_cls_direction         direction,
    struct ops_cls_statistics      *statistics,
    int                            num_entries,
    struct ops_cls_pd_list_status  *status);

int call_ofproto_ops_cls_statistics_clear(
    struct acl                      *acl,
    struct port                     *bridgec_port,
    struct ofproto                  *ofproto,
    struct ops_cls_interface_info   *interface_info,
    enum ops_cls_direction          direction,
    struct ops_cls_pd_list_status   *status);

int call_ofproto_ops_cls_statistics_clear_all(
    struct ops_cls_pd_list_status    *status);

#endif  /* __SWITCHD__PLUGIN__ACL_OFPROTO_H__ */
