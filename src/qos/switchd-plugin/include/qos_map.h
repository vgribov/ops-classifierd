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
 ***************************************************************************/

#ifndef _QOS_MAP_H_
#define _QOS_MAP_H_

#include "vswitch-idl.h"
#include "ofproto/ofproto-provider.h"

void qos_configure_global_cos_map(struct ofproto *,
                                  struct ovsdb_idl *, unsigned int);
void qos_configure_global_dscp_map(struct ofproto *,
                                   struct ovsdb_idl *, unsigned int);

#endif /* _QOS_MAP_H_ */
