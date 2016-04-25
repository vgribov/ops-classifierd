/*
 * (C) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 *   Licensed under the Apache License, Version 2.0 (the "License"); you may
 *   not use this file except in compliance with the License. You may obtain
 *   a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *   License for the specific language governing permissions and limitations
 *   under the License.
 */

#ifndef _OPS_CLS_STATUS_TABLE_H_

#define _OPS_CLS_STATUS_TABLE_H_

#include <openvswitch/vlog.h>
#include <openvswitch/compiler.h>

#include "ops-cls-asic-plugin.h"

/**
 * Classifier List status table entry structure
 */
struct ops_cls_status_table_entry
{
    enum ops_cls_list_status_code   status_code;    /**< feature operation
                                                         status code */
    const char                      *status_str;    /**< description for
                                                         the status_code */
};

/**
 * Populates the global status table for the feature messages
 *
 * @param  status_table, used to populate the global status table
 * @param  n_entries number of table entries to be populated
 *
 */
void ops_cls_status_table_populate(
                   const struct ops_cls_status_table_entry status_table[],
                   int n_entries);

/**
 * Returns the status message string for the given status_code
 *
 * @param  status_code, status code for which status string to be retrieved
 *
 * @return status message string for the status code if found, otherwise
 *         returns NULL
 */
const char *ops_cls_status_table_get(
                   enum ops_cls_list_status_code status_code);


#endif /* _OPS_CLS_STATUS_TABLE_H_ */
