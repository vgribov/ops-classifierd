/*
 * (c) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may
 * not use this file except in compliance with the License. You may obtain
 * a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
/************************************************************************//**
 * @ingroup  ops_cls_status_table
 *
 * @file
 * Source for classifier status table functions.
 *
 ***************************************************************************/

#include <openvswitch/vlog.h>
#include "ops-cls-asic-plugin.h"
#include "ops_cls_status_table.h"

/** Create logging module */
VLOG_DEFINE_THIS_MODULE(ops_cls_status_table);

/** @ingroup ops_cls_status_table
 * @{ */

/* global status table used to hold predefined status messages for various
 * classifier features.
 */
struct ops_cls_status_table_entry
                          *cls_global_status_table[OPS_CLS_STATUS_MAX] = {0};

/*
 * Populates the global status table for the feature messages
 */
void
ops_cls_status_table_populate(
                const struct ops_cls_status_table_entry status_table[],
                int n_entries)
{
    int i, status_code;
    struct ops_cls_status_table_entry *status_entry;

    VLOG_DBG("Populating global status table with %d entries ", n_entries);
    for(i = 0; i < n_entries; i++) {
        status_code = status_table[i].status_code;
        VLOG_DBG("Populate global status table at %d for status_code %d ",
                 i, status_code);
        /* make sure status_code is within global status table size */
        if(status_code < OPS_CLS_STATUS_MAX) {
            status_entry = cls_global_status_table[status_code];
            if(status_entry) {
                VLOG_DBG("Overwriting existing status table entry => %s "
                         "for status_code %d",
                         status_entry->status_str, status_code);
            }
            cls_global_status_table[status_code] =
                (struct ops_cls_status_table_entry *)&status_table[i];
            status_entry = cls_global_status_table[status_code];
            VLOG_DBG("status table entry => %s at %d",
                                            status_entry->status_str,i);
        } else {
            VLOG_ERR("status_code => %d exceeds the global status table "
                     "max entries %d",status_code,OPS_CLS_STATUS_MAX);
        } /* end if status_code < OPS_CLS_STATUS_MAX */
    } /* end for loop */
}


/*
 * Returns the status message string for the given status_code
 */
const char *
ops_cls_status_table_get(enum ops_cls_list_status_code status_code)
{
    struct ops_cls_status_table_entry *status_entry;

    if(status_code >= OPS_CLS_STATUS_MAX) {
        VLOG_ERR("Invalid status_code => %d ",status_code);
        return NULL;
    }

    status_entry = cls_global_status_table[status_code];
    if(status_entry) {
        return (status_entry->status_str);
    } else {
        VLOG_ERR("status_code %d not populated in the status table",
                  status_code);
        return NULL;
    }
}

/** @} end of group ops_cls_status_table */
