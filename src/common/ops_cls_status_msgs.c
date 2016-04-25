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
 * @ingroup  ops_cls_status_msgs
 *
 * @file
 * Source for classifier status messages functions.
 *
 ***************************************************************************/

#include <openvswitch/vlog.h>
#include "ops-cls-asic-plugin.h"
#include "ops_cls_status_table.h"
#include "ops_cls_status_msgs.h"

/** Create logging module */
VLOG_DEFINE_THIS_MODULE(ops_cls_status_msgs);

/** @ingroup ops_cls_status_msgs
 * @{ */

/** This defines a common string that will be prefixed to the specific
 *  error message. e.g.
 *  Failed to <operation> <feature> on <interface type> <interface#>
 *  <sequence_no_str>
 *   operation - apply, remove, replace, update, get, clear, clearall
 *   feature - acl, acl list, acl statistics
 *   interface type - port, vlan, etc
 *   interface# - interface number
 *   sequence_no_str - In case sequence number is valid, it will
 *                     display " at entry sequence number XX. "
 *                     otherwise, it will not display anything.
 * Note: there is no space between last two string format specifier
 *       for readability purpose as reasons string will be appended
 *       to this string
 */
#define OPS_CLS_STATUS_MSG_COMMON_ERR_PREFIX "Failed to %s %s on %s %s%s"

/** string to be displayed if sequence number is valid
 *  Note: one space at the end is added for readability because the reason
 *  string will be appended to this string.
 */
#define OPS_CLS_STATUS_MSG_SEQ_NUM_VALID    " at entry sequence number %d, "

/** string to be displayed if sequence number is NOT valid
 *  e.g. statistics operations or general failures not specific
 *  to an entry
 *  Note: one space at the end is added for readability because the reason
 *  string will be appended to this string.
 */
#define OPS_CLS_STATUS_MSG_SEQ_NUM_INVALID  ", "

/** sequence number string length
 *  strlen of OPS_CLS_STATUS_MSG_SEQ_VALID (27) + SEQ_NUM_TO_STR_MAX_LEN (11)
 *  and rounded the result to power of 2.
 */
#define OPS_CLS_STATUS_MSG_SEQ_NUM_STR_LEN 64

/* Classifier status messages */
const struct ops_cls_status_table_entry ops_cls_status_msgs[] = {
    {
        OPS_CLS_STATUS_SUCCESS,
        NULL
    },
    {
        OPS_CLS_STATUS_HW_INTERNAL_ERR,
        OPS_CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: internal error."
    },
    {
        OPS_CLS_STATUS_HW_MEMORY_ERR,
        OPS_CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: out of memory."
    },
    {
        OPS_CLS_STATUS_HW_UNIT_ERR,
        OPS_CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: invalid unit"
    },
    {
        OPS_CLS_STATUS_HW_PARAM_ERR,
        OPS_CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: invalid parameter"
    },
    {
        OPS_CLS_STATUS_HW_EMPTY_ERR,
        OPS_CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: empty table"
    },
    {
        OPS_CLS_STATUS_HW_FULL_ERR,
        OPS_CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: full table"
    },
    {
        OPS_CLS_STATUS_HW_NOT_FOUND_ERR,
        OPS_CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: entry not found"
    },
    {
        OPS_CLS_STATUS_HW_EXISTS_ERR,
        OPS_CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: entry already exist"
    },
    {
        OPS_CLS_STATUS_HW_TIMEOUT_ERR,
        OPS_CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: operation timed out"
    },
    {
        OPS_CLS_STATUS_HW_BUSY_ERR,
        OPS_CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: hardware busy"
    },
    {
        OPS_CLS_STATUS_HW_FAIL_ERR,
        OPS_CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: operation failed"
    },
    {
        OPS_CLS_STATUS_HW_DISABLED_ERR,
        OPS_CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: operation is disabled"
    },
    {
        OPS_CLS_STATUS_HW_BADID_ERR,
        OPS_CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: invalid identifier"
    },
    {
        OPS_CLS_STATUS_HW_RESOURCE_ERR,
        OPS_CLS_STATUS_MSG_COMMON_ERR_PREFIX
                  "reason: no resource for operation"
    },
    {
        OPS_CLS_STATUS_HW_CONFIG_ERR,
        OPS_CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: invalid configuration"
    },
    {
        OPS_CLS_STATUS_HW_UNAVAIL_ERR,
        OPS_CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: feature unavailable"
    },
    {
        OPS_CLS_STATUS_HW_INIT_ERR,
        OPS_CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: feature not initialized"
    },
    {
        OPS_CLS_STATUS_HW_PORT_ERR,
        OPS_CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: invalid port"
    },
    {
        OPS_CLS_STATUS_HW_UNKNOWN_ERR,
        OPS_CLS_STATUS_MSG_COMMON_ERR_PREFIX "reason: unknown error"
    }
};

/*
 * Populates the global status table with classifier common status messages
 */
void ops_cls_status_msgs_populate()
{
    unsigned int n_entries;
    /* populate global status table for classifier common status codes */
    n_entries = (unsigned int)
                  (sizeof(ops_cls_status_msgs)/
                        sizeof(ops_cls_status_msgs[0]));
    VLOG_DBG("Populating global_status_table for %d ops_cls_status_msg "
             "entries",n_entries);
    ops_cls_status_table_populate(&ops_cls_status_msgs[0],n_entries);
}

/*
 * Returns the classifier status message string for the specified
 * status code.
 */
void ops_cls_status_msgs_get(enum ops_cls_list_status_code status_code,
                         const char *op_str, const char *feature_str,
                         const char *iface_str, const char *iface_num,
                         unsigned int seq_num,  unsigned int len,
                         char *status_msg_str)
{
    const char *status_table_str;
    char seq_num_str[OPS_CLS_STATUS_MSG_SEQ_NUM_STR_LEN];
    status_table_str = ops_cls_status_table_get(status_code);

    if(status_table_str != NULL) {
        if(seq_num == 0) {
            /* invalid entry sequence number, so format the string without
             * entry sequence number string.
             */
            snprintf(status_msg_str,len,status_table_str,op_str,feature_str,
                     iface_str,iface_num,OPS_CLS_STATUS_MSG_SEQ_NUM_INVALID);
        } else {
            /* valid entry sequence number, so format the string using
             * entry sequence number.
             */
            snprintf(seq_num_str,OPS_CLS_STATUS_MSG_SEQ_NUM_STR_LEN,
                     OPS_CLS_STATUS_MSG_SEQ_NUM_VALID,seq_num);

            snprintf(status_msg_str,len,status_table_str,op_str,feature_str,
                     iface_str,iface_num,seq_num_str);

        } /* end if seq_num == 0 */
    } /* end if status_table_str != NULL */
}

/** @} end of group ops_cls_status_msgs */
