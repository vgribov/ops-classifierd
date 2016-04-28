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
 * @ingroup acl_daemon_acls
 *
 * @file
 * Source for ACL table related processing required by ACL feature in
 * classifier daemon.
 *
 ***************************************************************************/
#include <openvswitch/vlog.h>
#include <assert.h>
#include <vswitch-idl.h>
#include <acl_daemon.h>

VLOG_DEFINE_THIS_MODULE(acl_daemon_acls);

/**
 * Process ACL table changes to determine if in_progress_aces
 * needs to be updated or not
 */
int
acl_reconfigure(struct ovsdb_idl *idl, unsigned int idl_seqno)
{
    int rc = 0;
    const struct ovsrec_acl *acl_row = NULL;
    const char *status_version_str;
    uint64_t status_version;
    bool in_progress_cleared = false;

    VLOG_DBG("acl_reconfigure...\n");

    ovs_assert(idl);

    OVSREC_ACL_FOR_EACH (acl_row, idl) {
        if (OVSREC_IDL_IS_ROW_INSERTED(acl_row, idl_seqno) ||
            OVSREC_IDL_IS_ROW_MODIFIED(acl_row, idl_seqno)) {
            /* Get the status version */
            status_version_str = smap_get(&acl_row->status, "version");
            /* If the status version is valid, then update in_progress_aces
             * only when in_progress_version == status_version and
             * cfg_version > in_progress_version.
             */
            if (status_version_str) {
                status_version = strtoull(status_version_str, NULL, 0);
                if (acl_row->in_progress_version[0] == status_version) {
                    /* Clear the in_progress_aces as we have finished
                     * processing the in_progress_aces.
                     */
                    ovsrec_acl_set_in_progress_aces(acl_row, NULL, NULL, 0);
                    in_progress_cleared = true;
                    rc++;
                }
            }
            /* If status_version_str is NULL, it is the first time we are
             * programming anything into aces column. We need to update
             * in_progress_aces column. The other condition to check is
             * if UI made a change and in_progress_cleared flag is true */
            if (!status_version_str ||
                ((in_progress_cleared == true) &&
                 (acl_row->cfg_version[0] > acl_row->in_progress_version[0]))) {
                ovsrec_acl_set_in_progress_aces(acl_row, acl_row->key_cfg_aces,
                    acl_row->value_cfg_aces, acl_row->n_cfg_aces);
                ovsrec_acl_set_in_progress_version(acl_row,
                                                   acl_row->cfg_version,1);
                rc++;
            }
        }
    } /* for each acl ROW */

    VLOG_DBG("%s: number of updates back to db: %d",__FUNCTION__,rc);

    return rc;
} /* acl_reconfigure */


/** @} end of group acl_daemon_acls */
