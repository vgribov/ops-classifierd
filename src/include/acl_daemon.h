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

#ifndef _ACL_DAEMON_H_

#define _ACL_DAEMON_H_

/**
 * Initializes OVSDB tables and columns to cache for ACL
 *
 * @param[in]  idl pointer to the OVSDB IDL cache
 *
 */
void acl_ovsdb_init(struct ovsdb_idl *idl);

/**
 * Processes the changes to the ACL monitored columns of the port table
 * and sets the interface hw_ready_state based on the ACL configuration
 * and its applied status
 *
 * @param[in]  idl pointer to the OVSDB IDL cache
 * @param[in]  idl_seqno IDL sequence number
 *
 * @return returns > 0 if db needs to be updated for hw_ready_state update,
 * otherwise returns 0
 */
int  acl_ports_reconfigure(struct ovsdb_idl *idl, unsigned int idl_seqno);

/**
 * Processes the changes to the ACL monitored columns of the ACL table
 * and sets the in_progress_aces column
 *
 * @param[in]  idl pointer to the OVSDB IDL cache
 * @param[in]  idl_seqno IDL sequence number
 *
 * @return returns > 0 if db needs to be updated for in_progress_aces update,
 * otherwise returns 0
 */
int  acl_reconfigure(struct ovsdb_idl *idl, unsigned int idl_seqno);


#endif /* _ACL_DAEMON_H_ */
