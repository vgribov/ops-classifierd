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

#ifndef __SWITCHD__PLUGIN__ACL_PORT_LAG_UTILS_H__
#define __SWITCHD__PLUGIN__ACL_PORT_LAG_UTILS_H__ 1

#include "bridge.h"
#include "acl_port.h"


/**************************************************************************//**
 * This function returns the iface hw_bond_config value
 * corresponding to the requested key
 *
 * @param[in] iface - Pointer to iface struct
 * @param[in] key   - The key for which the value is
 *                    requested
 *
 * @return          - The boolean value of key requested in
 *                    hw_bond_config column
 *****************************************************************************/
bool
acl_port_get_iface_hw_bond_config_value(struct iface *iface,
                                        const char *key);

/**************************************************************************//**
 * This function checks all members of the LAG and if atleast
 * one member is up, marks the LAG to be active. Only if the LAG
 * is active, a PD call will be made to apply or replace an ACL
 * to this LAG.
 *
 * @param[in] acl_port - Pointer to the acl_port of the lag
 *****************************************************************************/
void
acl_port_lag_check_and_set_members_active(struct acl_port *acl_port);

/**************************************************************************//**
 * This function sets the hw_acl in PI to NULL, if the LAG is
 * not active
 *
 * @param[in] port     - Pointer to @see struct port
 * @param[in] acl_port - Pointer to @see struct acl_port
 *****************************************************************************/
void
acl_port_lag_check_and_unset_hw_acl(struct acl_port *acl_port);

/**************************************************************************//**
 * This function removes an interface element from a LAG port
 * interface list
 *
 * @param[in] iface_element  - interface element to be
 *                             removed
 *****************************************************************************/
void
acl_port_lag_iface_list_element_remove(struct acl_port_interface *iface_element);

/**************************************************************************//**
 * This function deletes a list of interfaces for a LAG port
 * from the acl_port
 *
 * @param[in] iface_list  - port interfaces list
 *****************************************************************************/
void
acl_port_lag_iface_list_delete(struct ovs_list *iface_list);

/**************************************************************************//**
 * This function adds the iface element to a list of interfaces
 * for a LAG port
 *
 * @param[in]  iface       - Pointer to @see struct iface
 * @param[out] iface_list  - port interfaces list
 *****************************************************************************/
void
acl_port_lag_iface_list_element_add(struct acl_port *acl_port,
                                    struct iface *iface);

/**************************************************************************//**
 * This function creates a list of interfaces for a LAG port in
 * the acl_port
 *
 * @param[in]   port        - Pointer to @see struct port
 * @param[out]  iface_list  - port interfaces list
 *****************************************************************************/
void
acl_port_lag_iface_list_create(struct acl_port *acl_port);

/**************************************************************************//**
 * This function checks if the rx and tx states in
 * hw_bond_config column in the interface table are set to true
 * for the iface
 *
 * @param[in]  iface - Pointer to @see struct iface
 *
 * @return    true       - If rx and tx states in
 *                         hw_bond_config are enabled
 *            false      - If rx and tx states in hw_bond_config
 *                         are disabled
 *****************************************************************************/
bool
acl_port_lag_iface_hw_bond_config_enabled(struct iface *iface);

/**************************************************************************//**
 * This function deletes the hw_status in the interface table
 * for the input iface
 *
 * @param[in] acl_port_iface - Pointer to @see struct
 *                             acl_port_interface
 *****************************************************************************/
void
acl_port_lag_iface_delete_intfd_hw_status(
    struct acl_port_interface *acl_port_iface);

/**************************************************************************//**
 * This function checks if the new iface got added to the LAG
 * port. If yes, it updates the internal LAG port with the new
 * iface
 *
 * @param[in] iface      - Pointer to @see struct iface
 * @param[in] acl_port   - Pointer to @see struct acl_port
 *
 * @return    true       - If a new iface was added to the LAG
 *                         port
 *            false      - If no new iface got added to the LAG
 *                         port
 *****************************************************************************/
bool
acl_port_lag_iface_added(struct iface *iface, struct acl_port *acl_port);

/**************************************************************************//**
 * This function checks if the iface in a LAG port changed to a
 * no shut state by checking if the corresponding rx and tx
 * states in hw_bond_config changed from false to true
 *
 * @param[in] iface      - Pointer to @see struct iface
 * @param[in] acl_port   - Pointer to @see struct acl_port
 *
 * @return    true       - If the iface state transitioned to
 *                         no shut or a new iface was added to
 *                         the LAG port
 *            false      - If there is no iface state transition
 *****************************************************************************/
bool
acl_port_lag_iface_changed_to_no_shutdown_state(struct iface *iface,
                                                struct acl_port *acl_port);

/**************************************************************************//**
 * This function checks if the iface in a LAG port changed to
 * shut state by checking if the corresponding rx and tx states
 * in hw_bond_config changed from true to false
 *
 * @param[in] iface      - Pointer to @see struct iface
 * @param[in] acl_port   - Pointer to @see struct acl_port
 *
 * @return    true       - If the iface state transitioned to
 *                         shut
 *            false      - If there is no iface state transition
 *****************************************************************************/
bool
acl_port_lag_iface_changed_to_shutdown_state(struct iface *iface,
                                             struct acl_port *acl_port);

/**************************************************************************//**
 * This function checks if the iface got removed from a LAG port
 *
 *  @param[in] acl_port_iface - Pointer to @see struct
 *                              acl_port_interface
 * @param[in] port            - Pointer to @see struct port
 *
 * @return    true            - If the iface was moved out of a
 *                              LAG
 *            false           - If the iface is part of LAG
 *****************************************************************************/
bool
acl_port_lag_iface_removed(struct acl_port_interface *acl_port_iface,
                           struct port *port);

#endif  /* __SWITCHD__PLUGIN__ACL_PORT_LAG_UTILS_H__ */
