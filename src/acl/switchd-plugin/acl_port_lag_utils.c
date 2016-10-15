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

#include "bridge.h"
#include "vrf.h"
#include "acl_port.h"
#include "acl_db_util.h"
#include "acl_port_lag_utils.h"
#include "vswitch-idl.h"
#include "openvswitch/vlog.h"
#include "ops_cls_status_msgs.h"
#include "openswitch-idl.h"


VLOG_DEFINE_THIS_MODULE(acl_switchd_plugin_port_lag);

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
                                        const char *key)
{
    if ((iface == NULL) || (key == NULL)) {
        return false;
    }

    return smap_get_bool(&iface->cfg->hw_bond_config,
                         key,
                         false);
}


/**************************************************************************//**
 * This function checks all members of the LAG and if atleast
 * one member is up, marks the LAG to be active. Only if the LAG
 * is active, a PD call will be made to apply or replace an ACL
 * to this LAG.
 *
 * @param[in] acl_port - Pointer to the acl_port of the lag
 *****************************************************************************/
void
acl_port_lag_check_and_set_members_active(struct acl_port *acl_port)
{
    bool all_members_inactive = true;
    struct acl_port_interface *iface = NULL;

    if (acl_port == NULL) {
        VLOG_ERR("acl_port cannot be NULL");
        return;
    }

    LIST_FOR_EACH(iface, iface_node, &acl_port->port_ifaces) {
        if (iface->tx_enable && iface->rx_enable) {
            all_members_inactive = false;
            break;
        }
    }

    if (all_members_inactive) {
        acl_port->lag_members_active = false;
    } else {
        acl_port->lag_members_active = true;
    }
}


/**************************************************************************//**
 * This function sets the hw_acl in PI to NULL, if the LAG is
 * not active
 *
 * @param[in] port     - Pointer to @see struct port
 * @param[in] acl_port - Pointer to @see struct acl_port
 *****************************************************************************/
void
acl_port_lag_check_and_unset_hw_acl(struct acl_port *acl_port)
{
    if (acl_port == NULL) {
        return;
    }

    if (acl_port->lag_members_active) {
        return;
    }

    /* If the LAG is inactive, then remove ACL from the internal hw_acl.
     * This is because, when LAG is inactive (i.e. all the LAG members are
     * inactive), the acl is removed from h/w. The acl will be reapplied
     * when atleast one member becomes active
     */
    for (int acl_type_iter = ACL_CFG_MIN_PORT_TYPES;
         acl_type_iter <= ACL_CFG_MAX_PORT_TYPES; acl_type_iter++) {
        if (acl_port->port_map[acl_type_iter].hw_acl) {
            acl_port_map_set_hw_acl(&acl_port->port_map[acl_type_iter], NULL);
        }
    }
}


/**************************************************************************//**
 * This function removes an interface element from a LAG port
 * interface list
 *
 * @param[in] iface_element  - interface element to be
 *                             removed
 *****************************************************************************/
void
acl_port_lag_iface_list_element_remove(struct acl_port_interface *iface_element)
{
    if (iface_element == NULL) {
        return;
    }

    list_remove(&iface_element->iface_node);
    free(iface_element);
}


/**************************************************************************//**
 * This function deletes a list of interfaces for a LAG port
 * from the acl_port
 *
 * @param[in] iface_list  - port interfaces list
 *****************************************************************************/
void
acl_port_lag_iface_list_delete(struct ovs_list *iface_list)
{
    struct acl_port_interface *iface_element      = NULL;
    struct acl_port_interface *iface_element_next = NULL;

    if ((iface_list == NULL) || (list_is_empty(iface_list))) {
        return;
    }

    LIST_FOR_EACH_SAFE(iface_element, iface_element_next, iface_node,
                       iface_list) {
        acl_port_lag_iface_list_element_remove(iface_element);
    }
}


/**************************************************************************//**
 * This function adds the iface element to a list of interfaces
 * for a LAG port
 *
 * @param[in]  iface       - Pointer to @see struct iface
 * @param[out] iface_list  - port interfaces list
 *****************************************************************************/
void
acl_port_lag_iface_list_element_add(struct acl_port *acl_port,
                                    struct iface *iface)
{
    if ((acl_port == NULL) || (iface == NULL)) {
        VLOG_ERR("acl_port and iface cannot be NULL");
        return;
    }

    struct acl_port_interface *iface_element =
            xzalloc(sizeof(struct acl_port_interface));

    if (!smap_is_empty(&iface->cfg->hw_bond_config)) {
        iface_element->rx_enable = acl_port_get_iface_hw_bond_config_value(
                                      iface,
                                      INTERFACE_HW_BOND_CONFIG_MAP_RX_ENABLED);
        iface_element->tx_enable = acl_port_get_iface_hw_bond_config_value(
                                      iface,
                                      INTERFACE_HW_BOND_CONFIG_MAP_TX_ENABLED);
    } else {
        VLOG_DBG("hw_bond_config not set for %s iface", iface->name);
        iface_element->rx_enable = false;
        iface_element->tx_enable = false;
    }

    iface_element->ofp_port = iface->ofp_port;
    iface_element->ovsdb_iface_row = iface->cfg;
    list_push_back(&acl_port->port_ifaces, &iface_element->iface_node);
}


/**************************************************************************//**
 * This function creates a list of interfaces for a LAG port in
 * the acl_port
 *
 * @param[in]   port        - Pointer to @see struct port
 * @param[out]  iface_list  - port interfaces list
 *****************************************************************************/
void
acl_port_lag_iface_list_create(struct acl_port *acl_port)
{
    struct iface *iface = NULL;

    if (acl_port == NULL) {
        VLOG_ERR("acl_port cannot be NULL");
        return;
    }

    LIST_FOR_EACH(iface, port_elem, &acl_port->port->ifaces) {
        acl_port_lag_iface_list_element_add(acl_port, iface);
    }

    acl_port_lag_check_and_set_members_active(acl_port);
}


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
acl_port_lag_iface_hw_bond_config_enabled(struct iface *iface)
{
    if (iface == NULL) {
        VLOG_ERR("iface cannot be NULL");
        return false;
    }

    if (smap_is_empty(&iface->cfg->hw_bond_config)) {
        return false;
    }

    if((smap_get_bool(&iface->cfg->hw_bond_config,
                     INTERFACE_HW_BOND_CONFIG_MAP_RX_ENABLED,
                     false))
                     &&
       (smap_get_bool(&iface->cfg->hw_bond_config,
                     INTERFACE_HW_BOND_CONFIG_MAP_TX_ENABLED,
                     false))) {
        return true;
    }

    return false;
}


/**************************************************************************//**
 * This function deletes the hw_status in the interface table
 * for the input iface
 *
 * @param[in] acl_port_iface - Pointer to @see struct
 *                             acl_port_interface
 *****************************************************************************/
void
acl_port_lag_iface_delete_intfd_hw_status(
    struct acl_port_interface *acl_port_iface)
{
    if (acl_port_iface == NULL) {
        VLOG_ERR("acl_port_iface cannot be NULL");
        return;
    }

    if (acl_port_iface->ovsdb_iface_row != NULL) {
        ovsrec_interface_update_hw_status_delkey(
                                acl_port_iface->ovsdb_iface_row,
                                OPS_INTF_HW_READY_KEY_STR);

        ovsrec_interface_update_hw_status_delkey(
                                acl_port_iface->ovsdb_iface_row,
                                OPS_INTF_HW_READY_BLOCKED_REASON_STR);
    }
}


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
acl_port_lag_iface_added(struct iface *iface, struct acl_port *acl_port)
{

    struct acl_port_interface *acl_port_iface = NULL;

    if ((iface == NULL) || (acl_port == NULL)) {
        return false;
    }

    LIST_FOR_EACH(acl_port_iface, iface_node, &acl_port->port_ifaces) {
        if (iface->ofp_port == acl_port_iface->ofp_port) {
            return false;
        }
    }

    acl_port_lag_iface_list_element_add(acl_port, iface);
    return true;
}


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
                                                struct acl_port *acl_port)
{
    struct acl_port_interface *acl_port_iface = NULL;

    if ((iface == NULL) || (acl_port == NULL)) {
        return false;
    }

    LIST_FOR_EACH(acl_port_iface, iface_node, &acl_port->port_ifaces) {
        if (iface->ofp_port == acl_port_iface->ofp_port) {
            /*Check if the hw_bond_config state tranisitioned */
            if (!acl_port_iface->rx_enable && !acl_port_iface->tx_enable) {
                if (acl_port_lag_iface_hw_bond_config_enabled(iface)) {

                    /* hw_bond_config state got enabled for this iface */
                    acl_port_iface->rx_enable = true;
                    acl_port_iface->tx_enable = true;
                    return true;
                }
            }
        }
    }

    return false;
}


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
                                             struct acl_port *acl_port)
{
    struct acl_port_interface *acl_port_iface = NULL;

    if ((iface == NULL) || (acl_port == NULL)) {
        return false;
    }

    LIST_FOR_EACH(acl_port_iface, iface_node, &acl_port->port_ifaces) {
        if (iface->ofp_port == acl_port_iface->ofp_port) {
            /* Check if the hw_bond_config state tranisitioned */
            if (acl_port_iface->rx_enable && acl_port_iface->tx_enable) {
                if (!acl_port_lag_iface_hw_bond_config_enabled(iface)) {

                    /* hw_bond_config state got disabled for this iface */
                    acl_port_iface->rx_enable = false;
                    acl_port_iface->tx_enable = false;
                    return true;
                }
            }
            return false;
        }
    }

    return false;
}


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
                           struct port *port)
{
    struct iface *iface = NULL;

    if ((acl_port_iface == NULL) || (port == NULL)) {
        return false;
    }

    LIST_FOR_EACH(iface, port_elem, &port->ifaces) {
        if (acl_port_iface->ofp_port == iface->ofp_port)
        {
            return false;
        }
    }

    return true;
}


/**************************************************************************//**
 * This function checks if an ACL is configured for a LAG port
 * and if yes, deletes the config status in the port table
 *
 * @param[in] acl_port  - Pointer to @see struct acl_port
 * @param[in] port      - Pointer to @see struct port
 *****************************************************************************/
void
acl_port_lag_check_and_delete_cfg_status(struct acl_port *acl_port,
                                         struct port *port)
{
    if ((acl_port == NULL) || (port == NULL)) {
        return;
    }

    for (int acl_type_iter = ACL_CFG_MIN_PORT_TYPES;
          acl_type_iter <= ACL_CFG_MAX_PORT_TYPES; acl_type_iter++) {
        const struct ovsrec_acl *ovsdb_acl =
                 acl_db_util_get_cfg(acl_port->port_map[acl_type_iter].acl_db,
                                     port->cfg);
        if (ovsdb_acl == NULL) {
            continue;
        }

        acl_db_util_status_delkey(acl_port->port_map[acl_type_iter].acl_db,
                                  port->cfg,
                                  OPS_CLS_STATUS_VERSION_STR);
        acl_db_util_status_delkey(acl_port->port_map[acl_type_iter].acl_db,
                                  port->cfg,
                                  OPS_CLS_STATUS_STATE_STR);
        acl_db_util_status_delkey(acl_port->port_map[acl_type_iter].acl_db,
                                  port->cfg,
                                  OPS_CLS_STATUS_CODE_STR);
        acl_db_util_status_delkey(acl_port->port_map[acl_type_iter].acl_db,
                                  port->cfg,
                                  OPS_CLS_STATUS_MSG_STR);
    }
}
