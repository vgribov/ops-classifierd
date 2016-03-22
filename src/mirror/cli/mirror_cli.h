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

#ifndef _MIRROR_CLI_H_
#define _MIRROR_CLI_H_

#define MAX_MIRROR_SESSION_NAME_LEN 64
#define MAX_BR_OR_VRF_NAME_LEN strlen(DEFAULT_BRIDGE_NAME)
#define MAX_SRC_DIR_LEN      4

#define SRC_DIR_TX                  "tx"
#define SRC_DIR_RX                  "rx"
#define SRC_DIR_BOTH                "both"

#define SHOW_HELPSTR                "Show"
#define MIRROR_HELPSTR              "Configure Mirroring\n"
#define MIRROR_SESSION_HELPSTR      "Create a Mirror Session\n"
#define MIRROR_SESSION_NAME_HELPSTR "Mirror Session Name\n"
#define DST_HELPSTR                 "Mirror destination interface\n"
#define IFACE_HELPSTR               "System Interface\n"
#define IFACE_NAME_HELPSTR          "Interface's Name\n"
#define SRC_HELPSTR                 "A source of traffic to mirror\n"
#define SRC_DIR_TX_HELPSTR          "A source of transmit-only traffic\n"
#define SRC_DIR_RX_HELPSTR          "A source of receive-only traffic\n"
#define SRC_DIR_BOTH_HELPSTR        "A source of transmit & receive traffic\n"
#define SHUT_HELPSTR                "Mirror shutdown\n"
#define NO_HELPSTR                  "Undo an operation\n"

#define MIRROR_CONFIG_OPERATION_STATE "operation_state"
#define MIRROR_CONFIG_STATE_ACTIVE    "active"
#define MIRROR_CONFIG_STATE_SHUTDOWN  "shutdown"

vtysh_ret_val cli_show_mirror_running_config_callback(void*);
void mirror_pre_init(void);
void mirror_vty_init(void);

#endif /* _MIRROR_CLI_H_ */
