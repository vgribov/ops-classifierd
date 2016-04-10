/****************************************************************************
 * (c) Copyright 2015-2016 Hewlett Packard Enterprise Development LP
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

#include <config.h>

#include "qos_utils_vty.h"

#include <libaudit.h>

#include "memory.h"
#include "openswitch-idl.h"
#include "openvswitch/vlog.h"
#include "ovsdb-idl.h"
#include "qos_utils.h"
#include "smap.h"
#include "vswitch-idl.h"
#include "vtysh/command.h"
#include "vtysh/vtysh.h"
#include "vtysh/vtysh_ovsdb_config.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_user.h"

VLOG_DEFINE_THIS_MODULE(vtysh_qos_utils_cli);
extern struct ovsdb_idl *idl;

int audit_fd;

/**
 * Returns true if the given character is valid.
 */
static bool
is_valid_char(char c)
{
    return isalnum(c) || c == '_' || c == '-' || c == '.';
}

/**
 * Returns true if the given string is valid.
 */
bool
qos_is_valid_string(const char *string)
{
    if (string == NULL) {
        return false;
    }

    int length = strlen(string);
    if (length > QOS_CLI_MAX_STRING_LENGTH) {
        return false;
    }

    int i;
    for (i = 0; i < length; i++) {
        char c = string[i];

        if (!is_valid_char(c)) {
            return false;
        }
    }

    return true;
}

/**
 * Returns the port_row for the given port_name.
 */
struct ovsrec_port *
port_row_for_name(const char *port_name)
{
    const struct ovsrec_port *port_row;
    OVSREC_PORT_FOR_EACH(port_row, idl) {
        if (strncmp(port_row->name, port_name,
                QOS_CLI_STRING_BUFFER_SIZE) == 0) {
            return (struct ovsrec_port *) port_row;
        }
    }

    return NULL;
}

/**
 * Returns true if the port_name is a member of a lag.
 */
bool
is_member_of_lag(const char *port_name)
{
    const struct ovsrec_port *port_row;
    OVSREC_PORT_FOR_EACH(port_row, idl) {
        int i;
        for (i = 0; i < port_row->n_interfaces; i++) {
            if ((strncmp(port_row->interfaces[i]->name, port_name,
                    QOS_CLI_STRING_BUFFER_SIZE) == 0)
                    && (strncmp(port_row->name, port_name,
                            QOS_CLI_STRING_BUFFER_SIZE) != 0)) {
                return true;
            }
        }
    }

    return false;
}

/**
 * Initializes the audit log.
 */
void qos_audit_init(void) {
    audit_fd = audit_open();
}

/**
 * Encodes the given arg_name and arg_value into the given aubuf and ausize.
 */
void
qos_audit_encode(char *aubuf, size_t ausize, const char *arg_name,
        const char *arg_value)
{
    if (arg_value != NULL) {
        char *cfg = audit_encode_nv_string(arg_name, arg_value, 0);
        if (cfg != NULL) {
            size_t current_length = strlen(aubuf);
            strncat(aubuf, cfg, ausize - current_length);
            free(cfg);
        }
    }
}

/**
 * Logs the given aubuf and command_result to the audit log.
 */
void
qos_audit_log(const char *aubuf, int command_result)
{
    char hostname[HOST_NAME_MAX];
    gethostname(hostname, HOST_NAME_MAX);

    audit_log_user_message(audit_fd, AUDIT_USYS_CONFIG,
            aubuf, hostname, NULL, NULL, command_result);
}
