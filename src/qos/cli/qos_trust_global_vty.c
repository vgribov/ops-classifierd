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

#include "qos_trust_global_vty.h"

#include <libaudit.h>

#include "memory.h"
#include "openswitch-idl.h"
#include "openvswitch/vlog.h"
#include "ovsdb-idl.h"
#include "qos_utils.h"
#include "qos_utils_vty.h"
#include "smap.h"
#include "vswitch-idl.h"
#include "vtysh/command.h"
#include "vtysh/vtysh.h"
#include "vtysh/vtysh_ovsdb_config.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_user.h"

VLOG_DEFINE_THIS_MODULE(vtysh_qos_trust_global_cli);
extern struct ovsdb_idl *idl;

/**
 * Executes the qos_trust_global_command for the given qos_trust_name.
 */
static int
qos_trust_global_command(const char *qos_trust_name)
{
    if (qos_trust_name == NULL) {
        vty_out(vty, "qos trust name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    const struct ovsrec_system *system_row = ovsrec_system_first(idl);
    if (system_row == NULL) {
        vty_out(vty, "System config does not exist.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    struct ovsdb_idl_txn *txn = cli_do_config_start();
    if (txn == NULL) {
        vty_out(vty, "Unable to start transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    struct smap smap;
    smap_clone(&smap, &system_row->qos_config);
    smap_replace(&smap, QOS_TRUST_KEY, qos_trust_name);
    ovsrec_system_set_qos_config(system_row, &smap);
    smap_destroy(&smap);

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

/**
 * Executes the qos_trust_global_command.
 */
DEFUN(qos_trust_global,
        qos_trust_global_cmd,
        "qos trust (none|cos|dscp)",
        QOS_HELP_STRING
        "Set the top-level QoS Trust Mode configuration\n"
        "Do not trust any priority fields, and remark \
all of them to 0 (Default)\n"
        "Trust 802.1p priority and preserve DSCP or IP-ToS\n"
        "Trust DSCP and remark the 802.1p priority to match\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE] = "op=CLI: qos trust";

    const char *qos_trust_name = argv[0];
    qos_audit_encode(aubuf, sizeof(aubuf), "qos_trust_name", qos_trust_name);

    int result = qos_trust_global_command(qos_trust_name);

    qos_audit_log(aubuf, result);

    return result;
}

/**
 * Executes the qos_trust_global_no_command.
 */
static int
qos_trust_global_no_command(void)
{
    qos_trust_global_command(QOS_TRUST_DEFAULT);

    return CMD_SUCCESS;
}

/**
 * Executes the qos_trust_global_no_command.
 */
DEFUN(qos_trust_global_no,
        qos_trust_global_no_cmd,
        "no qos trust {none|cos|dscp}",
        NO_STR
        QOS_HELP_STRING
        "Restore the top-level QoS Trust Mode to its factory default\n"
        "Do not trust any priority fields, and \
remark all of them to 0 (Default)\n"
        "Trust 802.1p priority and preserve DSCP or IP-ToS\n"
        "Trust DSCP and remark the 802.1p priority to match\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE] = "op=CLI: no qos trust";

    int result = qos_trust_global_no_command();

    qos_audit_log(aubuf, result);

    return result;
}

/**
 * Executes the qos_trust_global_show_command for the given default_parameter.
 */
static int
qos_trust_global_show_command(const char *default_parameter)
{
    const char *qos_trust_name;
    if (default_parameter != NULL) {
        /* Show the factory default. */
        qos_trust_name = QOS_TRUST_DEFAULT;
    } else {
        /* Show the active value. */
        const struct ovsrec_system *system_row = ovsrec_system_first(idl);
        if (system_row == NULL) {
            vty_out(vty, "System config does not exist.%s", VTY_NEWLINE);
            return CMD_OVSDB_FAILURE;
        }

        qos_trust_name = smap_get(&system_row->qos_config, QOS_TRUST_KEY);
    }

    vty_out(vty, "qos trust %s%s", qos_trust_name, VTY_NEWLINE);

    return CMD_SUCCESS;
}

/**
 * Executes the qos_trust_global_show_command.
 */
DEFUN(qos_trust_global_show,
        qos_trust_global_show_cmd,
        "show qos trust {default}",
        SHOW_STR
        "Show QoS Configuration\n"
        "Show QoS Trust Configuration\n"
        "Display the factory default value\n")
{
    const char *default_parameter = argv[0];

    return qos_trust_global_show_command(default_parameter);
}

/**
 * The callback function for qos_trust_global_show_running_config.
 */
static vtysh_ret_val
qos_trust_global_show_running_config_callback(
        void *p_private)
{
    const struct ovsrec_system *system_row = ovsrec_system_first(idl);
    if (system_row == NULL) {
        return e_vtysh_ok;
    }

    const char *qos_trust_name = smap_get(&system_row->qos_config,
            QOS_TRUST_KEY);
    if (qos_trust_name == NULL) {
        return e_vtysh_ok;
    }

    if (strncmp(qos_trust_name, QOS_TRUST_DEFAULT,
            QOS_CLI_STRING_BUFFER_SIZE) != 0) {
        vty_out(vty, "qos trust %s%s", qos_trust_name, VTY_NEWLINE);
    }

    return e_vtysh_ok;
}

/**
 * Installs the callback function for qos_trust_global_show_running_config.
 */
void
qos_trust_global_show_running_config(void)
{
    vtysh_ret_val retval = install_show_run_config_context(
                              e_vtysh_qos_trust_global_context,
                              &qos_trust_global_show_running_config_callback,
                              NULL, NULL);
    if (retval != e_vtysh_ok) {
        vtysh_ovsdb_config_logmsg(VTYSH_OVSDB_CONFIG_ERR,
                           "Context unable "\
                           "to add config callback");
    }
}

/**
 * Initializes qos_trust_global_vty.
 */
void
qos_trust_global_vty_init(void)
{
    install_element(CONFIG_NODE, &qos_trust_global_cmd);
    install_element(CONFIG_NODE, &qos_trust_global_no_cmd);
    install_element (ENABLE_NODE, &qos_trust_global_show_cmd);
}

/**
 * Initializes qos_trust_global_ovsdb.
 */
void
qos_trust_global_ovsdb_init(void)
{
    ovsdb_idl_add_table(idl, &ovsrec_table_system);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_qos_config);
}
