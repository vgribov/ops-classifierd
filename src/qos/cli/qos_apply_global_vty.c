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

#include "qos_apply_global_vty.h"

#include <libaudit.h>

#include "memory.h"
#include "openswitch-idl.h"
#include "openvswitch/vlog.h"
#include "ovsdb-idl.h"
#include "qos_queue_profile_vty.h"
#include "qos_schedule_profile_vty.h"
#include "qos_utils.h"
#include "qos_utils_vty.h"
#include "smap.h"
#include "vswitch-idl.h"
#include "vtysh/command.h"
#include "vtysh/vtysh.h"
#include "vtysh/vtysh_ovsdb_config.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_user.h"

VLOG_DEFINE_THIS_MODULE(vtysh_qos_apply_global_cli);
extern struct ovsdb_idl *idl;

/**
 * Returns true if the given queue_profile_row and schedule_profile_row
 * contain the same queues.
 */
bool
qos_profiles_contain_same_queues(
        struct ovsrec_q_profile * queue_profile_row,
        struct ovsrec_qos *schedule_profile_row)
{
    /* Check that each queue profile queue_num is in the schedule profile. */
    int i;
    for (i = 0; i < queue_profile_row->n_q_profile_entries; i++) {
        int64_t queue_num = queue_profile_row->key_q_profile_entries[i];
        if (!qos_schedule_profile_has_queue_num(
                schedule_profile_row, queue_num)) {
            return false;
        }
    }

    /* Check that each schedule profile queue_num is in the queue profile. */
    for (i = 0; i < schedule_profile_row->n_queues; i++) {
        int64_t queue_num = schedule_profile_row->key_queues[i];
        if (!qos_queue_profile_has_queue_num(queue_profile_row, queue_num)) {
            return false;
        }
    }

    return true;
}

/**
 * Returns true if the queue_profile_row contains the same queues as all
 * of the port schedule profiles.
 */
static bool
qos_port_profiles_contain_same_queues(
        struct ovsrec_q_profile * queue_profile_row)
{
    const struct ovsrec_port *port_row;
    OVSREC_PORT_FOR_EACH(port_row, idl) {
        struct ovsrec_qos *port_schedule_profile = port_row->qos;
        if (port_schedule_profile == NULL) {
            continue;
        }

        if (!qos_profiles_contain_same_queues(
                queue_profile_row, port_schedule_profile)) {
            vty_out(vty, "The queue profile and the schedule\
 profile applied on port %s cannot contain different queues.%s",
                    port_row->name, VTY_NEWLINE);
            return false;
        }
    }

    return true;
}

/**
 * Executes the qos_apply_global_command for the given queue_profile_name
 * and schedule_profile_name.
 */
static int
qos_apply_global_command(const char *queue_profile_name,
        const char *schedule_profile_name)
{
    if (queue_profile_name == NULL) {
        vty_out(vty, "queue_profile_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (!qos_is_valid_string(queue_profile_name)) {
        vty_out(vty, QOS_INVALID_STRING_ERROR_MESSAGE, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (schedule_profile_name == NULL) {
        vty_out(vty, "schedule_profile_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (!qos_is_valid_string(schedule_profile_name)) {
        vty_out(vty, QOS_INVALID_STRING_ERROR_MESSAGE, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    /* Retrieve the queue profile. */
    struct ovsrec_q_profile *queue_profile_row = qos_get_queue_profile_row(
            queue_profile_name);
    if (queue_profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                queue_profile_name, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    /* Check that the profile is complete. */
    if (!qos_queue_profile_is_complete(queue_profile_row, true)) {
        return CMD_OVSDB_FAILURE;
    }

    /* If the profile is strict, make sure the 'strict' profile exists. */
    if (strncmp(schedule_profile_name, OVSREC_QUEUE_ALGORITHM_STRICT,
            QOS_CLI_STRING_BUFFER_SIZE) == 0) {
        int result = qos_schedule_profile_create_strict_profile_commit();
        if (result != CMD_SUCCESS) {
            return result;
        }
    }

    /* Retrieve the schedule profile. */
    struct ovsrec_qos *schedule_profile_row = qos_get_schedule_profile_row(
            schedule_profile_name);
    if (schedule_profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                schedule_profile_name, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    /* Perform some checks, but only if the profile is not strict.
     * The strict profile does not contain any queues. */
    if (strncmp(schedule_profile_name, OVSREC_QUEUE_ALGORITHM_STRICT,
            QOS_CLI_STRING_BUFFER_SIZE) != 0) {
        /* Check that the profile is complete. */
        if (!qos_schedule_profile_is_complete(schedule_profile_row, true)) {
            return CMD_OVSDB_FAILURE;
        }

        /* Check that profiles contain all the same queues. */
        if (!qos_profiles_contain_same_queues(queue_profile_row,
                schedule_profile_row)) {
            vty_out(vty, "The queue profile and the schedule\
 profile cannot contain different queues.%s",
                    VTY_NEWLINE);
            return CMD_OVSDB_FAILURE;
        }
    }

    /* Validate that the queue profile is consistent with any other
     * port-applied schedule profiles. */
    if (!qos_port_profiles_contain_same_queues(queue_profile_row)) {
        return CMD_OVSDB_FAILURE;
    }

    /* Retrieve the system row. */
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

    /* Set the profiles in the system row. */
    ovsrec_system_set_q_profile(system_row, queue_profile_row);
    ovsrec_system_set_qos(system_row, schedule_profile_row);

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

/**
 * Executes the qos_apply_global_command for the given queue_profile_name
 * and schedule_profile_name.
 */
DEFUN(qos_apply_global,
        qos_apply_global_cmd,
        "apply qos queue-profile NAME schedule-profile NAME",
        "Apply a configuration\n"
        "Configure QoS\n"
        "The queue-profile to apply\n"
        "The queue-profile to apply\n"
        "The schedule-profile to apply\n"
        "The schedule-profile to apply\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE] = "op=CLI: apply qos";

    const char *queue_profile_name = argv[0];
    qos_audit_encode(aubuf, sizeof(aubuf),
            "queue_profile_name", queue_profile_name);

    const char *schedule_profile_name = argv[1];
    qos_audit_encode(aubuf, sizeof(aubuf),
            "schedule_profile_name", schedule_profile_name);

    int result = qos_apply_global_command(
            queue_profile_name, schedule_profile_name);

    qos_audit_log(aubuf, result);

    return result;
}

/**
 * Executes the qos_apply_global_strict_command for the given
 * queue_profile_name and schedule_profile_name.
 */
DEFUN(qos_apply_global_strict,
        qos_apply_global_strict_cmd,
        "apply qos queue-profile NAME schedule-profile strict",
        "Apply a configuration\n"
        "Configure QoS\n"
        "The queue-profile to apply\n"
        "The queue-profile to apply\n"
        "The schedule-profile to apply\n"
        "Use the strict schedule profile which has all\
 queues configured to use the strict algorithm\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE] = "op=CLI: appy qos";

    const char *queue_profile_name = argv[0];
    qos_audit_encode(aubuf, sizeof(aubuf),
            "queue_profile_name", queue_profile_name);

    const char *schedule_profile_name = OVSREC_QUEUE_ALGORITHM_STRICT;
    qos_audit_encode(aubuf, sizeof(aubuf),
            "schedule_profile_name", schedule_profile_name);

    int result = qos_apply_global_command(
            queue_profile_name, schedule_profile_name);

    qos_audit_log(aubuf, result);

    return result;
}

/**
 * Contains the callback function for qos_apply_global_show_running_config.
 */
static vtysh_ret_val
qos_apply_global_show_running_config_callback(
        void *p_private)
{
    qos_queue_profile_show_running_config();
    qos_schedule_profile_show_running_config();

    const struct ovsrec_system *system_row = ovsrec_system_first(idl);
    struct ovsrec_q_profile *q_profile_row = system_row->q_profile;
    struct ovsrec_qos *schedule_profile_row = system_row->qos;

    bool queue_profile_differs_from_default =
            strncmp(q_profile_row->name, QOS_DEFAULT_NAME,
                    QOS_CLI_STRING_BUFFER_SIZE) != 0;

    bool schedule_profile_differs_from_default =
            strncmp(schedule_profile_row->name, QOS_DEFAULT_NAME,
                    QOS_CLI_STRING_BUFFER_SIZE) != 0;

    if (queue_profile_differs_from_default ||
            schedule_profile_differs_from_default) {
        /* Show the apply command. */
        vty_out(vty, "apply qos queue-profile %s schedule-profile %s%s",
                q_profile_row->name, schedule_profile_row->name,
                VTY_NEWLINE);
    }

    return e_vtysh_ok;
}

/**
 * Installs the callback function for qos_apply_global_show_running_config.
 */
void
qos_apply_global_show_running_config(void)
{
    vtysh_ret_val retval = install_show_run_config_context(
                              e_vtysh_qos_apply_global_context,
                              &qos_apply_global_show_running_config_callback,
                              NULL, NULL);
    if (retval != e_vtysh_ok) {
        vtysh_ovsdb_config_logmsg(VTYSH_OVSDB_CONFIG_ERR,
                           "Context unable "\
                           "to add config callback");
    }
}

/**
 * Initializes qos_apply_global_vty.
 */
void
qos_apply_global_vty_init(void)
{
    install_element(CONFIG_NODE, &qos_apply_global_cmd);
    install_element(CONFIG_NODE, &qos_apply_global_strict_cmd);
}

/**
 * Initializes qos_apply_global_ovsdb.
 */
void
qos_apply_global_ovsdb_init(void)
{
    ovsdb_idl_add_table(idl, &ovsrec_table_system);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_q_profile);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_qos);
}
