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

#include "qos_schedule_profile_vty.h"

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

VLOG_DEFINE_THIS_MODULE(vtysh_qos_schedule_profile_cli);
extern struct ovsdb_idl *idl;

/**
 * Global state for the profile name.
 */
static char g_profile_name[QOS_CLI_STRING_BUFFER_SIZE];

/**
 * Returns the schedule_profile_row for the given profile_name.
 */
struct ovsrec_qos *
qos_get_schedule_profile_row(
        const char *profile_name)
{
    const struct ovsrec_qos *profile_row;
    OVSREC_QOS_FOR_EACH(profile_row, idl) {
        if (strncmp(profile_row->name, profile_name,
                QOS_CLI_STRING_BUFFER_SIZE) == 0) {
            return (struct ovsrec_qos *) profile_row;
        }
    }

    return NULL;
}

/**
 * Returns the schedule_profile_entry_row for the given profile_row and
 * queue_num.
 */
static struct ovsrec_queue *
qos_get_schedule_profile_entry_row(
        struct ovsrec_qos *profile_row, int64_t queue_num)
{
    int i;
    for (i = 0; i < profile_row->n_queues; i++) {
        if (profile_row->key_queues[i] == queue_num) {
            return profile_row->value_queues[i];
        }
    }

    return NULL;
}

/**
 * Returns true if the given profile_row has the given queue_num.
 */
bool
qos_schedule_profile_has_queue_num(struct ovsrec_qos *profile_row,
        int64_t queue_num)
{
    int j;
    for (j = 0; j < profile_row->n_queues; j++) {
        int64_t profile_queue_num = profile_row->key_queues[j];
        if (queue_num == profile_queue_num) {
            return true;
        }
    }

    return false;
}

/**
 * Returns the max queue_num for the given profile_row.
 */
static int64_t
get_max_queue_num(struct ovsrec_qos *profile_row)
{
    int64_t max_queue_num = -1;

    int i;
    for (i = 0; i < profile_row->n_queues; i++) {
        if (profile_row->key_queues[i] > max_queue_num) {
            max_queue_num = profile_row->key_queues[i];
        }
    }

    return max_queue_num;
}

/**
 * Returns true if the given profile_row is complete. If 'print_error' is
 * true, then any errors will be printed.
 */
bool
qos_schedule_profile_is_complete(struct ovsrec_qos *profile_row,
        bool print_error)
{
    if (profile_row->n_queues == 0) {
        if (print_error) {
            vty_out(vty, "The schedule profile must have at least\
one queue.%s", VTY_NEWLINE);
        }
        return false;
    }

    /**
     * The spec is:
     * There are two allowed forms for schedule profiles: 1. All queues use
     * the same scheduling algorithm (e.g. dwrr) 2. The highest queue number
     * uses Strict Priority and all remaining (lower) queues use the same
     * algorithm (e.g. dwrr)
     *
     * Or, to phrase another way, all queues always use the same scheduling
     * algorithm, but the max queue number can either be the same as all of
     * the others, or it can be strict.
     */

    int64_t max_queue_num = get_max_queue_num(profile_row);
    const char *algorithm = NULL;
    int i;
    for (i = 0; i < profile_row->n_queues; i++) {
        /* If it's the max and it's strict, then skip it. */
        if (max_queue_num == profile_row->key_queues[i] &&
                strncmp(profile_row->value_queues[i]->algorithm,
                        OVSREC_QUEUE_ALGORITHM_STRICT,
                        QOS_CLI_STRING_BUFFER_SIZE) == 0) {
            continue;
        }

        if (algorithm == NULL) {
            algorithm = profile_row->value_queues[i]->algorithm;
        }

        if (strncmp(profile_row->value_queues[i]->algorithm,
                algorithm, QOS_CLI_STRING_BUFFER_SIZE) != 0) {
            if (print_error) {
                vty_out(vty, "The schedule profile must have the same\
 algorithm assigned to each queue.%s",
                        VTY_NEWLINE);
            }
            return false;
        }
    }

    return true;
}

/**
 * Returns true if the given profile_row is applied.
 */
static bool
is_row_applied(const struct ovsrec_qos *profile_row)
{
    if (profile_row == NULL) {
        return false;
    }

    const struct ovsrec_system *system_row = ovsrec_system_first(idl);
    if (system_row->qos == profile_row) {
        return true;
    }

    const struct ovsrec_port *port_row;
    OVSREC_PORT_FOR_EACH(port_row, idl) {
        if (port_row->qos == profile_row) {
            return true;
        }
    }

    return false;
}

/**
 * Returns true if the given profile_name is applied.
 */
static bool
is_applied(const char *profile_name)
{
    struct ovsrec_qos *profile_row = qos_get_schedule_profile_row(
            profile_name);

    return is_row_applied(profile_row);
}

/**
 * Returns true if the given profile_row is a hw_default row.
 */
static bool
is_row_hw_default(const struct ovsrec_qos *profile_row)
{
    if (profile_row == NULL) {
        return false;
    }

    if (profile_row->hw_default == NULL) {
        return false;
    }

    return *profile_row->hw_default;
}

/**
 * Returns true is the row for the given profile_name is a hw_default row.
 */
static bool
is_hw_default(const char *profile_name)
{
    struct ovsrec_qos *profile_row = qos_get_schedule_profile_row(
            profile_name);

    return is_row_hw_default(profile_row);
}

/**
 * Inserts into the database and returns the queue_row for the given
 * profile_row, queue_num, and txn.
 */
static struct ovsrec_queue *
insert_queue_row(
        struct ovsrec_qos *profile_row, int64_t queue_num,
        struct ovsdb_idl_txn *txn)
{
    /* Create the queue row. */
    struct ovsrec_queue *queue_row =
            ovsrec_queue_insert(txn);

    /* Update the profile row. */
    int64_t *key_list =
            xmalloc(sizeof(int64_t) *
                    (profile_row->n_queues + 1));
    struct ovsrec_queue **value_list =
            xmalloc(sizeof *profile_row->value_queues *
                    (profile_row->n_queues + 1));

    int i;
    for (i = 0; i < profile_row->n_queues; i++) {
        key_list[i] = profile_row->key_queues[i];
        value_list[i] = profile_row->value_queues[i];
    }
    key_list[profile_row->n_queues] = queue_num;
    value_list[profile_row->n_queues] = queue_row;
    ovsrec_qos_set_queues(profile_row, key_list,
            value_list, profile_row->n_queues + 1);
    free(key_list);
    free(value_list);

    return queue_row;
}

/**
 * Executes the qos_schedule_profile_command for the given profile_name.
 */
static bool
qos_schedule_profile_command(struct ovsdb_idl_txn *txn,
        const char *profile_name)
{
    /* Retrieve the row. */
    struct ovsrec_qos *profile_row =
            qos_get_schedule_profile_row(profile_name);
    if (profile_row == NULL) {
        /* Create a new row. */
        profile_row = ovsrec_qos_insert(txn);
        ovsrec_qos_set_name(profile_row, profile_name);
    }

    return true;
}

/**
 * Executes and commits the qos_schedule_profile_command for the
 * given profile_name.
 */
static int
qos_schedule_profile_command_commit(const char *profile_name)
{
    if (profile_name == NULL) {
        vty_out(vty, "profile_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (!qos_is_valid_string(profile_name)) {
        vty_out(vty, QOS_INVALID_STRING_ERROR_MESSAGE, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (strncmp(profile_name, OVSREC_QUEUE_ALGORITHM_STRICT,
            QOS_CLI_STRING_BUFFER_SIZE) == 0) {
        vty_out(vty, "The profile name cannot be '%s'.%s",
                OVSREC_QUEUE_ALGORITHM_STRICT, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_applied(profile_name)) {
        vty_out(vty, "An applied profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_hw_default(profile_name)) {
        vty_out(vty,
                "A hardware default profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    struct ovsdb_idl_txn *txn = cli_do_config_start();
    if (txn == NULL) {
        vty_out(vty, "Unable to start transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    bool success = qos_schedule_profile_command(txn, profile_name);
    if (!success) {
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    strncpy(g_profile_name, profile_name, sizeof(g_profile_name));
    vty->node = QOS_SCHEDULE_PROFILE_NODE;
    vty->index = g_profile_name;
    return CMD_SUCCESS;
}

/**
 * Executes the qos_schedule_profile_command.
 */
DEFUN(qos_schedule_profile,
        qos_schedule_profile_cmd,
       "qos schedule-profile NAME",
       "Configure QoS\n"
       "Set the QoS Schedule Profile configuration\n"
       "The name of the Schedule Profile\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE] = "op=CLI: qos schedule-profile";

    const char *profile_name = argv[0];
    qos_audit_encode(aubuf, sizeof(aubuf), "profile_name", profile_name);

    int result = qos_schedule_profile_command_commit(profile_name);

    qos_audit_log(aubuf, result);

    return result;
}

/**
 * Executes the qos_schedule_profile_no_command for the given
 * profile_name.
 */
static bool
qos_schedule_profile_no_command(struct ovsdb_idl_txn *txn,
        const char *profile_name)
{
    /* Retrieve the row. */
    struct ovsrec_qos *profile_row =
            qos_get_schedule_profile_row(profile_name);
    if (profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                profile_name, VTY_NEWLINE);
        return false;
    }

    if (strncmp(profile_name, QOS_DEFAULT_NAME,
            QOS_CLI_STRING_BUFFER_SIZE) == 0) {
        /* For the profile named 'default', restore the factory defaults. */

        /* Delete all default profile queue rows. */
        ovsrec_qos_set_queues(profile_row, NULL, NULL, 0);

        /* Retrieve the factory default row. */
        struct ovsrec_qos *factory_default_profile_row =
                qos_get_schedule_profile_row(QOS_FACTORY_DEFAULT_NAME);
        if (factory_default_profile_row == NULL) {
            vty_out(vty, "Profile %s does not exist.%s",
                    QOS_FACTORY_DEFAULT_NAME, VTY_NEWLINE);
            return false;
        }

        /* Copy all factory defaults into new entry rows. */
        int64_t queue_row_count =
                factory_default_profile_row->n_queues;
        int64_t *key_list =
                xmalloc(sizeof(int64_t) *
                        queue_row_count);
        struct ovsrec_queue **value_list =
                xmalloc(sizeof *profile_row->value_queues *
                        queue_row_count);
        int j;
        for (j = 0; j < queue_row_count; j++) {
            struct ovsrec_queue *queue_row =
                    ovsrec_queue_insert(txn);
            struct ovsrec_queue *default_row =
                    factory_default_profile_row->value_queues[j];
            ovsrec_queue_set_algorithm(queue_row, default_row->algorithm);
            ovsrec_queue_set_weight(queue_row, default_row->weight,
                    default_row->weight == NULL ? 0 : 1);
            key_list[j] = factory_default_profile_row->key_queues[j];
            value_list[j] = queue_row;
        }

        /* Add the new entry rows to the profile row. */
        ovsrec_qos_set_queues(profile_row, key_list,
                value_list, queue_row_count);
        free(key_list);
        free(value_list);
    } else {
        /* If not the profile named 'default', delete the row. */
        ovsrec_qos_delete(profile_row);
    }

    return true;
}

/**
 * Executes and commits the qos_schedule_profile_no_command for the given
 * profile_name.
 */
static int
qos_schedule_profile_no_command_commit(const char *profile_name)
{
    if (profile_name == NULL) {
        vty_out(vty, "profile_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (!qos_is_valid_string(profile_name)) {
        vty_out(vty, QOS_INVALID_STRING_ERROR_MESSAGE, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (strncmp(profile_name, OVSREC_QUEUE_ALGORITHM_STRICT,
            QOS_CLI_STRING_BUFFER_SIZE) == 0) {
        vty_out(vty, "The profile name cannot be '%s'.%s",
                OVSREC_QUEUE_ALGORITHM_STRICT, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_applied(profile_name)) {
        vty_out(vty, "An applied profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_hw_default(profile_name)) {
        vty_out(vty,
                "A hardware default profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    struct ovsdb_idl_txn *txn = cli_do_config_start();
    if (txn == NULL) {
        vty_out(vty, "Unable to start transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    bool success = qos_schedule_profile_no_command(txn, profile_name);
    if (!success) {
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

/**
 * Executes the qos_schedule_profile_no_command.
 */
DEFUN(qos_schedule_profile_no,
        qos_schedule_profile_no_cmd,
        "no qos schedule-profile NAME",
        NO_STR
        "Configure QoS\n"
        "Deletes a Schedule Profile, if it is not currently applied\n"
        "The name of the Schedule Profile to delete\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE] = "op=CLI: no qos schedule-profile";

    const char *profile_name = argv[0];
    qos_audit_encode(aubuf, sizeof(aubuf), "profile_name", profile_name);

    int result = qos_schedule_profile_no_command_commit(profile_name);

    qos_audit_log(aubuf, result);

    return result;
}

/**
 * Executes the qos_schedule_profile_strict_command for the given
 * profile_name.
 */
static bool
qos_schedule_profile_strict_command(struct ovsdb_idl_txn *txn,
        const char *profile_name,
        int64_t queue_num)
{
    /* Retrieve the profile row. */
    struct ovsrec_qos *profile_row =
            qos_get_schedule_profile_row(profile_name);
    if (profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                profile_name, VTY_NEWLINE);
        return false;
    }

    /* Retrieve the existing queue row. */
    struct ovsrec_queue *queue_row =
            qos_get_schedule_profile_entry_row(profile_row, queue_num);

    /* If no existing row, then insert a new queue row. */
    if (queue_row == NULL) {
        queue_row = insert_queue_row(profile_row, queue_num, txn);
    }

    /* Update the queue row. */
    ovsrec_queue_set_algorithm(queue_row, OVSREC_QUEUE_ALGORITHM_STRICT);
    ovsrec_queue_set_weight(queue_row, NULL, 0);

    return true;
}

/**
 * Executes and commits the qos_schedule_profile_strict_command for the given
 * profile_name.
 */
static int
qos_schedule_profile_strict_command_commit(
        const char *profile_name,
        int64_t queue_num)
{
    if (profile_name == NULL) {
        vty_out(vty, "profile_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_applied(profile_name)) {
        vty_out(vty, "An applied profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_hw_default(profile_name)) {
        vty_out(vty,
                "A hardware default profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    struct ovsdb_idl_txn *txn = cli_do_config_start();
    if (txn == NULL) {
        vty_out(vty, "Unable to start transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    bool success = qos_schedule_profile_strict_command(txn, profile_name,
            queue_num);
    if (!success) {
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

/**
 * Executes the qos_schedule_profile_strict_command.
 */
DEFUN(qos_schedule_profile_strict,
        qos_schedule_profile_strict_cmd,
       "strict queue <0-7>",
       "Configure a queue in a Schedule Profile to use strict scheduling\n"
       "The number of the queue\n"
       "The number of the queue\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE] = "op=CLI: strict queue";

    const char *profile_name = (char*) vty->index;
    qos_audit_encode(aubuf, sizeof(aubuf), "profile_name", profile_name);

    const char *queue_num = argv[0];
    qos_audit_encode(aubuf, sizeof(aubuf), "queue_num", queue_num);
    int64_t queue_num_int = atoi(queue_num);

    int result = qos_schedule_profile_strict_command_commit(
            profile_name, queue_num_int);

    qos_audit_log(aubuf, result);

    return result;
}

/**
 * Returns true if the given queue_row is not empty.
 */
static bool
has_content(struct ovsrec_queue *queue_row)
{
    if ((queue_row->algorithm == NULL) &&
            (queue_row->weight == NULL ||
                    queue_row->n_weight == 0)) {
        return false;
    } else {
        return true;
    }
}

/**
 * Deletes the queue_row for the given queue_num.
 */
static void
delete_queue_row(
        struct ovsrec_qos *profile_row, int64_t queue_num)
{
    int64_t *key_list =
            xmalloc(sizeof(int64_t) *
                    (profile_row->n_queues - 1));
    struct ovsrec_queue **value_list =
            xmalloc(sizeof *profile_row->value_queues *
                    (profile_row->n_queues - 1));
    int i;
    int j = 0;
    for (i = 0; i < profile_row->n_queues; i++) {
        if (profile_row->key_queues[i] != queue_num) {
            key_list[j] = profile_row->key_queues[i];
            value_list[j] = profile_row->value_queues[i];
            j++;
        }
    }
    ovsrec_qos_set_queues(profile_row, key_list,
            value_list, profile_row->n_queues - 1);
    free(key_list);
    free(value_list);
}

/**
 * Executes the qos_schedule_profile_strict_no_command for the given
 * profile_name and queue_num. Returns true if an error occurred.
 */
static bool
qos_schedule_profile_strict_no_command(
        struct ovsdb_idl_txn *txn,
        const char *profile_name,
        int64_t queue_num)
{
    /* Retrieve the profile row. */
    struct ovsrec_qos *profile_row =
            qos_get_schedule_profile_row(profile_name);
    if (profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                profile_name, VTY_NEWLINE);
        return false;
    }

    /* Retrieve the existing queue row. */
    struct ovsrec_queue *queue_row =
            qos_get_schedule_profile_entry_row(profile_row, queue_num);
    if (queue_row == NULL) {
        vty_out(vty,
                "Profile %s does not have queue %" PRId64 " configured.%s",
                profile_name, queue_num, VTY_NEWLINE);
        return false;
    }

    /* If the algorithm is strict, then clear it. */
    if (queue_row->algorithm != NULL &&
            strncmp(queue_row->algorithm,
                    OVSREC_QUEUE_ALGORITHM_STRICT,
                    QOS_CLI_STRING_BUFFER_SIZE) == 0) {
        ovsrec_queue_set_algorithm(queue_row, NULL);
        ovsrec_queue_set_weight(queue_row, NULL, 0);
    }

    /* If row has no content, then delete the queue row. */
    if (!has_content(queue_row)) {
        delete_queue_row(profile_row, queue_num);
    }

    return true;
}

/**
 * Executes and commits the qos_schedule_profile_strict_no_command for
 * the given profile_name and queue_num.
 */
static int
qos_schedule_profile_strict_no_command_commit(
        const char *profile_name,
        int64_t queue_num)
{
    if (profile_name == NULL) {
        vty_out(vty, "profile_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_applied(profile_name)) {
        vty_out(vty, "An applied profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_hw_default(profile_name)) {
        vty_out(vty,
                "A hardware default profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    struct ovsdb_idl_txn *txn = cli_do_config_start();
    if (txn == NULL) {
        vty_out(vty, "Unable to start transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    bool success = qos_schedule_profile_strict_no_command(txn, profile_name,
            queue_num);
    if (!success) {
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

/**
 * Executes the qos_schedule_profile_strict_no_command.
 */
DEFUN(qos_schedule_profile_strict_no,
        qos_schedule_profile_strict_no_cmd,
        "no strict queue <0-7>",
        NO_STR
        "Clears the algorithm for a queue, if the algorithm is 'strict'\n"
        "The number of the queue\n"
        "The number of the queue\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE] = "op=CLI: no strict queue";

    const char *profile_name = (char*) vty->index;
    qos_audit_encode(aubuf, sizeof(aubuf), "profile_name", profile_name);

    const char *queue_num = argv[0];
    qos_audit_encode(aubuf, sizeof(aubuf), "queue_num", queue_num);
    int64_t queue_num_int = atoi(queue_num);

    int result = qos_schedule_profile_strict_no_command_commit(
            profile_name, queue_num_int);

    qos_audit_log(aubuf, result);

    return result;
}

/**
 * Executes the qos_schedule_profile_dwrr_command for the given profile_name,
 * queue_num, and weight.
 */
static bool
qos_schedule_profile_dwrr_command(struct ovsdb_idl_txn *txn,
        const char *profile_name,
        int64_t queue_num, int64_t weight)
{
    /* Retrieve the profile row. */
    struct ovsrec_qos *profile_row =
            qos_get_schedule_profile_row(profile_name);
    if (profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                profile_name, VTY_NEWLINE);
        return false;
    }

    /* Retrieve the existing queue row. */
    struct ovsrec_queue *queue_row =
            qos_get_schedule_profile_entry_row(profile_row, queue_num);

    /* If no existing row, then insert a new queue row. */
    if (queue_row == NULL) {
        queue_row = insert_queue_row(profile_row, queue_num, txn);
    }

    /* Update the queue row. */
    ovsrec_queue_set_algorithm(queue_row, OVSREC_QUEUE_ALGORITHM_DWRR);
    ovsrec_queue_set_weight(queue_row, &weight, 1);

    return true;
}

/**
 * Executes and commits the qos_schedule_profile_dwrr_command for
 * the given profile_name, queue_num, and weight.
 */
static int
qos_schedule_profile_dwrr_command_commit(
        const char *profile_name,
        int64_t queue_num, int64_t weight)
{
    if (profile_name == NULL) {
        vty_out(vty, "profile_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_applied(profile_name)) {
        vty_out(vty, "An applied profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_hw_default(profile_name)) {
        vty_out(vty,
                "A hardware default profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    struct ovsdb_idl_txn *txn = cli_do_config_start();
    if (txn == NULL) {
        vty_out(vty, "Unable to start transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    bool success = qos_schedule_profile_dwrr_command(txn, profile_name,
            queue_num, weight);
    if (!success) {
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

/**
 * Executes and commits the qos_schedule_profile_dwrr_command for
 * the given profile_name, queue_num, and weight.
 */
DEFUN(qos_schedule_profile_dwrr,
        qos_schedule_profile_dwrr_cmd,
       "dwrr queue <0-7> weight <1-127>",
       "Configure a queue in a Schedule Profile to use dwrr scheduling\n"
       "The number of the queue\n"
       "The number of the queue\n"
       "The weight to configure\n"
       "The weight to configure\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE] = "op=CLI: dwrr queue";

    const char *profile_name = (char*) vty->index;
    qos_audit_encode(aubuf, sizeof(aubuf), "profile_name", profile_name);

    const char *queue_num = argv[0];
    qos_audit_encode(aubuf, sizeof(aubuf), "queue_num", queue_num);
    int64_t queue_num_int = atoi(queue_num);

    const char *weight = argv[1];
    qos_audit_encode(aubuf, sizeof(aubuf), "weight", weight);
    int64_t weight_int = atoi(weight);

    int result = qos_schedule_profile_dwrr_command_commit(
            profile_name, queue_num_int, weight_int);

    qos_audit_log(aubuf, result);

    return result;
}

/**
 * Executes the qos_schedule_profile_dwrr_no_command for
 * the given profile_name and queue_num.
 */
static bool
qos_schedule_profile_dwrr_no_command(struct ovsdb_idl_txn *txn,
        const char *profile_name,
        int64_t queue_num)
{
    /* Retrieve the profile row. */
    struct ovsrec_qos *profile_row =
            qos_get_schedule_profile_row(profile_name);
    if (profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                profile_name, VTY_NEWLINE);
        return false;
    }

    /* Retrieve the existing queue row. */
    struct ovsrec_queue *queue_row =
            qos_get_schedule_profile_entry_row(profile_row, queue_num);
    if (queue_row == NULL) {
        vty_out(vty,
                "Profile %s does not have queue %" PRId64 " configured.%s",
                profile_name, queue_num, VTY_NEWLINE);
        return false;
    }

    /* If the algorithm is dwrr, then clear it. */
    if (queue_row->algorithm != NULL &&
            strncmp(queue_row->algorithm,
                    OVSREC_QUEUE_ALGORITHM_DWRR,
                    QOS_CLI_STRING_BUFFER_SIZE) == 0) {
        ovsrec_queue_set_algorithm(queue_row, NULL);
        ovsrec_queue_set_weight(queue_row, NULL, 0);
    }

    /* If row has no content, then delete the queue row. */
    if (!has_content(queue_row)) {
        delete_queue_row(profile_row, queue_num);
    }

    return true;
}

/**
 * Executes and commits the qos_schedule_profile_dwrr_no_command for
 * the given profile_name and queue_num.
 */
static int
qos_schedule_profile_dwrr_no_command_commit(
        const char *profile_name,
        int64_t queue_num)
{
    if (profile_name == NULL) {
        vty_out(vty, "profile_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_applied(profile_name)) {
        vty_out(vty, "An applied profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (is_hw_default(profile_name)) {
        vty_out(vty,
                "A hardware default profile cannot be amended or deleted.%s",
                VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    struct ovsdb_idl_txn *txn = cli_do_config_start();
    if (txn == NULL) {
        vty_out(vty, "Unable to start transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    bool success = qos_schedule_profile_dwrr_no_command(txn, profile_name,
            queue_num);
    if (!success) {
        cli_do_config_abort(txn);
        return CMD_OVSDB_FAILURE;
    }

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

/**
 * Executes and commits the qos_schedule_profile_dwrr_no_command for
 * the given profile_name and queue_num.
 */
DEFUN(qos_schedule_profile_dwrr_no,
        qos_schedule_profile_dwrr_no_cmd,
       "no dwrr queue <0-7> {weight <1-127>}",
       NO_STR
       "Clears the algorithm for a queue, if the algorithm is 'dwrr'\n"
       "The number of the queue\n"
       "The number of the queue\n"
       "The weight to configure\n"
       "The weight to configure\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE] = "op=CLI: no dwrr queue";

    const char *profile_name = (char*) vty->index;
    qos_audit_encode(aubuf, sizeof(aubuf), "profile_name", profile_name);

    const char *queue_num = argv[0];
    qos_audit_encode(aubuf, sizeof(aubuf), "queue_num", queue_num);
    int64_t queue_num_int = atoi(queue_num);

    int result = qos_schedule_profile_dwrr_no_command_commit(profile_name,
            queue_num_int);

    qos_audit_log(aubuf, result);

    return result;
}

/**
 * Prints the schedule_profile_entry_row for the given queue_num and
 * profile_entry_row.
 */
static void
print_schedule_profile_entry_row(int64_t queue_num,
        struct ovsrec_queue *profile_entry_row)
{
    char buffer[QOS_CLI_STRING_BUFFER_SIZE];

    vty_out (vty, "%-9" PRId64 " ", queue_num);

    vty_out (vty, "%-9s ", profile_entry_row->algorithm);

    buffer[0] = '\0';
    if (profile_entry_row->weight != NULL) {
        snprintf(buffer, sizeof(buffer),
                "%" PRId64,  *profile_entry_row->weight);
    }
    vty_out (vty, "%-6s ", buffer);

    vty_out (vty, "%s", VTY_NEWLINE);
}

/**
 * Executes the qos_schedule_profile_show_command for the given name.
 */
static int
qos_schedule_profile_show_command(const char *name)
{
    if (name == NULL) {
        vty_out(vty, "name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (!qos_is_valid_string(name)) {
        vty_out(vty, QOS_INVALID_STRING_ERROR_MESSAGE, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (strncmp(name, OVSREC_QUEUE_ALGORITHM_STRICT,
            QOS_CLI_STRING_BUFFER_SIZE) == 0) {
        vty_out(vty, "The profile name cannot be '%s'.%s",
                OVSREC_QUEUE_ALGORITHM_STRICT, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    struct ovsrec_qos *profile_row = qos_get_schedule_profile_row(name);
    if (profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                name, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    vty_out (vty, "queue_num algorithm weight%s", VTY_NEWLINE);
    vty_out (vty, "--------- --------- ------%s", VTY_NEWLINE);

    int i;
    for (i = 0; i < profile_row->n_queues; i++) {
        print_schedule_profile_entry_row(profile_row->key_queues[i],
                profile_row->value_queues[i]);
    }

    return CMD_SUCCESS;
}

/**
 * Executes the qos_schedule_profile_show_command for the given name.
 */
DEFUN(qos_schedule_profile_show,
    qos_schedule_profile_show_cmd,
    "show qos schedule-profile NAME",
    SHOW_STR
    "Show QoS Configuration\n"
    "Show QoS Schedule Profile Configuration\n"
    "The name of the Schedule Profile to display\n")
{
    const char *name = argv[0];

    return qos_schedule_profile_show_command(name);
}

/**
 * Executes the qos_schedule_profile_show_all_command.
 */
static int
qos_schedule_profile_show_all_command(void)
{
    vty_out (vty, "profile_status profile_name%s", VTY_NEWLINE);
    vty_out (vty, "-------------- ------------%s", VTY_NEWLINE);

    char buffer[QOS_CLI_STRING_BUFFER_SIZE];

    const struct ovsrec_qos *profile_row;
    OVSREC_QOS_FOR_EACH(profile_row, idl) {
        if (is_row_applied(profile_row)) {
            vty_out (vty, "applied        ");
        } else if (qos_schedule_profile_is_complete(
                (struct ovsrec_qos *) profile_row, false)) {
            vty_out (vty, "complete       ");
        } else {
            vty_out (vty, "incomplete     ");
        }

        buffer[0] = '\0';
        if (profile_row->name != NULL &&
                strncmp(profile_row->name, "",
                        QOS_CLI_STRING_BUFFER_SIZE) != 0) {
            strncpy(buffer,
                    profile_row->name,
                    sizeof(buffer));
        }
        vty_out (vty, "%s ", buffer);

        vty_out (vty, "%s", VTY_NEWLINE);
    }

    return CMD_SUCCESS;
}

/**
 * Executes the qos_schedule_profile_show_all_command.
 */
DEFUN(qos_schedule_profile_show_all,
    qos_schedule_profile_show_all_cmd,
    "show qos schedule-profile",
    SHOW_STR
    "Show QoS Configuration\n"
    "Show QoS Schedule Profile Configuration\n")
{
    return qos_schedule_profile_show_all_command();
}

/**
 * Shows the running config for schedule_profile. Returns true if the applied
 * profile differs from the default profile.
 */
bool
qos_schedule_profile_show_running_config(void)
{
    struct ovsrec_qos *default_profile_row = qos_get_schedule_profile_row(
            QOS_FACTORY_DEFAULT_NAME);
    if (default_profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                QOS_FACTORY_DEFAULT_NAME, VTY_NEWLINE);
        return false;
    }

    const struct ovsrec_system *system_row = ovsrec_system_first(idl);
    struct ovsrec_qos *applied_profile_row = system_row->qos;

    bool differs_from_default = false;

    /* Compare profile name. */
    if (strncmp(applied_profile_row->name, default_profile_row->name,
            QOS_CLI_STRING_BUFFER_SIZE) != 0 &&
            strncmp(applied_profile_row->name, QOS_DEFAULT_NAME,
                    QOS_CLI_STRING_BUFFER_SIZE) != 0) {
        differs_from_default = true;
    }

    int i;
    for (i = 0; i < default_profile_row->n_queues; i++) {
        int64_t default_queue_num =
                default_profile_row->key_queues[i];
        struct ovsrec_queue *default_profile_entry =
                default_profile_row->value_queues[i];

        struct ovsrec_queue *applied_profile_entry =
                qos_get_schedule_profile_entry_row(
                        applied_profile_row, default_queue_num);
        if (applied_profile_entry == NULL) {
            /* If the applied profile does not contain a queue_num from the */
            /* default profile, then a difference was found and the loop */
            /* can be terminated. */
            differs_from_default = true;
            break;
        }

        /* Compare algorithm. */
        if (applied_profile_entry->algorithm != NULL &&
                strncmp(applied_profile_entry->algorithm,
                        default_profile_entry->algorithm,
                        QOS_CLI_STRING_BUFFER_SIZE) != 0) {
            differs_from_default = true;
        }

        /* Compare weight. */
        if (applied_profile_entry->weight !=
                default_profile_entry->weight) {
            if (applied_profile_entry->weight == NULL ||
                    default_profile_entry->weight == NULL) {
                differs_from_default = true;
            } else if (*applied_profile_entry->weight !=
                    *default_profile_entry->weight) {
                differs_from_default = true;
            }
        }
    }

    /* If it's the strict profile, then there's no command to create the
     * strict profile, so just return. */
    if (strncmp(applied_profile_row->name, OVSREC_QUEUE_ALGORITHM_STRICT,
            QOS_CLI_STRING_BUFFER_SIZE) == 0) {
        return differs_from_default;
    }

    /* Show the command if it differs from the default. */
    if (differs_from_default) {
        /* Show profile name. */
        vty_out(vty, "qos schedule-profile %s%s", applied_profile_row->name,
                VTY_NEWLINE);

        int i;
        for (i = 0; i < applied_profile_row->n_queues; i++) {
            int64_t queue_num =
                    applied_profile_row->key_queues[i];
            struct ovsrec_queue *applied_profile_entry =
                    applied_profile_row->value_queues[i];

            /* Show algorithm. */
            if (applied_profile_entry->algorithm != NULL &&
                    strncmp(applied_profile_entry->algorithm, "",
                            QOS_CLI_STRING_BUFFER_SIZE) != 0) {
                vty_out(vty, "    %s queue %" PRId64 " ",
                        applied_profile_entry->algorithm, queue_num);
            }

            /* Show weight. */
            if (applied_profile_entry->weight != NULL) {
                vty_out(vty, "weight %" PRId64 " ",
                        *applied_profile_entry->weight);
            }

            /* End with a new line. */
            vty_out(vty, "%s", VTY_NEWLINE);
        }
    }

    return differs_from_default;
}

/**
 * Creates the 'strict' schedule profile.
 */
int
qos_schedule_profile_create_strict_profile_commit(void)
{
    const char *strict_profile_name = OVSREC_QUEUE_ALGORITHM_STRICT;

    /* Retrieve the row. */
    struct ovsrec_qos *profile_row =
            qos_get_schedule_profile_row(strict_profile_name);
    if (profile_row != NULL) {
        /* If the profile already exists, then there is no work to do. */
        return CMD_SUCCESS;
    }

    struct ovsdb_idl_txn *txn = cli_do_config_start();
    if (txn == NULL) {
        vty_out(vty, "Unable to start transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    qos_schedule_profile_command(txn, strict_profile_name);

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

/**
 * Initializes qos_schedule_profile_vty.
 */
void
qos_schedule_profile_vty_init(void)
{
    install_element(QOS_SCHEDULE_PROFILE_NODE, &vtysh_exit_interface_cmd);
    install_element(QOS_SCHEDULE_PROFILE_NODE, &vtysh_end_all_cmd);

    install_element(CONFIG_NODE, &qos_schedule_profile_cmd);
    install_element(CONFIG_NODE, &qos_schedule_profile_no_cmd);
    install_element(ENABLE_NODE, &qos_schedule_profile_show_cmd);
    install_element(ENABLE_NODE, &qos_schedule_profile_show_all_cmd);

    install_element(QOS_SCHEDULE_PROFILE_NODE,
            &qos_schedule_profile_strict_cmd);
    install_element(QOS_SCHEDULE_PROFILE_NODE,
            &qos_schedule_profile_strict_no_cmd);

    install_element(QOS_SCHEDULE_PROFILE_NODE,
            &qos_schedule_profile_dwrr_cmd);
    install_element(QOS_SCHEDULE_PROFILE_NODE,
            &qos_schedule_profile_dwrr_no_cmd);
}

/**
 * Contains the display prompt for the profile node.
 */
static struct cmd_node qos_schedule_profile_node = {
    QOS_SCHEDULE_PROFILE_NODE,
    "%s(config-schedule)# ",
};

/**
 * Initializes qos_schedule_profile_ovsdb.
 */
void
qos_schedule_profile_ovsdb_init(void)
{
    install_node(&qos_schedule_profile_node, NULL);
    vtysh_install_default(QOS_SCHEDULE_PROFILE_NODE);

    ovsdb_idl_add_table(idl, &ovsrec_table_system);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_qos);

    ovsdb_idl_add_table(idl, &ovsrec_table_qos);
    ovsdb_idl_add_column(idl, &ovsrec_qos_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_qos_col_queues);
    ovsdb_idl_add_column(idl, &ovsrec_qos_col_hw_default);
    ovsdb_idl_add_column(idl, &ovsrec_qos_col_other_config);
    ovsdb_idl_add_column(idl, &ovsrec_qos_col_external_ids);

    ovsdb_idl_add_table(idl, &ovsrec_table_queue);
    ovsdb_idl_add_column(idl, &ovsrec_queue_col_algorithm);
    ovsdb_idl_add_column(idl, &ovsrec_queue_col_weight);
    ovsdb_idl_add_column(idl, &ovsrec_queue_col_hw_default);
    ovsdb_idl_add_column(idl, &ovsrec_queue_col_other_config);
    ovsdb_idl_add_column(idl, &ovsrec_queue_col_external_ids);
}
