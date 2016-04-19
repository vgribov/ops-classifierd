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

#include "qos_queue_profile_vty.h"

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

VLOG_DEFINE_THIS_MODULE(vtysh_qos_queue_profile_cli);
extern struct ovsdb_idl *idl;

/**
 * Global state for the profile name.
 */
static char g_profile_name[QOS_CLI_STRING_BUFFER_SIZE];

/**
 * Returns true if the given queue_row contains the given local_proiority.
 */
static bool
queue_has_local_priority(
        struct ovsrec_q_profile_entry *queue_row,
        int64_t local_priority)
{
    int i;
    for (i = 0; i < queue_row->n_local_priorities; i++) {
        if (queue_row->local_priorities[i] == local_priority) {
            return true;
        }
    }

    return false;
}

/**
 * Returns the queue_profile_row for the given profile_name.
 */
struct ovsrec_q_profile *
qos_get_queue_profile_row(
        const char *profile_name)
{
    const struct ovsrec_q_profile *profile_row;
    OVSREC_Q_PROFILE_FOR_EACH(profile_row, idl) {
        if (strncmp(profile_row->name, profile_name,
                QOS_CLI_STRING_BUFFER_SIZE) == 0) {
            return (struct ovsrec_q_profile *) profile_row;
        }
    }

    return NULL;
}

/**
 * Returns the queue_profile_entry_row for the given profile_row
 * and queue_num.
 */
static struct ovsrec_q_profile_entry *
qos_get_queue_profile_entry_row(
        struct ovsrec_q_profile *profile_row, int64_t queue_num)
{
    int i;
    for (i = 0; i < profile_row->n_q_profile_entries; i++) {
        if (profile_row->key_q_profile_entries[i] == queue_num) {
            return profile_row->value_q_profile_entries[i];
        }
    }

    return NULL;
}

/**
 * Returns true if the given profile_row contains the given queue_num.
 */
bool
qos_queue_profile_has_queue_num(struct ovsrec_q_profile *profile_row,
        int64_t queue_num)
{
    int j;
    for (j = 0; j < profile_row->n_q_profile_entries; j++) {
        int64_t profile_queue_num = profile_row->key_q_profile_entries[j];
        if (queue_num == profile_queue_num) {
            return true;
        }
    }

    return false;
}

/**
 * Returns true if the given profile_row is complete. If print_error is
 * true, then any errors will be printed.
 */
bool
qos_queue_profile_is_complete(struct ovsrec_q_profile *profile_row,
        bool print_error)
{
    bool found_local_priorities[QOS_LOCAL_PRIORITY_COUNT];
    int i;
    for (i = 0; i < QOS_LOCAL_PRIORITY_COUNT; i++) {
        found_local_priorities[i] = false;
    }

    /* Validate that each local priority does not appear more than once. */
    int j;
    for (j = 0; j < profile_row->n_q_profile_entries; j++) {
        struct ovsrec_q_profile_entry *queue_row =
                profile_row->value_q_profile_entries[j];
        for (i = 0; i < queue_row->n_local_priorities; i++) {
            int64_t local_priority = queue_row->local_priorities[i];
            if (found_local_priorities[local_priority] == true) {
                if (print_error) {
                    vty_out(vty, "The queue profile\
 has local priority %" PRId64 " assigned more than once.%s",
                            local_priority, VTY_NEWLINE);
                }
                return false;
            }
            found_local_priorities[local_priority] = true;
        }
    }

    /* Validate that all local priorities have been assigned. */
    for (i = 0; i < QOS_LOCAL_PRIORITY_COUNT; i++) {
        if (found_local_priorities[i] == false) {
            if (print_error) {
                vty_out(vty,
                        "The queue profile is missing local priority %d.%s",
                        i, VTY_NEWLINE);
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
is_row_applied(const struct ovsrec_q_profile *profile_row)
{
    if (profile_row == NULL) {
        return false;
    }

    const struct ovsrec_system *system_row = ovsrec_system_first(idl);
    if (system_row->q_profile == profile_row) {
        return true;
    }

    const struct ovsrec_port *port_row;
    OVSREC_PORT_FOR_EACH(port_row, idl) {
        if (port_row->q_profile == profile_row) {
            return true;
        }
    }

    return false;
}

/**
 * Returns true if the profile_row for the given profile_name is applied.
 */
static bool
is_applied(const char *profile_name)
{
    struct ovsrec_q_profile *profile_row = qos_get_queue_profile_row(
            profile_name);

    return is_row_applied(profile_row);
}

/**
 * Returns true if the given profile_row is a hw_default.
 */
static bool
is_row_hw_default(const struct ovsrec_q_profile *profile_row)
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
 * Returns true if the profile_row for the given profile_name is hw_default.
 */
static bool
is_hw_default(const char *profile_name)
{
    struct ovsrec_q_profile *profile_row = qos_get_queue_profile_row(
            profile_name);

    return is_row_hw_default(profile_row);
}

/**
 * Inserts into the database and returns the queue_row for the given
 * profile_row, queue_num, and txn.
 */
static struct ovsrec_q_profile_entry *
insert_queue_row(
        struct ovsrec_q_profile *profile_row, int64_t queue_num,
        struct ovsdb_idl_txn *txn)
{
    /* Create the queue row. */
    struct ovsrec_q_profile_entry *queue_row =
            ovsrec_q_profile_entry_insert(txn);

    /* Update the profile row. */
    int64_t *key_list =
            xmalloc(sizeof(int64_t) *
                    (profile_row->n_q_profile_entries + 1));
    struct ovsrec_q_profile_entry **value_list =
            xmalloc(sizeof *profile_row->value_q_profile_entries *
                    (profile_row->n_q_profile_entries + 1));

    int i;
    for (i = 0; i < profile_row->n_q_profile_entries; i++) {
        key_list[i] = profile_row->key_q_profile_entries[i];
        value_list[i] = profile_row->value_q_profile_entries[i];
    }
    key_list[profile_row->n_q_profile_entries] = queue_num;
    value_list[profile_row->n_q_profile_entries] = queue_row;
    ovsrec_q_profile_set_q_profile_entries(profile_row, key_list,
            value_list, profile_row->n_q_profile_entries + 1);
    free(key_list);
    free(value_list);

    return queue_row;
}

/**
 * Executes the qos_queue_profile_command for the given
 * profile_name.
 */
static bool
qos_queue_profile_command(struct ovsdb_idl_txn *txn,
        const char *profile_name)
{
    /* Retrieve the row. */
    struct ovsrec_q_profile *profile_row =
            qos_get_queue_profile_row(profile_name);
    if (profile_row == NULL) {
        /* Create a new row. */
        profile_row = ovsrec_q_profile_insert(txn);
        ovsrec_q_profile_set_name(profile_row, profile_name);
    }

    return true;
}

/**
 * Executes and commits the qos_queue_profile_command for the given
 * profile_name.
 */
static int
qos_queue_profile_command_commit(const char *profile_name)
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

    bool success = qos_queue_profile_command(txn, profile_name);
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
    vty->node = QOS_QUEUE_PROFILE_NODE;
    vty->index = g_profile_name;
    return CMD_SUCCESS;
}

/**
 * Executes and commits the qos_queue_profile_command for the given
 * profile_name.
 */
DEFUN(qos_queue_profile,
        qos_queue_profile_cmd,
       "qos queue-profile NAME",
       QOS_HELP_STRING
       "Set the QoS Queue Profile configuration\n"
       "The name of the Queue Profile\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE] = "op=CLI: qos queue-profile";

    const char *profile_name = argv[0];
    qos_audit_encode(aubuf, sizeof(aubuf), "profile_name", profile_name);

    int result = qos_queue_profile_command_commit(profile_name);

    qos_audit_log(aubuf, result);

    return result;
}

/**
 * Executes the qos_queue_profile_no_command for the given
 * profile_name.
 */
static bool
qos_queue_profile_no_command(struct ovsdb_idl_txn *txn,
        const char *profile_name)
{
    /* Retrieve the row. */
    struct ovsrec_q_profile *profile_row =
            qos_get_queue_profile_row(profile_name);
    if (profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                profile_name, VTY_NEWLINE);
        return false;
    }

    if (strncmp(profile_name, QOS_DEFAULT_NAME,
            QOS_CLI_STRING_BUFFER_SIZE) == 0) {
        /* For the profile named 'default', restore the factory defaults. */

        /* Delete all default profile queue rows. */
        ovsrec_q_profile_set_q_profile_entries(profile_row, NULL, NULL, 0);

        /* Retrieve the factory default row. */
        struct ovsrec_q_profile *factory_default_profile_row =
                qos_get_queue_profile_row(QOS_FACTORY_DEFAULT_NAME);
        if (factory_default_profile_row == NULL) {
            vty_out(vty, "Profile %s does not exist.%s",
                    QOS_FACTORY_DEFAULT_NAME, VTY_NEWLINE);
            return false;
        }

        /* Copy all factory defaults into new entry rows. */
        int64_t queue_row_count =
                factory_default_profile_row->n_q_profile_entries;
        int64_t *key_list =
                xmalloc(sizeof(int64_t) *
                        queue_row_count);
        struct ovsrec_q_profile_entry **value_list =
                xmalloc(sizeof *profile_row->value_q_profile_entries *
                        queue_row_count);
        int j;
        for (j = 0; j < queue_row_count; j++) {
            struct ovsrec_q_profile_entry *queue_row =
                    ovsrec_q_profile_entry_insert(txn);
            struct ovsrec_q_profile_entry *default_row =
                    factory_default_profile_row->value_q_profile_entries[j];
            ovsrec_q_profile_entry_set_description(queue_row,
                    default_row->description);
            ovsrec_q_profile_entry_set_local_priorities(
                    queue_row, default_row->local_priorities,
                    default_row->n_local_priorities);
            key_list[j] =
                    factory_default_profile_row->key_q_profile_entries[j];
            value_list[j] = queue_row;
        }

        /* Add the new entry rows to the profile row. */
        ovsrec_q_profile_set_q_profile_entries(profile_row, key_list,
                value_list, queue_row_count);
        free(key_list);
        free(value_list);
    } else {
        /* If not the profile named 'default', delete the row. */
        ovsrec_q_profile_delete(profile_row);
    }

    return true;
}

/**
 * Executes and commits the qos_queue_profile_no_command for the given
 * profile_name.
 */
static int
qos_queue_profile_no_command_commit(const char *profile_name)
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

    bool success = qos_queue_profile_no_command(txn, profile_name);
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
 * Executes and commits the qos_queue_profile_no_command for the given
 * profile_name.
 */
DEFUN(qos_queue_profile_no,
        qos_queue_profile_no_cmd,
        "no qos queue-profile NAME",
        NO_STR
        QOS_HELP_STRING
        "Deletes a Queue Profile, if it is not currently applied\n"
        "The name of the Queue Profile to delete\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE] = "op=CLI: no qos queue-profile";

    const char *profile_name = argv[0];
    qos_audit_encode(aubuf, sizeof(aubuf), "profile_name", profile_name);

    int result = qos_queue_profile_no_command_commit(profile_name);

    qos_audit_log(aubuf, result);

    return result;
}

/**
 * Executes the qos_queue_profile_name_command for the given
 * profile_name, queue_num, and queue_name.
 */
static bool
qos_queue_profile_name_command(struct ovsdb_idl_txn *txn,
        const char *profile_name,
        int64_t queue_num, const char *queue_name)
{
    /* Retrieve the profile row. */
    struct ovsrec_q_profile *profile_row =
            qos_get_queue_profile_row(profile_name);
    if (profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                profile_name, VTY_NEWLINE);
        return false;
    }

    /* Retrieve the existing queue row. */
    struct ovsrec_q_profile_entry *queue_row =
            qos_get_queue_profile_entry_row(profile_row, queue_num);

    /* If no existing row, then insert a new queue row. */
    if (queue_row == NULL) {
        queue_row = insert_queue_row(profile_row, queue_num, txn);
    }

    /* Update the queue row. */
    ovsrec_q_profile_entry_set_description(queue_row, queue_name);

    return true;
}

/**
 * Executes and commits the qos_queue_profile_name_command for the given
 * profile_name, queue_num, and queue_name.
 */
static int
qos_queue_profile_name_command_commit(const char *profile_name,
        int64_t queue_num, const char *queue_name)
{
    if (profile_name == NULL) {
        vty_out(vty, "profile_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (queue_name == NULL) {
        vty_out(vty, "queue_name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (!qos_is_valid_string(queue_name)) {
        vty_out(vty, QOS_INVALID_STRING_ERROR_MESSAGE, VTY_NEWLINE);
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

    bool success = qos_queue_profile_name_command(txn, profile_name,
            queue_num, queue_name);
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
 * Executes the qos_queue_profile_name_command for the given
 * profile_name, queue_num, and queue_name.
 */
DEFUN(qos_queue_profile_name,
        qos_queue_profile_name_cmd,
       "name queue <0-7> NAME",
       "Configure the name of a queue in a Queue Profile\n"
       "Sets the name of a queue\n"
       "The number of the queue\n"
       "The name of the queue\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE] = "op=CLI: name queue";

    const char *profile_name = (char*) vty->index;
    qos_audit_encode(aubuf, sizeof(aubuf), "profile_name", profile_name);

    const char *queue_num = argv[0];
    qos_audit_encode(aubuf, sizeof(aubuf), "queue_num", queue_num);
    int64_t queue_num_int = atoi(queue_num);

    const char *queue_name = argv[1];
    qos_audit_encode(aubuf, sizeof(aubuf), "queue_name", queue_name);

    int result = qos_queue_profile_name_command_commit(
            profile_name, queue_num_int, queue_name);

    qos_audit_log(aubuf, result);

    return result;
}

/**
 * Returns true if the given queue_row is not empty.
 */
static bool
has_content(struct ovsrec_q_profile_entry *queue_row)
{
    if ((queue_row->description == NULL) &&
            (queue_row->local_priorities == NULL ||
                    queue_row->n_local_priorities == 0)) {
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
        struct ovsrec_q_profile *profile_row, int64_t queue_num)
{
    int64_t *key_list =
            xmalloc(sizeof(int64_t) *
                    (profile_row->n_q_profile_entries - 1));
    struct ovsrec_q_profile_entry **value_list =
            xmalloc(sizeof *profile_row->value_q_profile_entries *
                    (profile_row->n_q_profile_entries - 1));
    int i;
    int j = 0;
    for (i = 0; i < profile_row->n_q_profile_entries; i++) {
        if (profile_row->key_q_profile_entries[i] != queue_num) {
            key_list[j] = profile_row->key_q_profile_entries[i];
            value_list[j] = profile_row->value_q_profile_entries[i];
            j++;
        }
    }
    ovsrec_q_profile_set_q_profile_entries(profile_row, key_list,
            value_list, profile_row->n_q_profile_entries - 1);
    free(key_list);
    free(value_list);
}

/**
 * Executes the qos_queue_profile_name_no_command for the given
 * profile_name and queue_num.
 */
static bool
qos_queue_profile_name_no_command(struct ovsdb_idl_txn *txn,
        const char *profile_name,
        int64_t queue_num)
{
    /* Retrieve the profile row. */
    struct ovsrec_q_profile *profile_row =
            qos_get_queue_profile_row(profile_name);
    if (profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                profile_name, VTY_NEWLINE);
        return false;
    }

    /* Retrieve the existing queue row. */
    struct ovsrec_q_profile_entry *queue_row =
            qos_get_queue_profile_entry_row(profile_row, queue_num);
    if (queue_row == NULL) {
        vty_out(vty,
                "Profile %s does not have queue %" PRId64 " configured.%s",
                profile_name, queue_num, VTY_NEWLINE);
        return false;
    }

    /* Update the queue row. */
    ovsrec_q_profile_entry_set_description(queue_row, NULL);

    /* If row has no content, then delete the queue row. */
    if (!has_content(queue_row)) {
        delete_queue_row(profile_row, queue_num);
    }

    return true;
}

/**
 * Executes and commits the qos_queue_profile_name_no_command for the given
 * profile_name and queue_num.
 */
static int
qos_queue_profile_name_no_command_commit(const char *profile_name,
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

    bool success = qos_queue_profile_name_no_command(txn,
            profile_name, queue_num);
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
 * Executes the qos_queue_profile_name_no_command for the given
 * profile_name and queue_num.
 */
DEFUN(qos_queue_profile_name_no,
        qos_queue_profile_name_no_cmd,
        "no name queue <0-7> {NAME}",
        NO_STR
        "Configure the name of a queue in a Queue Profile\n"
        "Deletes the name of a queue\n"
        "The number of the queue\n"
        "The name of the queue\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE] = "op=CLI: no name queue";

    const char *profile_name = (char*) vty->index;
    qos_audit_encode(aubuf, sizeof(aubuf), "profile_name", profile_name);

    const char *queue_num = argv[0];
    qos_audit_encode(aubuf, sizeof(aubuf), "queue_num", queue_num);
    int64_t queue_num_int = atoi(queue_num);

    int result = qos_queue_profile_name_no_command_commit(
            profile_name, queue_num_int);

    qos_audit_log(aubuf, result);

    return result;
}

/**
 * Adds the given local_priority to the given queue_row.
 */
static void
add_local_priority(struct ovsrec_q_profile_entry *queue_row,
        int64_t local_priority)
{
    if (queue_has_local_priority(queue_row, local_priority)) {
        return;
    }

    /* local_priority was not found, so add it. */
    int64_t *value_list =
            xmalloc(sizeof(int64_t) *
                    (queue_row->n_local_priorities + 1));
    int i;
    for (i = 0; i < queue_row->n_local_priorities; i++) {
        value_list[i] = queue_row->local_priorities[i];
    }
    value_list[queue_row->n_local_priorities] = local_priority;
    ovsrec_q_profile_entry_set_local_priorities(
            queue_row, value_list, queue_row->n_local_priorities + 1);
    free(value_list);
}

/**
 * Executes the qos_queue_profile_map_command for the given
 * profile_name, queue_num, and local_priority.
 */
static bool
qos_queue_profile_map_command(struct ovsdb_idl_txn *txn,
        const char *profile_name,
        int64_t queue_num, const char *local_priorities)
{
    /* Retrieve the profile row. */
    struct ovsrec_q_profile *profile_row =
            qos_get_queue_profile_row(profile_name);
    if (profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                profile_name, VTY_NEWLINE);
        return false;
    }

    /* Retrieve the existing queue row. */
    struct ovsrec_q_profile_entry *queue_row =
            qos_get_queue_profile_entry_row(profile_row, queue_num);

    /* If no existing row, then insert a new queue row. */
    if (queue_row == NULL) {
        queue_row = insert_queue_row(profile_row, queue_num, txn);
    }

    /* Make a copy, since strtok modifies the string. */
    char buffer[QOS_CLI_STRING_BUFFER_SIZE];
    strncpy(buffer, local_priorities, sizeof(buffer));

    /* Parse the comma-separated list of priorities. */
    char *token = strtok(buffer, ",");
    while (token != NULL) {
        int64_t local_priority = atoi(token);

        /* Update the queue row. */
        add_local_priority(queue_row, local_priority);

        token = strtok(NULL, ",");
    }

    return true;
}

/**
 * Executes and commits the qos_queue_profile_map_command for the given
 * profile_name, queue_num, and local_priority.
 */
static int
qos_queue_profile_map_command_commit(const char *profile_name,
        int64_t queue_num, const char *local_priorities)
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

    bool success = qos_queue_profile_map_command(txn, profile_name,
            queue_num, local_priorities);
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
 * Executes the qos_queue_profile_map_command for the given
 * profile_name, queue_num, and local_priority.
 */
DEFUN(qos_queue_profile_map,
        qos_queue_profile_map_cmd,
       "map queue <0-7> local-priority <C:0-7>",
       "Configure the local-priority map for a queue in a Queue Profile\n"
       "Configure the local-priority map for a queue in a Queue Profile\n"
       "The number of the queue\n"
       "The local-priority to configure\n"
       "The local-priority to configure\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE] = "op=CLI: map queue";

    const char *profile_name = (char*) vty->index;
    qos_audit_encode(aubuf, sizeof(aubuf), "profile_name", profile_name);

    const char *queue_num = argv[0];
    qos_audit_encode(aubuf, sizeof(aubuf), "queue_num", queue_num);
    int64_t queue_num_int = atoi(queue_num);

    const char *local_priority = argv[1];
    qos_audit_encode(aubuf, sizeof(aubuf), "local_priority", local_priority);
    const char * local_priorities = local_priority;

    int result = qos_queue_profile_map_command_commit(
            profile_name, queue_num_int, local_priorities);

    qos_audit_log(aubuf, result);

    return result;
}

/**
 * Removes the given local_priority from the given queue_row.
 */
static void
remove_local_priority(
        struct ovsrec_q_profile_entry *queue_row,
        int64_t local_priority)
{
    if (!queue_has_local_priority(queue_row, local_priority)) {
        return;
    }

    /* local_priority was found, so remove it. */
    int64_t *value_list =
            xmalloc(sizeof(int64_t) *
                    (queue_row->n_local_priorities - 1));
    int i;
    int j = 0;
    for (i = 0; i < queue_row->n_local_priorities; i++) {
        if (queue_row->local_priorities[i] != local_priority) {
            value_list[j] = queue_row->local_priorities[i];
            j++;
        }
    }
    ovsrec_q_profile_entry_set_local_priorities(
            queue_row, value_list, queue_row->n_local_priorities - 1);
    free(value_list);
}

/**
 * Executes the qos_queue_profile_map_no_command for the given
 * profile_name, queue_num, and local_priority.
 */
static bool
qos_queue_profile_map_no_command(struct ovsdb_idl_txn *txn,
        const char *profile_name,
        int64_t queue_num, const char *local_priorities)
{
    /* Retrieve the profile row. */
    struct ovsrec_q_profile *profile_row =
            qos_get_queue_profile_row(profile_name);
    if (profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                profile_name, VTY_NEWLINE);
        return false;
    }

    /* Retrieve the existing queue row. */
    struct ovsrec_q_profile_entry *queue_row =
            qos_get_queue_profile_entry_row(profile_row, queue_num);
    if (queue_row == NULL) {
        vty_out(vty,
                "Profile %s does not have queue %" PRId64 " configured.%s",
                profile_name, queue_num, VTY_NEWLINE);
        return false;
    }

    /* Update the queue row. */
    if (local_priorities == NULL) {
        /* Delete all local-priorities. */
        ovsrec_q_profile_entry_set_local_priorities(
                queue_row, NULL, 0);
    } else {
        /* Make a copy, since strtok modifies the string. */
        char buffer[QOS_CLI_STRING_BUFFER_SIZE];
        strncpy(buffer, local_priorities, sizeof(buffer));

        /* Parse the comma-separated list of priorities. */
        char *token = strtok(buffer, ",");
        while (token != NULL) {
            int64_t local_priority = atoi(token);

            /* Delete a single local-priority. */
            remove_local_priority(queue_row, local_priority);

            token = strtok(NULL, ",");
        }
    }

    /* If row has no content, then delete the queue row. */
    if (!has_content(queue_row)) {
        delete_queue_row(profile_row, queue_num);
    }

    return true;
}

/**
 * Executes and commits the qos_queue_profile_map_no_command for the given
 * profile_name, queue_num, and local_priority.
 */
static int
qos_queue_profile_map_no_command_commit(const char *profile_name,
        int64_t queue_num, const char *local_priorities)
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

    bool success = qos_queue_profile_map_no_command(txn, profile_name,
            queue_num, local_priorities);
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
 * Executes the qos_queue_profile_map_no_command for the given
 * profile_name, queue_num, and local_priority.
 */
DEFUN(qos_queue_profile_map_no,
        qos_queue_profile_map_no_cmd,
       "no map queue <0-7> {local-priority <C:0-7>}",
       NO_STR
       "Configure the local-priority map for a queue in a Queue Profile\n"
       "Deletes the local-priority for a queue in a Queue Profile\n"
       "The number of the queue\n"
       "The local-priority to delete\n"
       "The local-priority to delete\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE] = "op=CLI: no map queue";

    const char *profile_name = (char*) vty->index;
    qos_audit_encode(aubuf, sizeof(aubuf), "profile_name", profile_name);

    const char *queue_num = argv[0];
    qos_audit_encode(aubuf, sizeof(aubuf), "queue_num", queue_num);
    int64_t queue_num_int = atoi(queue_num);

    const char *local_priority = argv[1];
    qos_audit_encode(aubuf, sizeof(aubuf), "local_priority", local_priority);
    const char * local_priorities = local_priority;

    int result = qos_queue_profile_map_no_command_commit(
            profile_name, queue_num_int, local_priorities);

    qos_audit_log(aubuf, result);

    return result;
}

/**
 * Copies in sorted order the local_priorities from the given
 * profile_entry_row into the given buffer.
 */
static void
snprintf_local_priorities(char *buffer, int64_t n,
        struct ovsrec_q_profile_entry *profile_entry_row)
{
    bool printed[profile_entry_row->n_local_priorities];
    memset(printed, 0, profile_entry_row->n_local_priorities * sizeof(bool));

    size_t min_not_printed_index = -1;
    int64_t min_not_printed_value = INT_MAX;

    int i;
    for (i = 0; i < profile_entry_row->n_local_priorities; i++) {
        /* Find the next smallest value. */
        int j;
        for (j = 0; j < profile_entry_row->n_local_priorities; j++) {
            if (printed[j] == false &&
                    profile_entry_row->local_priorities[j] <
                    min_not_printed_value) {
                min_not_printed_index = j;
                min_not_printed_value = profile_entry_row->local_priorities[j];
            }
        }

        /* Print the value. */
        buffer += snprintf(buffer, n,
                "%" PRId64,
                profile_entry_row->local_priorities[min_not_printed_index]);
        printed[min_not_printed_index] = true;

        /* If not the last one, then print a comma. */
        if (i < profile_entry_row->n_local_priorities - 1) {
            buffer += snprintf(buffer, n, ",");
        }

        min_not_printed_index = -1;
        min_not_printed_value = INT_MAX;
    }
}

/**
 * Prints the queue_profile_entry_row for the given queue_num.
 */
static void
print_queue_profile_entry_row(int64_t queue_num,
        struct ovsrec_q_profile_entry *profile_entry_row)
{
    char buffer[QOS_CLI_STRING_BUFFER_SIZE];

    vty_out (vty, "%-9" PRId64 " ", queue_num);

    buffer[0] = '\0';
    snprintf_local_priorities(buffer,
            sizeof(buffer), profile_entry_row);
    vty_out (vty, "%-16s ", buffer);

    buffer[0] = '\0';
    if (profile_entry_row->description != NULL &&
            strncmp(profile_entry_row->description, "",
                    QOS_CLI_STRING_BUFFER_SIZE) != 0) {
        strncpy(buffer,
                profile_entry_row->description,
                sizeof(buffer));
    }
    vty_out (vty, "%s ", buffer);

    vty_out (vty, "%s", VTY_NEWLINE);
}

/**
 * Executes the qos_queue_profile_show_command for the given name.
 */
static int
qos_queue_profile_show_command(const char *name)
{
    if (name == NULL) {
        vty_out(vty, "name cannot be NULL.%s", VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    if (!qos_is_valid_string(name)) {
        vty_out(vty, QOS_INVALID_STRING_ERROR_MESSAGE, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    struct ovsrec_q_profile *profile_row = qos_get_queue_profile_row(name);
    if (profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                name, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    vty_out (vty, "queue_num local_priorities name%s", VTY_NEWLINE);
    vty_out (vty, "--------- ---------------- ----%s", VTY_NEWLINE);

    int i;
    for (i = 0; i < profile_row->n_q_profile_entries; i++) {
        print_queue_profile_entry_row(profile_row->key_q_profile_entries[i],
                profile_row->value_q_profile_entries[i]);
    }

    return CMD_SUCCESS;
}

/**
 * Executes the qos_queue_profile_show_command for the given name.
 */
DEFUN(qos_queue_profile_show,
    qos_queue_profile_show_cmd,
    "show qos queue-profile NAME",
    SHOW_STR
    "Show QoS Configuration\n"
    "Show QoS Queue Profile Configuration\n"
    "The name of the Queue Profile to display\n")
{
    const char *name = argv[0];

    return qos_queue_profile_show_command(name);
}

/**
 * Executes the qos_queue_profile_show_all_command.
 */
static int
qos_queue_profile_show_all_command(void)
{
    vty_out (vty, "profile_status profile_name%s", VTY_NEWLINE);
    vty_out (vty, "-------------- ------------%s", VTY_NEWLINE);

    char buffer[QOS_CLI_STRING_BUFFER_SIZE];

    const struct ovsrec_q_profile *profile_row;
    OVSREC_Q_PROFILE_FOR_EACH(profile_row, idl) {
        if (is_row_applied(profile_row)) {
            vty_out (vty, "applied        ");
        } else if (qos_queue_profile_is_complete(
                (struct ovsrec_q_profile *) profile_row, false)) {
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
 * Executes the qos_queue_profile_show_all_command.
 */
DEFUN(qos_queue_profile_show_all,
    qos_queue_profile_show_all_cmd,
    "show qos queue-profile",
    SHOW_STR
    "Show QoS Configuration\n"
    "Show QoS Queue Profile Configuration\n")
{
    return qos_queue_profile_show_all_command();
}

/**
 * Prints the profile.
 */
static void
print_profile(struct ovsrec_q_profile *profile_row)
{
    /* Show profile name. */
    vty_out(vty, "qos queue-profile %s%s", profile_row->name,
            VTY_NEWLINE);

    int i;
    for (i = 0; i < profile_row->n_q_profile_entries; i++) {
        int64_t queue_num =
                profile_row->key_q_profile_entries[i];
        struct ovsrec_q_profile_entry *profile_entry =
                profile_row->value_q_profile_entries[i];

        /* Show local-priorities. */
        char applied_buffer[QOS_CLI_STRING_BUFFER_SIZE];
        applied_buffer[0] = '\0';
        snprintf_local_priorities(applied_buffer,
                sizeof(applied_buffer), profile_entry);
        if (applied_buffer != NULL &&
                strncmp(applied_buffer, "",
                        QOS_CLI_STRING_BUFFER_SIZE) != 0) {
            vty_out(vty, "    map queue %" PRId64 " local-priority %s%s",
                    queue_num, applied_buffer, VTY_NEWLINE);
        }

        /* Show description. */
        if (profile_entry->description != NULL &&
                strncmp(profile_entry->description, "",
                        QOS_CLI_STRING_BUFFER_SIZE) != 0) {
            vty_out(vty, "    name queue %" PRId64 " %s%s",
                    queue_num, profile_entry->description,
                    VTY_NEWLINE);
        }
    }
}

/**
 * Returns true if the given profile differs from the factory default.
 */
static bool
differs_from_factory_default(struct ovsrec_q_profile *profile_row)
{
    struct ovsrec_q_profile *default_profile_row = qos_get_queue_profile_row(
            QOS_FACTORY_DEFAULT_NAME);
    if (default_profile_row == NULL) {
        vty_out(vty, "Profile %s does not exist.%s",
                QOS_FACTORY_DEFAULT_NAME, VTY_NEWLINE);
        return false;
    }

    /* Compare profile name. */
    if (strncmp(profile_row->name, default_profile_row->name,
            QOS_CLI_STRING_BUFFER_SIZE) != 0 &&
            strncmp(profile_row->name, QOS_DEFAULT_NAME,
                    QOS_CLI_STRING_BUFFER_SIZE) != 0) {
        return true;
    }

    int i;
    for (i = 0; i < default_profile_row->n_q_profile_entries; i++) {
        int64_t default_queue_num =
                default_profile_row->key_q_profile_entries[i];
        struct ovsrec_q_profile_entry *default_profile_entry =
                default_profile_row->value_q_profile_entries[i];

        struct ovsrec_q_profile_entry *profile_entry =
                qos_get_queue_profile_entry_row(
                        profile_row, default_queue_num);
        if (profile_entry == NULL) {
            /* If the applied profile does not contain a queue_num from the */
            /* default profile, then a difference was found. */
            return true;
        }

        /* Compare local-priorities. */
        char default_buffer[QOS_CLI_STRING_BUFFER_SIZE];
        default_buffer[0] = '\0';
        char applied_buffer[QOS_CLI_STRING_BUFFER_SIZE];
        applied_buffer[0] = '\0';
        snprintf_local_priorities(default_buffer,
                sizeof(default_buffer), default_profile_entry);
        snprintf_local_priorities(applied_buffer,
                sizeof(applied_buffer), profile_entry);
        if (strncmp(applied_buffer, default_buffer,
                sizeof(applied_buffer)) != 0) {
            return true;
        }

        /* Compare description. */
        if (profile_entry->description != NULL &&
                strncmp(profile_entry->description,
                        default_profile_entry->description,
                        QOS_CLI_STRING_BUFFER_SIZE) != 0) {
            return true;
        }
    }

    return false;
}

/**
 * Shows the running config for the profile.
 */
void
qos_queue_profile_show_running_config(void)
{
    const struct ovsrec_q_profile *profile_row;
    OVSREC_Q_PROFILE_FOR_EACH(profile_row, idl) {
        if (strncmp(profile_row->name, QOS_FACTORY_DEFAULT_NAME,
                QOS_CLI_STRING_BUFFER_SIZE) == 0) {
            /* Never print factory default profile since it never changes. */
        } else if (strncmp(profile_row->name, QOS_DEFAULT_NAME,
                QOS_CLI_STRING_BUFFER_SIZE) == 0) {
            /* Print the default profile if different from factory default. */
            if (differs_from_factory_default(
                    (struct ovsrec_q_profile *) profile_row)) {
                print_profile((struct ovsrec_q_profile *) profile_row);
            }
        } else {
            /* Always print non-default profiles. */
            print_profile((struct ovsrec_q_profile *) profile_row);
        }
    }
}

/**
 * Initializes qos_queue_profile_vty.
 */
void
qos_queue_profile_vty_init(void)
{
    install_element(QOS_QUEUE_PROFILE_NODE, &vtysh_exit_interface_cmd);
    install_element(QOS_QUEUE_PROFILE_NODE, &vtysh_end_all_cmd);

    install_element(CONFIG_NODE, &qos_queue_profile_cmd);
    install_element(CONFIG_NODE, &qos_queue_profile_no_cmd);
    install_element(ENABLE_NODE, &qos_queue_profile_show_cmd);
    install_element(ENABLE_NODE, &qos_queue_profile_show_all_cmd);

    install_element(QOS_QUEUE_PROFILE_NODE, &qos_queue_profile_name_cmd);
    install_element(QOS_QUEUE_PROFILE_NODE, &qos_queue_profile_name_no_cmd);

    install_element(QOS_QUEUE_PROFILE_NODE, &qos_queue_profile_map_cmd);
    install_element(QOS_QUEUE_PROFILE_NODE, &qos_queue_profile_map_no_cmd);
}

/**
 * Contains the display prompt for the profile node.
 */
static struct cmd_node qos_queue_profile_node = {
    QOS_QUEUE_PROFILE_NODE,
    "%s(config-queue)# ",
};

/**
 * Initializes qos_queue_profile_ovsdb.
 */
void
qos_queue_profile_ovsdb_init(void)
{
    install_node(&qos_queue_profile_node, NULL);
    vtysh_install_default(QOS_QUEUE_PROFILE_NODE);

    ovsdb_idl_add_table(idl, &ovsrec_table_system);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_q_profile);

    ovsdb_idl_add_table(idl, &ovsrec_table_q_profile);
    ovsdb_idl_add_column(idl, &ovsrec_q_profile_col_name);
    ovsdb_idl_add_column(idl, &ovsrec_q_profile_col_q_profile_entries);
    ovsdb_idl_add_column(idl, &ovsrec_q_profile_col_hw_default);
    ovsdb_idl_add_column(idl, &ovsrec_q_profile_col_other_config);
    ovsdb_idl_add_column(idl, &ovsrec_q_profile_col_external_ids);

    ovsdb_idl_add_table(idl, &ovsrec_table_q_profile_entry);
    ovsdb_idl_add_column(idl,
            &ovsrec_q_profile_entry_col_local_priorities);
    ovsdb_idl_add_column(idl, &ovsrec_q_profile_entry_col_description);
    ovsdb_idl_add_column(idl, &ovsrec_q_profile_entry_col_hw_default);
    ovsdb_idl_add_column(idl, &ovsrec_q_profile_entry_col_other_config);
    ovsdb_idl_add_column(idl, &ovsrec_q_profile_entry_col_external_ids);
}
