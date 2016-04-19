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

#include "qos_cos_map_vty.h"

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

VLOG_DEFINE_THIS_MODULE(vtysh_qos_cos_map_cli);
extern struct ovsdb_idl *idl;

/**
 * Returns the cos_map_row for the given code_point.
 */
static struct ovsrec_qos_cos_map_entry *
qos_cos_map_row_for_code_point(
        int64_t code_point)
{
    const struct ovsrec_qos_cos_map_entry *cos_map_row;
    OVSREC_QOS_COS_MAP_ENTRY_FOR_EACH(cos_map_row, idl) {
        if (cos_map_row->code_point == code_point) {
            return (struct ovsrec_qos_cos_map_entry *) cos_map_row;
        }
    }

    return NULL;
}

/**
 * Executes the qos_cos_map_command for the given
 * code_point, local_priority, color, and description.
 */
static int
qos_cos_map_command(int64_t code_point, int64_t local_priority,
        const char *color, const char *description)
{
    if (description != NULL) {
        if (!qos_is_valid_string(description)) {
            vty_out(vty, QOS_INVALID_STRING_ERROR_MESSAGE, VTY_NEWLINE);
            return CMD_OVSDB_FAILURE;
        }
    }

    /* Retrieve the row. */
    struct ovsrec_qos_cos_map_entry *cos_map_row =
            qos_cos_map_row_for_code_point(code_point);
    if (cos_map_row == NULL) {
        vty_out(vty, "COS Map code point %" PRId64 " does not exist.%s",
                code_point, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    struct ovsdb_idl_txn *txn = cli_do_config_start();
    if (txn == NULL) {
        vty_out(vty, "Unable to start transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_CREATE_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    /* Update the row. */
    ovsrec_qos_cos_map_entry_set_local_priority(cos_map_row, local_priority);
    ovsrec_qos_cos_map_entry_set_color(cos_map_row,
            (color == NULL ? QOS_COLOR_DEFAULT : color));
    ovsrec_qos_cos_map_entry_set_description(cos_map_row,
            (description == NULL ? QOS_DESCRIPTION_DEFAULT : description));

    enum ovsdb_idl_txn_status status = cli_do_config_finish(txn);
    if (status != TXN_SUCCESS && status != TXN_UNCHANGED) {
        vty_out(vty, "Unable to commit transaction.%s", VTY_NEWLINE);
        VLOG_ERR(OVSDB_TXN_COMMIT_ERROR);
        return CMD_OVSDB_FAILURE;
    }

    return CMD_SUCCESS;
}

/**
 * Executes the qos_cos_map_command for the given
 * code_point, local_priority, color, and description.
 */
DEFUN(qos_cos_map,
        qos_cos_map_cmd,
        "qos cos-map <0-7> local-priority <0-7>\
 {color (green|yellow|red) | name STRING}",
        QOS_HELP_STRING
        "Configure QoS COS Map\n"
        "The QoS COS Map code point\n"
        "Configure QoS COS Map local-priority\n"
        "The QoS COS Map local-priority\n"
        "Configure QoS COS Map color\n"
        "Set color to green (Default)\n"
        "Set color to yellow\n"
        "Set color to red\n"
        "Configure QoS COS Map name\n"
        "The QoS COS Map name\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE] = "op=CLI: qos cos-map";

    const char *code_point = argv[0];
    qos_audit_encode(aubuf, sizeof(aubuf), "code_point", code_point);
    int64_t code_point_int = atoi(code_point);

    const char *local_priority = argv[1];
    qos_audit_encode(aubuf, sizeof(aubuf), "local_priority", local_priority);
    int64_t local_priority_int = atoi(local_priority);

    const char *color = argv[2];
    qos_audit_encode(aubuf, sizeof(aubuf), "color", color);

    const char *description = argv[3];
    qos_audit_encode(aubuf, sizeof(aubuf), "description", description);

    int result = qos_cos_map_command(
            code_point_int, local_priority_int, color, description);

    qos_audit_log(aubuf, result);

    return result;
}

/**
 * Executes the qos_cos_map_no_command for the given code_point.
 */
static int
qos_cos_map_no_command(int64_t code_point)
{
    /* Retrieve the row. */
    struct ovsrec_qos_cos_map_entry *cos_map_row =
            qos_cos_map_row_for_code_point(code_point);
    if (cos_map_row == NULL) {
        vty_out(vty, "COS Map code point %" PRId64 " does not exist.%s",
                code_point, VTY_NEWLINE);
        return CMD_OVSDB_FAILURE;
    }

    int64_t local_priority = atoi(smap_get(
            &cos_map_row->hw_defaults, QOS_DEFAULT_LOCAL_PRIORITY_KEY));
    const char *color = smap_get(
            &cos_map_row->hw_defaults, QOS_DEFAULT_COLOR_KEY);
    const char *description = smap_get(
            &cos_map_row->hw_defaults, QOS_DEFAULT_DESCRIPTION_KEY);

    int result = qos_cos_map_command(code_point, local_priority,
            color, description);

    return result;
}

/**
 * Executes the qos_cos_map_no_command for the given code_point.
 */
DEFUN(qos_cos_map_no,
        qos_cos_map_no_cmd,
        "no qos cos-map <0-7> {local-priority <0-7>\
 | color (green|yellow|red) | name STRING}",
        NO_STR
        QOS_HELP_STRING
        "Restore the QoS COS Map values for a given\
 code point to their factory default\n"
        "The QoS COS Map code point\n"
        "Configure QoS COS Map local-priority\n"
        "The QoS COS Map local-priority\n"
        "Configure QoS COS Map color\n"
        "Set color to green (Default)\n"
        "Set color to yellow\n"
        "Set color to red\n"
        "Configure QoS COS Map name\n"
        "The QoS COS Map name\n")
{
    char aubuf[QOS_CLI_AUDIT_BUFFER_SIZE] = "op=CLI: no qos cos-map";

    const char *code_point = argv[0];
    qos_audit_encode(aubuf, sizeof(aubuf), "code_point", code_point);
    int64_t code_point_int = atoi(code_point);

    int result = qos_cos_map_no_command(code_point_int);

    qos_audit_log(aubuf, result);

    return result;
}

/**
 * Prints the given cos_map_row. If is_default is true, then the
 * hw_defaults will be shown.
 */
static void
print_cos_map_row(struct ovsrec_qos_cos_map_entry *cos_map_row,
        bool is_default)
{
    int64_t code_point = is_default
            ? atoi(smap_get(&cos_map_row->hw_defaults,
                    QOS_DEFAULT_CODE_POINT_KEY))
            : cos_map_row->code_point;
    vty_out (vty, "%-10" PRId64 " ", code_point);

    int64_t local_priority = is_default
            ? atoi(smap_get(&cos_map_row->hw_defaults,
                    QOS_DEFAULT_LOCAL_PRIORITY_KEY))
            : cos_map_row->local_priority;
    vty_out (vty, "%-14" PRId64 " ", local_priority);

    const char *color = is_default
            ? smap_get(&cos_map_row->hw_defaults, QOS_DEFAULT_COLOR_KEY)
            : cos_map_row->color;
    vty_out (vty, "%-7s ", color);

    const char *description = is_default
            ? smap_get(&cos_map_row->hw_defaults, QOS_DEFAULT_DESCRIPTION_KEY)
            : cos_map_row->description;
    vty_out (vty, "%s ", description);

    vty_out (vty, "%s", VTY_NEWLINE);
}

/**
 * Executes the qos_cos_map_show_command. If the default_parameter is
 * not NULL, then the defaults will be shown.
 */
static int
qos_cos_map_show_command(const char *default_parameter)
{
    vty_out (vty, "code_point local_priority color   name%s", VTY_NEWLINE);
    vty_out (vty, "---------- -------------- ------- ----%s", VTY_NEWLINE);

    /* Create an ordered array of rows. */
    struct ovsrec_qos_cos_map_entry *cos_map_rows[QOS_COS_MAP_ENTRY_COUNT];
    const struct ovsrec_qos_cos_map_entry *cos_map_row;
    OVSREC_QOS_COS_MAP_ENTRY_FOR_EACH(cos_map_row, idl) {
        cos_map_rows[cos_map_row->code_point] =
                (struct ovsrec_qos_cos_map_entry *) cos_map_row;
    }

    /* Print the ordered rows. */
    bool is_default = (default_parameter != NULL);
    int i;
    for (i = 0; i < QOS_COS_MAP_ENTRY_COUNT; i++) {
        print_cos_map_row(cos_map_rows[i], is_default);
    }

    return CMD_SUCCESS;
}

/**
 * Executes the qos_cos_map_show_command. If the default_parameter is
 * not NULL, then the defaults will be shown.
 */
DEFUN(qos_cos_map_show,
        qos_cos_map_show_cmd,
        "show qos cos-map {default}",
        SHOW_STR
        "Show QoS Configuration\n"
        "Show QoS COS-Map Configuration\n"
        "Display the factory default values\n")
{
    const char *default_parameter = argv[0];

    return qos_cos_map_show_command(default_parameter);
}

/**
 * Contains the callback for qos_cos_map_show_running_config.
 */
static vtysh_ret_val
qos_cos_map_show_running_config_callback(
        void *p_private)
{
    /* Create an ordered array of rows. */
    struct ovsrec_qos_cos_map_entry *cos_map_rows[QOS_COS_MAP_ENTRY_COUNT];
    const struct ovsrec_qos_cos_map_entry *cos_map_row;
    OVSREC_QOS_COS_MAP_ENTRY_FOR_EACH(cos_map_row, idl) {
        cos_map_rows[cos_map_row->code_point] =
                (struct ovsrec_qos_cos_map_entry *) cos_map_row;
    }

    /* Check the ordered rows. */
    int i;
    for (i = 0; i < QOS_COS_MAP_ENTRY_COUNT; i++) {
        const struct ovsrec_qos_cos_map_entry *cos_map_row = cos_map_rows[i];
        int64_t code_point = cos_map_row->code_point;
        bool differs_from_default = false;

        /* Compare local_priority. */
        int64_t default_local_priority = atoi(smap_get(
                &cos_map_row->hw_defaults, QOS_DEFAULT_LOCAL_PRIORITY_KEY));
        if (cos_map_row->local_priority != default_local_priority) {
            differs_from_default = true;
        }

        /* Compare color. */
        const char *default_color =
                smap_get(&cos_map_row->hw_defaults, QOS_DEFAULT_COLOR_KEY);
        if (strncmp(cos_map_row->color, default_color,
                QOS_CLI_STRING_BUFFER_SIZE) != 0) {
            differs_from_default = true;
        }

        /* Compare description. */
        const char *default_description =
                smap_get(&cos_map_row->hw_defaults,
                        QOS_DEFAULT_DESCRIPTION_KEY);
        if (strncmp(cos_map_row->description, default_description,
                QOS_CLI_STRING_BUFFER_SIZE) != 0) {
            differs_from_default = true;
        }

        /* Show the command if it differs from the default. */
        if (differs_from_default) {
            vty_out(vty, "qos cos-map %" PRId64 " local-priority %" PRId64 " ",
                    code_point, cos_map_row->local_priority);

            if (cos_map_row->color != NULL) {
                vty_out(vty, "color %s ", cos_map_row->color);
            }

            if (cos_map_row->description != NULL &&
                    strncmp(cos_map_row->description, "",
                            QOS_CLI_STRING_BUFFER_SIZE) != 0) {
                vty_out(vty, "name %s ", cos_map_row->description);
            }

            vty_out(vty, "%s", VTY_NEWLINE);
        }
    }

    return e_vtysh_ok;
}

/**
 * Installs the callback function for qos_cos_map_show_running_config.
 */
void
qos_cos_map_show_running_config(void)
{
    vtysh_ret_val retval = install_show_run_config_context(
                              e_vtysh_qos_cos_map_context,
                              &qos_cos_map_show_running_config_callback,
                              NULL, NULL);
    if (retval != e_vtysh_ok) {
        vtysh_ovsdb_config_logmsg(VTYSH_OVSDB_CONFIG_ERR,
                           "Context unable "\
                           "to add config callback");
    }
}

/**
 * Initializes qos_cos_map_vty.
 */
void
qos_cos_map_vty_init(void)
{
    install_element(CONFIG_NODE, &qos_cos_map_cmd);
    install_element(CONFIG_NODE, &qos_cos_map_no_cmd);
    install_element (ENABLE_NODE, &qos_cos_map_show_cmd);
}

/**
 * Initializes qos_cos_map_ovsdb.
 */
void
qos_cos_map_ovsdb_init(void)
{
    ovsdb_idl_add_table(idl, &ovsrec_table_system);
    ovsdb_idl_add_column(idl, &ovsrec_system_col_qos_cos_map_entries);

    ovsdb_idl_add_table(idl, &ovsrec_table_qos_cos_map_entry);
    ovsdb_idl_add_column(idl, &ovsrec_qos_cos_map_entry_col_code_point);
    ovsdb_idl_add_column(idl, &ovsrec_qos_cos_map_entry_col_local_priority);
    ovsdb_idl_add_column(idl, &ovsrec_qos_cos_map_entry_col_color);
    ovsdb_idl_add_column(idl, &ovsrec_qos_cos_map_entry_col_description);
    ovsdb_idl_add_column(idl, &ovsrec_qos_cos_map_entry_col_hw_defaults);
    ovsdb_idl_add_column(idl, &ovsrec_qos_cos_map_entry_col_other_config);
    ovsdb_idl_add_column(idl, &ovsrec_qos_cos_map_entry_col_external_ids);
}
