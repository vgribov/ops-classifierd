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
 * Handle QoS queue- and schedule-profile callbacks from bridge_reconfigure
 ***************************************************************************/

#include <config.h>
#include "qos_profile.h"

#include <stdlib.h>
#include <string.h>

#include "openvswitch/vlog.h"
#include "qos-asic-provider.h"
#include "qos_plugin.h"
#include "qos_utils.h"
#include "smap.h"


VLOG_DEFINE_THIS_MODULE(qos_profile);

static bool global_queue_profile_changed = false;
static bool global_schedule_profile_changed = false;

/* Queue and Schedule profiles. */

/* Construct queue-profile_settings parameter for API call. */
static struct queue_profile_settings *
qos_get_queue_profile_settings(const struct ovsrec_q_profile *ovsrec_q_profile)
{
    struct queue_profile_settings *settings;
    const struct ovsrec_q_profile_entry *ovsrec_q_profile_entry;
    int q_index;
    int lp_index;
    struct queue_profile_entry *qp_entry;


    /* if no queue profile defined, let caller decide what to do next */
    if (!ovsrec_q_profile) {
        return NULL;
    }

    /* start constructing the variable-length settings for the API call */
    settings = calloc(1, sizeof*settings);

    settings->n_entries = (int)ovsrec_q_profile->n_q_profile_entries;
    settings->entries = malloc(settings->n_entries * sizeof(void *));

    VLOG_DBG("%s %s %d", __FUNCTION__,
             ovsrec_q_profile->name, settings->n_entries);

    /* collect all queues in the profiles whether or not they changed */
    for (q_index = 0; q_index < settings->n_entries; q_index++) {

        /* each queue gets a separate entry in settings parameter */
        qp_entry = calloc(1, sizeof(struct queue_profile_entry));
        settings->entries[q_index] = qp_entry;
        qp_entry->queue =
            (unsigned)ovsrec_q_profile->key_q_profile_entries[q_index];

        /* point at a q_settings entry in the q_profile row */
        ovsrec_q_profile_entry =
                        ovsrec_q_profile->value_q_profile_entries[q_index];

        /* handle local priorities, if present */
        if (ovsrec_q_profile_entry->local_priorities) {

            qp_entry->n_local_priorities =
                            ovsrec_q_profile_entry->n_local_priorities;
            /* create the local_priority pointer array */
            qp_entry->local_priorities =
                        calloc(ovsrec_q_profile_entry->n_local_priorities,
                               sizeof(void *));

            /* now handle each local priority for this queue */
            for (lp_index = 0;
                  lp_index < ovsrec_q_profile_entry->n_local_priorities;
                  lp_index++) {

                struct local_priority_entry *lp_entry;
                lp_entry = calloc(1, sizeof(struct local_priority_entry));
                qp_entry->local_priorities[lp_index] = lp_entry;
                if (ovsrec_q_profile_entry->local_priorities[lp_index]) {
                    lp_entry->local_priority = (unsigned)
                        ovsrec_q_profile_entry->local_priorities[lp_index];
                    VLOG_DBG("%s ... %d lp=%d", __FUNCTION__,
                             lp_index, lp_entry->local_priority);
                }
            }
        }
    }

    return settings;
}

/* free the memory associated with the queue-profile settings parameter */
static void
qos_free_queue_profile_settings(struct queue_profile_settings *settings)
{
    int q_index;
    int lp_index;
    struct queue_profile_entry *qp_entry;

    if (settings) {
        /* free up all the settings allocations */
        for (q_index = 0; q_index < settings->n_entries; q_index++) {

            /* handle each queue entry */
            qp_entry = settings->entries[q_index];
            for (lp_index = 0;
                  lp_index < qp_entry->n_local_priorities;
                  lp_index++ ) {

                /* free each local priority entry */
                free(qp_entry->local_priorities[lp_index]);
            }

            /* free the variable-length local-priority pointer array */
            free(qp_entry->local_priorities);

            /* then free the queue entry itself */
            free(qp_entry);
        }

        /* finally, free up the settings parameter itself */
        free(settings->entries);
    }
    return;
}

/* translate DB-based algorithm string into internal enumeration value */
static enum schedule_algorithm
qos_get_schedule_algorithm(char *db_algorithm)
{
    enum schedule_algorithm algorithm;

    /* if no match, return STRICT */
    algorithm = ALGORITHM_STRICT;

    if (db_algorithm) {
        if (!strncmp(db_algorithm, OVSREC_QUEUE_ALGORITHM_STRICT, 8)) {
            algorithm = ALGORITHM_STRICT;
        }
        else if (!strncmp(db_algorithm, OVSREC_QUEUE_ALGORITHM_DWRR, 8)) {
            algorithm = ALGORITHM_DWRR;
        }
    }

    return algorithm;
}

/* Construct schedule-profile_settings parameter for API call.
 *
 * If schedule profile is 'strict', create a synthetic profile based on
 * the number of queues in the queue profile.
 */
static struct schedule_profile_settings *
qos_get_schedule_profile_settings(const struct ovsrec_qos *ovsrec_qos,
                                  int n_queues)
{
    struct schedule_profile_settings *settings;
    const struct ovsrec_queue *ovsrec_queue;
    int q_index;
    struct schedule_profile_entry *sp_entry;


    /* start constructing the variable-length settings for the API call */
    settings = calloc(1, sizeof *settings);

    VLOG_DBG("%s %s %d", __FUNCTION__,
             ovsrec_qos->name, settings->n_entries);
    if (!strcmp(ovsrec_qos->name, OVSREC_QUEUE_ALGORITHM_STRICT)) {
        settings->n_entries = n_queues;
        settings->entries = malloc(settings->n_entries * sizeof(void *));

        /* 'strict' profile - synthesize a schedule profile. */
        for (q_index = 0; q_index < n_queues; q_index++) {
            /* set each profile entry to the same 'strict' entry. */
            sp_entry = calloc(1, sizeof(struct schedule_profile_entry));
            sp_entry->queue = (unsigned)ovsrec_qos->key_queues[q_index];
            settings->entries[q_index] = sp_entry;

            sp_entry->algorithm = ALGORITHM_STRICT;
            sp_entry->weight = 0;
            sp_entry->other_config = NULL;
        }
    }
    else {
        settings->n_entries = (int)ovsrec_qos->n_queues;
        settings->entries = malloc(settings->n_entries * sizeof(void *));

        /* collect all queues in the profiles whether or not they changed */
        for (q_index = 0; q_index < settings->n_entries; q_index++) {

            /* each queue gets a separate entry in settings parameter */
            sp_entry = calloc(1, sizeof(struct schedule_profile_entry));
            sp_entry->queue = (unsigned)ovsrec_qos->key_queues[q_index];
            settings->entries[q_index] = sp_entry;

            /* point at a ovsrec_queue in the qos table */
            ovsrec_queue = ovsrec_qos->value_queues[q_index];

            /* construct a queue entry in the settings parameter */
            sp_entry->algorithm = qos_get_schedule_algorithm(ovsrec_queue->algorithm);

            if (ovsrec_queue->weight) {
                sp_entry->weight = (int)(*ovsrec_queue->weight);
            }
        }
    }

    return settings;
}

/* free the memory associated with the schedule-profile settings parameter */
static void
qos_free_schedule_profile_settings(struct schedule_profile_settings *settings)
{
    int q_index;
    struct schedule_profile_entry *sp_entry;

    if (settings) {
        /* free up all the settings allocations */
        for (q_index = 0; q_index < settings->n_entries; q_index++) {

            /* free each schedule entry */
            sp_entry = settings->entries[q_index];
            free(sp_entry);
        }

        /* finally, free up the settings parameter itself */
        free(settings->entries);
    }
    return;
}

/* Apply a single set up of queue- and schedule- profiles. */
int
qos_apply_profile(struct ofproto *ofproto,
                  void *aux, /* struct port *port */
                  const struct ovsrec_qos *ovsrec_qos,
                  const struct ovsrec_q_profile *ovsrec_q_profile)
{
    struct schedule_profile_settings *schedule_settings;
    struct queue_profile_settings *queue_settings;
    int status;

    /* Construct API settings parameter that contains the queue &
       schedule profile.
       Provider APIs must handle either or both profile pointers
       set to NULL.
     */
    queue_settings = NULL;
    if (ovsrec_q_profile) {
        queue_settings = qos_get_queue_profile_settings(ovsrec_q_profile);
    }
    schedule_settings = NULL;
    if (ovsrec_qos) {
        schedule_settings = qos_get_schedule_profile_settings(ovsrec_qos,
                                                  queue_settings->n_entries);
    }

    status = ofproto_apply_qos_profile(ofproto, aux,
                                       schedule_settings,
                                       queue_settings);

    qos_free_schedule_profile_settings(schedule_settings);
    qos_free_queue_profile_settings(queue_settings);

    return status;
}

/* Apply queue and schedule profiles globally. */
void
qos_configure_global_profiles(struct ofproto *ofproto,
                              struct ovsdb_idl *idl, unsigned int idl_seqno)
{
    const struct ovsrec_system *ovs_row = NULL;
    const struct ovsrec_q_profile *ovsrec_q_profile;
    const struct ovsrec_qos *ovsrec_qos;
    const char *queue_profile_applied;
    const char *schedule_profile_applied;
    bool apply_profile_needed;
    bool apply_queue_profile_needed = false;
    bool apply_schedule_profile_needed = false;


    /* Clear global changed flags. */
    global_queue_profile_changed = global_schedule_profile_changed = false;

    ovs_row = ovsrec_system_first(idl);

    /* Has System row changed? */
    if (OVSREC_IDL_IS_ROW_MODIFIED(ovs_row, idl_seqno) ||
        OVSREC_IDL_IS_ROW_INSERTED(ovs_row, idl_seqno)) {

        /* compare configured name with applied name.  If they
         * don't match, try to apply them.
         *
         * NOTE: if no profile is configured, use "default" profile
         *      if no default, give up -- don't change anything.
         */
        queue_profile_applied = smap_get(&ovs_row->qos_status, "queue_profile");
        schedule_profile_applied = smap_get(&ovs_row->qos_status, "schedule_profile");

        apply_profile_needed = false;
        if (!queue_profile_applied) {
            /* No queue profile is applied, we need to apply one. */
            apply_profile_needed = true;
            apply_queue_profile_needed = apply_profile_needed;
            queue_profile_applied = "";
        }

        /* if no queue profile is configured, try to find "default" */
        ovsrec_q_profile = ovs_row->q_profile;
        if (ovsrec_q_profile == NULL) {
            OVSREC_Q_PROFILE_FOR_EACH(ovsrec_q_profile, idl) {
                if (!strcmp(QOS_DEFAULT_NAME, ovsrec_q_profile->name))
                    break;
            }
        }

        if (ovsrec_q_profile != NULL) {
            /* If name changed, we must apply new profile. */
            if (ovsrec_q_profile->name) {
                /* strcmp returns true if names don't match. */
                apply_profile_needed = strcmp(ovsrec_q_profile->name,
                                              queue_profile_applied);
                apply_queue_profile_needed = apply_profile_needed;
            }
        }
        else {
            /* no queue profile defined -- do no harm -- get out. */
            return;
        }

        if (!schedule_profile_applied) {

            /* No schedule profile is applied, we need to apply one. */
            apply_profile_needed = true;
            apply_schedule_profile_needed = apply_profile_needed;
            schedule_profile_applied = "";
        }

        /* if no queue profile is configured, try to find "default" */
        ovsrec_qos = ovs_row->qos;
        if (ovsrec_qos == NULL) {
            OVSREC_QOS_FOR_EACH(ovsrec_qos, idl) {
                if (!strcmp(QOS_DEFAULT_NAME, ovsrec_qos->name))
                    break;
            }
        }

        if (ovsrec_qos != NULL) {
            /* If name changed, we must apply new profile. */
            if (ovsrec_qos->name) {
                /* strcmp returns true if names don't match. */
                apply_profile_needed = strcmp(ovsrec_qos->name,
                                              schedule_profile_applied);
                apply_schedule_profile_needed = apply_profile_needed;
            }
        }
        else {
            /* no schedule profile defined -- do no harm -- get out. */
            return;
        }

        if (apply_profile_needed) {

            if (qos_apply_profile(ofproto,
                                  NULL, /* global profile */
                                  ovsrec_qos,
                                  ovsrec_q_profile) == 0) {
                /* profiles were applied, save profile names so we stop
                   trying to update them. */
                struct smap smap;

                smap_clone(&smap, &ovs_row->qos_status);
                if (ovsrec_q_profile) {
                    smap_replace(&smap, "queue_profile",
                                 ovsrec_q_profile->name);
                }
                if (ovsrec_qos) {
                    smap_replace(&smap, "schedule_profile",
                                 ovsrec_qos->name);
                }
                ovsrec_system_set_qos_status(ovs_row, &smap);
                smap_destroy(&smap);

                global_queue_profile_changed = apply_queue_profile_needed;
                global_schedule_profile_changed = apply_schedule_profile_needed;
            }
        }
    }
    return;
}

/* Apply queue and schedule profiles to a port. */
void
qos_configure_port_profiles(struct ofproto *ofproto,
                            const struct ovsrec_port *port_cfg,
                            void *aux, /* struct port *port */
                            struct ovsdb_idl *idl, unsigned int idl_seqno)
{
    const struct ovsrec_system *ovs_row = NULL;
    const struct ovsrec_q_profile *ovsrec_q_profile;
    const struct ovsrec_qos *ovsrec_qos;
    const char *queue_profile_applied;
    const char *schedule_profile_applied;
    bool apply_profile_needed;


    ovs_row = ovsrec_system_first(idl);

    /* if no queue profile is configured, try to find something to use:
     * 1. global queue profile from System row
     * 2. "default" queue profile
     * 3. "factory-default" queue profile (iow, profile has hw_default = TRUE)
     */
    ovsrec_q_profile = port_cfg->q_profile;
    if (ovsrec_q_profile == NULL) {
        ovsrec_q_profile = ovs_row->q_profile;
        if (ovsrec_q_profile == NULL) {
            OVSREC_Q_PROFILE_FOR_EACH(ovsrec_q_profile, idl) {
                if (!strcmp(QOS_DEFAULT_NAME, ovsrec_q_profile->name))
                    break;
            }
            if (ovsrec_q_profile == NULL) {
                /* search for "factory-default" profile */
                OVSREC_Q_PROFILE_FOR_EACH(ovsrec_q_profile, idl) {
                    if (ovsrec_q_profile->hw_default &&
                                    *ovsrec_q_profile->hw_default) {
                        break;
                    }
                }
            }
        }
    }
    if (ovsrec_q_profile == NULL) {
        /* no queue profile defined -- do no harm -- get out. */
        VLOG_INFO("%s: port %s no queue profile defined. NO CHANGE.",
                  __FUNCTION__, port_cfg->name);
        return;
    }

    /* if no schedule profile is configured, try to find something to use:
     * 1. global schedule profile (already done at the start of this function)
     * 2. "default" schedule profile
     * 3. "factory-default" schedule profile (iow, profile has hw_default = TRUE)
     */
    ovsrec_qos = port_cfg->qos;
    if (ovsrec_qos == NULL) {
        ovsrec_qos = ovs_row->qos;
    }
    if (ovsrec_qos == NULL) {
        /* search for "default" profile */
        OVSREC_QOS_FOR_EACH(ovsrec_qos, idl) {
            if (!strcmp(QOS_DEFAULT_NAME, ovsrec_qos->name))
                break;
        }
        if (ovsrec_qos == NULL) {
            /* search for "factory-default" profile */
            OVSREC_QOS_FOR_EACH(ovsrec_qos, idl) {
                if (ovsrec_qos->hw_default && *ovsrec_qos->hw_default) {
                    break;
                }
            }
        }
    }
    if (ovsrec_qos == NULL) {
        /* no schedule profile defined -- do no harm -- get out. */
        VLOG_INFO("%s: port %s no schedule profile defined. NO CHANGE.",
                  __FUNCTION__, port_cfg->name);
        return;
    }

    /* compare configured name with applied name.  If they
     * don't match, try to apply them.
     */
    queue_profile_applied = smap_get(&port_cfg->qos_status,
                                     "queue_profile");
    schedule_profile_applied = smap_get(&port_cfg->qos_status,
                                        "schedule_profile");

    apply_profile_needed = false;

    /* Investigate if applied queue profile has changed. */
    if (!queue_profile_applied) {
        /* No queue profile is applied, we need to apply one. */
        apply_profile_needed = true;
        queue_profile_applied = "";
    }

    /* If name changed, we must apply new profile. */
    if (ovsrec_q_profile->name) {
        /* strcmp returns true if names don't match. */
        apply_profile_needed = strcmp(ovsrec_q_profile->name,
                                      queue_profile_applied);
    }

    if (!schedule_profile_applied) {
        /* No schedule profile is applied, we need to apply one. */
        apply_profile_needed = true;
        schedule_profile_applied = "";
    }

    /* If name changed, we must apply new profile. */
    if (ovsrec_qos->name) {
        /* strcmp returns true if names don't match. */
        if (strcmp(ovsrec_qos->name, schedule_profile_applied)) {
            apply_profile_needed = true;
        }
    }

    /* a sanity check: queue & schedule profiles must have same # of queues.
     * Exception for "strict" profile as it doesn't have any queue rows.
     */
    if (strcmp(ovsrec_qos->name, OVSREC_QUEUE_ALGORITHM_STRICT) &&
        (ovsrec_qos->n_queues != ovsrec_q_profile->n_q_profile_entries)) {
        VLOG_INFO("%s: port %s #-queues mismatched Q=%d S=%d", __FUNCTION__,
                  port_cfg->name,
                  (int)ovsrec_qos->n_queues,
                  (int)ovsrec_q_profile->n_q_profile_entries);
        return;
    }

    /* Finally ready to apply the profiles. */
    if (apply_profile_needed) {

        if (qos_apply_profile(ofproto, aux,
                              ovsrec_qos,
                              ovsrec_q_profile) == 0) {
            /* profiles were applied, save profile names so we stop
               trying to update them. */
            struct smap smap;

            smap_clone(&smap, &port_cfg->qos_status);
            if (ovsrec_q_profile) {
                smap_replace(&smap, "queue_profile", ovsrec_q_profile->name);
            }
            if (ovsrec_qos) {
                smap_replace(&smap, "schedule_profile", ovsrec_qos->name);
            }
            if (port_cfg != NULL) {
                ovsrec_port_set_qos_status(port_cfg, &smap);
            }
            else {
                ovsrec_system_set_qos_status(ovs_row, &smap);
            }
            smap_destroy(&smap);
        }
    }
}
