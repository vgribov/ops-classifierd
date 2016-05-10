#!/usr/bin/env python
# Copyright (C) 2015-2016 Hewlett Packard Enterprise Development LP
# All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

from opsrest.utils import utils
from opsvalidator.base import BaseValidator
from opsvalidator import error
from opsvalidator.error import ValidationError

import qos_utils

#
# REST Custom Validator for QoS for the System table.
#


class SystemQosValidator(BaseValidator):
    resource = "system"

    #
    # Validates that the given modification to a given row is allowed.
    #
    def validate_modification(self, validation_args):
        system_row = validation_args.resource_row
        self.validate_trust_global_is_not_empty(system_row)
        self.validate_apply_global_queue_profile_has_all_local_priorities(
            system_row)
        self.validate_apply_global_q_p_has_no_duplicate_local_priorities(
            system_row)
        self.validate_apply_global_s_p_has_same_algorithm_on_all_queues(
            system_row)
        self.validate_apply_global_profiles_contain_same_queues(
            system_row)
        self.validate_apply_port_profiles_contain_same_queues(
            system_row, validation_args)

    #
    # Validates that the given deletion of a given row is allowed.
    #
    def validate_deletion(self, validation_args):
        pass

    #
    # Validates that the global trust value is not empty.
    #
    def validate_trust_global_is_not_empty(self, system_row):
        qos_config = utils.get_column_data_from_row(system_row, "qos_config")
        qos_trust_value = qos_config.get(qos_utils.QOS_TRUST_KEY, None)
        if qos_trust_value is None:
            details = "The qos trust value cannot be empty."
            raise ValidationError(error.VERIFICATION_FAILED, details)

    #
    # Validates that the global apply has a queue profile that contains
    # all local priorities.
    #
    def validate_apply_global_queue_profile_has_all_local_priorities(
            self, system_row):
        q_profile = utils.get_column_data_from_row(system_row, "q_profile")
        if not q_profile:
            return

        for local_priority in range(0, qos_utils.QOS_MAX_LOCAL_PRIORITY + 1):
            if not self.profile_has_local_priority(
                    q_profile[0], local_priority):
                details = "The queue profile is missing local priority " + \
                    str(local_priority) + "."
                raise ValidationError(error.VERIFICATION_FAILED, details)

    #
    # Validates that the global apply has a queue profile that does not
    # contain any duplicate local priorities.
    #
    def validate_apply_global_q_p_has_no_duplicate_local_priorities(
            self, system_row):
        found_local_priorities = []

        q_profile = utils.get_column_data_from_row(system_row, "q_profile")
        if not q_profile:
            return

        q_profile_entries = utils.get_column_data_from_row(
            q_profile[0], "q_profile_entries")
        for q_profile_entry in q_profile_entries.values():
            local_priorities = q_profile_entry.local_priorities
            for local_priority in local_priorities:
                if local_priority in found_local_priorities:
                    details = "The queue profile has local priority " + \
                        str(local_priority) + " assigned more than once."
                    raise ValidationError(error.VERIFICATION_FAILED, details)
                found_local_priorities.append(local_priority)

    #
    # Returns True if the q_profile contains the given local_priority.
    #
    def profile_has_local_priority(self, q_profile, local_priority):
        q_profile_entries = utils.get_column_data_from_row(
            q_profile, "q_profile_entries")
        for q_profile_entry in q_profile_entries.values():
            if self.queue_has_local_priority(q_profile_entry, local_priority):
                return True

        return False

    #
    # Returns True if the q_profile_entry contains the given local_priority.
    #
    def queue_has_local_priority(self, q_profile_entry, local_priority):
        local_priorities = utils.get_column_data_from_row(
            q_profile_entry, "local_priorities")
        for local_priority_from_row in local_priorities:
            if local_priority_from_row == local_priority:
                return True

        return False

    #
    # Validates that the global apply schedule profile
    # contains the same algorithm on all queues.
    #
    def validate_apply_global_s_p_has_same_algorithm_on_all_queues(
            self, system_row):
        schedule_profile = utils.get_column_data_from_row(system_row, "qos")
        if not schedule_profile:
            return

        qos_utils.validate_schedule_profile_has_same_algorithm_on_all_queues(
            schedule_profile[0])

    #
    # Validates that the global apply profiles contain the same queues.
    #
    def validate_apply_global_profiles_contain_same_queues(self, system_row):
        q_profile = utils.get_column_data_from_row(system_row, "q_profile")
        if not q_profile:
            return

        schedule_profile = utils.get_column_data_from_row(system_row, "qos")
        if not schedule_profile:
            return

        qos_utils.validate_profiles_contain_same_queues(
            q_profile[0], schedule_profile[0])

    #
    # Validates that the port profiles contain the same queues.
    #
    def validate_apply_port_profiles_contain_same_queues(
            self, system_row, validation_args):
        idl = validation_args.idl

        q_profile = utils.get_column_data_from_row(system_row, "q_profile")
        if not q_profile:
            return

        for port_row in idl.tables["Port"].rows.itervalues():
            if len(port_row.qos) != 0:
                qos_utils.validate_profiles_contain_same_queues(
                    q_profile[0], port_row.qos[0])
