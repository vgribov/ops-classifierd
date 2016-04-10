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
from opsvalidator import error
from opsvalidator.error import ValidationError

QOS_FACTORY_DEFAULT_NAME = "factory-default"
QOS_DEFAULT_NAME = "default"

QOS_TRUST_KEY = "qos_trust"
QOS_TRUST_NONE_STRING = "none"
QOS_TRUST_DEFAULT = QOS_TRUST_NONE_STRING

QOS_COS_OVERRIDE_KEY = "cos_override"
QOS_DSCP_OVERRIDE_KEY = "dscp_override"

QOS_LOCAL_PRIORITY_DEFAULT = 0
QOS_COLOR_DEFAULT = "green"
QOS_DESCRIPTION_DEFAULT = ""

QOS_STRICT = "strict"
QOS_DWRR = "dwrr"
QOS_MAX_WEIGHT = 127

QOS_MAX_LOCAL_PRIORITY = 7

QOS_COS_MAP_ENTRY_COUNT = 8

QOS_DSCP_MAP_ENTRY_COUNT = 64

#
# Validates that a string contains only valid characters.
#


def validate_string_contains_valid_chars(string):
    for c in string:
        if not is_valid_char(c):
            details = "The allowed characters are alphanumeric, " + \
                "underscore ('_'), hyphen ('-'), and dot ('.')."
            raise ValidationError(error.VERIFICATION_FAILED, details)

#
# Returns True is the given characeter is valid.
#


def is_valid_char(c):
    return c.isalnum() or c == "_" or c == "-" or c == "."

#
# Returns True if the given queue_profile_row is applied.
#


def queue_profile_is_applied(validation_args, queue_profile_row):
    idl = validation_args.idl

    for system_row in idl.tables["System"].rows.itervalues():
        if system_row.q_profile is not None and \
                system_row.q_profile[0] == queue_profile_row:
            return True

    for port_row in idl.tables["Port"].rows.itervalues():
        if len(port_row.q_profile) != 0 and \
                port_row.q_profile[0] == queue_profile_row:
            return True

    return False

#
# Returns True if the given schedule_profile_row is applied.
#


def schedule_profile_is_applied(validation_args, schedule_profile_row):
    idl = validation_args.idl

    for system_row in idl.tables["System"].rows.itervalues():
        if system_row.qos is not None and \
                system_row.qos[0] == schedule_profile_row:
            return True

    for port_row in idl.tables["Port"].rows.itervalues():
        if len(port_row.qos) != 0 and \
                port_row.qos[0] == schedule_profile_row:
            return True

    return False

#
# Returns True if the given queue_profile_row is a hw_default.
#


def queue_profile_is_hw_default(validation_args, queue_profile_row):
    return queue_profile_row.hw_default

#
# Returns True if the given schedule_profile_row is a hw_default.
#


def schedule_profile_is_hw_default(validation_args, schedule_profile_row):
    return schedule_profile_row.hw_default

#
# Validates that the schedule profile has the same algorithm on all queues.
#


def validate_schedule_profile_has_same_algorithm_on_all_queues(
        schedule_profile):
    # The profile named 'strict' is exempt, since it is a special case. #
    if schedule_profile.name == QOS_STRICT:
        return

    queues = utils.get_column_data_from_row(schedule_profile, "queues")

    if len(queues) == 0:
        details = "The schedule profile must have at least one queue."
        raise ValidationError(error.VERIFICATION_FAILED, details)

    max_queue_num = get_max_queue_num(schedule_profile)

    algorithm = ""
    for queue_entry in queues.items():
        queue_num = queue_entry[0]
        schedule_profile_entry = queue_entry[1]

        schedule_profile_entry_algorithm = schedule_profile_entry.algorithm[0]

        # If it's the max and it's strict, then skip it. #
        if max_queue_num == queue_num and \
                schedule_profile_entry_algorithm == QOS_STRICT:
            continue

        if algorithm == "":
            algorithm = schedule_profile_entry_algorithm

        if schedule_profile_entry_algorithm != algorithm:
            details = "The schedule profile must have " + \
                "the same algorithm on all queues."
            raise ValidationError(error.VERIFICATION_FAILED, details)

#
# Returns the max queue num for the given schedule_profile.
#


def get_max_queue_num(schedule_profile):
    max_queue_num = -1

    for queue_num in schedule_profile.queues.keys():
        if queue_num > max_queue_num:
            max_queue_num = queue_num

    return max_queue_num

#
# Validates that the profiles contain the same queues.
#


def validate_profiles_contain_same_queues(q_profile, schedule_profile):
    # The profile named 'strict' is exempt, since it is a special case. #
    if schedule_profile.name == QOS_STRICT:
        return

    queues = utils.get_column_data_from_row(schedule_profile, "queues")
    for queue_num in queues.keys():
        if not queue_profile_has_queue_num(q_profile, queue_num):
            details = "The queue profile must contain " + \
                "all of the schedule profile queue numbers."
            raise ValidationError(error.VERIFICATION_FAILED, details)

    q_profile_entries = utils.get_column_data_from_row(
        q_profile, "q_profile_entries")
    for queue_num in q_profile_entries.keys():
        if not schedule_profile_has_queue_num(schedule_profile, queue_num):
            details = "The schedule profile must contain " + \
                "all of the queue profile queue numbers."
            raise ValidationError(error.VERIFICATION_FAILED, details)

#
# Returns True if the given q_profile contains the given queue_num.
#


def queue_profile_has_queue_num(q_profile, queue_num):
    q_profile_entries = utils.get_column_data_from_row(
        q_profile, "q_profile_entries")
    for profile_queue_num in q_profile_entries.keys():
        if queue_num == profile_queue_num:
            return True
    return False

#
# Returns True if the given schedule_profile contains the given queue_num.
#


def schedule_profile_has_queue_num(schedule_profile, queue_num):
    schedule_profile_entries = utils.get_column_data_from_row(
        schedule_profile, "queues")
    for profile_queue_num in schedule_profile_entries.keys():
        if queue_num == profile_queue_num:
            return True
    return False
