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

from opsvalidator.base import BaseValidator
from opsvalidator import error
from opsvalidator.error import ValidationError

import qos_utils

#
# REST Custom Validator for QoS for the QoS DSCP Map Entry table.
#


class QosDscpMapEntryValidator(BaseValidator):
    resource = "qos_dscp_map_entry"

    #
    # Validates that the given modification to a given row is allowed.
    #
    def validate_modification(self, validation_args):
        qos_dscp_map_entry_row = validation_args.resource_row
        self.validate_dscp_map_description_contains_valid_chars(
            qos_dscp_map_entry_row)

        # Cos (priority_code_point) is not supported for dill.
        self.validate_priority_code_point_is_empty(
            qos_dscp_map_entry_row)

    #
    # Validates that the given deletion of a given row is allowed.
    #
    def validate_deletion(self, validation_args):
        details = "DSCP Map Entries cannot be deleted."
        raise ValidationError(error.VERIFICATION_FAILED, details)

    #
    # Validates that the dscp map desctiption contains valid characters.
    #
    def validate_dscp_map_description_contains_valid_chars(
            self, qos_dscp_map_entry_row):
        if qos_dscp_map_entry_row.description is None:
            return

        description = qos_dscp_map_entry_row.description[0]
        qos_utils.validate_string_contains_valid_chars(description)

    #
    # Validates that the priority_code_point field is empty, since it is
    # not supported for dill.
    #
    def validate_priority_code_point_is_empty(
            self, qos_dscp_map_entry_row):
        # Cos (priority_code_point) is not supported for dill.
        if qos_dscp_map_entry_row.priority_code_point != []:
            details = "The priority_code_point field " + \
                "is not currently supported."
            raise ValidationError(error.VERIFICATION_FAILED, details)
