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
# REST Custom Validator for QoS for the QoS COS Map Entry table.
#


class QosCosMapEntryValidator(BaseValidator):
    resource = "qos_cos_map_entry"

    #
    # Validates that the given modification to a given row is allowed.
    #
    def validate_modification(self, validation_args):
        if validation_args.is_new:
            details = "COS Map Entries cannot be created."
            raise ValidationError(error.VERIFICATION_FAILED, details)

        qos_cos_map_entry_row = validation_args.resource_row
        self.validate_cos_map_description_contains_valid_chars(
            qos_cos_map_entry_row)

    #
    # Validates that the given deletion of a given row is allowed.
    #
    def validate_deletion(self, validation_args):
        details = "COS Map Entries cannot be deleted."
        raise ValidationError(error.VERIFICATION_FAILED, details)

    #
    # Validates that the cos map desctiption contains valid characters.
    #
    def validate_cos_map_description_contains_valid_chars(
            self, qos_cos_map_entry_row):
        if qos_cos_map_entry_row.description is None:
            return

        description = qos_cos_map_entry_row.description[0]
        qos_utils.validate_string_contains_valid_chars(description)
