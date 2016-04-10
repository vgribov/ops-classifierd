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
# REST Custom Validator for the QoS table.
#


class QosValidator(BaseValidator):
    resource = "qos"

    #
    # Validates that the given modification to a given row is allowed.
    #
    def validate_modification(self, validation_args):
        profile_row = validation_args.resource_row
        self.validate_profile_applied_cannot_be_amended_or_deleted(
            validation_args, profile_row)
        self.validate_profile_name_contains_valid_chars(profile_row)
        self.validate_profile_name_cannot_be_strict(profile_row)

        # If it is new, then it cannot have hw_default set.
        if not validation_args.is_new:
            self.validate_profile_hw_default_cannot_be_amended_or_deleted(
                validation_args, profile_row)

    #
    # Validates that the given deletion of a given row is allowed.
    #
    def validate_deletion(self, validation_args):
        profile_row = validation_args.resource_row
        self.validate_profile_applied_cannot_be_amended_or_deleted(
            validation_args, profile_row)
        self.validate_profile_hw_default_cannot_be_amended_or_deleted(
            validation_args, profile_row)
        self.validate_profile_default_cannot_be_deleted(
            validation_args, profile_row)

    #
    # Validates that an applied profile cannot be amended or deleted.
    #
    def validate_profile_applied_cannot_be_amended_or_deleted(
            self, validation_args, profile_row):
        if qos_utils.schedule_profile_is_applied(validation_args, profile_row):
            details = "An applied profile cannot be amended or deleted."
            raise ValidationError(error.VERIFICATION_FAILED, details)

    #
    # Validates that a hardware default profile cannot be amended or deleted.
    #
    def validate_profile_hw_default_cannot_be_amended_or_deleted(
            self, validation_args, profile_row):
        if qos_utils.queue_profile_is_hw_default(validation_args, profile_row):
            details = "A hardware default profile " + \
                "cannot be amended or deleted."
            raise ValidationError(error.VERIFICATION_FAILED, details)

    #
    # Validates that the default profile cannot be deleted.
    #
    def validate_profile_default_cannot_be_deleted(
            self, validation_args, profile_row):
        profile_name = profile_row.name
        if profile_name == qos_utils.QOS_DEFAULT_NAME:
            details = "The default profile cannot be deleted."
            raise ValidationError(error.VERIFICATION_FAILED, details)

    #
    # Validates that a profile name contains all valid characters.
    #
    def validate_profile_name_contains_valid_chars(self, profile_row):
        profile_name = profile_row.name
        qos_utils.validate_string_contains_valid_chars(profile_name)

    #
    # Validates that the profile's name is not 'strict'.
    #
    def validate_profile_name_cannot_be_strict(self, profile_row):
        profile_name = profile_row.name
        if profile_name == qos_utils.QOS_STRICT:
            details = "The profile name cannot be '" + \
                qos_utils.QOS_STRICT + "'."
            raise ValidationError(error.VERIFICATION_FAILED, details)
