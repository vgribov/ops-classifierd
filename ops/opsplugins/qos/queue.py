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
# REST Custom Validator for QoS for the Queue table.
#


class QueueValidator(BaseValidator):
    resource = "queue"

    #
    # Validates that the given modification to a given row is allowed.
    #
    def validate_modification(self, validation_args):
        profile_row = validation_args.p_resource_row
        profile_entry_row = validation_args.resource_row

        self.validate_profile_applied_cannot_be_amended_or_deleted(
            validation_args, profile_row)
        self.validate_profile_entry_with_dwrr_has_weight_less_than_max_weight(
            profile_entry_row)
        self.validate_profile_hw_default_cannot_be_amended_or_deleted(
            validation_args, profile_row)

    #
    # Validates that the given deletion of a given row is allowed.
    #
    def validate_deletion(self, validation_args):
        profile_row = validation_args.p_resource_row

        self.validate_profile_applied_cannot_be_amended_or_deleted(
            validation_args, profile_row)
        self.validate_profile_hw_default_cannot_be_amended_or_deleted(
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
    # Validates that a profile entry with dwrr has a weight less
    # than max weight.
    #
    def validate_profile_entry_with_dwrr_has_weight_less_than_max_weight(
            self, profile_entry_row):
        if profile_entry_row.algorithm is None:
            return

        if profile_entry_row.algorithm[0] == qos_utils.QOS_DWRR:
            if not profile_entry_row.weight:
                details = "A dwrr profile entry must have a weight."
                raise ValidationError(error.VERIFICATION_FAILED, details)

            if profile_entry_row.weight[0] > qos_utils.QOS_MAX_WEIGHT:
                details = "The weight cannot be larger than the max weight."
                raise ValidationError(error.VERIFICATION_FAILED, details)
