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

#
# REST Custom Validator for the Mirror table.
#


class MirrorValidator(BaseValidator):
    resource = "mirror"

    #
    # Validates that the given modification to a given row is allowed.
    #
    def validate_modification(self, validation_args):
        mirror_row = validation_args.resource_row
        # Only check active mirrors.
        if not hasattr(mirror_row, 'active') or \
                mirror_row.active == [False]:
            return

        self.validate_output_port_is_not_empty(mirror_row)
        self.validate_selects_are_not_empty(mirror_row)
        self.validate_output_port_is_not_this_select_src_port(mirror_row)
        self.validate_output_port_is_not_this_select_dst_port(mirror_row)
        self.validate_ports_are_system_ports(mirror_row)

        idl = validation_args.idl
        for other_mirror_row in idl.tables["Mirror"].rows.itervalues():
            # Only check active mirrors.
            if not hasattr(other_mirror_row, 'active') or \
                    other_mirror_row.active == [False]:
                continue

            # Skip our own row.
            if other_mirror_row == mirror_row:
                continue

            self.validate_output_port_is_not_select_src_port(mirror_row,
                                                             other_mirror_row)
            self.validate_output_port_is_not_select_dst_port(mirror_row,
                                                             other_mirror_row)
            self.validate_output_port_is_not_output_port(mirror_row,
                                                         other_mirror_row)
            self.validate_select_src_port_is_not_output_port(mirror_row,
                                                             other_mirror_row)
            self.validate_select_dst_port_is_not_output_port(mirror_row,
                                                             other_mirror_row)

    #
    # Validates that the given deletion of a given row is allowed.
    #
    def validate_deletion(self, validation_args):
        pass

    #
    # Validates that the output-port is not empty.
    #
    def validate_output_port_is_not_empty(self, mirror_row):
        if not hasattr(mirror_row, 'output_port') or \
                mirror_row.output_port == []:
            details = "The output port cannot be empty."
            raise ValidationError(error.VERIFICATION_FAILED, details)

    #
    # Validates that the select src port and select dst port are not
    # both empty.
    #
    def validate_selects_are_not_empty(self, mirror_row):
        if (not hasattr(mirror_row, 'select_src_port') or \
                mirror_row.select_src_port == []) and \
                (not hasattr(mirror_row, 'select_dst_port') or \
                 mirror_row.select_dst_port == []):
            details = "The select src port and select dst port " \
                "cannot both be empty."
            raise ValidationError(error.VERIFICATION_FAILED, details)

    #
    # Validates that the output port is not also a select src port.
    #
    def validate_output_port_is_not_this_select_src_port(self, mirror_row):
        if hasattr(mirror_row, 'select_src_port') and \
                hasattr(mirror_row, 'output_port') and \
                mirror_row.output_port[0] in mirror_row.select_src_port:
            details = "The output port cannot also be a select src port."
            raise ValidationError(error.VERIFICATION_FAILED, details)

    #
    # Validates that the output port is not also a select dst port.
    #
    def validate_output_port_is_not_this_select_dst_port(self, mirror_row):
        if hasattr(mirror_row, 'select_dst_port') and \
                hasattr(mirror_row, 'output_port') and \
                mirror_row.output_port[0] in mirror_row.select_dst_port:
            details = "The output port cannot also be a select dst port."
            raise ValidationError(error.VERIFICATION_FAILED, details)

    #
    # Validates that the output port and select ports are all system ports.
    #
    def validate_ports_are_system_ports(self, mirror_row):
        ports = []

        if hasattr(mirror_row, 'select_src_port'):
            ports.extend(mirror_row.select_src_port)

        if hasattr(mirror_row, 'select_dst_port'):
            ports.extend(mirror_row.select_dst_port)

        if hasattr(mirror_row, 'output_port'):
            ports.extend(mirror_row.output_port)

        for port in ports:
            if not hasattr(port, 'interfaces') or \
                    port.interfaces == []:
                details = "Port " + port.name + " must contain at " \
                    "least one interface."
                raise ValidationError(error.VERIFICATION_FAILED, details)

            for interface in port.interfaces:
                if hasattr(interface, 'type') and \
                        interface.type != "system":
                    details = "The mirror can only contain interfaces " + \
                        "of type system."
                    raise ValidationError(error.VERIFICATION_FAILED, details)

    #
    # Validates that the output-port UUID is not in any other
    # active=true mirror row select-src-port.
    #
    def validate_output_port_is_not_select_src_port(self, mirror_row,
                                                    other_mirror_row):
        if not hasattr(other_mirror_row, 'select_src_port'):
            return

        if not hasattr(mirror_row, 'output_port'):
            return

        if mirror_row.output_port[0] in other_mirror_row.select_src_port:
            details = "The output port cannot be a " + \
                "select src port of another active mirror row."
            raise ValidationError(error.VERIFICATION_FAILED, details)

    #
    # Validates that the output-port UUID is not in any other
    # active=true mirror row select-dst-port.
    #
    def validate_output_port_is_not_select_dst_port(self, mirror_row,
                                                    other_mirror_row):
        if not hasattr(other_mirror_row, 'select_dst_port'):
            return

        if not hasattr(mirror_row, 'output_port'):
            return

        if mirror_row.output_port[0] in other_mirror_row.select_dst_port:
            details = "The output port cannot be a " + \
                "select dst port of another active mirror row."
            raise ValidationError(error.VERIFICATION_FAILED, details)

    #
    # Validates that the output-port UUID is not in any other
    # active=true mirror row output-port column.
    #
    def validate_output_port_is_not_output_port(self, mirror_row,
                                                other_mirror_row):
        if not hasattr(mirror_row, 'output_port'):
            return

        if not hasattr(other_mirror_row, 'output_port'):
            return

        if other_mirror_row.output_port[0] == mirror_row.output_port[0]:
            details = "The output port cannot be an " + \
                "output port of another active mirror row."
            raise ValidationError(error.VERIFICATION_FAILED, details)

    #
    # Validates that the UUID(s) in the select-src-port column are not
    # in any other active=true row output-port column.
    #
    def validate_select_src_port_is_not_output_port(self, mirror_row,
                                                    other_mirror_row):
        if not hasattr(mirror_row, 'select_src_port'):
            return

        if not hasattr(other_mirror_row, 'output_port'):
            return

        if other_mirror_row.output_port[0] in mirror_row.select_src_port:
            details = "A select src port cannot be an " + \
                "output port of another active mirror row."
            raise ValidationError(error.VERIFICATION_FAILED, details)

    #
    # Validates that the UUID(s) in the select-dst-port column are not
    # in any other active=true row output-port column.
    #
    def validate_select_dst_port_is_not_output_port(self, mirror_row,
                                                    other_mirror_row):
        if not hasattr(mirror_row, 'select_dst_port'):
            return

        if not hasattr(other_mirror_row, 'output_port'):
            return

        if other_mirror_row.output_port[0] in mirror_row.select_dst_port:
            details = "A select dst port cannot be an " + \
                "output port of another active mirror row."
            raise ValidationError(error.VERIFICATION_FAILED, details)
