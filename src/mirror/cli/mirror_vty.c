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

#include "vtysh/command.h"
#include "vtysh/vtysh.h"
#include "vtysh/vtysh_user.h"
#include "vswitch-idl.h"
#include "ovsdb-idl.h"
#include "smap.h"
#include "memory.h"
#include "openvswitch/vlog.h"
#include "openswitch-idl.h"
#include "vtysh/vtysh_ovsdb_if.h"
#include "vtysh/vtysh_ovsdb_config.h"
#include "mirror_cli.h"

VLOG_DEFINE_THIS_MODULE(vtysh_mirror_vty);

/**
 * Initialize cli.
 */
void cli_pre_init(void) {
   mirror_pre_init();
}

/**
 * Initialize cli.
 */
void cli_post_init(void) {

	vtysh_ret_val retval;
    mirror_vty_init();

    /* Register show running-configuration callback */
    retval = install_show_run_config_context(
                    e_vtysh_mirror_context,
                    &cli_show_mirror_running_config_callback,
                    NULL, NULL);
    if (e_vtysh_ok != retval) {
        vtysh_ovsdb_config_logmsg(VTYSH_OVSDB_CONFIG_ERR,
                    "unable to add mirror show running callback");
        assert(0);
        return;
    }
}
