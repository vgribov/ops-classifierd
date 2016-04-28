/*
 * (C) Copyright 2016 Hewlett Packard Enterprise Development LP
 *
 *   Licensed under the Apache License, Version 2.0 (the "License"); you may
 *   not use this file except in compliance with the License. You may obtain
 *   a copy of the License at
 *
 *        http://www.apache.org/licenses/LICENSE-2.0
 *
 *   Unless required by applicable law or agreed to in writing, software
 *   distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *   WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 *   License for the specific language governing permissions and limitations
 *   under the License.
 */

#include <stdio.h>
#include <getopt.h>
#include <stdlib.h>
#include <string.h>
#include <daemon.h>
#include <poll-loop.h>
#include <unixctl.h>
#include <fatal-signal.h>
#include <command-line.h>
#include <dirs.h>
#include <vswitch-idl.h>
#include <dynamic-string.h>
#include <openvswitch/vlog.h>

#include "classifierd.h"

VLOG_DEFINE_THIS_MODULE(ops_classifierd);

/** @ingroup ops-classifierd
 * @{ */


static void
usage(void)
{
    printf("%s: OpenSwitch classifier daemon\n"
           "usage: %s [OPTIONS] [DATABASE]\n"
           "where DATABASE is a socket on which ovsdb-server is listening\n"
           "      (default: \"unix:%s/db.sock\").\n",
           program_name, program_name, ovs_rundir());
    daemon_usage();
    vlog_usage();
    printf("\nOther options:\n"
           "  --unixctl=SOCKET        override default control socket name\n"
           "  -h, --help              display this help message\n");
    exit(EXIT_SUCCESS);
} /* usage */

static void
classifierd_unixctl_dump(struct unixctl_conn *conn, int argc,
                          const char *argv[], void *aux OVS_UNUSED)
{
    struct ds ds = DS_EMPTY_INITIALIZER;

    classifierd_debug_dump(&ds, argc, argv);

    unixctl_command_reply(conn, ds_cstr(&ds));
    ds_destroy(&ds);
} /* classifierd_unixctl_dump */

static void
classifierd_init(const char *db_path)
{
    /* Initialize IDL through a new connection to the DB. */
    classifierd_ovsdb_init(db_path);

    /* Register ovs-appctl commands for this daemon. */
    unixctl_command_register("ops-classifierd/dump", "[port_name]", 0, 1,
                                classifierd_unixctl_dump, NULL);

} /* classifierd_init */

static void
classifierd_exit(void)
{
    classifierd_ovsdb_exit();
} /* classifierd_exit */

static char *
parse_options(int argc, char *argv[], char **unixctl_pathp)
{
    enum {
        OPT_UNIXCTL = UCHAR_MAX + 1,
        VLOG_OPTION_ENUMS,
        DAEMON_OPTION_ENUMS,
    };
    static const struct option long_options[] = {
        {"help",        no_argument, NULL, 'h'},
        {"unixctl",     required_argument, NULL, OPT_UNIXCTL},
        DAEMON_LONG_OPTIONS,
        VLOG_LONG_OPTIONS,
        {NULL, 0, NULL, 0},
    };
    char *short_options = long_options_to_short_options(long_options);

    for (;;) {
        int c;

        c = getopt_long(argc, argv, short_options, long_options, NULL);
        if (c == -1) {
            break;
        }

        switch (c) {
        case 'h':
            usage();

        case OPT_UNIXCTL:
            *unixctl_pathp = optarg;
            break;

        VLOG_OPTION_HANDLERS
        DAEMON_OPTION_HANDLERS

        case '?':
            exit(EXIT_FAILURE);

        default:
            abort();
        }
    }
    free(short_options);

    argc -= optind;
    argv += optind;

    switch (argc) {
    case 0:
        return xasprintf("unix:%s/db.sock", ovs_rundir());

    case 1:
        return xstrdup(argv[0]);

    default:
        VLOG_FATAL("at most one non-option argument accepted; "
                   "use --help for usage");
    }
} /* parse_options */

static void
ops_classifierd_exit(struct unixctl_conn *conn, int argc OVS_UNUSED,
                  const char *argv[] OVS_UNUSED, void *exiting_)
{
    bool *exiting = exiting_;
    *exiting = true;
    unixctl_command_reply(conn, NULL);
} /* ops_classifierd_exit */

int
main(int argc, char *argv[])
{
    char *appctl_path = NULL;
    struct unixctl_server *appctl;
    char *ovsdb_sock;
    bool exiting;
    int retval;

    set_program_name(argv[0]);
    proctitle_init(argc, argv);
    fatal_ignore_sigpipe();

    /* Parse commandline args and get the name of the OVSDB socket. */
    ovsdb_sock = parse_options(argc, argv, &appctl_path);

    /* Initialize the metadata for the IDL cache. */
    ovsrec_init();

    /* Fork and return in child process; but don't notify parent of
     * startup completion yet. */
    daemonize_start();

    /* Create UDS connection for ovs-appctl. */
    retval = unixctl_server_create(appctl_path, &appctl);
    if (retval) {
        exit(EXIT_FAILURE);
    }

    /* Register the ovs-appctl "exit" command for this daemon. */
    unixctl_command_register("exit", "", 0, 0, ops_classifierd_exit, &exiting);

    /* Create the IDL cache of the dB at ovsdb_sock. */
    classifierd_init(ovsdb_sock);
    free(ovsdb_sock);

    /* Notify parent of startup completion. */
    daemonize_complete();

    /* Enable asynch log writes to disk. */
    vlog_enable_async();

    VLOG_INFO_ONCE("%s (OpenSwitch Classifier Daemon) started", program_name);

    exiting = false;
    while (!exiting) {
        classifierd_run();
        unixctl_server_run(appctl);
        classifierd_wait();
        unixctl_server_wait(appctl);
        if (exiting) {
            poll_immediate_wake();
        } else {
            poll_block();
        }
    }

    classifierd_exit();
    unixctl_server_destroy(appctl);

    return 0;
} /* main */
