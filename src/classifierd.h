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

#ifndef _CLASSIFIERD_H_

#define _CLASSIFIERD_H_

/**
 * Initializes the connection to the OVSDB at db_path and create a db cache
 * for this daemon.
 *
 * @param[in]  db_path string representing OVSDB socket path
 *
 */
void classifierd_ovsdb_init(const char *db_path);

/**
 * Destroys the db cache for this daemon.
 */
void classifierd_ovsdb_exit(void);

/**
 * This function processes the batch of messages from OVSDB and
 * pushed any changes back to db
 */
void classifierd_run(void);

/**
 * Arranges for poll_block() to wake up when classifierd_run has
 * something to process or when activity occurs on transaction on
 * idl.
 */
void classifierd_wait(void);

/**
 * Displays the debug information from classifier daemon
 */
void classifierd_debug_dump(struct ds *ds, int argc, const char *argv[]);

#endif /* _CLASSIFIERD_H_ */
