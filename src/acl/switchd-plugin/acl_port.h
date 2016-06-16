/*
 * Copyright (C) 2016 Hewlett Packard Enterprise Development LP
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at:
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef __SWITCHD__PLUGIN__ACL_PORT_H__
#define __SWITCHD__PLUGIN__ACL_PORT_H__ 1

#include "hmap.h"
#include "uuid.h"
#include "acl.h"
#include "reconfigure-blocks.h"
#include "stats-blocks.h"
#include "acl_db_util.h"

/*************************************************************
 * acl_port_map structures
 *
 * This is stored in an arrary inside acl_port.
 *************************************************************/
struct acl_port_map {
    /* points back to my parent */
    struct acl_port *parent;

    /* Reference the meta-data about this acl_port_map: */
    /*    type, dir, ovsdb_colgrpdef */
    struct acl_db_util *acl_db;

    struct acl  *hw_acl; /* No ownership. Just borrowing pointer */
    struct ovs_list acl_node; /* For linking into hw_acl's acl_port_maps list. */
};

/*************************************************************
 * acl_port structures
 *
 * Structures to store ACL-specific information about each port
 *
 * There should be one of these for every 'struct port'
 * maintained by bridge.c.
 *
 *************************************************************/
struct acl_port {
    unsigned int       interface_flags; /*< Type of port, L3 only, L2 etc */
    struct port        *port;       /*< struct port */
    /* Hold all of my acl_port_map records internally, no need to
       allocate them separately. */
    struct acl_port_map port_map[ACL_CFG_NUM_PORT_TYPES];

    const struct ovsrec_port *ovsdb_row;
    unsigned int       delete_seqno; /* mark/sweep to identify deleted */
};

/**************************************************************************//**
 * This function looks up an acl_port based on name of the port
 *
 * @param[in] name   - name of the port to be found
 *
 * @returns  Pointer to acl_port if found
 *           NULL otherwise
 *****************************************************************************/
struct acl_port *acl_port_lookup (const char *name);

/************************************************************
 * Top level routine to check if a port's ACLs need to reconfigure
 ************************************************************/

/**************************************************************************//**
 * Reconfigure block callback for port delete operation.
 * This function is called when @see bridge_reconfigure() is called from
 * switchd. This callback will look for all ports that are about to be deleted
 * and unapply any applied ACLs from such ports
 *
 * @param[in] blk_params - Pointer to the block parameters structure
 *****************************************************************************/
void acl_callback_port_delete(struct blk_params *blk_params);

/**************************************************************************//**
 * Reconfigure block callback for port reconfigure operation.
 * This function is called when @see bridge_reconfigure() is called from
 * switchd. This callback will look for all ports that are modified
 * and reconfigure ACL on such such ports
 *
 * @param[in] blk_params - Pointer to the block parameters structure
 *****************************************************************************/
void acl_callback_port_reconfigure(struct blk_params *blk_params);

/**************************************************************************//**
 * Reconfigure block callback for Port Update operation.
 * This function is called when @see port_configure() is called from switchd.
 * At this point in time, switchd has finished configuring a port in PI and
 * PD data structures. During init sequence, if we encounter a port row
 * that has an ACL applied in the cfg column, that ACL will be applied to
 * the given port from here.
 *
 * @param[in] blk_params - Pointer to the block parameters structure
 *****************************************************************************/
void acl_callback_port_update(struct blk_params *blk_params);

/**************************************************************************//**
 * Statistics callback for every port in the bridge or vrf.
 * This function gets statistics for each port that has ACL applied
 * whenever @see run_stats_update() is called from switchd
 *
 * @param[in] sblk - Pointer to the stats block parameters structure
 * @param[in] blk_id - Stats block id to identify the operation
 *****************************************************************************/
void acl_callback_port_stats_get(struct stats_blk_params *sblk,
                                 enum stats_block_id blk_id);

/**************************************************************************//**
 * ACL port debug init
 *****************************************************************************/
void acl_port_debug_init(void);

/**************************************************************************//**
 * This function unapplies an ACL from all ports to which it is applied.
 * It is called when an ACL is deleted after applying to interfaces
 *
 * @param[in] acl - Pointer to the @see struct acl
 *****************************************************************************/
void acl_port_unapply_if_needed(struct acl *acl);

#endif  /* __SWITCHD__PLUGIN__ACL_PORT_H__ */
