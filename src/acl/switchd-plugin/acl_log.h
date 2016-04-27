/* Copyright (C) 2016 Hewlett Packard Enterprise Development LP
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

#ifndef ACL_LOG_H
#define ACL_LOG_H

#include <stdint.h>
#include <linux/if_ether.h>

#include "ops-cls-asic-plugin.h"
#include "run-blocks.h"

/**
 * The main loop of some processes, such as the main loop of switchd, will wake
 * up when the value of a registered seq struct changes. The seq struct may be
 * referred to as a sequence number (it gets monotonically incremented) in
 * other parts of the code, but to avoid ambiguity, it is referred to as a seq
 * struct here.  This function returns a pointer to the seq struct that is used
 * for signaling that an ACL logging packet has been received and is ready for
 * processing.
 *
 * @return The ACL logging seq struct.
 *
 */
struct seq *acl_log_pktrx_seq_get(void);

/**
 * This function returns the information about a packet received for ACL
 * logging. The function will not return information for the same packet twice.
 * The information is returned by value to avoid potential problems with parts
 * of a struct being written while others are being read.
 *
 * @param pkt_info_to_get A pointer to an acl_log_info struct instance into
 *                        which information about a received packet will be
 *                        put.
 *
 */
void acl_log_pkt_data_get(struct acl_log_info *pkt_info_to_get);

/**
 * This function accepts information about a packet received for ACL
 * logging.
 *
 * @param new_pkt A pointer to available information about a received packet.
 *
 */
void acl_log_pkt_data_set(struct acl_log_info *new_pkt);

void acl_log_init(void);

void acl_log_run(struct run_blk_params *blk_params);

void acl_log_wait(struct run_blk_params *blk_params);

#endif /* ACL_LOG_H */
