/*
 * Copyright (c) 2016 Hewlett Packard Enterprise Development LP
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
 *
 *
 * This file contains the definition of data structures common to ACL API
 * between ASIC providers and platform-independent code.
 */
#ifndef OPS_CLS_ASIC_PLUGIN_H_
#define OPS_CLS_ASIC_PLUGIN_H_   1

#include <netinet/in.h>
#include <stdint.h>
#include "uuid.h"
#include "packets.h"
#include "ofproto/ofproto.h"

/** @def OPS_CLS_ASIC_PLUGIN_INTERFACE_NAME
 *  @brief ACL ASIC plugin name definition
 */
#define OPS_CLS_ASIC_PLUGIN_INTERFACE_NAME      "OPS_CLS_ASIC_PLUGIN"

/** @def OPS_CLS_ASIC_PLUGIN_INTERFACE_MAJOR
 *  @brief Plugin major version definition
 */
#define OPS_CLS_ASIC_PLUGIN_INTERFACE_MAJOR     1

/** @def ACL_ASIC_PLUGIN_INTERFACE_MINOR
 *  @brief Plugin minor version definition
 */
#define OPS_CLS_ASIC_PLUGIN_INTERFACE_MINOR     1

#define ACL_LOG_INGRESS_PORT   0x00000001 /**< Indicates the ingress_port_name field contains valid data */
#define ACL_LOG_EGRESS_PORT    0x00000002 /**< Indicates the egress_port field contains valid data */
#define ACL_LOG_INGRESS_VLAN   0x00000004 /**< Indicates the ingress_vlan field contains valid data */
#define ACL_LOG_EGRESS_VLAN    0x00000008 /**< Indicates the egress_vlan field contains valid data */
#define ACL_LOG_NODE           0x00000010 /**< Indicates the node field contains valid data */
#define ACL_LOG_IN_COS         0x00000020 /**< Indicates the in_cos field contains valid data */
#define ACL_LOG_ENTRY_NUM      0x00000040 /**< Indicates the entry_num field contains valid data */
#define ACL_LOG_LIST_TYPE      0x00000080 /**< Indicates the list_type field contains valid data */
#define ACL_LOG_LIST_NAME      0x00000100 /**< Indicates the list_name field contains valid data */
#define ACL_LOG_LIST_ID        0x00000200 /**< Indicates the list_id field contains valid data */

#define ACL_LOG_PORT_NAME_LEN 16 /**< Max length of a port name for ACL logging */

/* Data Structures */

/**
 * Classifier List Type Enumeration
 */
enum ops_cls_type
{
    OPS_CLS_ACL_INVALID = 0,
    OPS_CLS_ACL_V4,
    OPS_CLS_ACL_V6
};

struct acl_log_info {
    /**< Data needed from the ASIC */
    uint32_t    valid_fields; /**< Some ASICs may not provide all of the fields
                                in this struct. Bits in this member indicate
                                which other members of the struct actually have
                                valid values. The bit definitions are given by
                                the ACL_LOG_* defines. */
    uint32_t    ingress_port; /**< @deprecated */
    char        ingress_port_name[ACL_LOG_PORT_NAME_LEN + 1]; /**< The name of
                                the port that the packet ingresses on. */
    uint32_t    egress_port;  /**< The destination port (if available),
                                generally for unicast packets. */
    uint16_t    ingress_vlan; /**< The ID of the VLAN that the packet ingresses
                                on. */
    uint16_t    egress_vlan;  /**< The ID of the VLAN that the packet egresses
                                on. This will be different from the ingress VLAN
                                only for routed packets. */
    uint8_t     node;         /**< The node/ASIC number that received the
                                packet. */
    uint8_t     in_cos;       /**< The COS of the packet on ingress. */
    /**< Information about the ACE that the packet matched */
    uint32_t    entry_num;    /**< The entry number of the ACL that the packet
                                matched. Note that this is the index into the
                                list of ACE's rather than the ACE sequence
                                number that is exposed in the config. The PI
                                code is responsible for translating the
                                entry_num into a sequence number. */
    enum ops_cls_type list_type; /**< The ACL type, e.g., IPv4. */
    char        list_name[64 + 1]; /**< The name of the ACL. */
    struct uuid list_id;      /**< The UUID of the ACL. */
    /**< Packet data including the header */
    uint16_t    total_pkt_len;  /**< The size of the packet received */
    uint16_t    pkt_buffer_len; /**< The number of packet bytes in the data
                                    buffer */
    uint8_t     pkt_data[256]; /**< The beginning of the packet including the
                                 header. */
};

/**
 * Classifier List Application Direction Enumeration
 */
enum ops_cls_direction
{
    OPS_CLS_DIRECTION_INVALID = 0,
    OPS_CLS_DIRECTION_IN,
    OPS_CLS_DIRECTION_OUT
};

/**
 * Classifier List Application Interface Enumeration
 */
enum ops_cls_interface
{
    OPS_CLS_INTERFACE_INVALID = 0,
    OPS_CLS_INTERFACE_PORT,
    OPS_CLS_INTERFACE_VLAN,
    OPS_CLS_INTERFACE_TUNNEL
};

/**
 * Classifier List Application Interface flags
 */
#define OPS_CLS_INTERFACE_L3ONLY  0x00000001 /**< L3 only flag */

/**
 * Classifier List Application Interface struct.
 * Contains details about the interface on which
 * a classifier list is to be applied.
 */
struct ops_cls_interface_info
{
    enum ops_cls_interface       interface; /**< interface type*/
    uint32_t                     flags;  /**< bitwise-OR of interface flags */
};

/**
 * Classifier List Entry Match Field Valid Flags
 */

#define    OPS_CLS_SRC_IPADDR_VALID      0x00000001 /**< Indicates that the
                                                         source IP address is
                                                         valid */
#define    OPS_CLS_DEST_IPADDR_VALID     0x00000002 /**< Indicates that the
                                                         dest IP address is
                                                         valid */
#define    OPS_CLS_L4_SRC_PORT_VALID     0x00000004 /**< Indicates that the
                                                         source port is
                                                         valid */
#define    OPS_CLS_L4_DEST_PORT_VALID    0x00000008 /**< Indicates that the
                                                         dest port is
                                                         valid */
#define    OPS_CLS_PROTOCOL_VALID        0x00000010 /**< Indicates that the
                                                         protocol field is
                                                         set */
#define    OPS_CLS_TOS_VALID             0x00000020 /**< Indicates that the
                                                         ToS field is
                                                         set */
#define    OPS_CLS_TCP_FLAGS_VALID       0x00000040 /**< Indicates that the
                                                         TCP flags are set */
#define    OPS_CLS_TCP_ESTABLISHED       0x00000080 /**< Indicates that the
                                                         TCP established field is set */
#define    OPS_CLS_ICMP_CODE_VALID       0x00000100 /**< Indicates that the
                                                         ICMP code field is
                                                         set */
#define    OPS_CLS_ICMP_TYPE_VALID       0x00000200 /**< Indicates that the
                                                         ICMP type field is
                                                         set */
#define    OPS_CLS_VLAN_VALID            0x00000400 /**< Indicates that the
                                                         VLAN is set */
#define    OPS_CLS_DSCP_VALID            0x00000800 /**< Indicates that the
                                                         DSCP is set */
#define    OPS_CLS_SRC_MAC_VALID         0x00001000 /**< Indicates that the
                                                         source mac is
                                                         set */
#define    OPS_CLS_DST_MAC_VALID         0x00002000 /**< Indicates that the
                                                         dest mac is set */
#define    OPS_CLS_L2_COS_VALID          0x00004000 /**< Indicates that cos
                                                         is set */
#define    OPS_CLS_L2_ETHERTYPE_VALID    0x00008000 /**< Indicates that L2
                                                         ethertype is set */

/**
 * Classifier List Entry L4 Comparison operator
 */
enum ops_cls_L4_operator
{
    OPS_CLS_L4_PORT_OP_NONE = 0,
    OPS_CLS_L4_PORT_OP_EQ,
    OPS_CLS_L4_PORT_OP_NEQ,
    OPS_CLS_L4_PORT_OP_LT,
    OPS_CLS_L4_PORT_OP_GT,
    OPS_CLS_L4_PORT_OP_RANGE
};

/**
 * Classifier Address Family
 */
enum ops_cls_addr_family
{
    OPS_CLS_AF_UNSPEC    = 0,
    OPS_CLS_AF_INET      = AF_INET,
    OPS_CLS_AF_INET6     = AF_INET6
};

/**
 * Classifier List Entry Match Field Structure
 */
struct ops_cls_list_entry_match_fields
{
    uint32_t            entry_flags;        /**< bitwise-OR of match field
                                                 flags */
    union
    {
        struct in6_addr v6;
        struct in_addr  v4;
    } src_ip_address;                       /**< v4 or v6 address */
    union
    {
        struct in6_addr v6;
        struct in_addr  v4;
    } src_ip_address_mask;                  /**< v4 or v6 address */
    union
    {
        struct in6_addr v6;
        struct in_addr  v4;
    } dst_ip_address;                       /**< v4 or v6 address */
    union
    {
        struct in6_addr v6;
        struct in_addr  v4;
    } dst_ip_address_mask;                  /**< v4 or v6 address */

    enum ops_cls_addr_family  src_addr_family;    /**< address family */
    enum ops_cls_addr_family  dst_addr_family;    /**< address family */
    uint16_t            L4_src_port_min;    /**< Minimum TCP/UDP source port,
                                                 used as minimum parameter when op is range,
                                                 and only parameter when op is lt, gt, eq and neq */
    uint16_t            L4_src_port_max;    /**< Maximum TCP/UDP source port, used as
                                                 maximum value parameter when op is range */
    uint16_t            L4_dst_port_min;    /**< Minimum TCP/UDP destination port
                                                 used as minimum parameter when op is range,
                                                 and only parameter when op is lt, gt, eq and neq */
    uint16_t            L4_dst_port_max;    /**< Maximum TCP/UDP destination port
                                                 used as maximum value parameter when op is range */
    enum ops_cls_L4_operator     L4_src_port_op;     /**< eq, neq, lt, gt, range */
    enum ops_cls_L4_operator     L4_dst_port_op;     /**< eq, neq, lt, gt, range */
    uint8_t             protocol;           /**< IP protocol number, e.g. tcp=6, udp=17 */
    uint8_t             tos;                /**< IP Type of Service/DiffServ Code Point (DSCP) */
    uint8_t             tos_mask;           /**< Mask of ToS bits */
    uint8_t             icmp_type;          /**< ICMP Type */
    uint8_t             icmp_code;          /**< ICMP Code */
    uint8_t             tcp_flags;          /**< TCP flag bits */
    uint8_t             tcp_flags_mask;     /**< Mask of TCP flag bits */
    uint16_t            vlan;               /**< 802.1q VLAN ID */
    uint8_t             src_mac[ETH_ADDR_LEN];      /**< Source MAC Address */
    uint8_t             src_mac_mask[ETH_ADDR_LEN]; /**< Source MAC Address Mask */
    uint8_t             dst_mac[ETH_ADDR_LEN];      /**< Destination MAC Address */
    uint8_t             dst_mac_mask[ETH_ADDR_LEN]; /**< Destination MAC Address Mask */
    uint16_t            L2_ethertype;       /**< Ethertype */
    uint8_t             L2_cos;             /**< 802.1p Class of Service (CoS)/PCP */
};

/**
 * Classifier List Entry Action Flags
 */
#define  OPS_CLS_ACTION_PERMIT  0x00000001 /**< Permit action flag */
#define  OPS_CLS_ACTION_DENY    0x00000002 /**< Deny action flag   */
#define  OPS_CLS_ACTION_LOG     0x00000004 /**< Log action flag    */
#define  OPS_CLS_ACTION_COUNT   0x00000008 /**< Count action flag  */

/**
 * Classifier List Entry Action Structure
 */
struct ops_cls_list_entry_actions
{
    uint32_t         action_flags; /**< bitwise-OR of action flags */
    /* additional actions to be added later */
};

/**
 * Classifier List Entry Structure
 */
struct ops_cls_list_entry
{
    struct ops_cls_list_entry_match_fields   entry_fields;   /**< field(s)/value(s) to match */
    struct ops_cls_list_entry_actions        entry_actions;  /**< action(s) to take */
};

/**
 * Classifier List Structure
 */
struct ops_cls_list
{
    struct uuid                 list_id;        /**< uuid of classifier list in OVSDB */
    const char *                list_name;      /**< name of classifier list */
    enum ops_cls_type           list_type;      /**< type of classifier list - aclv4, aclv6, aclMac */
    struct ops_cls_list_entry   *entries;       /**< array of classifier list entries */
    uint16_t                    num_entries;    /**< number of entries in a classifier list */
};

/**
 * Classifier List status codes
 */
enum ops_cls_list_status_code
{
    OPS_CLS_STATUS_SUCCESS = 0,         /**< Success */

    /* PD status codes */
    OPS_CLS_STATUS_HW_INTERNAL_ERR,     /**< Internal error */
    OPS_CLS_STATUS_HW_MEMORY_ERR,       /**< Out of memory error */
    OPS_CLS_STATUS_HW_UNIT_ERR,         /**< Invalid unit error */
    OPS_CLS_STATUS_HW_PARAM_ERR,        /**< Invalid parameter error */
    OPS_CLS_STATUS_HW_EMPTY_ERR,        /**< Table empty error */
    OPS_CLS_STATUS_HW_FULL_ERR,         /**< Table full error */
    OPS_CLS_STATUS_HW_NOT_FOUND_ERR,    /**< Entry not found error */
    OPS_CLS_STATUS_HW_EXISTS_ERR,       /**< Entry exists error */
    OPS_CLS_STATUS_HW_TIMEOUT_ERR,      /**< Operation timed out error */
    OPS_CLS_STATUS_HW_BUSY_ERR,         /**< Operation still running error */
    OPS_CLS_STATUS_HW_FAIL_ERR,         /**< Operation failed error */
    OPS_CLS_STATUS_HW_DISABLED_ERR,     /**< Operation disabled error */
    OPS_CLS_STATUS_HW_BADID_ERR,        /**< Invalid identifier error */
    OPS_CLS_STATUS_HW_RESOURCE_ERR,     /**< No resource for operation error */
    OPS_CLS_STATUS_HW_CONFIG_ERR,       /**< Invalid configuration error */
    OPS_CLS_STATUS_HW_UNAVAIL_ERR,      /**< Feature unavailable error */
    OPS_CLS_STATUS_HW_INIT_ERR,         /**< Feature not initialized error */
    OPS_CLS_STATUS_HW_PORT_ERR,         /**< Invalid port error */
    OPS_CLS_STATUS_HW_UNKNOWN_ERR,      /**< Unknown error */
    OPS_CLS_STATUS_HW_UNSUPPORTED_ERR,  /**< Entry contains unsupported
                                                           parameter error */

    /* PI status codes */
    OPS_CLS_STATUS_LIST_PARSE_ERR,      /**< Failed to parse list error */

    /* This must be last entry */
    OPS_CLS_STATUS_MAX                  /**< Max status codes */
};

/**
 * Classifier Platform Dependent Status
 */
struct ops_cls_pd_status
{
    enum ops_cls_list_status_code    status_code; /**< Status of the classifier
                                                       feature operation such
                                                       as apply,remove,replace
                                                       on the interface (port,
                                                       vlan, etc) */
    uint16_t                         entry_id;    /**< First entry that
                                                       encountered an error,
                                                       0 based index into
                                                       array of entries as
                                                       created by user  */
};

/**
 * Classifier Platform Dependent List Status
 */
struct ops_cls_pd_list_status
{
    enum ops_cls_list_status_code    status_code; /**< Status of the classifier
                                                       feature list operations
                                                       such as list update,
                                                       stats get,clear,etc on
                                                       the interfaces that has
                                                       the feaure list applied
                                                       */
    uint16_t                         entry_id;    /**< First entry that
                                                       encountered an error,
                                                       0 based index into
                                                       array of entries as
                                                       created by user  */
    struct ofport                    *port;       /**< first interface on
                                                       which list operation
                                                       has failed */
};

/**
 * Classifier List statistics structure
 */
struct ops_cls_statistics
{
    bool            stats_enabled;
    uint64_t        hitcounts;       /* hitcounts from hw */
};


/**************************************************************************//**
 * Classifier Plugin Interface
 *
 * This is the Classifier plugin interface for use in the plugin extension
 * framework.
 *
 * Each provider plugin (e.g. opennsl, container, etc.) which wants to
 * support Classifier Lists will need to provide an implementation for
 * each of these signatures and add pointers to those implementations
 * in this interface instance. Each provider will also register Classifier
 * plugin extension using @see register_plugin_extension()
 *****************************************************************************/

struct ops_cls_plugin_interface {
    /**
     * API from switchd platform independent layer to platform dependent
     * layer to specify the switch interface on which a given Classifier
     * List is to be applied.
     *
     * All pointer arguments reference objects whose lifetimes are not
     * guaranteed to outlast this call. If you want to remember them for
     * later, you must make a copy.
     *
     * Success or failure is all or nothing.  Status must be
     * returned for the switch interface passed in pd_status  parameter.
     *
     * @param[in]   list            - classifier list to apply
     * @param[in]   ofproto         - ofproto of bridge containing
     *                                desired switch interface
     * @param[in]   aux             - opaque key to desired switch interface
     *                                used with ofproto to get
     *                                ofproto_bundle
     * @param[in]   interface_info  - interface information necessary for
     *                                programming hw (e.g. L3 only, port, vlan)
     * @param[in]   direction       - direction in which the list
     *                                should be applied
     * @param[out]  pd_status       - pointer to struct pre-allocated by
     *                                calling function
     * @retval      0               - if list successfully added to hw
     * @retval      !=0             - otherwise and update pd_status
     *
     */
    int (*ofproto_ops_cls_apply)(struct ops_cls_list           *list,
                                struct ofproto                 *ofproto,
                                void                           *aux,
                                struct ops_cls_interface_info  *interface_info,
                                enum ops_cls_direction         direction,
                                struct ops_cls_pd_status       *pd_status);


    /**
     * API from switchd platform independent layer to platform dependent layer
     * to specify the switch interface on which a given Classifier List is to
     * be removed
     *
     * All pointer arguments reference objects whose lifetimes are not
     * guaranteed to outlast this call. If you want to remember them for
     * later, you must make a copy.
     *
     * Success or failure is all or nothing.  Status must be
     * returned for the switch interface passed in pd_status parameter.
     *
     * @param[in]   list_id         - uuid of classifier list
     * @param[in]   list_name       - name of the classifier list
     * @param[in]   list_type       - classifier list type
     * @param[in]   ofproto         - ofproto of bridge containing
     *                                desired switch interface
     * @param[in]   aux             - opaque key to desired switch interface
     *                                used with ofproto to get
     *                                ofproto_bundle
     * @param[in]   interface_info  - interface information necessary for
     *                                programming hw (e.g. L3 only, port, vlan)
     * @param[in]   direction       - direction in which the list
     *                                should be removed
     * @param[out]  pd_status       - pointer to struct pre-allocated by
     *                                calling function
     * @retval      0               - if list successfully added to hw
     * @retval      !=0             - otherwise and updates
     *                                pd_status
     *
     */
    int (*ofproto_ops_cls_remove)(const struct uuid         *list_id,
                            const char                      *list_name,
                            enum ops_cls_type               list_type,
                            struct ofproto                  *ofproto,
                            void                            *aux,
                            struct ops_cls_interface_info   *interface_info,
                            enum ops_cls_direction          direction,
                            struct ops_cls_pd_status        *pd_status);


    /**
     * API from switchd platform independent layer to platform dependent layer
     * to specify the switch interface on which a given Classifier List is to
     * be replaced.
     *
     * All pointer arguments reference objects whose lifetimes are not
     * guaranteed to outlast this call. If you want to remember them for
     * later, you must make a copy.
     *
     * Success or failure is all or nothing.  If the new list cannot
     * be applied in hw then the original list must be re-installed.
     *
     * Status must be returned for the switch interface passed in pd_status
     * parameter.
     *
     * @param[in]   list_id_orig    - uuid of original classifier list
     * @param[in]   list_name_orig  - name of original classifier list
     * @param[in]   list_new        - new classifier list
     * @param[in]   ofproto         - ofproto of bridge containing
     *                                desired switch interface
     * @param[in]   aux             - opaque key to desired switch interface
     *                                used with ofproto to get
     *                                ofproto_bundle
     * @param[in]   interface_info  - interface information necessary for
     *                                programming hw (e.g. L3 only, port, vlan)
     * @param[in]   direction       - direction in which the list should
     *                                be replaced
     * @param[out]  pd_status       - pointer to struct pre-allocated by
     *                                calling function
     * @retval      0               - if list successfully added to hw
     * @retval      !=0             - otherwise and updates pd_status
     *
     */
    int (*ofproto_ops_cls_replace)(
                        const struct uuid               *list_id_orig,
                        const char                      *list_name_orig,
                        struct ops_cls_list             *list_new,
                        struct ofproto                  *ofproto,
                        void                            *aux,
                        struct ops_cls_interface_info   *interface_info,
                        enum ops_cls_direction          direction,
                        struct ops_cls_pd_status        *pd_status);


    /**
     * API to modify a Classifier List that is applied in hw
     * (e.g. the user has added entries to or removed entries from the
     * classifier list), all applications must succeed or fail atomically.
     *
     * All pointer arguments reference objects whose lifetimes are not
     * guaranteed to outlast this call. If you want to remember them for
     * later, you must make a copy.
     *
     * In the event of a modification failure, the expectation is that the
     * original version of the Classifier list will remain configured in hw.
     *
     * @param[in]  list            - pointer to classifier list info
     * @param[out] status          - pointer to strcut pre-allocated by calling
     *                               function
     * @retval     0               - if list successfully added to hw
     * @retval     !=0             - otherwise and updates status
     */
    int (*ofproto_ops_cls_list_update)(
                                struct ops_cls_list              *list,
                                struct ops_cls_pd_list_status    *status);


    /**
     * API to retrieve statistics for a given applied ACL on a given
     * classifier interface in a given direction.
     *
     * All pointer arguments reference objects whose lifetimes are not
     * guaranteed to outlast this call. If you want to remember them for
     * later, you must make a copy.
     *
     * @param[in]  list_id         - uuid of classifier list
     * @param[in]  list_name       - name of classifier list
     * @param[in]  list_type       - classifier list type
     * @param[in]   ofproto        - ofproto of bridge containing
     *                               desired switch interface
     * @param[in]   aux            - opaque key to desired switch interface
     *                               used with ofproto to get
     *                               ofproto_bundle
     * @param[in]  interface_info  - type of interface on which the list is
     *                               applied, port, vlan, l3 only port, etc.
     * @param[in]  direction       - direction in which the list is applied
     * @param[in]  statistics      - pointer to caller allocated array in
     *                               list priority order. array will be
     *                               initialized with 'statistics enabled'
     *                               flag set to false, entries with hitcounts
     *                               enabled will be updated with packet
     *                               hitcounts from hw and will set
     *                               'statistics enabled' flag to true.
     * @param[in]  num_entries     - number of entries in the statistics array
     * @param[out] status          - pointer to struct pre-allocated by calling
     *                               function
     * @retval     0               - if statistics successfully retrieved from
     *                               hw
     * @retval     !=0             - otherwise and updates status
     */
    int (*ofproto_ops_cls_statistics_get)(
                                const struct uuid              *list_id,
                                const char                     *list_name,
                                enum ops_cls_type              list_type,
                                struct ofproto                 *ofproto,
                                void                           *aux,
                                struct ops_cls_interface_info  *interface_info,
                                enum ops_cls_direction         direction,
                                struct ops_cls_statistics      *statistics,
                                int                            num_entries,
                                struct ops_cls_pd_list_status  *status);


    /**
     * API to clear statistics for a given applied ACL on a given
     * switch interface in a given direction.
     *
     * All pointer arguments reference objects whose lifetimes are not
     * guaranteed to outlast this call. If you want to remember them for
     * later, you must make a copy.
     *
     * @param[in]  list_id         - uuid of classifier list
     * @param[in]  list_name       - name of classifier list
     * @param[in]  list_type       - classifier list type
     * @param[in]  ofproto         - ofproto of bridge containing
     *                               desired switch interface
     * @param[in]  aux             - opaque key to desired switch interface
     *                               used with ofproto to get
     *                               ofproto_bundle
     * @param[in]  interface_info  - interface information necessary for
     *                               programming hw (e.g. L3 only, port, vlan)
     * @param[in]  direction       - direction in which the list is applied
     * @param[in]  ofproto         - interface on which the classifier list is
     *                               applied
     * @param[out] status          - pointer to struct pre-allocated
     *                               by calling function
     * @retval     0               - if statistics successfully retrieved from
     *                               hw
     * @retval     !=0             - otherwise and updates status
     */
    int (*ofproto_ops_cls_statistics_clear)(
                            const struct uuid               *list_id,
                            const char                      *list_name,
                            enum ops_cls_type               list_type,
                            struct ofproto                  *ofproto,
                            void                            *aux,
                            struct ops_cls_interface_info   *interface_info,
                            enum ops_cls_direction          direction,
                            struct ops_cls_pd_list_status   *status);


    /**
     * API to clear all statistics for all applied classifier lists of all
     * types in all directions.
     *
     * All pointer arguments reference objects whose lifetimes are not
     * guaranteed to outlast this call. If you want to remember them for
     * later, you must make a copy.
     *
     * @param[out] status          - pointer to struct pre-allocated by calling
     *                               function
     * @retval     0               - if statistics successfully cleared in hw
     * @retval     !=0             - otherwise and updates status
     */
    int (*ofproto_ops_cls_statistics_clear_all)(
                                        struct ops_cls_pd_list_status *status);

    /**
     * API to register the callback to log the packet that was copied to the
     * CPU as a result of ACL logging
     *
     * @param[in] callback_handler - pointer to the function provided by PI for
     *                               passing information about an ACL logging
     *                               packet
     * @retval OPS_OK              - if a non-NULL function pointer was passed
     * @retval OPS_FAIL            - if a NULL value was passed
     */
    int (*ofproto_ops_cls_acl_log_pkt_register_cb)(
                              void (*callback_handler)(struct acl_log_info *));
};
#endif /* OPS_CLS_ASIC_PLUGIN_H_ */
