# Quality of Service (QoS) High Level Design
<!-- Version 2 -->

The QoS features are implemented completely by the switching ASIC.  There is no dedicated QoS daemon.  Openswitch provides the means for the user to configure and monitor the ASIC capabilities.

## Contents
- [Introduction](#introduction)
- [Key design choices](#key-design-choices)
- [Logical View](#logical-view)
- [Structure View](#structure-view)
- [OVSDB-Schema](#ovsdb-schema)
- [Provider APIs](#provider-apis)
- [References](#references)


## Introduction

The primary purpose for QoS capabilities is to provide differentiated service to traffic - specifically some traffic is treated preferentially over other kinds of traffic.  Queuing and scheduling are the fundamental capabilities of switching ASIC pipelines that provide differentiated service to traffic.

Classification is a related ASIC capability that identifies packets that share common criteria, but it is queuing and scheduling that actually implement differentiated behavior.

### ASIC QoS Metadata
ASICs keep additional information about a packet called metadata.  Examples of meta-data are: arrival port and VLAN, the intended destination port, etc.  There are two pieces of packet metadata used by QoS to differentiate packets' handling and buffering:

**local-priority**
Generally one of 8 levels (0-7) although some vendors use a 64 level encoding.
Zero is the lowest priority.  The allowed maximum will vary per ASIC family.

**color**
One of three values (0-2) - commonly named green (0), yellow (1), and red (2).
These are mostly used with packets marked with Assured Forwarding code points.

###Initial metadata assignment (trust)
ASICs can be configured to inspect any VLAN priority tag or IP DSCP header of newly arrived packets to generate the initial values for packets' QoS metadata.  By default these fields are ignored and all arriving traffic get the same QoS metadata.  Administrators can configure the trust mode to 'cos' or 'dscp'  when the upstream sender is trusted to properly marks the packets' CoS or DSCP fields appropriately for the traffic type.

Two global maps, cos-map and dscp-map, are used for the initial metadata assignment.  Arriving packets' CoS priority or DSCP value is used as an index into the maps to retrieve the local-priority and color metadata assignment for each packet.

### Queueing
As packets await transmission they are kept in separate queues depending on their local-priority metadata.  Queues are numbered consecutively in priority order with zero being the lowest.  Queue profiles provide administrators the capability to configure the queue each local-priority will use.

### Scheduling
Scheduling is the process of selecting from which queue the next packet will be transmitted out the port to ensure the prioritized traffic is transmitted with the desired quality of service.


## Key design choices
A key principle is that QoS capabilities and scale vary across ASIC families and vendors.  The design has to be flexible and extensible.  For example, some ASICs are capable of applying  QOS settings for each interface, and some apply the same QOS settings for all interfaces across the system.  Also,factory defaults for the features are customized depending on the ASIC and product.

Any per-port configuration can be applied to a LAG and all member interfaces would be configured identically.   Therefore, the API uses bundles instead of netdev interfaces.  This makes it the ASIC-specific Provider responsibility to track membership changes.

The platform-independent part of SwitchD for QoS is implemented as a dynamically loaded feature plug-in with its own provider API (i.e. not additions to the existing bufmon, nedev, or ofproto provider APIs).  The exception is the code to periodically query the ASIC provider for per-queue statistics - it uses a pre-existing netdev-provider API.


## Logical view

```ditaa
         +---------+ +----------+
qos.yaml | Command | |   REST   |
+------+ |  Line   | |  Custom  |
| SYSD | |Interface| |Validators|
+--+---+ +----+----+ +----+-----+
   |          |           |
   v          |           |
+--+----------+-----------+-----+
|              OVSDB            |
+----------------+--------------+
                 |
  SWITCHD        |       plugins.yaml
+----------------+-------+------+
|                        | QoS  |
|                        |Plugin|
+-bufmon--netdev--ofproto--qos--+ Provider APIs
|           ASIC-Specific       |
|             Provider          |
+-------------------------------+
|            ASIC SDK           |
+----------------+--------------+
                 |
       ASIC      |
      +----------+----------+
      |CoS Map              |
      |DSCP Map             +
   ~~>]~~~~~~~~\   /~~Queues[~~>
   ~~>]~~~~~~~~~[X]~~~Queues[~~>
   ~~>]~~~~~~~~/   \~~Queues[~~>
      +---------------------+
```

### SYSD and qos.yaml
Upon boot, SYSD reads the product's qos.yaml file to populate factory (hardware) default rows in several tables if they are not already present:
- System
    - qos_config with trust mode
    - qos_status key with factory default trust mode
- QoS_CoS_Map_Entry
    - Eight rows with default local_priority and color configuration
    - hw_config{} map also has keys that contain the factory default values
- QoS_DSCP_Map_Entry
    - Sixty four rows with default local_priority and color configuration
    - hw_config{} map also has keys that contain the factory default values
- QoS and Queue
    - Add two QoS rows for the default and factory-default schedule profiles.  The default profile can be modified by the customer, while factory-default is never modified or deleted.
        - The factory-default row has its hw_config boolean set to true.  This is used by the REST custom validator to prevent delete or modification operation on the row.
    - Add children Queue rows for the default and factory-default profiles
        - The factory-default Queue child rows have their hw_config boolean set to true. This is used by the REST custom validator to prevent delete or modification operation on the row.
- Q_Profile and Q_Profile_Entry
    - Two Q_Profile rows for the default and factory-default queue profiles.  The default profile can be modified by the customer, while factory-default is never modified or deleted.
        - The factory-default row has its hw_config boolean set to true.  This is used by the REST custom validator to prevent delete or modification operation on the row.
    - Add children Q_Profile_Entry rows for the default and factory-default profiles
        - The factory-default Q_Profile_Entry child rows have their hw_config boolean set to true. This is used by the REST custom validator to prevent delete or modification operation on the row.

Some of columns are category status and/or marked immutable so the factory default values are always available to CLI, REST, and QoS Plugin.

### Command Line Interface
Implements the global and interface configuration commands, and all the qos show commands.  There also extensions to the show running-config and show interface commands.

### REST Custom Validators
There are two types of custom validators:
- Check transactions against the same acceptance rules as CLI changes
    - Name or description strings have only the allowed characters
    - No modifications to applied queue or schedule profiles
    - The queues of a schedule profile have the proper algorithms
        - All queues have same algorithm with the exception of the highest, which may be strict.
    - The same queues are present in both queue and schedule profiles
- Prevent deletion or modification of factory (hw) default key values or rows

### SWITCHD
#### Configuration changes
The code to handle configuration notifications and API is implemented as a dynamically loaded feature plug-in.

When SwitchD spawns, its plug-in infra will load all plugins listed in plugins.yaml, including QoS plug-in.  During QoS Plug-in initialization it will:
-  Call the SwitchD plug-in infra to find the ASIC-Specific Provider QoS APIs and verifies their version is supported by the QOS plug-in
-  Register with SwitchD plug-in infra for callbacks:
    - Bridge reconfigure initialization
    - Bridge reconfigure ports
    - VRF reconfigure ports
    - Bridge feature reconfiguration complete
    - VRF feature reconfiguration complete (reconfigure neighbors)
    - Periodic statistics per bridge and VRF

When a reconfiguration starts, system table QoS columns will be evaluated for changes and any API calls are made.  Then for each port add/change, port table QoS columns will be evaluated for changes and any API calls are made for that port.

SwitchD periodically queries every interface (every 5 seconds by default) the provider queue statistics netdev-provider statistic API, dump_queue_stats(), and publishes the counts in the Interface row.

### ASIC-Specific Provider
These QoS APIs from the following headers must be implemented by every provider to support QoS:
- qos-asic-provider.h
    - qos_cos_map_set()
    - qos_dscp_map_set()
    - qos_port_config_set()
    - qos_apply_profile()
- netdev-provider.h
    - dump_queue_stats()

Most pre-existing netdev-provider QoS and Queue APIs are not used as they are more oriented to Linux qdisc and do not have the needed flexibility/extensiblity.  They are also per-interface without global QoS settings.

The QoS API follows a flexible & extensible pattern:
- providers must configure a capability globally but can choose to support configuring a capability per-port
    - when a bundle pointer is NULL, this means to configure a capability globally
- other_config key-value map included in every API
    - this allows custom parameters to be configured via REST and passed to the ASIC-specific provider

For example, the QoS CoS and DSCP Map APIs only support configuring a single global map.  Still a bundle pointer parameter is included to be forward compatible with ASICs that may implement CoS or DSCP maps per port.  Also, the other_config key-value hash map is a parameter.


## Structure View
The following repositories have QoS specific implementations:
```ditaa
     ops_cli                       ops_hw_config
    +----------------+            +-------------+
    |Profile contexts|            |qos.yaml     |
    +----------------+            |plugins.yaml |
                                  +-------------+

     ops_intfd                       ops_sysd
    +--------------+         +------------------------+
    |show interface|         |Publish factory defaults|
    +--------------+         +------------------------+

     ops_lacpd                          ops
    +--------------+              +-------------+
    |show interface|              |Schema       |
    +--------------+              |CLI Manuals  |
                                  +-------------+
      ops_classifierd/QOS
    +-----------------------+     ops_openvswitch
    | Command Lines         |    +----------------+
    |    show running_config|    |vswitch_idl.[ch]|
    | Component Tests       |    +----------------+
    | REST Custom Validators|
    | QoS SwitchD Plug_in   |       ops_switchd
    +-----------------------+     +-------------+
                                  |Plug_in infra|
                                  +-------------+
                            ops_switchd_container_plugin
                            ops_switchd_opennsl_plugin
                            ops_switchd_?????_plugin
                           +----------------------------+
                           |QoS API ASIC specific driver+-+
                           +----------------------------+ +-+
                             +----------------------------+ |
                               +----------------------------+
```
**ops**
This repository has the schema containing the QoS tables & columns and the VSI framework feature tests.  The conversion to the new TOX framework will occur after Dill PSI.

**ops-classifierd**
This repository houses several features, namely ACLs and QoS.  The various QoS subdirectories contain:
- Most command line (VTYSH) functions including the distributed component of 'show running-config' for QoS
    - The exception is the 'show interface' commands which are implmeneted in ops-intfd and ops-lacp.
- All REST Custom Validators
- CLI and REST Component tests
    - These are written to the existing VSI framework
    - Conversion to the new TOX framework will occur afer Dill PSI.
- QoS SwitchD plug-in

**ops-cli**
QoS additions of two context nodes for the queue & schedule profile configuration sub-commands.

**ops-hw-config**
This repository has the qos.yaml and plugins.yaml files for each target platform.

**ops-intfd**
QoS additions to the 'show interface' and 'show running-config interface' for ports.

**ops-lacpd**
QoS additions to the 'show interface' and 'show running-config interface' for LAGs.

**ops-openvswitch**
The OVSDB generated IDL library is stored in the lib subdirectory.

**ops-switchd**
The plug-in infrastructure is instructed, via the plugins.yaml file, to load the QoS Plug-in.  QoS plug-in will register for callbacks from the infrastructure for:
- Bridge initialization
    - One time IDL configuration
- Bridge reconfigure initialization
    - Call set_cos_map() and/or set_dscp_map() APIs for any CoS or DSCP Map changes, respectively.
    - Call apply_qos_profile() API for global-only profile changes
- Bridge reconfigure ports
    - Call set_port_qos_cfg() for the port's trust mode and dscp override configuration
    - Call apply_qos_profile() for the port's profile overrides
- VRF reconfigure ports
    - Call set_port_qos_cfg() for any changes to the port's trust mode or dscp override.
    - Call apply_qos_profile() for any changes to the port's profile overrides
- Bridge feature reconfiguration complete
    - For all bundles in the bridge (not already reconfigured):
        - Call set_port_qos_cfg() for any changes to the global trust mode
        - Call apply_qos_profile() for any changes to the global profiles
- VRF feature reconfiguration complete (reconfigure neighbors)
    - For all bundles in the bridge (not already reconfigured):
        - Call set_port_qos_cfg() for any changes to the global trust mode
        - Call apply_qos_profile() for any changes to the global profiles
- Periodic statistics per bridge and VRF

To assist ASIC-specific provider to ensure all members of a bundle (LAG) are programmed identically, most of the QoS API calls are performed **after** all LAG membership changes have been processed by bundle_set().  The QoS API calls made for each bridge/VRF reconfigured port are always performed even when no QoS configuration has changed so the ASIC-specific provider can program for any new LAG members.  The ASIC-specific provider should avoid programming the ASIC when no QoS change is needed.  Similarly, changes to global port trust and profiles are done at the end to ensure all LAG membership is current when QoS API calls arfe performed.

**ops-switchd-container-plugin**
QoS API stub functions were added.

**ops-switchd-opennsl-plugin**
QoS API functions are added to program the OpenNSL SDK.


## OVSDB-Schema
Six tables are added:
- **QoS_CoS_Map_Entry**
    - 8 row CoS Map table for use by Trust CoS mode.
- **QoS_DSCP_Map_Entry**
    - 64 row DSCP Map table for use by Trust DSCP mode.
- **Q_Profile** and **Q_Profile_Entry**
    - For queue profiles
    - There is a special 'factory-default' profile with the hw_default column set to true
        - It is written by SYSD upon boot if not already present
        - REST custom validators will not allow this profile or its entries from being modified or deleted
- **QoS** and **Queue**
    - For schedule profiles
    - There is a special 'factory-default' profile with the hw_default column set to true
        - It is written by SYSD upon boot if not already present
        - REST custom validators will not allow this profile or its entries from being modified or deleted

Extra columns are added to the the following tables:
- **System** for global or default configuration
    - qos & q_profile references to the default profiles
    - qos_config map has the key for the default trust mode
    - qos_status map has keys:
        - Factory default trust mode
        - Name of the last successfully applied default queue profile
        - Name of the last successfully applied default schedule profile
- **Port** for per-port configuration
    - qos & q_profile references to schedule & queue profile defintions
    - qos_config has keys:
        - Trust mode
        - DSCP override
        - (future) CoS override
    - qos_config has keys:
        - Name of the last successfully applied default queue profile
        - Name of the last successfully applied default schedule profile
- **Interface** for per-queue statistics
    - A map column per count keyed by queue number

```ditaa
 System
+----------------------------------------------------------------------------+
|qos|q_profile|dscp_map_entries[]|cos_map_entries[]|qos_config{}|qos_status{}|
+-+---+---------+------------------+-----------------------------------------+
  |   |         |                  |    QoS_CoS_Map_Entry
  |   |         |                  |   +--------------------------------------------------------+
  |   |         |                  +-->|code_point|local_priority|color|description|hw_default{}|
  |   |         |                  +-->|code_point|local_priority|color|description|hw_default{}|
  |   |         |                      +--------------------------------------------------------+
  |   |         |    QoS_DSCP_Map_Entry
  |   |         |   +----------------------------------------------------------------------------+
  |   |         +-->|code_point|local_priority|priority_code_point|color|description|hw_default{}|
  |   |         +-->|code_point|local_priority|priority_code_point|color|description|hw_default{}|
  |   |             +----------------------------------------------------------------------------+
  |   |              QoS "schedule-profile"
  |   |             +--------------------------------+
  +---------------->|name|queues{num,uuid}|hw_default|
      |   +-------->|name|queues{num,uuid}|hw_default|
      |   |         +--------+-----------------------+
      |   |                  |    Queue
      |   |              1:m |   +---------------------------+
      |   |                  +-->|algorithm|weight|hw_default|
      |   |                  +-->|algorithm|weight|hw_default|
      |   |                      +---------------------------+
      |   |          Q_Profile "queue-profile"
      |   |         +-------------------------------------------+
      +------------>|name|q_profile_entries{num,uuid}|hw_default|
          |   +---->|name|q_profile_entries{num,uuid}|hw_default|
          |   |     +------+------------------------------------+
          |   |            |    Q_Profile_Entry
          |   |        1:m |   +-----------------------------------------+
          |   |            +-->|local_priorities[]|description|hw_default|
          |   |            +-->|local_priorities[]|description|hw_default|
          |   |                +-----------------------------------------+
     Port |   |
        +-+---+---------------------------------+
        |qos|q_profile|qos_config{}|qos_status{}|
        +---------------------------------------+
     Interface
        +--------------------------------------------------------------------------+
        |queue_tx_packets{num,int}|queue_tx_bytes{num,int}|queue_tx_errors{num,int}|
        +--------------------------------------------------------------------------+
```

## Provider APIs

Thre are four new provider APIs and one pre-existing netdev API.

### QoS Configuration API
Four new APIs are declared in qos-asic-provider.h.  They are implemented as an optional extension API.  ASIC-Specific Provider plug-ins can choose not to include the entire API set, or only implement a subset of the functions.

```ditaa
int (*set_cos_map)(struct ofproto *ofproto,
                   void *aux,
                   const struct cos_map_settings *settings);
```
set_cos_map() configures one or more entries of the CoS Map table.  When the ofproto and/or aux pointers are NULL, the configuration is for the system default CoS Map table.  Currently, only setting the system default CoS Map table is supported.

EOPNOTSUPP is returned when the underlying ASIC cannot support the configuration.  EINVAL is returned when any parameter fails validation checks.

```ditaa
int (*set_dscp_map)(struct ofproto *ofproto,
                    void *aux,
                    const struct dscp_map_settings *settings);
```
set_dscp_map() configures one or more entries of the DSCP Map table.  When the ofproto and/or aux pointers are NULL, the configuration is for the system default DSCP Map table.  Currently, only setting the system default DSCP Map table is supported.

EOPNOTSUPP is returned when the underlying ASIC cannot support the configuration.  EINVAL is returned when any parameter fails validation checks.

```ditaa
int (*set_port_qos_cfg)(struct ofproto *ofproto,
                        void *aux,
                        const struct qos_port_settings *settings);
```
set_port_qos_cfg() configures per port trust mode and DSCP override settings. The configuration is for all the interface members of the bundle identified by the ofproto's struct port pointer passed by the aux parameter.  It is ASIC-specific provider responsibility to apply this configuration to any interface members subsequently added to the bundle.

EOPNOTSUPP is returned when the underlying ASIC cannot support the configuration.  EINVAL is returned when any parameter fails validation checks.

```ditaa
int (*apply_qos_profile)(struct ofproto *ofproto,
                         void *aux,
                         const struct schedule_profile_settings *s_settings,
                         const struct queue_profile_settings *q_settings);
```
apply_qos_profile() configures either global or per port queue or schedule profiles.

When the ofproto and/or aux pointers are NULL, the configuration is for the system default.  The both are valid, the configuration is for all the interface members of the bundle identified by the ofproto's struct port pointer passed by the aux parameter.  It is ASIC-specific provider responsibility to apply this configuration to any interface members subsequently added to the bundle.

The currently support combinations are:

|ofproto & aux|s_settings|q_settings|Operation|
|-------------|----------|----------|-----------|
|NULL|NULL|NULL|Invalid|
|NULL|Valid|NULL|Configure new global default schedule profile with existing global default queue profile|
|NULL|NULL|Valid|Configure new global default queue profile with existing global default schedule profile|
|NULL|Valid|Valid|Configure new global default queue and schedule profiles|
|Valid|NULL|NULL|Configure bundle with the global default queue and schedule profiles|
|Valid|Valid|NULL|Configure bundle with new schedule profile with existing global default queue profile|
<!-- Not currently supported
|Valid|NULL|Valid|Configure bundle with queue profile with existing global default schedule profile|
|Valid|Valid|Valid|Configure bundle with new global default queue and schedule profiles|
-->

EOPNOTSUPP is returned when the underlying ASIC cannot support the configuration.  EINVAL is returned when any parameter fails validation checks.

### Queue Statistics API
```ditaa
int (*get_queue_stats)(const struct netdev *netdev,
                       unsigned int queue_id,
                       struct netdev_queue_stats *stats);
```
The get_queue_stats() function in netdev-provider.h is called periodically for each system interface to publish the per-queue statistics into the corresponding interface table row map columns:
-  tx_packets = number of packets successfully transmitted from the queue
-  tx_bytes = sum of the L2 byte lengths (excluding framing) of packet successfully transmitted from the queue
-  tx_errors = number of packets that were either unable to be queued (tail dropped), discarded, or were unsuccessfully transmitted from the queue


Caller supplies netdev_queue_stats buffer for the ASIC-Specific Provider to fill.  Any unsupported counts shall be returned with all one bits (UINT64_MAX).

'queue_id' start at zero.  Return EINVAL when 'queue_id' is greater than or equal to the number of supported queues.


## References

* [IEEE 802.1Q-2014](http://www.ieee802.org/1/pages/802.1Q-2014.html) *Bridges and Bridged Networks*
* [IETF RFC 791](https://tools.ietf.org/html/rfc791) *Internet Protocol Specification*
* [IETF RFC 2460](https://tools.ietf.org/html/rfc2460) *Internet Protocol, Version 6 (IPv6) Specification*
* [IETF RFC 2474](https://tools.ietf.org/html/rfc2474) *Definition of the Differentiated Services Field (DS Field) in the IPv4 and IPv6 Headers*
    * [IETF RFC 2475](https://tools.ietf.org/html/rfc2475) *An Architecture for Differentiated Services*
    * [IETF RFC 2497](https://tools.ietf.org/html/rfc2497) *Assured Forwarding PHB Group*
    * [IETF RFC 3246](https://tools.ietf.org/html/rfc3246) *An Expedited Forwarding PHB (Per-Hop Behavior)*
* [IETF RFC 3260](https://tools.ietf.org/html/rfc3260) *New Terminology and Clarifications for Diffserv*
