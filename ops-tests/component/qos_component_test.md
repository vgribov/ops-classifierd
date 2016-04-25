# Quality of Service Component Test Cases

## Contents

## CLI

### Objective
Verify configuration validation checks by CLI

### Requirements
The requirements for this test case are:
 - container (docker) OpenSwitch under test
 - four interfaces
     - LAG100 with interfaces 3 & 4

### Setup
#### Topology Diagram
```
    ^  ^
    |  |
    |  |
+---1--2---+
|          |
|OpenSwitch|
|  LAG100  |
+---3--4---+
    |  |
    |  |
    v  v
```

#### Test Setup
### Description

1. **Global Trust**
    - Validate setting legal qos trust value succeeds
    - Validate setting illegal or missing qos trust fails
    - Validate 'no qos trust' restores qos trust to its factory default

2. **COS Map**
    - Validate setting legal cos-map values succeeds
    - Validate setting illegal or missing code-point fails
    - Validate setting illegal or missing local-priority fails
    - Validate setting illegal or missing color fails
    - Validate illegal or missing name fails
        - Illegal length
        - Unexpected characters
    - Validate 'no qos cos-map' restores an entry to its factory default

3. **DSCP Map**
    - Validate setting legal dscp-map values succeeds
    - Validate setting illegal or missing code-point fails
    - Validate setting illegal or missing local-priority fails
    - Validate setting illegal or missing color fails
    - Validate illegal or missing name fails
        - Illegal length
        - Unexpected characters
    - Validate 'no qos dscp-map' restores an entry to its factory default

4. **Port Trust Override**
    - Validate setting legal port trust override succeeds
    - Validate setting illegal or missing port trust override fails
    - Validate that qos trust cannot be configured on an interface that is a member of a LAG
    - Validate 'no qos trust' removes the port trust override
    - Validate that 'no qos trust' fails on an interface that is a member of a LAG

5. **Port Trust None with DSCP Override**
    - Validate setting legal port dscp override succeeds when port trust override is 'none'
    - Validate setting port dscp override fails when port trust override is empty
    - Validate setting port dscp override fails when port trust override is 'dscp'
    - Validate setting illegal or missing port trust override fails
    - Validate that port dscp override cannot be configured on an interface that is a member of a LAG
    - Validate 'no qos dscp' removes the port dscp override
    - Validate that 'no qos dscp' fails on an interface that is a member of a LAG

6. **Queue Profile**
    - Validate 'qos queue-profile p1' succeeds for profile p1
    - Validate 'qos queue-profile' fails with illegal or missing name
        - Illegal length
        - Unexpected characters
    - Validate that 'qos queue-profile strict' fails
    - Validate 'qos queue-profile p1' fails when profile p1 is applied
    - Validate 'no qos queue-profile' fails with illegal or missing name
        - Illegal length
        - Unexpected characters
    - Validate that 'no qos queue-profile strict' fails
    - Validate 'no qos queue-profile p1' fails when profile p1 is applied
    - Validate 'name' command with legal queue name succeeds
    - Validate 'name' command with illegal or missing queue name fails
    - Validate 'name' command with illegal or missing queue number fails
    - Validate 'no name' command with legal queue name succeeds
    - Validate 'no name' command with illegal or missing queue name fails
    - Validate 'no name' command with illegal or missing queue number fails
    - Validate 'map' command with legal local priority succeeds
    - Validate 'map' command with illegal or missing local priority fails
    - Validate 'map' command with illegal or missing queue number fails
    - Validate 'no map' command with legal local priority succeeds
        - Validate removing a single local priority from a list of local priorities for a queue num
            - e.g. 'no map queue 1 local-priority 2'
        - Validate clearing all local priorities for a queue num
            - e.g. 'no map queue 1'
    - Validate 'no map' command with illegal or missing local priority fails
    - Validate 'no map' command with illegal or missing queue number fails

7. **Schedule Profile**
    - Validate 'qos schedule-profile p1' succeeds for profile p1
    - Validate 'qos schedule-profile' fails with illegal or missing name
        - Illegal length
        - Unexpected characters
    - Validate that 'qos schedule-profile strict' fails
    - Validate 'qos schedule-profile p1' fails when profile p1 is applied
    - Validate 'no qos schedule-profile' fails with illegal or missing name
        - Illegal length
        - Unexpected characters
    - Validate that 'no qos schedule-profile strict' fails
    - Validate 'no qos schedule-profile p1' fails when profile p1 is applied
    - Validate 'strict' command with legal queue number succeeds
    - Validate 'strict' command with illegal or missing queue number fails
    - Validate 'no strict' command with legal queue number succeeds
    - Validate 'no strict' command with illegal or missing queue number fails
    - Validate 'wrr' command with legal weight succeeds
    - Validate 'wrr' command with illegal or missing weight fails
    - Validate 'wrr' command with illegal or missing queue number fails
    - Validate 'no wrr' command with legal weight succeeds
    - Validate 'no wrr' command with illegal or missing weight fails
    - Validate 'no wrr' command with illegal or missing queue number fails

8. **Global Apply Queue Profile and Schedule Profile**
    - Validate 'apply qos' succeeds with valid queue profile and schedule profile
    - Validate 'apply qos' fails when the queue profile has fewer queues than the schedule profile
    - Validate 'apply qos' fails when the queue profile has more queues than the schedule profile
    - Validate 'apply qos' with illegal or missing queue profile fails
    - Validate 'apply qos' with illegal or missing schedule profile fails
    - Validate 'apply qos' succeeds with valid queue profile and 'strict' schedule profile
    - Validate 'apply qos' succeeds with all queues 'strict'
    - Validate 'apply qos' succeeds with all queues 'wrr'
    - Validate 'apply qos' succeeds with all queues 'wrr' and the max queue 'strict'
    - Validate 'apply qos' fails with half of the queues 'wrr' and half of the queues 'strict'

9. **Port Schedule Profile Override**
    - Validate port override 'apply qos' succeeds with valid schedule profile
    - Validate port override 'apply qos' fails when the queue profile has fewer queues than the schedule profile
    - Validate port override 'apply qos' fails when the queue profile has more queues than the schedule profile
    - Validate port override 'apply qos' with illegal or missing schedule profile fails
    - Validate port override 'apply qos' succeeds with 'strict' schedule profile
    - Validate port override 'apply qos' succeeds with all queues 'strict'
    - Validate port override 'apply qos' succeeds with all queues 'wrr'
    - Validate port override 'apply qos' succeeds with all queues 'wrr' and the max queue 'strict'
    - Validate port override 'apply qos' fails with half of the queues 'wrr' and half of the queues 'strict'
    - Validate that port override 'apply qos' cannot be configured on an interface that is a member of a LAG
    - Validate 'no apply qos schedule-profile' removes the port schedule profile override
    - Validate that 'no apply qos schedule-profile' fails on an interface that is a member of a LAG

### Test Result Criteria
Configuration command succeed or fail as expected. Show command displays correct information.

## REST Custom Validators

### Objective
Verify configuration validation checks by REST

### Requirements
The requirements for this test case are:
 - container (docker) OpenSwitch under test
 - four interfaces
     - LAG100 with interfaces 3 & 4

### Setup
#### Topology Diagram
```
    ^  ^
    |  |
    |  |
+---1--2---+
|          |
|OpenSwitch|
|  LAG100  |
+---3--4---+
    |  |
    |  |
    v  v
```

#### Test Setup
### Description

1. **Port Table**
    - Validate Port PATCH succeeds with valid config
    - Validate Port PATCH fails when port cos override is set
    - Validate Port PATCH fails when port dscp override does not have port trust mode 'none'
    - Validate Port PATCH fails when the port queue profile override is not null
        - This is because port queue profile override is not currently supported
    - Validate Port PATCH fails when the port schedule profile override does not have the same algorithm on all queues
    - Validate Port PATCH fails when the port schedule profile override does not contain the same queues as the globally applied queue profile
    - Validate Port PUT succeeds with valid config
    - Validate Port PATCH fails when port cos override is set
    - Validate Port PUT fails when port dscp override does not have port trust mode 'none'
    - Validate Port PUT fails when the port queue profile override is not null
        - This is because port queue profile override is not currently supported
    - Validate Port PUT fails when the port schedule profile override does not have the same algorithm on all queues
    - Validate Port PUT fails when the port schedule profile override does not contain the same queues as the globally applied queue profile

2. **Q_Profile_Entry Table**
    - Validate Q_Profile_Entry POST succeeds with valid config
    - Validate Q_Profile_Entry POST fails when the entry is part of an applied profile
    - Validate Q_Profile_Entry POST fails when the entry is part of the factory-default profile
    - Validate Q_Profile_Entry POST fails when the name contains illegal characters
    - Validate Q_Profile_Entry PATCH succeeds with valid config
    - Validate Q_Profile_Entry PATCH fails when the entry is part of an applied profile
    - Validate Q_Profile_Entry PATCH fails when the entry is part of the factory-default profile
    - Validate Q_Profile_Entry PATCH fails when the name contains illegal characters
    - Validate Q_Profile_Entry PUT succeeds with valid config
    - Validate Q_Profile_Entry PUT fails when the entry is part of an applied profile
    - Validate Q_Profile_Entry PUT fails when the entry is part of the factory-default profile
    - Validate Q_Profile_Entry PUT fails when the name contains illegal characters
    - Validate Q_Profile_Entry DELETE succeeds with valid config
    - Validate Q_Profile_Entry DELETE fails when the entry is part of an applied profile
    - Validate Q_Profile_Entry DELETE fails when the entry is part of the factory-default profile

3. **Q_Profile Table**
    - Validate Q_Profile POST succeeds with valid config
    - Validate Q_Profile POST fails when the name contains illegal characters
    - Validate Q_Profile POST fails when the name is 'strict'
    - Validate Q_Profile PATCH succeeds with valid config
    - Validate Q_Profile PATCH fails when the profile is an applied profile
    - Validate Q_Profile PATCH fails when the profile is the factory-default profile
    - Validate Q_Profile PUT succeeds with valid config
    - Validate Q_Profile PUT fails when the profile is an applied profile
    - Validate Q_Profile PUT fails when the profile is the factory-default profile
    - Validate Q_Profile DELETE succeeds with valid config
    - Validate Q_Profile DELETE fails when the profile is an applied profile
    - Validate Q_Profile DELETE fails when the profile is the factory-default profile
    - Validate Q_Profile DELETE fails when the profile is the default profile

4. **QoS_COS_Map_Entry Table**
    - Validate QoS_COS_Map_Entry POST fails
        - QoS_COS_Map_Entry rows cannot be created
    - Validate QoS_COS_Map_Entry PATCH succeeds with valid config
    - Validate QoS_COS_Map_Entry PATCH fails when the description contains illegal characters
    - Validate QoS_COS_Map_Entry PUT succeeds with valid config
    - Validate QoS_COS_Map_Entry PUT fails when the description contains illegal characters
    - Validate QoS_COS_Map_Entry DELETE fails
        - QoS_COS_Map_Entry rows cannot be deleted

5. **QoS_DSCP_Map_Entry Table**
    - Validate QoS_DSCP_Map_Entry POST fails
        - QoS_DSCP_Map_Entry rows cannot be created
    - Validate QoS_DSCP_Map_Entry PATCH succeeds with valid config
    - Validate QoS_DSCP_Map_Entry PATCH fails when the description contains illegal characters
    - Validate QoS_DSCP_Map_Entry PUT succeeds with valid config
    - Validate QoS_DSCP_Map_Entry PUT fails when the description contains illegal characters
    - Validate QoS_DSCP_Map_Entry DELETE fails
        - QoS_DSCP_Map_Entry rows cannot be deleted

6. **QoS Table**
    - Validate QoS POST succeeds with valid config
    - Validate QoS POST fails when the name contains illegal characters
    - Validate QoS POST fails when the name is 'strict'
    - Validate QoS PATCH succeeds with valid config
    - Validate QoS PATCH fails when the profile is an applied profile
    - Validate QoS PATCH fails when the profile is the factory-default profile
    - Validate QoS PUT succeeds with valid config
    - Validate QoS PUT fails when the profile is an applied profile
    - Validate QoS PUT fails when the profile is the factory-default profile
    - Validate QoS DELETE succeeds with valid config
    - Validate QoS DELETE fails when the profile is an applied profile
    - Validate QoS DELETE fails when the profile is the factory-default profile
    - Validate QoS DELETE fails when the profile is the default profile

7. **Queue Table**
    - Validate Queue POST succeeds with valid config
    - Validate Queue POST fails when the entry is part of an applied profile
    - Validate Queue POST fails when the entry is part of the factory-default profile
    - Validate Queue POST fails when the algorithm is wrr and the weight is greater than the max weight
    - Validate Queue PATCH succeeds with valid config
    - Validate Queue PATCH fails when the entry is part of an applied profile
    - Validate Queue PATCH fails when the entry is part of the factory-default profile
    - Validate Queue PATCH fails when the algorithm is wrr and the weight is greater than the max weight
    - Validate Queue PUT succeeds with valid config
    - Validate Queue PUT fails when the entry is part of an applied profile
    - Validate Queue PUT fails when the entry is part of the factory-default profile
    - Validate Queue PUT fails when the algorithm is wrr and the weight is greater than the max weight
    - Validate Queue DELETE succeeds with valid config
    - Validate Queue DELETE fails when the entry is part of an applied profile
    - Validate Queue DELETE fails when the entry is part of the factory-default profile

8. **System Table**
    - Validate System PATCH succeeds with valid config
    - Validate System PATCH fails when global qos_trust is empty
    - Validate System PATCH fails when the global queue profile does not have all local priorities
    - Validate System PATCH fails when the global queue profile contains duplicate local priorities
    - Validate System PATCH fails when the global schedule profile does not have the same algorithm on all queues
    - Validate System PATCH fails when the global queue profile and the global schedule profile do not contain the same queues
    - Validate System PATCH fails when the global queue profile and any port schedule profile do not contain the same queues
    - Validate System PUT succeeds with valid config
    - Validate System PUT fails when global qos_trust is empty
    - Validate System PUT fails when the global queue profile does not have all local priorities
    - Validate System PUT fails when the global queue profile contains duplicate local priorities
    - Validate System PUT fails when the global schedule profile does not have the same algorithm on all queues
    - Validate System PUT fails when the global queue profile and the global schedule profile do not contain the same queues
    - Validate System PUT fails when the global queue profile and any port schedule profile do not contain the same queues

### Test Result Criteria
Configuration command succeed or fail as expected. Show command displays correct information.
