# Quality of Service Feature Test Cases

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
    - Validate 'show running-config'
        - Does not show any qos trust info when qos trust is set to the factory-default
    - Validate 'show qos trust'
        - Displays the qos trust setting
    - Validate 'show qos trust default'
        - Shows the factory-default qos trust setting

2. **COS Map**
    - Validate 'show running-config'
        - Does not show any cos-map info when the cos-map is set to factory-default values
    - Validate 'show qos cos-map'
        - Displays all eight entries
    - Validate 'show qos cos-map default'
        - Shows the factory-default cos-map

3. **DSCP Map**
    - Validate 'show running-config'
        - Does not show any dscp-map info when the dscp-map is set to factory-default values
    - Validate 'show qos dscp-map'
        - Displays all eight entries
    - Validate 'show qos dscp-map default'
        - Shows the factory-default dscp-map

4. **Port Trust Override**
    - Validate 'show running-config'
        - Shows the port trust override, when it is set to the factory-default value.
        - Shows the port trust override, when it is not set to the factory-default value.
    - Validate 'show running-config interface'
        - Shows the port trust override, when it is set to the factory-default value.
        - Shows the port trust override, when it is not set to the factory-default value.
    - Validate 'show interface'
        - Shows the port trust override, when it is set to the factory-default value.
        - Shows the port trust override, when it is not set to the factory-default value.

5. **Port Trust None with DSCP Override**
    - Validate 'show running-config'
        - Shows the port dscp override
    - Validate 'show running-config interface'
        - Shows the port dscp override
    - Validate 'show interface'
        - Shows the port dscp override

6. **Queue Profile**
    - Validate 'show qos queue-profile p1' shows the settings for profile p1
    - Validate 'show qos queue-profile' with an illegal or missing name fails
    - Validate 'show qos queue-profile' shows all profiles
        - Check that an incomplete profile should be displayed as 'incomplete'
        - Check that an complete profile should be displayed as 'complete'
        - Check that an applied profile should be displayed as 'applied'
    - Validate 'show qos queue-profile factory-default' shows the factory-default profile

7. **Schedule Profile**
    - Validate 'show qos schedule-profile p1' shows the settings for profile p1
    - Validate 'show qos schedule-profile' with an illegal or missing name fails
    - Validate 'show qos schedule-profile' shows all profiles
        - Check that an incomplete profile should be displayed as 'incomplete'
        - Check that an complete profile should be displayed as 'complete'
        - Check that an applied profile should be displayed as 'applied'
    - Validate 'show qos schedule-profile factory-default' shows the factory-default profile

### Test Result Criteria
Configuration command succeed or fail as expected. Show command displays correct information.
