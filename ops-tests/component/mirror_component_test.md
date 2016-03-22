# Mirror Component Test Cases
<!-- version 2 -->

## Contents
- [Verify CLI Configuration](#verify_cli_configuration)
- [Verify REST Configuration](#verify_rest_configuration)

## Verify CLI configuration

### Objective
Verify multiple mirrors can be configured, sharing source ports, as long as they do not share destination ports

### Requirements
The requirements for this test case are:
 - one OpenSwitch under test
 - four ports

### Setup
#### Topology Diagram
```
    ^  ^
    |  |
    |  |
+---1--2---+
|OpenSwitch|
+---3--4---+
    |  |
    |  |
    v  v
```

#### Test Setup

### Description

1. **Activate mirror session FOO succeeds**
    - CLI succeeds:
        - mirror session FOO
            - source interface 2 both
            - destination interface 3
            - no shutdown
            - end
    - 'show mirror' lists FOO as active
    - 'show mirror FOO' displays correct info
2. **Add second source to active mirror session FOO succeeds**
    - CLI succeeds:
        - mirror session FOO
            - source interface 1 rx
            - end
    - 'show mirror FOO' displays correct info
3. **Remove first source to active mirror session FOO succeeds**
Note: No form using a different direction (tx) than is configured (both)
    - CLI succeeds:
        - mirror session FOO
            - no source interface 2 tx
            - end
    - 'show mirror FOO' displays correct info (only source 1 remains)
4. **Activate mirror session BAR succeeds**
    - CLI succeeds:
        - mirror session BAR
            - source interface 2 tx
            - destination interface 4
            - no shutdown
            - end
    - 'show mirror' lists lists BAR as active
    - 'show mirror BAR' displays correct info
    - 'show running-config' displays both FOO and BAR sessions
5. **Attempt another session using existing destination fails**
    - CLI fails:
        - mirror session DUP
            - source interface 1 rx
            - destination interface 4
            - no shutdown
            - end
    - 'show mirror' lists DUP as inactive
    - 'show mirror DUP' displays correct info
    - CLI: clean up
        - no mirror session DUP
6. **Attempt another session with destination using existing RX source interface fails**
    - CLI fails:
        - mirror session DUP
            - source interface 2 rx
            - destination interface 1
            - no shutdown
            - end
    - CLI: clean up
        - no mirror session DUP
7. **Attempt another session with destination using existing TX source interface fails**
    - CLI fails:
        - mirror session DUP
            - source interface 1 rx
            - destination interface 2
            - no shutdown
            - end
    - CLI: clean up
        - no mirror session DUP
8. **Attempt another session with source RX using existing destination interface fails**
    - CLI fails:
        - mirror session DUP
            - source interface 3 rx
            - destination interface 4
            - no shutdown
            - end
    - CLI: clean up
        - no mirror session DUP
9. **Attempt another session with source TX using existing destination interface fails**
    - CLI fails:
        - mirror session DUP
            - source interface 3 tx
            - destination interface 4
            - no shutdown
            - end
    - CLI: clean up
        - no mirror session DUP
10. **Attempt another session with same source RX and destination interface fails**
    - CLI fails:
        - mirror session DUP
            - source interface 3 rx
            - destination interface 3
            - no shutdown
            - end
    - CLI: clean up
        - no mirror session DUP
11. **Attempt another session with same source TX and destination interface fails**
    - CLI fails:
        - mirror session DUP
            - source interface 3 tx
            - destination interface 3
            - no shutdown
            - end
    - CLI: clean up
        - no mirror session DUP
12. **Attempt another session without a destination interface fails**
    - CLI fails:
        - mirror session DUP
            - source interface 1 tx
            - no shutdown
            - end
    - CLI: clean up
        - no mirror session DUP
13. **Create inactive duplicate mirror session DUP succeeds**
    - CLI succeeds:
        - mirror session DUP
            - source interface 1 rx
            - destination interface 3
            - end
    - 'show mirror' lists DUP as inactive
14. **Deactivate mirror session FOO**
    - CLI succeeds:
        - mirror session FOO
            - shutdown
            - end
    - 'show mirror' lists FOO as inactive
15. **Activate mirror session DUP**
    - CLI succeeds:
        - mirror session DUP
            - no shutdown
            - end
    - 'show mirror' lists DUP as active
16. **Remove inactive mirror session FOO succeeds**
    - CLI succeeds:
        - no mirror session FOO
    - 'show mirror' omits FOO
    - 'show mirror FOO' (fails)
17. **Remove active mirror session DUP succeeds**
    - CLI succeeds:
        - no mirror session DUP
    - 'show mirror' omits DUP
    - 'show mirror DUP' fails
18. **Remove active mirror session BAR succeeds**
    - CLI succeeds:
        - no mirror session BAR
    - 'show mirror BAR' fails
    - 'show mirror' displays empty list
    - 'show running-config' contains no mirror sessions
19. **Create LAG succeeds**
    - CLI succeeds:
        - interface lag 100
            - no shutdown
        - interface 1
            - lag 100
        - interface 2
            - lag 100
20. **Mirror session with source LAG succeeds**
    - CLI succeeds:
        - mirror session FOO
            - source interface lag100 rx
            - destination interface 3
            - no shutdown
            - end
    - 'show mirror' lists FOO as active
    - 'show mirror FOO' display correct info
    - Remove mirror
        - no mirror session FOO
21. **Mirror session with destination LAG succeeds**
    - CLI succeeds:
        - mirror session BAR
            - source interface 3 rx
            - destination interface lag100
            - no shutdown
            - end
    - 'show mirror' lists BAR as active
    - 'show mirror BAR' display correct info
    - Remove mirror
        - no mirror session BAR

### Test Result Criteria
- Does '[no] shutdown' command succeed or fail as expected
- Does 'show mirror' list the name and status as expected
- Does 'show mirror <NAME>' display as expected


## Verify REST configuration

### Objective
Verify multiple mirrors can be configured, sharing source ports, as long as they do not share destination ports

### Requirements
The requirements for this test case are:
 - one OpenSwitch under test
 - four ports

### Setup

#### Topology Diagram
```
    ^  ^
    |  |
    |  |
+---1--2---+
|OpenSwitch|
+---3--4---+
    |  |
    |  |
    v  v
```

#### Test Setup

### Description

1. **Activate mirror session FOO succeeds**
    - POST succeeds
        - name=FOO
        - select-src-port=2
        - select-dst-port=2
        - output-port=3
        - active=true
    - Validate GET returns correct info and mirror_status:operation_state=active
2. **Add second source to active mirror session FOO succeeds**
    - PATCH Add to FOO
        - select-src-port=1
    - Validate GET returns correct info and mirror_status:operation_state=active
        -  select-src-port=[1,2]
        -  select-dst-port=[2]
        -  mirror_status:operation_state=active
3. **Remove first source from active mirror session FOO succeeds**
    - PATCH Remove FOO
        - select-src-port=[2]
        - select-dst-port=[2]
    - Validate GET returns:
        -  select-src-port=[1]
        -  mirror_status:operation_state=active
4. **Attempt another mirror session without an output-port fails**
    - POST fails
        - name=BAR
        - select-src-port=2
        - active=true
    - Validate GET fails (no entry found)
5. **Attempt another mirror session without any source ports fails**
    - POST fails
        - name=BAR
        - output-port=4
        - active=true
    - Validate GET fails (no entry found)
6. **Activate mirror session BAR succeeds**
    - POST succeeds
        - name=BAR
        - select-dst-port=1
        - output-port=4
        - active=true
    - Validate GET returns correct info and mirror_status:operation_state=active
7. **Replace source (1) with (2) in active mirror session BAR succeeds**
    - PUT BAR
        - name=BAR
        - select-dst-port=2
        - output-port=4
        - active=true
    - Validate GET returns mirror_status:operation_state=active
8. **Attempt another mirror session using existing destination fails**
    - POST fails
        - name=DUP
        - select-src-port=1
        - output-port=3
        - active=true
    - Validate GET fails (no entry found)
9. **Attempt another mirror session output-port using existing RX source interface fails**
    - POST fails
        - name=DUP
        - select-src-port=2
        - output-port=1
        - active=true
    - Validate GET fails (no entry found)
10. **Attempt another mirror session output-port using existing TX source interface fails**
    - POST fails
        - name=DUP
        - select-src-port=1
        - output-port=2
        - active=true
    - Validate GET fails (no entry found)
11. **Attempt another mirror session RX source using existing output-port fails**
    - POST fails
        - name=DUP
        - select-src-port=3
        - output-port=4
        - active=true
    - Validate GET fails (no entry found)
12. **Attempt another mirror session TX source using existing output-port fails**
    - POST fails
        - name=DUP
        - select-dst-port=3
        - output-port=4
        - active=true
    - Validate GET fails (no entry found)
13. **Attempt another mirror session with same RX source and output-port fails**
    - POST fails
        - name=DUP
        - select-src-port=4
        - output-port=4
        - active=true
    - Validate GET fails (no entry found)
14. **Attempt another mirror session with same TX source and output-port fails**
    - POST fails
        - name=DUP
        - select-dst-port=4
        - output-port=4
        - active=true
    - Validate GET fails (no entry found)
15. **Create inactive duplicate of mirror session succeeds**
    - POST succeeds
        - name=DUP
        - select-src-port=1
        - output-port=3
    - Validate GET returns mirror_status:operation_state not active
16. **Deactivate mirror session FOO **
    - PATCH Replace FOO
        - active=false
    - Validate GET returns mirror_status:operation_state not active
17. **Activate mirror session DUP succeeds**
    - PATCH Replace DUP
        - active=true
    - Validate GET returns mirror_status:operation_state=active
18. **Remove inactive mirror session FOO succeeds**
    - DELETE FOO succeeds
    - Validate GET fails (no entry found)
19. **Remove active mirror session DUP succeeds**
    - DELETE DUP succeeds
    - Validate GET fails (no entry found)
20. **Remove active mirror session BAR succeeds**
    - DELETE BAR succeeds
    - Validate GET fails (no entry found)

### Test Result Criteria
- POST, PATCH, or PUT returns the expected result
- GET returns the correct information
