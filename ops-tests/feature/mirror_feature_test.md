# Mirror Feature Test Cases
<!-- version 3 -->

## Contents
- [Port Mirroring](#port-mirroring)


##  Port Mirroring

### Objective
Single interface mirror operations:
- All three source port directions: both, rx, & tx
- Add and remove sources

This is the shortest, least resource intensive feature test.  It would be good for frequently run CIT suites

### Requirements
The requirements for this test case are:
 - one OpenSwitch under test
 - three Unix hosts
 - one "Sniffer" host with packet inspection capability (e.g. scapy)
     - promiscuous mode receive only (no transmit)
     - inspect all traffic (e.g. source & destination addresses)

### Setup
#### Topology Diagram
```
             +-------+
             |Sniffer|
             +---^---+
                 |
                 |
+----------------4----------------+
|           OpenSwitch            |
+----1-----------2-----------3----+
     |           |           |
     |           |           |
+----v----+ +----v----+ +----v----+
|10.0.10.1| |10.0.10.2| |10.0.10.3|
|  Host1  | |  Host2  | |  Host3  |
+---------+ +---------+ +---------+
```

#### Test Setup
Configure OpenSwitch:
1. Two VLANs 100 & 200
2. VLAN 100 with 3 ports, one for each Host
    - Each Host is assigned address in the same subnet 10.10.10.X/24
3. VLAN 200 with one port to Sniffer node


### Description
This test verifies all mirror operations:
- each source direction
- adding and removing sources

1. **Verify Host connectivity**
    - Start host1 and host2 continual pinging host3 in the background, preferably using interval of 1/2 second
        - Host1: **```ping -i .5 10.0.10.3```**
        - Host2: **```ping -i .5 10.0.10.3```**
    - Verify no pings are lost between the hosts
    - Sniffer: Verify no ICMP packets are received by the Sniffer host
        - i.e. listen for 5 seconds without any ICMP packets received

2. **Verify Source Receive**
    - OpenSwitch: Activate mirror session FOO
        - mirror session FOO
        - source interface 1 rx
        - destination interface 4
        - no shutdown
        - end
    - Sniffer: Validate only ICMP packets with Host 1 source IP are received
        - i.e. listen for a minimum of 5 seconds

3. **Verify Source Transmit**
    - OpenSwitch: Alter active mirror session:
        - mirror session FOO
        - source interface 1 tx
        - end
    - Sniffer: Validate only ICMP packets with Host 3 source IP are received
        - i.e. listen for a minimum of 5 seconds

4. **Verify Source Bi-directional**
    - OpenSwitch: Alter active mirror session:
        - mirror session FOO
        - source interface 1 both
        - end
    - Sniffer: Validate only ICMP packets with Host 1 or 3 source IPs are received
        - i.e. listen for a minimum of 5 seconds

5. **Verify Two sources**
    - OpenSwitch: Alter active mirror session:
        - mirror session FOO
        - source interface 1 rx
        - source interface 2 rx
        - end
    - Sniffer: Validate only ICMP packets with Host 1 or 2 source IPs are received
        - i.e. listen for a minimum of 5 seconds

6. **Verify source removal**
    - OpenSwitch: Alter active mirror session:
        - mirror session FOO
        - no source interface 1 rx
        - end
    - Sniffer: Validate only ICMP packets with Host 2 source IP are received
        - i.e. listen for a minimum of 5 seconds

7. **Verify mirror shutdown**
    - OpenSwitch: Alter active mirror session:
        - no mirror session FOO
    - OpenSwitch: 'show mirror FOO' fails
    - Sniffer: Verify no ICMP packets are received by the Sniffer host
        - i.e. listen for 5 seconds without any ICMP packets received


### Test Result Criteria
The Sniffer node link is promiscuously capturing and inspecting all packets.  For each configuration, the source IP addresses of mirror packets are validated against what is expected.

#### Test Pass Criteria
Packets from correct Host are received by the Sniffer node

#### Test Fail Criteria
No unexpected packets are received by the Sniffer node
