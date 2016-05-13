# ACL Component Test Cases

## Contents
- [Verify ACL CLI](#verify_acl_cli)
- [Verify ACL on Port](#verify_acl_on_port)
- [Verify ACL Manageability](#verify_acl_manageability)

## Verify ACL CLI
-----------------
1. test acl create delete
    - create ACL with name contains one char, success
    - Create ACL with name contains apostrophe, success
    - Create ACL with name contains quotation mark, success
    - Create ACL with name contains at sign, success
    - Create ACL with name contains grave accent, success
    - Create ACL with name contains number sign, success
    - Create ACL with name contains percent, success
    - Create ACL with name contains greater than sign, success
    - Create ACL with name contains less than sign, success
    - Create ACL with name contains exclamation mark, success
    - Create ACL with name contains period, success
    - Create ACL with name contains brackets, success
    - Create ACL with name contains asterisk, success
    - Create ACL with name contains dollar sign, success
    - Create ACL with name contains semicolon, success
    - Create ACL with name contains colon, success
    - Create ACL with name contains question mark, failure
    - Create ACL with name contains caret, success
    - Create ACL with name contains braces, success
    - Create ACL with name contains plus sign, success
    - Create ACL with name contains hyphen, success
    - Create ACL with name contains equal sign, success
    - Create ACL with name contains tilde, success
    - Create ACL with name contains slash, success
    - Create ACL with name contains backslash, success
    - Create ACL with name contains pipe, success
    - Create ACL with name contains ampersand, success
    - Create ACL with name contains bracket, success
    - Create ACL with name contains dash, success
    - Create ACL with name contains underscore, success
    - Create ACL with name contains no char, failure
    - Create ACL with name contains space, failure
    - Create ACL with name greater than maximum allowed length, failure
    - Create ACL with name contains upper and lower case letters
    - Create ACL with the same name but different capitalization
    - Modify empty ACL with invalid resequence number, failure
    - Modify empty ACL with resequence number, failure due to ACL is empty
    - Delete ACL with non-existent name, failure
    - Delete ACL, success

2. test acl entry add remove replace
    - Add ACE with sctp eq parameter with invalid L4 source port, failure
    - Add ACE with sctp eq parameter with invalid L4 destination port, failure
    - Add ACE with sctp range parameter with L4 source and destination ports, minimum port number greater than maximum port number, failure
    - Add ACE with invalid prefix source and destination IP network addresses, failure
    - Add ACE with invalid subnet masking source and destination IP network addresses, failure
    - Add ACE with invalid numeric value of protocol (<0 or >256) with source and destination addresses, failure due to unknown commands
    - Add ACE with not supported numerical value of protocol (e.g. 0 for IPv6 HOPOPT), failure due to unknown commands
    - Add ACE with description, success
    - Add ACE with invalid char in description, failure
    - Add ACE with description length greater than maximum allowed length, failure
    - Add ACE, replace description, success
    - Add ACE, failure due to resources
    - Resequence ACEs, success
    - Resequence ACEs with high start and increment, failure due to invalid sequence number for some ACEs after resequencing
    - Replace ACE with non-existent sequence number, failure
    - Replace ACE, success
    - Remove ACE with non-existent sequence number, failure
    - Remove ACE, success

## Verify ACL on Port
-----------
3. test acl apply on port
    - Apply IPv4 ACL on one Port with switched traffic, success
    - Apply IPv4 ACL on one Port with routed traffic, success
    - Apply IPv4 ACL on one Port, with A.B.C.D source and destination IP hosts addresses, success
    - Apply IPv4 ACL on one Port, with A.B.C.D/M source and destination IP network addresses, success
    - Apply IPv4 ACL on one Port, with A.B.C.D/W.X.Y.Z source and destination IP network addresses, success
    - Apply IPv4 ACL on one Port, with any source and destination IP addresses, verify IPv6 traffic is allowed, verify non-IP (such as ARP) is allowed, verify other traffic is blocked, success
    - Apply IPv4 ACL on one Port, with protocol any with source and destination addresses, success
    - Apply IPv4 ACL on one Port, with sctp eq parameter with L4 source and destination ports, success
    - Apply IPv4 ACL on one Port, with sctp neq parameter with L4 source and destination ports, success
    - Apply IPv4 ACL on one Port, with sctp gt parameter with L4 source and destination ports, success
    - Apply IPv4 ACL on one Port, with sctp lt parameter with L4 source and destination ports, success
    - Apply IPv4 ACL on one Port, with sctp range parameter with L4 source and destination ports, success
    - Apply IPv4 ACL on one Port, with 6 (tcp) eq parameter with L4 source and destination ports, success
    - Apply IPv4 ACL on one Port, with 6 (tcp) range parameter with L4 source and destination ports, success
    - Apply IPv4 ACL on one Port, add Port to VLAN, failure
    - Apply IPv4 ACL on one Port, add Port to LAG, failure

4. test acl modify port
    - Apply IPv4 ACL on Port, add entry to list, success
    - Apply Ipv4 ACL on Port, delete entry from list, success
    - Apply IPv4 ACL on Port, replace existing entry in list, success
    - Apply IPv4 ACL on Port, add entry to list with count keyword, failure due to not enough count resources
    - Apply IPv4 ACL on Port, delete ACL from Port, success
    - Apply IPv4 ACL on one Port, add L4 entry to list, failure due to tcam resources
    - Apply IPv4 ACL on one Port, replace existing entry when tcam is full, failure

5. test acl multiple ports
    - Apply IPv4 ACL on multiple Ports, with any source and destination IP addresses, verify IPv6 traffic is allowed, verify non-IP (such as ARP) is allowed, verify other traffic is blocked, success on all Ports
    - Apply IPv4 ACL on multiple Ports, with protocol any with source and destination addresses, success on all Ports
    - Apply IPv4 ACL on multiple Ports, with tcp lt parameter with L4 source and destination ports, success on all Ports
    - Apply IPv4 ACL on multiple Ports, with tcp range parameter with L4 source and destination ports, success on all Ports
    - Apply IPv4 ACL on multiple Ports, with 17 (udp) gt parameter with L4 source and destination ports, success on all Ports
    - Apply IPv4 ACL on multiple Ports, with 17 (udp) range parameter with L4 source and destination ports, success on all Ports
    - Apply IPv4 ACL on multiple Ports, modify ACL, success on all Ports
    - Apply IPv4 ACL on multiple Ports, modify ACL, failure on some of the Ports
    - Apply multiple IPv4 ACLs on multiple Ports, success on all Ports
    - Apply multiple IPv4 ACLs on multiple Ports, failure on some of the Ports
    - Apply IPv4 ACL on multiple Ports, delete entry from list, success on all Ports
    - Apply IPv4 ACL on Port, replace existing entry in list, success on all Ports

## Verify ACL Manageability
-----------------
6. test acl show commands
    - Confirm ACL show commands, single ACL with multiple ACEs, success
    - Confirm ACL show commands, multiple ACLs with multiple ACEs spanning multiple pages, success