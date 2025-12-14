A firewall is a critical network security component that inspects both inbound and outbound traffic and applies predefined security policies to determine whether data packets should be permitted or denied. For more than 25 years, firewalls have served as a foundational safeguard in network defense, creating a secure boundary between trusted internal environments and untrusted external networks, such as the public Internet. Firewalls can exist as hardware appliances, software solutions, or a combination of both. In this project, the firewall implementation is entirely software-based.

_Design Overview_

This project utilizes two separate configuration files to manage filtering logic: one for inbound rules (inbound_rules.ini) and another for outbound rules (outbound_rules.ini).

Inbound rules specify which types of traffic are allowed to reach the server, including permitted ports and source addresses. If no inbound rules are defined, all incoming traffic is blocked by default.

Outbound rules determine what types of traffic the server is allowed to send out, specifying permitted ports and destination addresses. In the absence of outbound rules, no outgoing traffic is allowed.

The firewall processes data packets using three possible actions: Accept, Decline, or Reject, each dictating how the packet is handled based on the rule evaluation.
