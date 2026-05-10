# L2: Network Domain Core

## Legal and Ethical Disclaimer
**STRICT CONSENT REQUIREMENT:** This module utilizes raw sockets to perform deep packet inspection (`scapy.sniff`). Intercepting network traffic without explicit authorization is illegal. 
Execution requires the `NETWORK_MONITOR_CONSENT="true"` environment variable to be explicitly set. Bypassing this gate or running this module on networks without authorization is strictly prohibited.

## Implementation Status
- **v1 (Branch 1):** ARP Spoofing detection — **Operational**.
- **v2 (Branch 2):** SYN Scan detection — *Pending*.

## Architecture Overview
The network module operates as the L2 Domain Core within a Hexagonal Architecture. It passively sniffs traffic and dispatches detection events to L0 (SQLite) and L1 (Email Alerts).

```text
[Raw Sockets] --> (BPF Filter) --> start_sensor() 
                                        |
                                        v
                                 ArpDetector (L2)
                                        |
                                 (DetectionEvent)
                                        |
                             +----------+----------+
                             |                     |
                             v                     v
                     get_logger() (L0)    send_security_alert() (L1)
                     