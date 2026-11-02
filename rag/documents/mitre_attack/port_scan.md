# T1046 - Network Service Discovery (Port Scanning)

## Description
Adversaries probe a target host or network to identify open ports, active 
services, and potentially exploitable software versions. This is typically 
a reconnaissance step performed before a more targeted attack, though it can 
also be part of legitimate security testing.

## Common Indicators
- A single source IP contacting an unusually high number of distinct 
  destination ports in a short time window
- Very short flow durations with minimal or no payload data transferred
- Sequential port access patterns (e.g. 1, 2, 3, 4...) or well-known port 
  lists being probed in sequence
- High packet rate relative to bytes transferred (many small packets)
- Incomplete TCP handshakes (SYN sent, no corresponding ACK/data) in the 
  case of SYN/stealth scans

## Detection Guidance
- Monitor for connections to an abnormal number of unique ports from one 
  source within a short time interval
- Flag flows with very low Flow Bytes/s but high Flow Packets/s
- Correlate repeated SYN flags without completed sessions
- Watch for scans across sequential or common service ports (21, 22, 23, 
  80, 443, 445, 3389, etc.)

## Mitigation / Response
- Investigate the source host for signs of compromise or unauthorized tool 
  use (e.g. nmap, masscan)
- Verify whether the scan was authorized (internal security testing, 
  vulnerability assessment) before escalating
- Apply network segmentation and firewall rules to limit which hosts can 
  reach sensitive services
- Deploy network intrusion detection/prevention systems (NIDS/NIPS) tuned 
  to flag scanning behavior