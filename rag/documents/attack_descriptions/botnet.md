# Botnet Activity

## Description
A botnet is a network of compromised hosts ("bots") controlled remotely by 
an attacker, typically through a Command-and-Control (C2) channel. Bots are 
commonly used to launch DDoS attacks, send spam, perform distributed 
scanning, or exfiltrate data. Botnet traffic in a flow-based dataset 
usually reflects the C2 communication pattern rather than the payload of 
whatever action the botnet is performing.

## Common Indicators
- Periodic, regularly-timed outbound connections to the same external 
  destination (beaconing behavior)
- Small, consistent packet sizes on C2 channels, since the traffic is 
  often just check-ins or commands rather than bulk data
- Connections to destinations with poor reputation or newly-registered 
  domains/IPs (not always visible in flow-only data, but relevant if IP/DNS 
  context is available)
- A group of internal hosts independently contacting the same external 
  destination in a similar pattern (suggests common infection)

## Detection Guidance
- Look for regular, low-variance timing between a host's outbound 
  connections to the same destination (beacon interval)
- Flag flows with unusually consistent packet size/timing profiles compared 
  to normal user-driven traffic
- Cross-reference destination IPs against known bad indicators where threat 
  intelligence feeds are available
- Watch for multiple internal hosts exhibiting the same anomalous outbound 
  pattern, which points to a common compromise rather than isolated 
  misconfiguration

## Mitigation / Response
- Isolate suspected infected hosts from the network pending investigation
- Block or sinkhole the suspected C2 destination
- Run endpoint scans on flagged hosts to identify and remove the malware
- Review other hosts for the same beaconing pattern, since botnets rarely 
  infect only one machine