# T1498 / T1499 - Network Denial of Service / Endpoint Denial of Service

## Description
Adversaries attempt to degrade or deny availability of a service or network 
resource by overwhelming it with traffic or exhausting a specific resource 
(bandwidth, connection table, CPU, memory). A Distributed Denial of Service 
(DDoS) uses multiple source hosts simultaneously to amplify the effect.

## Common Indicators
- A sharp, sustained spike in Flow Packets/s or Flow Bytes/s toward a 
  single destination
- Many short-lived flows from the same or many source IPs to one 
  destination IP/port
- High volume of SYN packets without completed handshakes (SYN flood 
  pattern)
- Abnormally low Flow Duration combined with high packet counts
- For DDoS specifically: the same destination receiving high-volume 
  traffic from many distinct source IPs at once

## Detection Guidance
- Set thresholds on packets/sec and bytes/sec per destination IP/port and 
  alert on sustained breaches
- Monitor SYN-to-ACK ratios; a persistently high ratio suggests SYN 
  flooding
- Track the number of distinct source IPs hitting a single destination in 
  a short window (helps distinguish DDoS from a single noisy host)
- Compare against a baseline of normal traffic volume for that 
  service/time-of-day

## Mitigation / Response
- Apply rate limiting or traffic shaping at the network edge
- Use SYN cookies or connection-rate limits to blunt SYN flood impact
- Engage upstream ISP or a DDoS scrubbing service for volumetric attacks 
  that exceed local capacity
- Isolate or blackhole clearly malicious source IPs once confirmed
- Review affected service logs to confirm whether the outage was 
  resource-exhaustion (DoS) versus a configuration/hardware fault