# T1110 - Brute Force

## Description
Adversaries attempt to guess valid credentials by systematically trying 
many username/password combinations against a service (SSH, FTP, RDP, web 
login forms, etc.), rather than exploiting a software vulnerability.

## Common Indicators
- Many repeated connection attempts from the same source IP to the same 
  destination port over a short period
- Short flow durations with small, similar-sized packets (consistent with 
  repeated login attempts)
- A high count of failed authentication attempts in application/service 
  logs correlated with the flow data
- Targeting of common authentication ports/services (22, 21, 3389, 445, or 
  HTTP/HTTPS login endpoints)

## Detection Guidance
- Count connection attempts per source IP per destination port per time 
  window; flag sources exceeding a reasonable threshold
- Correlate network-level repeated connections with authentication service 
  logs (failed login counts) when available
- Look for consistent inter-arrival timing between attempts, which can 
  indicate automated/scripted attempts rather than human typing

## Mitigation / Response
- Enforce account lockout or exponential backoff after repeated failed 
  attempts
- Require multi-factor authentication on exposed services
- Rate-limit or geofence authentication endpoints where appropriate
- Investigate and potentially block the source IP if the pattern is 
  clearly malicious rather than a misconfigured legitimate client