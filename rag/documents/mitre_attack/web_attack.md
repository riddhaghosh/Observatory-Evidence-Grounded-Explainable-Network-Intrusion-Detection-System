# T1190 - Exploit Public-Facing Application (Web Attacks)

## Description
Adversaries target vulnerabilities in web applications exposed to the 
internet or internal network — for example SQL injection, cross-site 
scripting (XSS), or brute-forcing web login forms — to gain unauthorized 
access or execute code.

## Common Indicators
- Abnormal request patterns to a web server's port (typically 80/443), 
  including unusually large or malformed request sizes
- Repeated requests to the same endpoint with varying payloads (consistent 
  with automated vulnerability scanning or injection attempts)
- Sudden spikes in traffic to a specific URL path/port from a single source
- Response size or timing anomalies suggesting the server is 
  processing/erroring on crafted input

## Detection Guidance
- Flag flows with atypical packet size distributions or payload sizes 
  compared to normal traffic to that web service
- Monitor for a high rate of requests from a single source to the same 
  destination port in a short window
- Where available, cross-reference with web server/application logs for 
  HTTP status code anomalies (repeated 400/500 errors, SQL error strings, 
  etc.)

## Mitigation / Response
- Apply a Web Application Firewall (WAF) to filter known attack patterns
- Patch and keep the web application/framework up to date
- Validate and sanitize all user input server-side
- Review application logs for the flagged time window to confirm whether 
  the attempt succeeded