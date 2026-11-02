MITRE ATT&CK Technique T1110: Brute Force

Description:
Adversaries may use brute force techniques to gain access to accounts when
passwords are unknown or when password hashes are obtained. Without knowledge
of the password for an account, an adversary may systematically guess the
password using a repetitive or iterative mechanism.

Sub-techniques:
- T1110.001 Password Guessing: Systematically guessing passwords for known
  usernames, often using common or default password lists.
- T1110.002 Password Cracking: Attempting to recover plaintext passwords from
  a stored or captured hash.
- T1110.003 Password Spraying: Using a single common password (or small list)
  against many different accounts, to avoid account lockout thresholds
  triggered by many attempts against one account.
- T1110.004 Credential Stuffing: Using previously leaked username/password
  pairs (from other breaches) against a target service.

Common Indicators:
- A high number of authentication attempts from a single source IP to a
  single destination service/port within a short time window.
- Many failed login attempts against the same account or service.
- Rapid, repeated connections to authentication-related ports such as SSH
  (22), FTP (21), RDP (3389), SMB (445), Telnet (23), or database ports
  (1433, 3306), often with short flow durations consistent with automated,
  scripted login attempts rather than normal human-paced logins.
- Traffic from a single source targeting the SAME destination port
  repeatedly, as opposed to a port scan, which targets MANY different
  destination ports from one source.

Detection Guidance:
Defenders can detect brute-force activity by monitoring authentication logs
for a high volume of failed login attempts within a short period, especially
from a single source IP, and by monitoring network flow data for repeated,
rapid connection attempts to authentication-service ports. Rate-limiting,
account lockout policies, and multi-factor authentication are common
mitigations. Distinguishing brute-force traffic from a legitimate but
misconfigured client is important before taking action such as blocking a
source IP.

Relevant Mitigations:
- Account lockout policies after a threshold of failed attempts.
- Multi-factor authentication to reduce the impact of guessed credentials.
- Rate limiting or connection throttling on authentication services.
- Monitoring and alerting on abnormal authentication attempt volume.