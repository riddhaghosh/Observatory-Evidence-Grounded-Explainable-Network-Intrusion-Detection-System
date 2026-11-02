"""
Aggregate brute-force detector — complements the per-flow ML model and the
port-scan detector. Flags a source IP if it makes an unusually high number
of connection attempts to the SAME destination port within a short time
window (classic brute-force / repeated-login-attempt pattern), as opposed
to the port-scan detector which looks for many DIFFERENT ports.

Refinement: restricted to known authentication-service ports by default
(SSH, FTP, Telnet, RDP, SMB, databases, etc.) and to short, low-data flows,
since legitimate high-frequency traffic (DNS lookups, HTTPS connections)
can otherwise trigger false positives under a naive "N attempts in T
seconds" rule. Pass custom_ports to widen coverage (e.g. testing a
non-standard port like 2222).
"""

import pandas as pd

# Common authentication/service ports commonly targeted by brute-force attacks
DEFAULT_BRUTEFORCE_PORTS = {
    21,    # FTP
    22,    # SSH
    23,    # Telnet
    25,    # SMTP
    110,   # POP3
    143,   # IMAP
    445,   # SMB
    1433,  # MSSQL
    3306,  # MySQL
    3389,  # RDP
    5900,  # VNC
}

# Flows shorter than this (microseconds, matching CICIDS scale) are treated
# as "fast" -- consistent with rapid, automated login attempts rather than
# a legitimate, data-carrying session.
MAX_FLOW_DURATION_FOR_BRUTEFORCE = 500_000  # 0.5 seconds


def detect_bruteforce(live_flows_path="dataset/live_flows.csv",
                       time_window_seconds=10,
                       attempt_threshold=15,
                       target_ports=None,
                       require_short_duration=True):
    """
    Flags a (source_ip, destination_port) pair if it saw more than
    `attempt_threshold` connection attempts within `time_window_seconds`.

    target_ports: set of ports to restrict detection to. Defaults to
    DEFAULT_BRUTEFORCE_PORTS. Pass an explicit set (e.g. {2222}) to test
    a custom/non-standard port, or pass an empty set/None with
    require_short_duration=False to disable filtering entirely (not
    recommended -- reproduces the noisy, unfiltered behavior).
    """
    df = pd.read_csv(live_flows_path)
    if df.empty:
        return pd.DataFrame()

    if target_ports is None:
        target_ports = DEFAULT_BRUTEFORCE_PORTS

    if target_ports:
        df = df[df["Destination Port"].isin(target_ports)]

    if require_short_duration:
        df = df[df["Flow Duration"] <= MAX_FLOW_DURATION_FOR_BRUTEFORCE]

    if df.empty:
        return pd.DataFrame()

    df = df.sort_values("timestamp")
    alerts = []

    for (src_ip, dst_port), group in df.groupby(["src_ip", "Destination Port"]):
        group = group.sort_values("timestamp")
        timestamps = group["timestamp"].values
        dst_ips = group["dst_ip"].values

        start = 0
        for end in range(len(group)):
            while timestamps[end] - timestamps[start] > time_window_seconds:
                start += 1
            attempts_in_window = end - start + 1
            if attempts_in_window >= attempt_threshold:
                alerts.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ips[end],
                    "dst_port": int(dst_port),
                    "window_start": float(timestamps[start]),
                    "window_end": float(timestamps[end]),
                    "attempts_in_window": int(attempts_in_window),
                    "detection_type": "Brute-force (aggregate rule)",
                })
                break  # one alert per (src_ip, dst_port) pair is enough

    return pd.DataFrame(alerts)


if __name__ == "__main__":
    print("=== Default (known auth ports only) ===")
    alerts = detect_bruteforce()
    if alerts.empty:
        print("No brute-force patterns detected on standard auth ports.")
    else:
        print(f"Detected {len(alerts)} likely brute-force attempt(s):\n")
        print(alerts.to_string(index=False))

    print("\n=== Custom test: including port 2222 (this session's test service) ===")
    alerts_custom = detect_bruteforce(target_ports=DEFAULT_BRUTEFORCE_PORTS | {2222})
    if alerts_custom.empty:
        print("No brute-force patterns detected.")
    else:
        print(f"Detected {len(alerts_custom)} likely brute-force attempt(s):\n")
        print(alerts_custom.to_string(index=False))