"""
Aggregate/rate-based port scan detector — complements the per-flow ML model.

Per-flow classifiers struggle to detect port scans because each individual
probe (SYN + RST) looks like an ordinary short/failed connection. Real scan
detection requires looking at behavior ACROSS flows: the same source IP
contacting many distinct destination ports in a short time window.
"""

import pandas as pd

def detect_port_scans(live_flows_path="dataset/live_flows.csv", 
                       time_window_seconds=10, 
                       port_threshold=15):
    """
    Flags a source IP as a likely port scanner if it contacted more than
    `port_threshold` distinct destination ports within `time_window_seconds`.
    """
    df = pd.read_csv(live_flows_path)
    if df.empty:
        return pd.DataFrame()

    df = df.sort_values("timestamp")
    alerts = []

    for src_ip, group in df.groupby("src_ip"):
        group = group.sort_values("timestamp")
        timestamps = group["timestamp"].values
        ports = group["Destination Port"].values
        dst_ips = group["dst_ip"].values

        start = 0
        for end in range(len(group)):
            while timestamps[end] - timestamps[start] > time_window_seconds:
                start += 1
            window_ports = set(ports[start:end + 1])
            if len(window_ports) >= port_threshold:
                alerts.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ips[end],
                    "window_start": float(timestamps[start]),
                    "window_end": float(timestamps[end]),
                    "distinct_ports_contacted": len(window_ports),
                    "sample_ports": sorted(list(window_ports))[:10],
                    "detection_type": "PortScan (aggregate rule)",
                })
                break  # one alert per source IP is enough for now

    return pd.DataFrame(alerts)


if __name__ == "__main__":
    alerts = detect_port_scans()
    if alerts.empty:
        print("No port scan patterns detected.")
    else:
        print(f"Detected {len(alerts)} likely port-scanning source(s):\n")
        print(alerts.to_string(index=False))