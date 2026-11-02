"""
Aggregate DoS/flood detector — complements the port-scan and brute-force
rules. Flags a (source_ip, destination_ip) pair if the total NUMBER of
flow records towards that destination becomes abnormally high within a
short time window -- the signature of a volumetric flood.

NOTE: An earlier version also included a packets-per-second rate signal,
but this was found to produce false positives on ordinary short flows
(e.g. CDN/video traffic), because Flow Duration is floored at a very
small value for short flows in capture_v2.py, making the derived rate
unreliable regardless of byte volume. Volume/count-based detection over
a time window is more robust and is used here instead.
"""

import pandas as pd

FLOW_COUNT_THRESHOLD = 200


def detect_dos_flood(live_flows_path="dataset/live_flows.csv",
                      time_window_seconds=10,
                      flow_count_threshold=FLOW_COUNT_THRESHOLD):
    """
    Flags a (src_ip, dst_ip) pair if more than `flow_count_threshold`
    flow records towards that destination occur within
    `time_window_seconds` -- the signature of a volumetric flood.
    """
    df = pd.read_csv(live_flows_path)
    if df.empty:
        return pd.DataFrame()

    df = df.sort_values("timestamp")
    alerts = []

    for (src_ip, dst_ip), group in df.groupby(["src_ip", "dst_ip"]):
        group = group.sort_values("timestamp")
        timestamps = group["timestamp"].values

        start = 0
        for end in range(len(group)):
            while timestamps[end] - timestamps[start] > time_window_seconds:
                start += 1
            count_in_window = end - start + 1
            if count_in_window >= flow_count_threshold:
                alerts.append({
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                    "flow_count_in_window": int(count_in_window),
                    "window_start": float(timestamps[start]),
                    "window_end": float(timestamps[end]),
                    "detection_type": "DoS/Flood (aggregate rule)",
                })
                break

    return pd.DataFrame(alerts)


if __name__ == "__main__":
    alerts = detect_dos_flood()
    if alerts.empty:
        print("No DoS/flood patterns detected.")
    else:
        print(f"Detected {len(alerts)} likely DoS/flood source(s):\n")
        print(alerts.to_string(index=False))