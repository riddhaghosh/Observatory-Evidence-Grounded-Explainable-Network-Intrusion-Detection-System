"""
Phase 22 — Live capture computing the reduced 19-feature set,
writing completed flows to dataset/live_flows.csv for the dashboard to read.

Runs ONE sniff() thread per interface (Wi-Fi, Loopback, VMnet1, VMnet8)
because passing multiple interfaces to a single sniff() call is unreliable
on Windows/Npcap. All threads share the same flow-tracking state.

FIX (earlier): Flow Duration was previously floored at 1e-6 seconds, which let
very short flows (e.g. 1-2 packets landing within the same timestamp tick)
compute artificial rates of 1,000,000+ packets/sec -- not a real flood,
just a division-by-near-zero artifact. The floor is now 0.001s (1ms), a more
physically realistic minimum.

FIX (this version): Long-lived idle-but-not-silent flows (loopback/VMware
keep-alives that never go fully idle) could run for hours before ever being
flushed, producing an out-of-range Flow Duration. Combined with the old
positional csv.writer, a short/malformed row would silently misalign columns
on read-back. Fixed by:
  1. Adding MAX_FLOW_DURATION to force-flush any flow after 60s regardless
     of idle state.
  2. Switching to csv.DictWriter with fixed fieldnames, so a row with a
     missing/extra key raises an error instead of writing misaligned columns.
"""

from scapy.all import sniff, IP, TCP, UDP, IFACES
import threading
import time
import csv
import os
import numpy as np

OUTPUT_FILE = "dataset/live_flows.csv"
FLOW_TIMEOUT = 5
MAX_FLOW_DURATION = 60  # force-flush any flow still active after 60s, even if not idle
MIN_DURATION_SECONDS = 0.001  # 1ms floor -- was 1e-6, which caused rate artifacts

FEATURE_COLUMNS = [
    "Destination Port", "Flow Duration",
    "Total Length of Fwd Packets", "Total Length of Bwd Packets",
    "Fwd Packet Length Max", "Fwd Packet Length Mean",
    "Bwd Packet Length Max", "Bwd Packet Length Std",
    "Max Packet Length", "Min Packet Length",
    "Packet Length Mean", "Packet Length Std",
    "Average Packet Size",
    "Init_Win_bytes_forward", "Init_Win_bytes_backward",
    "Flow Bytes/s", "Flow Packets/s",
    "FIN Flag Count", "SYN Flag Count",
]

ALL_FIELDNAMES = ["timestamp", "src_ip", "dst_ip"] + FEATURE_COLUMNS

flows = {}
flows_lock = threading.Lock()   # protect shared dict across threads


def find_interfaces():
    selected = []
    for iface in IFACES.values():
        name = iface.name or ""
        if "Loopback" in name:
            selected.append(name)
        elif "Wi-Fi" in name or "MediaTek" in name or "Wireless" in name:
            selected.append(name)
        elif "VMware" in name:
            selected.append(name)

    if not selected:
        print("WARNING: Could not auto-detect interfaces. Falling back to default.")
        return []

    print("Will sniff on interfaces (one thread each):")
    for s in selected:
        print(" -", s)
    return selected


def init_csv():
    if not os.path.exists(OUTPUT_FILE):
        with open(OUTPUT_FILE, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=ALL_FIELDNAMES)
            writer.writeheader()


def flow_key(pkt):
    if IP not in pkt:
        return None
    src_ip, dst_ip = pkt[IP].src, pkt[IP].dst
    proto = pkt[IP].proto
    sport = dport = None
    if TCP in pkt:
        sport, dport = pkt[TCP].sport, pkt[TCP].dport
    elif UDP in pkt:
        sport, dport = pkt[UDP].sport, pkt[UDP].dport
    else:
        return None

    endpoint_a = (src_ip, sport)
    endpoint_b = (dst_ip, dport)
    if endpoint_a <= endpoint_b:
        return (src_ip, dst_ip, sport, dport, proto)
    else:
        return (dst_ip, src_ip, dport, sport, proto)


def new_flow_state(dst_port, now):
    return {
        "dst_port": dst_port,
        "start_time": now,
        "last_time": now,
        "fwd_lengths": [],
        "bwd_lengths": [],
        "all_lengths": [],
        "syn_count": 0,
        "fin_count": 0,
        "init_win_fwd": None,
        "init_win_bwd": None,
        "src_ip_first": None,
        "dst_ip_first": None,
        "dst_port_first": None,
    }


def write_flow_to_csv(key, flow):
    _, _, sport, dport, proto = key
    duration = max(flow["last_time"] - flow["start_time"], MIN_DURATION_SECONDS)

    fwd = flow["fwd_lengths"] or [0]
    bwd = flow["bwd_lengths"] or [0]
    all_len = flow["all_lengths"] or [0]

    total_fwd_bytes = sum(fwd)
    total_bwd_bytes = sum(bwd)
    total_packets = len(all_len)

    src_ip = flow["src_ip_first"]
    dst_ip = flow["dst_ip_first"]
    reported_dst_port = flow["dst_port_first"] if flow["dst_port_first"] is not None else dport

    row = {
        "timestamp": time.time(),
        "src_ip": src_ip,
        "dst_ip": dst_ip,
        "Destination Port": reported_dst_port,
        "Flow Duration": duration * 1_000_000,
        "Total Length of Fwd Packets": total_fwd_bytes,
        "Total Length of Bwd Packets": total_bwd_bytes,
        "Fwd Packet Length Max": max(fwd),
        "Fwd Packet Length Mean": np.mean(fwd),
        "Bwd Packet Length Max": max(bwd),
        "Bwd Packet Length Std": np.std(bwd),
        "Max Packet Length": max(all_len),
        "Min Packet Length": min(all_len),
        "Packet Length Mean": np.mean(all_len),
        "Packet Length Std": np.std(all_len),
        "Average Packet Size": np.mean(all_len),
        "Init_Win_bytes_forward": flow["init_win_fwd"] or 0,
        "Init_Win_bytes_backward": flow["init_win_bwd"] or 0,
        "Flow Bytes/s": (total_fwd_bytes + total_bwd_bytes) / duration,
        "Flow Packets/s": total_packets / duration,
        "FIN Flag Count": flow["fin_count"],
        "SYN Flag Count": flow["syn_count"],
    }

    with open(OUTPUT_FILE, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=ALL_FIELDNAMES)
        writer.writerow(row)  # raises ValueError if row is missing/has extra keys


def process_packet(pkt):
    key = flow_key(pkt)
    if key is None:
        return
    now = time.time()

    actual_src = pkt[IP].src
    actual_dst = pkt[IP].dst
    actual_dport = None
    if TCP in pkt:
        actual_dport = pkt[TCP].dport
    elif UDP in pkt:
        actual_dport = pkt[UDP].dport

    with flows_lock:
        if key not in flows:
            flows[key] = new_flow_state(actual_dport, now)
            flows[key]["src_ip_first"] = actual_src
            flows[key]["dst_ip_first"] = actual_dst
            flows[key]["dst_port_first"] = actual_dport

        flow = flows[key]
        flow["last_time"] = now

        length = len(pkt)
        flow["all_lengths"].append(length)

        if actual_src == flow["src_ip_first"]:
            flow["fwd_lengths"].append(length)
            if TCP in pkt and flow["init_win_fwd"] is None:
                flow["init_win_fwd"] = pkt[TCP].window
        else:
            flow["bwd_lengths"].append(length)
            if TCP in pkt and flow["init_win_bwd"] is None:
                flow["init_win_bwd"] = pkt[TCP].window

        if TCP in pkt:
            flags = pkt[TCP].flags
            if flags & 0x02:
                flow["syn_count"] += 1
            if flags & 0x01:
                flow["fin_count"] += 1
                write_flow_to_csv(key, flow)
                del flows[key]


def expire_stale_flows_loop():
    while True:
        time.sleep(2)
        now = time.time()
        with flows_lock:
            stale_keys = [
                k for k, f in flows.items()
                if (now - f["last_time"] > FLOW_TIMEOUT)
                or (now - f["start_time"] > MAX_FLOW_DURATION)
            ]
            for k in stale_keys:
                write_flow_to_csv(k, flows[k])
                del flows[k]


def packet_callback(pkt):
    process_packet(pkt)


def sniff_on_interface(iface_name):
    print(f"[thread started] sniffing on: {iface_name}")
    try:
        sniff(iface=iface_name, prn=packet_callback, store=False)
    except Exception as e:
        print(f"[thread error] {iface_name}: {e}")


if __name__ == "__main__":
    init_csv()
    ifaces_to_use = find_interfaces()

    if not ifaces_to_use:
        print("No interfaces found, exiting.")
        exit(1)

    print(f"\nLogging completed flows to {OUTPUT_FILE}")
    print("Run as Administrator. Ctrl+C to stop.\n")

    # One sniffing thread per interface
    threads = []
    for iface in ifaces_to_use:
        t = threading.Thread(target=sniff_on_interface, args=(iface,), daemon=True)
        t.start()
        threads.append(t)

    # Background thread to flush timed-out flows periodically
    expiry_thread = threading.Thread(target=expire_stale_flows_loop, daemon=True)
    expiry_thread.start()

    # Keep main thread alive
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\nStopping capture...")