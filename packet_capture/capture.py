"""
Phase 21 — Live packet capture with Scapy.

This is a first pass: capture packets, group them into simple flows
(by source IP, dest IP, source port, dest port, protocol), and print
basic flow-level stats as each flow is observed. This does NOT yet
match the exact 78 CICIDS2017 features — that's the next step, once
this basic capture loop is confirmed working.
"""

from scapy.all import sniff, IP, TCP, UDP
from collections import defaultdict
import time

# Store simple in-progress flow stats keyed by 5-tuple
flows = defaultdict(lambda: {
    "packet_count": 0,
    "byte_count": 0,
    "start_time": None,
    "last_time": None,
    "syn_count": 0,
    "fin_count": 0,
})


def flow_key(pkt):
    """Build a 5-tuple key: (src_ip, dst_ip, src_port, dst_port, proto)."""
    if IP not in pkt:
        return None

    src_ip = pkt[IP].src
    dst_ip = pkt[IP].dst
    proto = pkt[IP].proto  # 6 = TCP, 17 = UDP

    src_port = dst_port = None
    if TCP in pkt:
        src_port = pkt[TCP].sport
        dst_port = pkt[TCP].dport
    elif UDP in pkt:
        src_port = pkt[UDP].sport
        dst_port = pkt[UDP].dport

    return (src_ip, dst_ip, src_port, dst_port, proto)


def process_packet(pkt):
    key = flow_key(pkt)
    if key is None:
        return  # not an IP packet, skip

    now = time.time()
    flow = flows[key]

    if flow["start_time"] is None:
        flow["start_time"] = now
    flow["last_time"] = now

    flow["packet_count"] += 1
    flow["byte_count"] += len(pkt)

    if TCP in pkt:
        flags = pkt[TCP].flags
        if flags & 0x02:  # SYN flag
            flow["syn_count"] += 1
        if flags & 0x01:  # FIN flag
            flow["fin_count"] += 1

    duration = flow["last_time"] - flow["start_time"]
    pps = flow["packet_count"] / duration if duration > 0 else flow["packet_count"]

    print(
        f"Flow {key} | packets={flow['packet_count']} "
        f"bytes={flow['byte_count']} duration={duration:.3f}s "
        f"pps={pps:.1f} SYN={flow['syn_count']} FIN={flow['fin_count']}"
    )


if __name__ == "__main__":
    print("Starting packet capture... (Ctrl+C to stop)")
    print("Run this as Administrator, or capture will fail silently.\n")
    sniff(prn=process_packet, store=False)