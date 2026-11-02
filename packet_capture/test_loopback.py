from scapy.all import sniff, IP

def show(pkt):
    if IP in pkt:
        print(f"{pkt[IP].src} -> {pkt[IP].dst}")

print("Sniffing on loopback only... (Ctrl+C to stop)")
sniff(iface="Software Loopback Interface 1", prn=show, store=False)