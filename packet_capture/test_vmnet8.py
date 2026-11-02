from scapy.all import sniff, IP

def show(pkt):
    if IP in pkt:
        print(f"{pkt[IP].src} -> {pkt[IP].dst}")

print("Sniffing on VMnet8 only...")
sniff(iface="VMware Network Adapter VMnet8", prn=show, store=False)