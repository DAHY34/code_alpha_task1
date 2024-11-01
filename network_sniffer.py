from scapy.all import sniff, IP, TCP, UDP
from datetime import datetime
sniff_date = datetime.now().strftime("%Y-%m-%d  %I:%M:%S")
def packet(packet):
    if packet.haslayer(IP):
        ipsrc = packet[IP].src
        ipdst = packet[IP].dst
        macsrc= packet.src
        macdst=packet.dst
        if packet.haslayer(TCP):
            print("===== TCP Packet =====")
            print(sniff_date)
            print(f"Source IP: {ipsrc}")
            print(f"Destination IP: {ipdst}")
            print(f"Source MAC: {macsrc}")
            print(f"Destination MAC: {macdst}")
            print(f"Source Port: {packet[TCP].sport}")
            print(f"Destination Port: {packet[TCP].dport}")
        elif packet.haslayer(UDP):
            print("===== UDP Packet =====")
            print(sniff_date)
            print(f"Source IP: {ipsrc}")
            print(f"Destination IP: {ipdst}")
            print(f"Source MAC: {macsrc}")
            print(f"Destination MAC: {macdst}")
            print(f"Source Port: {packet[UDP].sport}")
            print(f"Destination Port: {packet[UDP].dport}")
        print("=============================================")

print("STARTING SNIFFING...")
try:
    sniff(iface="Wi-Fi", prn=packet, store=False)
except KeyboardInterrupt:
    print("\nSniffer stopped.")

