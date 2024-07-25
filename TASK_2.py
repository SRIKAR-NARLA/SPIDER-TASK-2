from scapy.all import sniff, rdpcap, IP, TCP, UDP, ICMP, ARP
from datetime import datetime

def packet_analysis(packet):
    packet_type = "Unknown"
    details = []

    if packet.haslayer(ARP):
        packet_type = "ARP"

    elif packet.haslayer(IP):
        ip = packet.getlayer(IP)
        src_ip = ip.src
        dst_ip = ip.dst
        protocol = ip.proto

        details.append(f"Source IP: {src_ip}")
        details.append(f"Destination IP: {dst_ip}")
        details.append(f"Protocol: {protocol}")

        if packet.haslayer(TCP):
            packet_type = "TCP"
            tcp = packet.getlayer(TCP)
            details.append(f"Source Port: {tcp.sport}")
            details.append(f"Destination Port: {tcp.dport}")
            details.append(f"Sequence Number: {tcp.seq}")
            details.append(f"Acknowledgment Number: {tcp.ack}")
            details.append(f"Flags: {tcp.flags}")

        elif packet.haslayer(UDP):
            packet_type = "UDP"
            udp = packet.getlayer(UDP)
            details.append(f"Source Port: {udp.sport}")
            details.append(f"Destination Port: {udp.dport}")
            details.append(f"Length: {udp.len}")

        elif packet.haslayer(ICMP):
            packet_type = "ICMP"
            icmp = packet.getlayer(ICMP)
            details.append(f"Type: {icmp.type}")
            details.append(f"Code: {icmp.code}")
            details.append(f"Checksum: {icmp.chksum}")

    print(f"\n--- Packet Captured ---")
    print(f"Time: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    print(f"Type: {packet_type}")
    print("Details:")
    for detail in details:
        print(f"    - {detail}")

def start_sniffing():
    print("Starting packet sniffing...")
    sniff(prn=packet_analysis, count=20)  

def sniff_from_file(filename):
    print(f"Reading packets from file: {filename}")
    packets = rdpcap(filename)
    for packet in packets:
        packet_analysis(packet)

if __name__ == "__main__":
    filename = "Net_capture.pcapng"  
    start_sniffing()
