from scapy.all import sniff, Raw
from scapy.layers.inet import IP, TCP, UDP
from datetime import datetime


def packet_callback(packet):
    print("\n" + "=" * 60)
    print("              PACKET CAPTURED")
    print("=" * 60)

    # Display current date and time
    print(f"Time           : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    if packet.haslayer(IP):
        print(f"Source IP      : {packet[IP].src}")
        print(f"Destination IP : {packet[IP].dst}")

        if packet.haslayer(TCP):
            protocol = "TCP"
        elif packet.haslayer(UDP):
            protocol = "UDP"
        else:
            protocol = "Other"

        print(f"Protocol       : {protocol}")
        print(f"Packet Length  : {len(packet)} bytes")

        # Display payload
        if packet.haslayer(Raw):
            print("Payload        :")
            print(packet[Raw].load[:100])
        else:
            print("Payload        : No readable payload")

    else:
        print("This packet does not contain an IP layer.")

    print("=" * 60)


print("=" * 60)
print("         BASIC NETWORK SNIFFER")
print("      Press CTRL + C to stop")
print("=" * 60)

sniff(prn=packet_callback, store=False)