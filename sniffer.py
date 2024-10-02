from scapy.all import *
from datetime import datetime

def packet_callback(packet):
    # Extract the timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Extract the IP layer (if present)
    if IP in packet:
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        proto = packet[IP].proto

        # Determine protocol name based on protocol number
        if proto == 1:
            protocol = "ICMP"
        elif proto == 6:
            protocol = "TCP"
        elif proto == 17:
            protocol = "UDP"
        else:
            protocol = "Other"

        print(f"Timestamp: {timestamp}")
        print(f"Source IP: {ip_src}")
        print(f"Destination IP: {ip_dst}")
        print(f"Protocol: {protocol}")

        # If the packet contains TCP/UDP layers, display payload data (if any)
        if Raw in packet:
            print(f"Payload: {packet[Raw].load}")
        print("-" * 50)

def start_sniffer(interface=None):
    print("Starting packet sniffer...")
    try:
        # Capture packets from the specified interface
        sniff(prn=packet_callback, iface=interface, store=False)
    except KeyboardInterrupt:
        print("\nPacket sniffer stopped.")
    except Exception as e:
        print(f"Error: {e}")

if __name__ == "__main__":
    # Specify the network interface (e.g., "eth0", "wlan0", etc.)
    interface = input("Enter the network interface to sniff (leave empty for default): ") or None

    start_sniffer(interface)
