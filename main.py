import argparse
import socket
import os
from packet_models import IPv4Packet, TCPSegment, UDPDatagram
from datetime import datetime

# Automatically get the local machine's hostname, then translate it to an IP
hostname = socket.gethostname()
HOST = socket.gethostbyname(hostname)       # Your local IPv4 address


def parse_args():
    parser = argparse.ArgumentParser(description="Windows IPv4/TCP/UDP packet sniffer")
    parser.add_argument("--proto", choices=["tcp", "udp"], help="Filter by protocol (tcp or udp)")
    parser.add_argument("--port", type=int, help="Filter by port number (matches src or dst)")
    return parser.parse_args()


def main():
    # 1. Parse CLI arguments for optional filters
    args = parse_args()

    # 2. Create the raw socket (IPv4, Raw Bytes, IP Protocol)
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    # 3. Bind the socket to your local machine on port 0
    sniffer.bind((HOST, 0))

    # 4. Include the IP headers in the captured data
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # 5. Windows specific: Send IOCTL command to turn ON promiscuous mode to capture
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print(f"[*] Sniffer started on {HOST}. Listening for traffic...")

    try:
        while True:
            # Receive up to 65535 bytes of data
            raw_packet, _ = sniffer.recvfrom(65535)

            # Pass the raw bytes into our IPv4 class
            ip_packet = IPv4Packet(raw_packet)

            timestamp = datetime.now().strftime("%H:%M:%S.%f")[:-3]

            # Check if the protocol is TCP (Protocol 6)
            if ip_packet.protocol == 6:
                # Skip if user filtered for UDP only
                if args.proto == "udp":
                    continue

                # Pass the IPv4 payload (which is the TCP packet) into our TCP class
                tcp = TCPSegment(ip_packet.payload)

                # Skip if user filtered for a port that doesn't match src or dst
                if args.port and args.port not in (tcp.src_port, tcp.dest_port):
                    continue

                # Figure out which flags are flipped on
                flags = []
                if tcp.flag_syn: flags.append("SYN")
                if tcp.flag_ack: flags.append("ACK")

                # If no SYN or ACK flags are set, we will just call it DATA for now
                flag_str = "+".join(flags) if flags else "DATA"

                # Print the clean TCP data with Ports and Flags
                print(f"[{timestamp}] TCP | {ip_packet.src_ip}:{tcp.src_port:<5} -> {ip_packet.dest_ip}:{tcp.dest_port:<5} | Flags: [{flag_str}]")

            # Check if the protocol is UDP (Protocol 17)
            elif ip_packet.protocol == 17:
                # Skip if user filtered for TCP only
                if args.proto == "tcp":
                    continue

                # Pass the IPv4 payload (which is the UDP datagram) into our UDP class
                udp = UDPDatagram(ip_packet.payload)

                # Skip if user filtered for a port that doesn't match src or dst
                if args.port and args.port not in (udp.src_port, udp.dest_port):
                    continue

                # Print the clean UDP data with Ports and Length
                print(f"[{timestamp}] UDP | {ip_packet.src_ip}:{udp.src_port:<5} -> {ip_packet.dest_ip}:{udp.dest_port:<5} | Len: {udp.length}")

    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer...")

    finally:
        # 6. Turn OFF promiscuous mode before exiting
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == "__main__":
    main()