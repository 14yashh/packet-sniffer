import socket
import os
from packet_models import IPv4Packet

# Automatically get the local machine's hostname, then translate it to an IP
hostname = socket.gethostname()
HOST = socket.gethostbyname(hostname)       # Your local IPv4 address


def main():
    # 1. Create the raw socket (IPv4, Raw Bytes, IP Protocol)
    sniffer = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)

    # 2. Bind the socket to your local machine on port 0
    sniffer.bind((HOST, 0))

    # 3. Include the IP headers in the captured data
    sniffer.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    # 4. Windows specific: Send IOCTL command to turn ON promiscuous mode to capture
    sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_ON)

    print(f"[*] Sniffer started on {HOST}. Listening for traffic...")

    try:
        while True:
            # Receive up to 65535 bytes of data
            raw_packet, addr = sniffer.recvfrom(65535)

            # Pass the raw bytes into our IPv4 class
            ip_packet = IPv4Packet(raw_packet)

            # Print the clean, structured data
            print(f"IPv4 -> Src: {ip_packet.src_ip:<15} Dest: {ip_packet.dest_ip:<15} Protocol: {ip_packet.protocol}")

    except KeyboardInterrupt:
        print("\n[*] Stopping sniffer...")

    finally:
        # 5. Turn OFF promiscuous mode before exiting
        sniffer.ioctl(socket.SIO_RCVALL, socket.RCVALL_OFF)

if __name__ == "__main__":
    main()