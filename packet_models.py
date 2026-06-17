import struct


class IPv4Packet:
    def __init__(self, raw_data):
        """
        Windows hands us the IPv4 packet starting at byte 0.
        The standard IPv4 header is 20 bytes long.

        Unpack format string: '! 8x B B 2x 4s 4s'
        !  = Network byte order (Ensures multi-byte numbers are read left-to-right)
        8x = Skip 8 bytes (Version, TOS, Total Length, ID, Flags)
        B  = 1 byte for TTL (Time to Live)
        B  = 1 byte for Protocol (6 = TCP, 17 = UDP)
        2x = Skip 2 bytes (Header Checksum)
        4s = 4 bytes for Source IP Address
        4s = 4 bytes for Destination IP Address
        """
        unpacked_data = struct.unpack('! 8x B B 2x 4s 4s', raw_data[:20])

        self.ttl = unpacked_data[0]
        self.protocol = unpacked_data[1]
        self.src_ip = self.format_ipv4(unpacked_data[2])
        self.dest_ip = self.format_ipv4(unpacked_data[3])

        # Everything after the 20-byte IP header is the payload (TCP, UDP, etc.)
        self.payload = raw_data[20:]

    def format_ipv4(self, addr):
        """
        Helper method to format raw bytes into standard IP string.
        Turns b'\xc0\xa8\x00\x68' into '192.168.0.104'
        """
        return '.'.join(map(str, addr))


class TCPSegment:
    def __init__(self, raw_data):
        """
        The standard TCP header is at least 20 bytes long.
        We unpack the first 14 bytes to get the Ports, Sequence numbers, and Flags.

        Format string layout: '! H H L L H'
        ! = Network byte order (Big-Endian)
        H = 2 bytes for Source Port
        H = 2 bytes for Destination Port
        L = 4 bytes for Sequence Number
        L = 4 bytes for Acknowledgment Number
        H = 2 bytes for Data Offset, Reserved bits, and Flags mixed together
        """
        # Unpack the first 14 bytes of the TCP header
        unpacked_data = struct.unpack('! H H L L H', raw_data[:14])

        self.src_port = unpacked_data[0]
        self.dest_port = unpacked_data[1]
        self.sequence = unpacked_data[2]
        self.acknowledgment = unpacked_data[3]

        # The 5th item contains the header offset and flags combined into a 16-bit integer.
        offset_reserved_flags = unpacked_data[4]

        # Using Bitwise AND (&) to isolate specific flag bits from the 16-bit field
        # SYN flag is the 2nd bit from the right (decimal value 2)
        self.flag_syn = (offset_reserved_flags & 2) != 0

        # ACK flag is the 5th bit from the right (decimal value 16)
        self.flag_ack = (offset_reserved_flags & 16) != 0

        # Extract the Data Offset (top 4 bits of the 16-bit integer)
        # Shift right by 12 bits to isolate it, then multiply by 4 to convert words to bytes
        tcp_header_length = (offset_reserved_flags >> 12) * 4

        # Everything after the header length is the actual application payload
        self.payload = raw_data[tcp_header_length:]

class UDPDatagram:
    def __init__(self, raw_data):
        """
        UDP header is fixed at 8 bytes.

        Format string: '! H H H H'
        ! = Network byte order (Big-Endian)
        H = 2 bytes for Source Port
        H = 2 bytes for Destination Port
        H = 2 bytes for Length (header + payload)
        H = 2 bytes for Checksum
        """
        unpacked_data = struct.unpack('! H H H H', raw_data[:8])

        self.src_port  = unpacked_data[0]
        self.dest_port = unpacked_data[1]
        self.length    = unpacked_data[2]
        self.checksum  = unpacked_data[3]

        # Everything after the 8-byte UDP header is the payload
        self.payload = raw_data[8:]