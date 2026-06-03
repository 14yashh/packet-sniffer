import struct


class IPv4Packet:
    def __init__(self, raw_data):
        """
        Windows hands us the IPv4 packet starting at byte 0.
        The standard IPv4 header is 20 bytes long.

        Unpack format string: '! 8x B B 2x 4s 4s'
        !  = Network byte order (Big-Endian)
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