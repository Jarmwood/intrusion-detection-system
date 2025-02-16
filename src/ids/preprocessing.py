import pandas as pd
from scapy.all import IP, TCP, UDP
from src.ids.preprocessing import ip_to_int

class Preprocessing:

    @staticmethod
    def ip_to_int(ip: str) -> int:
        """
        Convert an IP address to a unique integer representation.

        Args:
            ip (str): The IPv4 address in string format (e.g., '192.168.1.1').

        Returns:
            int: The integer representation of the IP address.

        Raises:
            ValueError: If the IP address is invalid.
        """
        octets = ip.split('.')
        if len(octets) != 4:
            raise ValueError(f"Invalid IP address: {ip}. IP should have 4 octets.")

        try:
            bytes_ = [int(octet) for octet in octets]
            if not all(0 <= byte <= 255 for byte in bytes_):
                raise ValueError(f"Invalid IP address: {ip}. Each octet should be between 0 and 255.")
        except ValueError:
            raise ValueError(f"Invalid IP address: {ip}. All octets must be integers.")

        return int.from_bytes(bytes_, byteorder='big')

    @staticmethod
    def preprocess_data(packets):
        features = []
        for packet in packets:
            if IP in packet:
                ip_src = ip_to_int(packet[IP].src)
                ip_dst = ip_to_int(packet[IP].dst)
                protocol = packet.proto
                if TCP in packet:
                    port_src = packet[TCP].sport
                    port_dst = packet[TCP].dport
                elif UDP in packet:
                    port_src = packet[UDP].sport
                    port_dst = packet[UDP].dport
                else:
                    port_src = port_dst = None
                features.append([ip_src, ip_dst, protocol, port_src, port_dst])

        return pd.DataFrame(features, columns=["ip_src", "ip_dst", "protocol", "port_src", "port_dst"])
