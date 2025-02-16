import pandas as pd
from scapy.all import IP, TCP, UDP
from src.ids.preprocessing import ip_to_int

class Preprocesing:

    def ip_to_int(self, ip: str) -> int:
        """
        Convert an IP address to a unique integer representation.
        """
        return int.from_bytes([int(x) for x in ip.split('.')], byteorder='big')

    def preprocess_data(self, packets):
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
