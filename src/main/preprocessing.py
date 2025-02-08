import pandas as pd
from scapy.all import IP, TCP, UDP, ICMP

def preprocess_data(packets):
    features = []
    for packet in packets:
        if IP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].dst
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


