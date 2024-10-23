from pyexpat import features
from scapy.all import sniff
from scapy.layers.inet import IP, TCP
from sklearn.ensemble import IsolationForest
import numpy as np

# initialize the ML IF model
model = IsolationForest(n_estimators=100, contamination=0.1, random_state=42)

# sample data for training(features like packet size can be used).
# in practice, this would come from a dataset of normal packets.
training_data = np.array([[500], [600], [450], [700],[480], [520], [470]])
model.fit(training_data)

def extract_features(packet):
    """
    Method to extract features from packet for the model.
    :param packet: network packet to extract features from.
    :return: list: a list of features extracted from the packet.
    """
    packet_size = len(packet)
    return [packet_size]


def packet_callback(packet):
    """
    Method to capture network packets and analyze them in real time,
    displaying the source and destination IP addresses and ports

    :param packet : The captured network packet
    """
    is_anomalous = analyze_packet(packet)
    if is_anomalous:
        print(f"Anomaly detected! Source IP: {packet[IP].src},"
              f"Destination IP: {packet[IP].dst}, "
              f"Size: {len(packet)} bytes")
    else:
        print(f"Normal packet from: {packet[IP].src} to "
              f"{packet[IP].dst}, Size: {len(packet)} bytes")


def analyze_packet(packet):
    """
    Method to analyze a single packet and determine if it's an anomaly.

    :param packet: string input of network packet to analyze.
    :return: boolean: true if packet is considered an anomaly and false otherwise.
    """
    if packet.haslayer(IP) and packet.haslayer(TCP):
        packet_size = len(packet)
        return packet_size > 1000
    return False

def start_sniffing(interface='eth0', packet_count=100):
    """
    mathod to sniff network packets on the specified interface and analyze them.
    :param interface: string input of the network interface to sniff on (e.g., 'eth0')
    :param packet_count: int input of the number of packets to capture
    """
    print(f'Starting packet capture on interface to sniff on (e.g., ''eth0)')
    sniff(prn=packet_callback, iface=interface, count=packet_count)
    print('Packet capture complete.')

if __name__ == "__main__":
    start_sniffing(interface='eth0', packet_count=10)
