from scapy.all import sniff, IP, TCP

data = []


def packet_callback(packet):
    """
    Method to capture network packets and analyze them,
    displaying the source and destination IP addresses and ports
    :param packet : string
    """
    if packet.haslayer(IP) and packet.haslayer(TCP):
        ip_src = packet[IP].src
        ip_dst = packet[IP].dst
        tcp_sport = packet[TCP].sport
        tcp_dport = packet[TCP].dsport
        print(f'Source IP: {ip_src} -> Destination IP: {ip_dst}')
        print(f'Source Port: {tcp_sport} -> Destination IP: {tcp_dport}')
        print(packet.summary())


sniff(prn=packet_callback, iface='eth0', count=10)


def analyze_packet(packet):
    """
    Method to analyze a single packet and return if it's an anomaly.
    :param packet: string
    :return: boolean
    """
    if packet.haslayer(IP) and packet.haslayer(TCP):
        packet_size = len(packet)
        return packet_size > 1000
    return False
