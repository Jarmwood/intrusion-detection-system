import scapy.all as scapy
import pandas as pd

def capture_packets(interface: str, count: int) -> pd.DataFrame:
    """
    Capture packets using Scapy and return a pandas DataFrame.
    """
    packets = scapy.sniff(iface=interface, count=count, timeout=30)
    data = []
    for pkt in packets:
        if pkt.haslayer(scapy.IP):
            data.append({
                'timestamp': pkt.time,
                'src': pkt[scapy.IP].src,
                'dst': pkt[scapy.IP].dst,
                'len': len(pkt),
                'proto': pkt[scapy.IP].proto
            })
    return pd.DataFrame(data)
