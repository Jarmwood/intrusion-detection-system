import scapy.all as scapy
import pandas as pd

def capture_packets(interface: str, count: int) -> pd.DataFrame:
    """
    Capture packets using Scapy and return a pandas DataFrame.
    This captures packets at Layer 3 (IP Layer).
    """

    # Capture only IP packets (Layer 3) using the filter "ip"
    packets = scapy.sniff(iface=interface, count=count, timeout=30, filter="ip")
    
    # Extract data from the captured packets
    data = []
    for pkt in packets:
        if pkt.haslayer(scapy.IP):  # Only process IP packets
            data.append({
                'timestamp': pkt.time,
                'src': pkt[scapy.IP].src,
                'dst': pkt[scapy.IP].dst,
                'len': len(pkt),
                'proto': pkt[scapy.IP].proto
            })
    
    # Return the captured data as a pandas DataFrame
    return pd.DataFrame(data)
