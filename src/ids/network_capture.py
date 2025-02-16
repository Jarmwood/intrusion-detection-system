import scapy.all as scapy
import pandas as pd

class NetworkCapture: 
    def capture_packets(self, interface: str, count: int) -> pd.DataFrame:
        """
        Capture packets using Scapy and return a pandas DataFrame.
        This captures packets at Layer 3 (IP Layer).
        """

        packets = scapy.sniff(iface=interface, count=count, timeout=30, filter="ip")
        
        # Extract data from the captured packets
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
