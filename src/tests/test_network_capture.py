from src.ids.network_capture import capture_packets
from unittest.mock import patch
import scapy.all as scapy

def test_capture_packets():
    # Simulate captured packets
    mock_packets = [
        scapy.IP(src="192.168.1.1", dst="192.168.1.2") / scapy.ICMP(),
        scapy.IP(src="192.168.1.3", dst="192.168.1.4") / scapy.TCP()
    ]
    
    # Mock scapy.sniff to return the mock packets
    with patch('scapy.sendrecv.sniff', return_value=mock_packets):
        df = capture_packets(interface='Wi-Fi', count=5)
        print(df)


