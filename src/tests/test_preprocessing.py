import pytest
from src.ids.preprocessing import preprocess_data
from scapy.all import IP, Ether, TCP

def test_preprocess_data():
    packet = Ether()/IP(src="192.168.1.1", dst="192.168.1.2")/TCP(sport=12345, dport=80)
    df = preprocess_data([packet])
    
    assert df.shape == (1, 5)  # One packet, five features
    assert df.columns.tolist() == ["ip_src", "ip_dst", "protocol", "port_src", "port_dst"]
