from src.main.network_capture import capture_packets

def test_capture_packets():
    df = capture_packets(interface='eth0', count=5)  # Adjust interface as needed
    assert not df.empty
    assert 'src' in df.columns
    assert 'dst' in df.columns
