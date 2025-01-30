from unittest.mock import patch, MagicMock

from scapy.layers.inet import IP, TCP

from src.main import network_analyzer
from src.main.network_analyzer import extract_features


def test_hello_world():
    print('Hello world!')
     

@patch('scapy.all.sniff')  # Mocking `sniff` function from Scapy
@patch('src.main.network_analyzer.packet_callback')  # Mock the packet_callback to avoid real network interaction
@patch('scapy.interfaces.conf.ifaces.dev_from_name')  # Mock interface resolution
def test_start_sniffing(mock_dev_from_name, mock_packet_callback, mock_sniff):
    # Mock the interface lookup to return a dummy interface (or any valid mock)
    mock_dev_from_name.return_value = MagicMock()

    # Create a mock packet that will be passed to the callback
    mock_packet = MagicMock()
    mock_packet.__len__.return_value = 700  # Mock the packet size

    # Ensure sniff calls the callback with the mock packet and terminates
    mock_sniff.return_value = None  # No actual packets, just simulate the callback being called

    # Use side_effect to simulate sniff capturing 1 packet and calling the callback
    def side_effect_function(prn, iface, count):
        for _ in range(count):
            prn(mock_packet)  # Call the callback with the mock packet

    mock_sniff.side_effect = side_effect_function

    # Replace 'eth0' with a valid network interface name for Windows (e.g., 'Ethernet')
    network_interface = 'Ethernet'  # Change this to the name of your actual network interface on Windows

    # Call start_sniffing to see if sniff is invoked and behaves correctly
    network_analyzer.start_sniffing(interface=network_interface, packet_count=1)

    # Verify that the sniff function was called with the correct parameters
    mock_sniff.assert_called_once_with(prn=mock_packet_callback, iface=network_interface, count=1)

    # Verify that the packet_callback was called exactly once with the mock packet
    mock_packet_callback.assert_called_once_with(mock_packet)


def test_extract_features():
    mock_packet = MagicMock()
    mock_packet.__len__.return_value = 500
    features = extract_features(mock_packet)
    assert features == [500], "Feature extraction should return the packet size"


@patch('src.main.network_analyzer.model.predict')
def test_analyze_packet_with_model(mock_predict):
    mock_predict.return_value = [-1]
    mock_packet = MagicMock()
    mock_packet.__len__.return_value = 700
    is_anomalous = network_analyzer.analyze_packet(mock_packet)
    assert is_anomalous, "The method should detect the packet as an anomaly when the model predicts -1"

    mock_predict.return_value = [1]
    is_anomalous = network_analyzer.analyze_packet(mock_packet)
    assert not is_anomalous, "The method should detect the packet as normal when the model predicts 1"


@patch('builtins.print')
def test_packet_callback(mock_print):
    mock_packet = MagicMock()
    mock_packet.haslayer.side_effect = lambda x: x in [IP, TCP]
    mock_packet[IP].src = '192.168.1.1'
    mock_packet[IP].dst = '192.168.1.100'
    mock_packet.__len__.return_value = 700

    with patch('src.main.network_analyzer.analyze_packet', return_value=True):
        network_analyzer.packet_callback(mock_packet)
        mock_print.assert_called_with(
            "Anomaly detected! Source IP: 192.168.1.1, Destination IP: 192.168.1.100, Size: 700 bytes"
        )

    with patch('src.main.network_analyzer.analyze_packet', return_value=False):
        network_analyzer.packet_callback(mock_packet)
        mock_print.assert_called_with(
            "Normal packet from: 192.168.1.1 to 192.168.1.100, Size: 700 bytes"
        )

