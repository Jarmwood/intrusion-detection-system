import pytest
from unittest.mock import MagicMock, patch
from src.main import network_analyzer
from scapy.layers.inet import IP, TCP
from src.main.network_analyzer import extract_features, analyze_packet, packet_callback, model


def test_extract_features():
    mock_packet = MagicMock()
    mock_packet.__len__.return_value = 500
    features = extract_features(mock_packet)
    assert features == [500], "Feature extraction should return the packet size"


@patch(network_analyzer.model.predict)
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

    with patch('network_analyzer.analyze_packet', return_value=True):
        network_analyzer.packet_callback(mock_packet)
        mock_print.assert_called_with(
            "Anomaly detected! source IP: 192.168.1.1, Destination IP: 192.168.1.100, Size: 700 bytes"
        )

    with patch('network_analyzer.analyze_packet', return_value=False):
        network_analyzer.packet_callback(mock_packet)
        mock_print.assert_called_with(
            "Normal packet from 192.168.1.1 to 192.168.1.100, Size: 700 bytes"
        )
