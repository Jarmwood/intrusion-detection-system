import pytest
from src.ids.main import main

def test_main():
    # This would ideally mock `scapy.sniff()` to simulate packet capture
    assert main() is None  # Since `main()` prints predictions, check for successful execution
