import network_scanner

def test_scan():
    result = network_scanner.scan_network()
    assert isinstance(result, str)  # Should return a string
