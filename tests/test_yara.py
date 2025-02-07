import yara_scanner

def test_yara_scan():
    result = yara_scanner.run_yara_scan()
    assert isinstance(result, str)  # Should return a string
