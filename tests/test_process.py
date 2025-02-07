import process_monitor

def test_process_check():
    result = process_monitor.detect_mining_processes()
    assert isinstance(result, list)  # Should return a list
