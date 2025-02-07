from network_scanner import scan_network
from process_monitor import monitor_processes
from yara_scanner import scan_for_malware
import logging

logging.basicConfig(level=logging.DEBUG)

def scan_system():
    logging.info("Starting Crypto Miner Detection Scan")

    logging.info("Scanning network...")
    network_results = scan_network("192.168.1.1/28")  #Scan a particular device or a range of network
    logging.debug(f"Network results: {network_results}")

    logging.info("Monitoring processes...")
    process_results = monitor_processes()
    logging.debug(f"Process results: {process_results}")

    logging.info("Scanning for malware using YARA...")
    yara_results = scan_for_malware()
    logging.debug(f"YARA results: {yara_results}")

    logging.info("Scan completed.")
    return {
        "network_scan": network_results,
        "process_monitor": process_results,
        "yara_scan": yara_results
    }

if __name__ == "__main__":
    print(scan_system())
