import scapy.all as scapy
import logging
import time

def scan_network(ip_range):
    logging.info(f"Starting network scan on range: {ip_range}")
    try:
        arp_request = scapy.ARP(pdst=ip_range)
        broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        arp_request_broadcast = broadcast / arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout=5, verbose=False)[0]
        
        devices = []
        for element in answered_list:
            devices.append({"ip": element[1].psrc, "mac": element[1].hwsrc})
            logging.info(f"Found device - IP: {element[1].psrc}, MAC: {element[1].hwsrc}")
        
        return devices
    except Exception as e:
        logging.error(f"Error during network scan: {e}")
        return []

if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
    logging.info("Network scanner script started")
    start_time = time.time()
    network_devices = scan_network("192.168.87.8")
    end_time = time.time()
    logging.info(f"Network scan completed in {end_time - start_time:.2f} seconds")
    print("Scan Results:")
    print(network_devices)
