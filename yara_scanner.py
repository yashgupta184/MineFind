import yara
import os
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")

# Define the correct scan path (update this to a real directory on your system)
SCAN_PATH = r"C:\Program Files"  # Change to a valid directory
YARA_RULES_PATH = "crypto_rules.yar"  # Ensure this file exists in the script directory

def scan_for_malware():
    """Scans the specified directory for malware using YARA rules."""
    logging.info(f"Scanning directory: {SCAN_PATH}")

    if not os.path.exists(SCAN_PATH):
        logging.error(f"Scan directory does not exist: {SCAN_PATH}")
        return {}
    
    if not os.path.isfile(YARA_RULES_PATH):
        logging.error(f"YARA rules file not found: {YARA_RULES_PATH}")
        return {}

    try:
        # Load YARA rules
        rules = yara.compile(filepath=YARA_RULES_PATH)
        
        # Dictionary to store results
        malware_hits = {}
        
        # Scan files in the specified directory
        for root, _, files in os.walk(SCAN_PATH):
            for file in files:
                file_path = os.path.join(root, file)
                try:
                    matches = rules.match(file_path)
                    if matches:
                        malware_hits[file_path] = [match.rule for match in matches]
                        logging.warning(f"Malware detected: {file_path} -> {matches}")
                except yara.Error as e:
                    logging.error(f"Error scanning {file_path}: {e}")
        
        logging.info("YARA Scan completed successfully.")
        return malware_hits
    except yara.Error as e:
        logging.error(f"YARA Scan failed: {e}")
        return {}

if __name__ == "__main__":
    logging.info("Starting cryptojacking malware scan...")
    results = scan_for_malware()
    logging.info(f"Results: {results}")