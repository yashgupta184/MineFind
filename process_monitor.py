import psutil
import threading

def monitor_processes():
    suspicious_processes = []
    
    def check_processes():
        for proc in psutil.process_iter(['pid', 'name', 'cpu_percent']):
            if 'miner' in proc.info['name'].lower() or proc.info['cpu_percent'] > 80:
                suspicious_processes.append(proc.info)
    
    monitor_thread = threading.Thread(target=check_processes)
    monitor_thread.start()
    monitor_thread.join()
    
    return suspicious_processes

if __name__ == "__main__":
    print("Monitoring running processes...")
    print("Suspicious processes:", monitor_processes())
