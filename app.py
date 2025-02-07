import threading
import time
from flask import Flask, render_template, request, redirect, url_for, jsonify
from main import scan_system

app = Flask(__name__, 
    static_url_path='/static',
    static_folder='static'
)
scan_results = {}  # ✅ Initialize scan_results as an empty dictionary

def run_scan():
    global scan_results
    print("[DEBUG] Scan started...")
    scan_results = scan_system()
    print(f"[DEBUG] Scan completed! Results: {scan_results}")

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan', methods=['POST'])
def scan():
    global scan_results
    scan_results = {}  # ✅ Reset results before starting a new scan
    scan_thread = threading.Thread(target=run_scan, daemon=True)
    scan_thread.start()

    # ✅ Wait until scan_results is updated (max 60 seconds)
    timeout = 40
    while not scan_results and timeout > 0:
        time.sleep(1)
        timeout -= 1

    return redirect(url_for('results'))

@app.route('/results')
def results():
    global scan_results
    if not scan_results:  # ✅ Prevents NoneType errors
        return render_template('results.html', scan_results={"message": "Scan is still in progress. Please wait..."})
    return render_template('results.html', scan_results=scan_results)

if __name__ == '__main__':
    app.run(debug=True, threaded=True)
