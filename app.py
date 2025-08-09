import os
import signal
import subprocess
import queue
import threading
import time
import json
import shlex # ENSURE THIS IMPORT IS PRESENT
from flask import Flask, render_template, request, Response, jsonify
from ansi2html import Ansi2HTMLConverter
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from flask import send_file

# --- Configuration ---
SCRIPT_PATH = "./sleuth.sh"
BASE_OUTPUT_DIR = "Recon" # No trailing slash

# --- Globals ---
app = Flask(__name__)
process = None
update_queue = queue.Queue()

# --- File Watcher Logic ---
class FileUpdateHandler(FileSystemEventHandler):
    # ... (This class is correct, no changes needed)
    def __init__(self, queue):
        self.queue = queue
        self.last_event_time = 0
    def on_any_event(self, event):
        current_time = time.time()
        if current_time - self.last_event_time > 1.5:
            try:
                self.queue.put_nowait({"action": "refresh_tree"})
                self.last_event_time = current_time
                print("[*] Queued file tree refresh notification.")
            except queue.Full: pass

def start_file_watcher(path, queue):
    # ... (This function is correct, no changes needed)
    if not os.path.exists(path): os.makedirs(path)
    observer = Observer()
    observer.schedule(FileUpdateHandler(queue), path, recursive=True)
    observer.start(); observer.join()

# --- Flask Routes ---
@app.route('/')
def index():
    return render_template('index.html')

@app.route('/start-scan', methods=['POST'])
def start_scan():
    # ... (This function is correct, no changes needed)
    global process
    if process and process.poll() is None: return jsonify({"error": "A scan is already in progress."}), 400
    data = request.json
    scan_type, command, target = data.get('scan_type'), [], ""

    if scan_type == 'simple':
        target = data.get('target')
        flag = data.get('flag')
        if not target: return jsonify({"error": "Target domain is required."}), 400
        if not flag: return jsonify({"error": "A scan type must be selected."}), 400
        command = [SCRIPT_PATH, "-d", target, flag]
    elif scan_type == 'manual':
        raw_command = data.get('command')
        if not raw_command: return jsonify({"error": "Manual command is empty."}), 400
        try:
            command = shlex.split(raw_command)
            if not command or command[0] != SCRIPT_PATH: return jsonify({"error": f"Manual command must start with '{SCRIPT_PATH}'."}), 400
            target_index = command.index('-d') + 1
            if target_index < len(command): target = command[target_index]
        except (ValueError, IndexError): return jsonify({"error": "Manual command must include a '-d <domain>'."}), 400
    else: return jsonify({"error": "Invalid scan type."}), 400

    if target:
        target = os.path.basename(target)
        scan_output_path = os.path.join(BASE_OUTPUT_DIR, target)
        try: os.makedirs(scan_output_path, exist_ok=True)
        except OSError as e: return jsonify({"error": f"Could not create directory: {e}"}), 500
        watcher_thread = threading.Thread(target=start_file_watcher, args=(scan_output_path, update_queue), daemon=True).start()
    
    try:
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, bufsize=1, universal_newlines=True, preexec_fn=os.setsid)
        return jsonify({"message": f"Scan started for {target}", "basePath": scan_output_path})
    except Exception as e: return jsonify({"error": str(e)}), 500


@app.route('/stop-scan', methods=['POST'])
def stop_scan():
    # ... (This function is correct, no changes needed)
    global process
    if process and process.poll() is None:
        try: os.killpg(os.getpgid(process.pid), signal.SIGINT); return jsonify({"message": "Stop signal sent."})
        except Exception as e: return jsonify({"error": str(e)}), 500
    return jsonify({"error": "No active scan to stop."}), 400

@app.route('/stream-console')
def stream_console():
    # ... (This function is correct, no changes needed)
    def generate():
        global process;
        if not process: yield "data: No scan is currently running.\n\n"; return
        converter = Ansi2HTMLConverter(inline=True)
        for line in iter(process.stdout.readline, ''): yield f"data: {converter.convert(line.strip(), full=False) + '<br>'}\n\n"
        process.stdout.close(); process.wait(); process = None
        yield "data: <b>--- CONSOLE STREAM FINISHED ---</b><br>\n\n"
    return Response(generate(), mimetype='text/event-stream')

@app.route('/stream-file-notifications')
def stream_file_notifications():
    # ... (This function is correct, no changes needed)
    def generate():
        while True: message = update_queue.get(); yield f"data: {json.dumps(message)}\n\n"
    return Response(generate(), mimetype='text/event-stream')


# --- CORRECTED API ENDPOINTS ---
# By convention, API routes are often grouped under a prefix.
# This makes them distinct and less likely to conflict.
@app.route('/api/list_directory', methods=['GET'])
def list_directory():
    req_path = request.args.get('path')
    if not req_path: return jsonify({"error": "Path parameter is required"}), 400
    
    abs_base_path = os.path.abspath(BASE_OUTPUT_DIR)
    # Sanitize and safely resolve path
    safe_subpath = os.path.normpath(req_path).lstrip(os.sep)
    abs_req_path = os.path.abspath(os.path.join(abs_base_path, safe_subpath))
    
    if not abs_req_path.startswith(abs_base_path): return jsonify({"error": "Access Denied"}), 403
    if not os.path.isdir(abs_req_path): return jsonify({"error": "Path not found"}), 404

    try:
        items = os.listdir(abs_req_path)
        folders = sorted([i for i in items if os.path.isdir(os.path.join(abs_req_path, i))])
        files = sorted([i for i in items if os.path.isfile(os.path.join(abs_req_path, i))])
        return jsonify({"path": req_path, "folders": folders, "files": files})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/get_file', methods=['GET'])
def get_file():
    req_path = request.args.get('path')
    if not req_path: return jsonify({"error": "File path is required"}), 400
    
    abs_base_path = os.path.abspath(BASE_OUTPUT_DIR)
    abs_req_path = os.path.abspath(os.path.join(abs_base_path, req_path.replace(abs_base_path, '')))

    if not abs_req_path.startswith(abs_base_path): return jsonify({"error": "Access Denied"}), 403
    if not os.path.isfile(abs_req_path): return jsonify({"error": "File not found"}), 404
    
    try:
        with open(abs_req_path, 'r', encoding='utf-8', errors='ignore') as f: content = f.read()
        return jsonify({"path": req_path, "content": content})
    except Exception as e: return jsonify({"error": str(e)}), 500

@app.route('/api/get_image')
def get_image():
    """API to get an image file."""
    req_path = request.args.get('path')
    if not req_path:
        return "File path is required", 400

    # Security check (same as other endpoints)
    abs_base_path = os.path.abspath(BASE_OUTPUT_DIR)
    # Sanitize and resolve the path
    safe_subpath = os.path.normpath(req_path).lstrip(os.sep)
    abs_req_path = os.path.abspath(os.path.join(abs_base_path, safe_subpath))

    if not abs_req_path.startswith(abs_base_path):
        return "Access Denied", 403
    if not os.path.isfile(abs_req_path):
        return "File not found", 404

    try:
        # Use Flask's send_file, which handles mime types and headers correctly.
        return send_file(abs_req_path)
    except Exception as e:
        print(f"[!] Error sending file {abs_req_path}: {e}")
        return "Server error", 500


if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True, threaded=True)