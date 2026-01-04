from flask import Flask, render_template, request, jsonify, Response, stream_with_context
import os
import json
import time
import threading
import queue
import sys
from werkzeug.utils import secure_filename

# Import core logic from main.py
from main import (
    crack_p12_password, 
    change_p12_password, 
    get_user_profile, 
    check_api_key,
    API_KEY
)

# Initialize Flask app
app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 50 * 1024 * 1024  # 50MB max upload

# Global queue for log streaming
log_queue = queue.Queue()

# Redirect stdout to capture logs for the web UI
class StreamLogger:
    def __init__(self, queue):
        self.queue = queue
        self.terminal = sys.stdout

    def write(self, message):
        self.terminal.write(message)
        if message.strip():
            self.queue.put(message)

    def flush(self):
        self.terminal.flush()

sys.stdout = StreamLogger(log_queue)

# Ensure upload directory exists
os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/user')
def user_info():
    """Get user profile and VIP status"""
    try:
        profile = get_user_profile()
        return jsonify(profile if profile else {'error': 'Failed to fetch profile'})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/crack', methods=['POST'])
def crack():
    """Handle cracking request"""
    try:
        print(f"DEBUG REQ: Files={list(request.files.keys())} Form={list(request.form.keys())}")
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400

        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            mode = request.form.get('mode', 'smart')
            kwargs = {'mode': mode}
            
            # Extract request data BEFORE starting thread (Request Context issue)
            if mode == 'dictionary':
                # Check for wordlist file or array
                if 'wordlist' in request.files:
                    wl_file = request.files['wordlist']
                    if wl_file and wl_file.filename:
                        wl_path = os.path.join(app.config['UPLOAD_FOLDER'], secure_filename(wl_file.filename))
                        wl_file.save(wl_path)
                        kwargs['wordlist'] = wl_path
                elif request.form.get('wordlist_url'):
                    kwargs['wordlist_url'] = request.form.get('wordlist_url')
                elif request.form.get('wordlist_array'):
                    # Parse array
                    passwords = request.form.get('wordlist_array').replace(',', '\n').split('\n')
                    passwords = [p.strip() for p in passwords if p.strip()]
                    kwargs['wordlist'] = passwords

            elif mode == 'brute_force':
                kwargs['charset'] = request.form.get('charset')
                kwargs['max_length'] = int(request.form.get('max_length', 4))
            
            # Start cracking in a separate thread to allow streaming logs
            def run_crack(p12_path, p12_name, crack_args):
                log_queue.put(f"[*] Starting {crack_args['mode']} attack on {p12_name}...")
                
                # Execute cracking
                try:
                    success, password, _ = crack_p12_password(p12_path, **crack_args)
                    if success and password:
                        log_queue.put(f"[+] SUCCESS: Password found: {password}")
                    else:
                        log_queue.put("[-] Failed to find password.")
                except Exception as e:
                    log_queue.put(f"[!] Error: {str(e)}")
                finally:
                    # Cleanup
                    if os.path.exists(p12_path):
                        os.remove(p12_path)
                    # Cleanup wordlist if it was a temp file
                    if 'wordlist' in crack_args and isinstance(crack_args['wordlist'], str) and os.path.exists(crack_args['wordlist']):
                        # Only delete if it's in our upload folder (basic check)
                        if app.config['UPLOAD_FOLDER'] in crack_args['wordlist']:
                             try:
                                 os.remove(crack_args['wordlist'])
                             except:
                                 pass

            # Start thread
            thread = threading.Thread(target=run_crack, args=(filepath, filename, kwargs))
            thread.start()
            
            return jsonify({'status': 'started', 'message': 'Cracking process started'})
            
    except Exception as e:
        return jsonify({'error': str(e)}), 500


@app.route('/api/change', methods=['POST'])
def change():
    """Handle password change request"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file part'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No selected file'}), 400
            
        old_pass = request.form.get('old_password')
        new_pass = request.form.get('new_password')
        
        if not old_pass or not new_pass:
            return jsonify({'error': 'Missing passwords'}), 400

        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            
            try:
                # Use main.py function (returns success, filename or None, error msg)
                success, download_url, error = change_p12_password(filepath, old_pass, new_pass, interactive=False)
                
                if success:
                    # Return success and download URL
                    return jsonify({'success': True, 'path': download_url})
                else:
                    return jsonify({'success': False, 'error': error})
            finally:
                if os.path.exists(filepath):
                    os.remove(filepath)
                    
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/stream')
def stream():
    """Stream console logs to the client"""
    def generate():
        while True:
            try:
                # Get message from queue, non-blocking
                message = log_queue.get(timeout=0.5)
                yield f"data: {json.dumps({'log': message})}\n\n"
            except queue.Empty:
                # Send keepalive
                yield f": keepalive\n\n"
            except Exception:
                break
    
    return Response(stream_with_context(generate()), mimetype='text/event-stream')

if __name__ == '__main__':
    print(f"[*] Starting Web UI on http://127.0.0.1:5000")
    print(f"[*] API Key configured: {'Yes' if API_KEY else 'No'}")
    app.run(debug=True, port=5000)
