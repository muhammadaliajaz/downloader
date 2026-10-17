import os
import uuid
import time
import json
import threading
from flask import Flask, render_template, request, jsonify, Response, send_file

from core.downloader import start_download_thread, get_progress, cancel_download
from core.cleanup import start_cleanup_scheduler
from core.security import (
    validate_url, 
    check_rate_limit, 
    acquire_concurrency_slot, 
    release_concurrency_slot, 
    is_safe_filepath
)

app = Flask(__name__)
app.secret_key = os.urandom(32) # Secure 256-bit random key for session safety
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024 # 1 MB Max payload size limit to prevent memory buffer DoS

DOWNLOADS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'downloads'))
os.makedirs(DOWNLOADS_DIR, exist_ok=True)

# Start background cleanup scheduler for temporary files
start_cleanup_scheduler(DOWNLOADS_DIR)

# Custom Security Error Handlers (Prevents Framework Information Disclosure)
@app.errorhandler(404)
def handle_404(e):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(500)
def handle_500(e):
    return jsonify({'error': 'Internal server error occurred'}), 500

@app.errorhandler(413)
def handle_413(e):
    return jsonify({'error': 'Payload size exceeds 1MB limit'}), 413

@app.errorhandler(429)
def handle_429(e):
    return jsonify({'error': 'Too many requests. Please slow down.'}), 429

# Global Security Response Headers Middleware
@app.after_request
def apply_security_headers(response):
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self' https: data: 'unsafe-inline' 'unsafe-eval'; "
        "frame-ancestors 'self';"
    )
    return response

def get_client_ip():
    """Extracts client IP address safely accounting for reverse proxies."""
    if request.headers.get('X-Forwarded-For'):
        return request.headers.get('X-Forwarded-For').split(',')[0].strip()
    return request.remote_addr or '127.0.0.1'

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/preview')
def preview_ui():
    return render_template('preview_ui.html')

@app.route('/api/download', methods=['POST'])
def trigger_download():
    # 1. Rate Limiting Check (Max 10 requests / min per IP)
    client_ip = get_client_ip()
    allowed, retry_after = check_rate_limit(client_ip)
    if not allowed:
        return jsonify({
            'error': f'Rate limit exceeded. Please wait {retry_after} seconds before starting another download.'
        }), 429

    # 2. JSON Request Validation
    data = request.get_json(silent=True)
    if not data or not isinstance(data, dict):
        return jsonify({'error': 'Invalid JSON request payload'}), 400

    url = data.get('url')
    format_type = str(data.get('format', 'mp4')).lower().strip()
    quality = str(data.get('quality', '720')).lower().strip()

    # 3. URL Security & SSRF Validation
    is_valid_url, error_msg = validate_url(url)
    if not is_valid_url:
        return jsonify({'error': f'Security Error: {error_msg}'}), 400

    # 4. Parameter Whitelist Validation
    ALLOWED_FORMATS = ['mp4', 'mp3']
    ALLOWED_QUALITIES = ['720', '1080', '480', '360', 'best']
    
    if format_type not in ALLOWED_FORMATS:
        return jsonify({'error': 'Invalid format parameter'}), 400

    if quality not in ALLOWED_QUALITIES:
        return jsonify({'error': 'Invalid quality parameter'}), 400

    # 5. Server Concurrency Slots Check (Max 5 active concurrent downloads)
    if not acquire_concurrency_slot():
        return jsonify({
            'error': 'Server is currently at maximum capacity. Please wait a moment and try again.'
        }), 503

    task_id = str(uuid.uuid4())
    
    try:
        # Start download in a background worker thread
        start_download_thread(task_id, url, format_type, quality, DOWNLOADS_DIR)
    except Exception:
        release_concurrency_slot()
        return jsonify({'error': 'Failed to launch download thread'}), 500

    return jsonify({'task_id': task_id})

@app.route('/api/status/<task_id>')
def status(task_id):
    # Security: Strict UUID format validation
    try:
        uuid.UUID(task_id)
    except ValueError:
        return jsonify({'error': 'Invalid task ID format'}), 400

    def event_stream():
        while True:
            progress_data = get_progress(task_id)
            if not progress_data:
                yield f"data: {{\"status\": \"initializing\"}}\n\n"
            else:
                yield f"data: {json.dumps(progress_data)}\n\n"
                if progress_data.get('status') in ['finished', 'error', 'cancelled']:
                    break
            time.sleep(1)
            
    return Response(event_stream(), mimetype="text/event-stream")

@app.route('/api/cancel/<task_id>', methods=['POST'])
def cancel(task_id):
    # Security: Strict UUID format validation
    try:
        uuid.UUID(task_id)
    except ValueError:
        return jsonify({'error': 'Invalid task ID format'}), 400
        
    success = cancel_download(task_id)
    if success:
        return jsonify({'status': 'success', 'message': 'Download cancellation signal sent'})
    return jsonify({'status': 'error', 'message': 'Task not found or already completed'}), 404

@app.route('/api/files/<task_id>')
def download_file(task_id):
    # Security: Strict UUID format validation
    try:
        uuid.UUID(task_id)
    except ValueError:
        return jsonify({'error': 'Invalid task ID format'}), 400

    progress_data = get_progress(task_id)
    if not progress_data or progress_data.get('status') != 'finished':
        return jsonify({'error': 'File not ready or task not found'}), 404
        
    file_path = progress_data.get('filepath')
    
    # Path Traversal Guard & File Existence Check
    if not file_path or not is_safe_filepath(file_path, DOWNLOADS_DIR) or not os.path.isfile(file_path):
        return jsonify({'error': 'Access Denied: Invalid or restricted file path'}), 403

    # Background auto-delete after browser retrieval attempt
    def secure_delete():
        for _ in range(180): # Try every second for up to 3 minutes
            time.sleep(1)
            try:
                if os.path.exists(file_path):
                    os.remove(file_path)
                break
            except Exception:
                pass
                
    threading.Thread(target=secure_delete, daemon=True).start()
    
    return send_file(file_path, as_attachment=True)

if __name__ == '__main__':
    # Production security: debug mode disabled
    app.run(host='0.0.0.0', port=5000, debug=False, threaded=True)
