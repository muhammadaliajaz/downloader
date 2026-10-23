import os
import shutil
import uuid
import time
import json
import threading
import urllib.parse
import ipaddress
from flask import Flask, render_template, request, jsonify, Response, send_file, redirect, url_for

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
app.secret_key = os.urandom(32) # Secure 256-bit cryptographically strong key
app.config['MAX_CONTENT_LENGTH'] = 1 * 1024 * 1024 # 1 MB Max payload limit to prevent DoS

DOWNLOADS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'downloads'))
os.makedirs(DOWNLOADS_DIR, exist_ok=True)

# Start background cleanup scheduler for temporary files (every 10 minutes)
start_cleanup_scheduler(DOWNLOADS_DIR)

# Custom Security Error Handlers (Prevents Framework Information Disclosure)
@app.errorhandler(400)
def handle_400(e):
    return jsonify({'error': 'Bad request'}), 400

@app.errorhandler(403)
def handle_403(e):
    return jsonify({'error': 'Access denied'}), 403

@app.errorhandler(404)
def handle_404(e):
    return jsonify({'error': 'Resource not found'}), 404

@app.errorhandler(413)
def handle_413(e):
    return jsonify({'error': 'Payload size exceeds 1MB limit'}), 413

@app.errorhandler(429)
def handle_429(e):
    return jsonify({'error': 'Too many requests. Please slow down.'}), 429

@app.errorhandler(500)
def handle_500(e):
    return jsonify({'error': 'Internal server error occurred'}), 500

# CSRF & Cross-Origin POST Attack Protection Middleware
@app.before_request
def csrf_cross_origin_guard():
    if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
        origin = request.headers.get('Origin')
        referer = request.headers.get('Referer')
        host = request.headers.get('Host')
        
        expected_host = request.headers.get('X-Forwarded-Host') or request.headers.get('Host')

        def _clean_host(h):
            if not h: return ''
            return h.split(':')[0].lower()

        # Verify Origin if supplied
        if origin:
            try:
                origin_host = urllib.parse.urlparse(origin).netloc
                if origin_host and expected_host and _clean_host(origin_host) != _clean_host(expected_host):
                    return jsonify({'error': 'Cross-Origin forbidden: Request Origin does not match Host'}), 403
            except Exception:
                return jsonify({'error': 'Malformed Origin header'}), 403
        elif referer:
            try:
                referer_host = urllib.parse.urlparse(referer).netloc
                if referer_host and expected_host and _clean_host(referer_host) != _clean_host(expected_host):
                    return jsonify({'error': 'Cross-Origin forbidden: Referer does not match Host'}), 403
            except Exception:
                return jsonify({'error': 'Malformed Referer header'}), 403

# Global Security Response Headers Middleware (OWASP Secure Headers)
@app.after_request
def apply_security_headers(response):
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'camera=(), microphone=(), geolocation=(), payment=()'
    response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'
    response.headers['Content-Security-Policy'] = (
        "default-src 'self' https: data: 'unsafe-inline'; "
        "frame-ancestors 'none';"
    )
    # Mask server header banner to prevent software fingerprinting
    response.headers['Server'] = 'Protected'
    return response

def get_client_ip():
    """Extracts client IP safely without trusting unverified spoofed headers."""
    remote_ip = request.remote_addr or '127.0.0.1'
    # Auto-detect Heroku (DYNO env exists) or explicitly enabled reverse proxy
    if 'DYNO' in os.environ or os.environ.get('TRUST_PROXY', 'false').lower() == 'true':
        xff = request.headers.get('X-Forwarded-For')
        if xff:
            first_ip = xff.split(',')[0].strip()
            try:
                ipaddress.ip_address(first_ip)
                return first_ip
            except ValueError:
                pass
    return remote_ip

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/preview')
def preview_ui():
    return redirect(url_for('index'))

@app.route('/api/health')
def health_check():
    repo_root = os.path.dirname(os.path.abspath(__file__))
    cookies_path = os.path.join(repo_root, 'cookies.txt')
    www_cookies_path = os.path.join(repo_root, 'www.youtube.com_cookies.txt')
    return jsonify({
        'status': 'healthy',
        'version': 'v1.4-visionos',
        'has_cookies_txt': os.path.isfile(cookies_path),
        'cookies_size': os.path.getsize(cookies_path) if os.path.isfile(cookies_path) else 0,
        'has_www_cookies': os.path.isfile(www_cookies_path),
        'node_found': shutil.which('node'),
        'ffmpeg_found': shutil.which('ffmpeg')
    })

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

    url = (data.get('url') or '').strip()
    format_type = str(data.get('format', 'mp4')).lower().strip()
    quality = str(data.get('quality', '720')).lower().strip()

    # Pre-normalize raw TikTok numeric IDs or short links
    if url.isdigit() and len(url) >= 15:
        url = f"https://www.tiktok.com/@user/video/{url}"
    elif url.startswith(('tiktok.com/', 'www.tiktok.com/', 'vm.tiktok.com/', 'vt.tiktok.com/')):
        url = f"https://{url}"

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
    
    # Resilient fallback: locate task file in DOWNLOADS_DIR if path was slightly mismatched
    if not file_path or not os.path.isfile(file_path):
        for fname in os.listdir(DOWNLOADS_DIR):
            if fname.startswith(f"{task_id}_") and not (fname.endswith('.part') or fname.endswith('.temp') or fname.endswith('.ytdl')):
                candidate = os.path.join(DOWNLOADS_DIR, fname)
                if os.path.isfile(candidate):
                    file_path = candidate
                    break

    # Path Traversal Guard & File Existence Check
    if not file_path or not is_safe_filepath(file_path, DOWNLOADS_DIR) or not os.path.isfile(file_path):
        return jsonify({'error': 'Access Denied: Invalid or restricted file path'}), 403

    # Clean download name for the user's browser
    raw_title = progress_data.get('title') or 'video'
    import re
    clean_title = re.sub(r'[\\/*?:"<>|]', "", raw_title).strip() or "video"
    clean_title = re.sub(r'\s+', ' ', clean_title)[:80]
    _, ext = os.path.splitext(file_path)
    clean_download_name = f"{clean_title}{ext}"

    # Background auto-delete after 3 minutes grace period to free disk space
    def secure_delete():
        time.sleep(180)
        try:
            if os.path.isfile(file_path):
                os.remove(file_path)
        except Exception:
            pass
                
    threading.Thread(target=secure_delete, daemon=True).start()
    
    return send_file(file_path, as_attachment=True, download_name=clean_download_name)

if __name__ == '__main__':
    # Production security: debug mode disabled
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=False, threaded=True)
