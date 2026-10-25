import os
import shutil
import uuid
import time
import json
import threading
import urllib.parse
import ipaddress
import secrets
from flask import Flask, render_template, request, jsonify, Response, send_file, redirect, url_for, session, g, abort
from werkzeug.middleware.proxy_fix import ProxyFix

from core.downloader import start_download_thread, get_progress, cancel_download
from core.cleanup import start_cleanup_scheduler
from core.security import (
    validate_url, 
    check_rate_limit, 
    acquire_concurrency_slot, 
    release_concurrency_slot, 
    is_safe_filepath,
    ssrf_safe_socket
)

from datetime import timedelta

# CMS & Database Layer
from core.db import init_db, get_all_settings, get_db_connection
from core.auth import generate_csrf_token, validate_csrf_token, get_current_user, login_required, admin_required
from core.blog_routes import blog_bp
from core.admin_routes import admin_bp

def load_or_generate_secret_key():
    """
    Returns a cryptographically secure session secret key.
    Prioritizes the SECRET_KEY environment variable.
    If absent, generates a persistent 64-byte random key stored in data/.secret_key.
    NEVER falls back to a static hardcoded key in source code.
    """
    env_secret = os.environ.get('SECRET_KEY')
    if env_secret and len(env_secret.strip()) >= 16:
        return env_secret.strip()

    data_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), 'data'))
    os.makedirs(data_dir, exist_ok=True)
    key_file = os.path.join(data_dir, '.secret_key')

    if os.path.isfile(key_file):
        try:
            with open(key_file, 'rb') as f:
                key = f.read().strip()
                if len(key) >= 32:
                    return key
        except Exception:
            pass

    fresh_secret = secrets.token_bytes(64)
    try:
        with open(key_file, 'wb') as f:
            f.write(fresh_secret)
    except Exception:
        pass
    return fresh_secret

app = Flask(__name__)
# Cryptographically strong session key with environment variable support
is_prod = 'DYNO' in os.environ or os.environ.get('FLASK_ENV') == 'production' or os.environ.get('ENVIRONMENT') == 'production'

def is_trusted_proxy():
    return 'DYNO' in os.environ or os.environ.get('TRUST_PROXY', 'false').lower() == 'true'

if is_trusted_proxy():
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1, x_prefix=1)

app.secret_key = load_or_generate_secret_key()
app.config['SESSION_COOKIE_HTTPONLY'] = True
app.config['SESSION_COOKIE_SAMESITE'] = 'Lax'
app.config['SESSION_COOKIE_SECURE'] = is_prod
app.config['SESSION_COOKIE_NAME'] = '__Host-stellar' if is_prod else '__stellar_session'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(hours=6)
app.config['MAX_CONTENT_LENGTH'] = 10 * 1024 * 1024 # 10 MB Max payload limit for media uploads
app.config['TEMPLATES_AUTO_RELOAD'] = True
app.config['SEND_FILE_MAX_AGE_DEFAULT'] = 0

# Concurrency limits for live SSE status streams to prevent Gunicorn thread exhaustion
SSE_STREAM_LOCK = threading.Lock()
ACTIVE_SSE_BY_TASK = {} # {task_id: int}
ACTIVE_SSE_BY_IP = {}   # {client_ip: int}
MAX_SSE_PER_TASK = 2    # Max 2 concurrent SSE listeners per task ID
MAX_SSE_PER_IP = 3      # Max 3 concurrent SSE listeners per client IP

# Initialize Database Schema safely
try:
    init_db()
except Exception as e:
    import traceback
    print(f"[DATABASE INIT ERROR] Could not initialize database on boot: {e}", flush=True)
    traceback.print_exc()

# Custom Secret Admin URL Slug (Default is 'stellar-vault-786', customizable via ADMIN_SLUG in .env)
ADMIN_SLUG = (os.environ.get('ADMIN_SLUG') or 'stellar-vault-786').strip().strip('/')
if not ADMIN_SLUG:
    ADMIN_SLUG = 'stellar-vault-786'

# Register Blueprints
app.register_blueprint(blog_bp)
app.register_blueprint(admin_bp, url_prefix=f'/{ADMIN_SLUG}')

# Decoy 404 for standard /admin scanning bots
if ADMIN_SLUG != 'admin':
    @app.route('/admin', defaults={'path': ''})
    @app.route('/admin/<path:path>')
    def decoy_admin_path(path):
        abort(404)

# Global Jinja Template Context Processor (Auto-syncs settings to ALL templates)
@app.context_processor
def inject_globals():
    return {
        'csrf_token': generate_csrf_token,
        'current_user': get_current_user(),
        'settings': get_all_settings(),
        'csp_nonce': getattr(g, 'csp_nonce', ''),
        'admin_slug': ADMIN_SLUG
    }

DOWNLOADS_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), 'downloads'))
os.makedirs(DOWNLOADS_DIR, exist_ok=True)

# Start background cleanup scheduler for temporary files (every 10 minutes)
start_cleanup_scheduler(DOWNLOADS_DIR)

# Custom Security Error Handlers (Prevents Framework Information Disclosure)
@app.errorhandler(400)
def handle_400(e):
    if request.path.startswith('/api/') or request.is_json:
        return jsonify({'error': 'Bad request'}), 400
    return "<h3>400 Bad Request</h3>", 400

@app.errorhandler(403)
def handle_403(e):
    if request.path.startswith('/api/') or request.is_json:
        return jsonify({'error': 'Access denied'}), 403
    return "<h3>403 Access Denied</h3>", 403

@app.errorhandler(404)
def handle_404(e):
    if request.path.startswith('/api/') or request.is_json:
        return jsonify({'error': 'Resource not found'}), 404
    return "<h3>404 Not Found</h3><p>The requested URL was not found on this server.</p>", 404

@app.errorhandler(413)
def handle_413(e):
    if request.path.startswith('/api/') or request.is_json:
        return jsonify({'error': 'Payload size exceeds 10MB limit'}), 413
    return "<h3>413 Payload Too Large (10MB limit)</h3>", 413

@app.errorhandler(429)
def handle_429(e):
    if request.path.startswith('/api/') or request.is_json:
        return jsonify({'error': 'Too many requests. Please slow down.'}), 429
    return "<h3>429 Too Many Requests</h3>", 429

@app.errorhandler(500)
def handle_500(e):
    if request.path.startswith('/api/') or request.is_json:
        return jsonify({'error': 'Internal server error occurred'}), 500
    return "<h3>500 Internal Server Error</h3>", 500

# HTTPS Enforcement & CSRF / Cross-Origin POST Attack Protection Middleware
@app.before_request
def security_before_request():
    # Generate cryptographic per-request CSP nonce
    g.csp_nonce = secrets.token_hex(16)

    # 1. Enforce HTTPS Redirection on production / public domains
    host = (request.headers.get('X-Forwarded-Host') or request.headers.get('Host') or '').split(':')[0].lower()
    is_public = host and not (host.startswith(('127.', '192.168.', '10.', '172.16.')) or host in ['localhost', 'testserver'])
    
    # Strictly trust forwarded proto ONLY if behind an authorized trusted proxy
    if is_trusted_proxy():
        is_https = (request.headers.get('X-Forwarded-Proto', 'http').lower() == 'https') or request.is_secure
    else:
        is_https = request.is_secure

    # Dynamic Session Cookie Security: If request is HTTPS or on public domain / prod, enforce Secure flag
    if is_https or is_public or is_prod:
        app.config['SESSION_COOKIE_SECURE'] = True
    else:
        app.config['SESSION_COOKIE_SECURE'] = False

    if (is_prod or is_public) and not is_https:
        https_url = request.url.replace('http://', 'https://', 1)
        return redirect(https_url, code=301)

    # 2. CSRF & Cross-Origin State-Changing Request Guard
    if request.method in ['POST', 'PUT', 'DELETE', 'PATCH']:
        origin = request.headers.get('Origin')
        referer = request.headers.get('Referer')
        
        expected_host = request.headers.get('X-Forwarded-Host') or request.headers.get('Host')

        def _clean_host(h):
            if not h: return ''
            h = h.split(':')[0].lower().strip()
            if h.startswith('www.'):
                h = h[4:]
            return h

        # Known authorized application domains
        app_domains = {'aryplusdownloader.tech', 'aryplusdownloader.herokuapp.com', 'localhost', '127.0.0.1'}

        # Verify Origin if supplied
        if origin:
            try:
                origin_host = urllib.parse.urlparse(origin).netloc
                ch_origin = _clean_host(origin_host)
                ch_expected = _clean_host(expected_host)
                if ch_origin and ch_expected and ch_origin != ch_expected:
                    if not (ch_origin in app_domains and ch_expected in app_domains):
                        return jsonify({'error': 'Cross-Origin forbidden: Request Origin does not match Host'}), 403
            except Exception:
                return jsonify({'error': 'Malformed Origin header'}), 403
        elif referer:
            try:
                referer_host = urllib.parse.urlparse(referer).netloc
                ch_referer = _clean_host(referer_host)
                ch_expected = _clean_host(expected_host)
                if ch_referer and ch_expected and ch_referer != ch_expected:
                    if not (ch_referer in app_domains and ch_expected in app_domains):
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

    nonce = getattr(g, 'csp_nonce', '')
    nonce_script = f"'nonce-{nonce}' " if nonce else ""
    csp_directives = [
        "default-src 'self'",
        f"script-src 'self' {nonce_script}https://cdnjs.cloudflare.com https://cdn.jsdelivr.net",
        "style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com https://fonts.googleapis.com https://cdn.jsdelivr.net",
        "font-src 'self' https://cdnjs.cloudflare.com https://fonts.gstatic.com data:",
        "img-src 'self' data: https: blob:",
        "media-src 'self' blob: https:",
        "connect-src 'self'",
        "object-src 'none'",
        "base-uri 'self'",
        "form-action 'self'",
        "frame-ancestors 'none'"
    ]
    response.headers['Content-Security-Policy'] = "; ".join(csp_directives)

    # HSTS: Strict-Transport-Security enforced on HTTPS, production environments, and public domains
    host = (request.headers.get('X-Forwarded-Host') or request.headers.get('Host') or '').split(':')[0].lower()
    is_public = host and not (host.startswith(('127.', '192.168.', '10.', '172.16.')) or host in ['localhost', 'testserver'])
    forwarded_proto = request.headers.get('X-Forwarded-Proto', '').lower()

    if request.is_secure or forwarded_proto == 'https' or is_prod or is_public:
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'

    # Prevent intermediate proxy caching of authenticated and personalized session pages (GHSA-68rp-wp8r-4726)
    if request.path.startswith(f'/{ADMIN_SLUG}') or request.path.startswith('/admin') or session.get('user_id') or session.get('_csrf_token'):
        response.headers['Vary'] = 'Cookie'

    # Anti-indexing headers: Ensure Search Engines NEVER index admin panel, login, setup, or internal APIs
    if (request.path.startswith(f'/{ADMIN_SLUG}') or 
        request.path.startswith('/admin') or 
        request.path.startswith('/api/')):
        response.headers['X-Robots-Tag'] = 'noindex, nofollow, noarchive, nosnippet'

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
    conn = get_db_connection()
    recent_articles = conn.execute("""
        SELECT a.id, a.title, a.slug, a.excerpt, a.featured_image, a.author_name,
               a.published_at, a.created_at, c.name as category_name, c.slug as category_slug
        FROM articles a
        LEFT JOIN categories c ON a.category_id = c.id
        WHERE a.status = 'published' AND a.published_at <= CURRENT_TIMESTAMP
        ORDER BY a.published_at DESC
        LIMIT 3
    """).fetchall()
    conn.close()
    return render_template('index.html', recent_articles=recent_articles)

@app.route('/preview')
def preview_ui():
    return redirect(url_for('index'))

@app.route('/api/health')
def health_check():
    """Sanitized public health endpoint for deployment probes and load balancers."""
    return jsonify({
        'status': 'healthy',
        'service': 'Stellar Engine'
    })

@app.route('/api/debug_ytdlp')
@login_required
@admin_required
def debug_ytdlp():
    """Restricted diagnostic tool accessible ONLY to authenticated administrators."""
    url = request.args.get('url', 'https://www.youtube.com/watch?v=Z3QQUSysT9M').strip()
    # SSRF Protection: Prevent internal loopback / cloud metadata scanning via diagnostic endpoint
    is_valid_url, err_msg = validate_url(url)
    if not is_valid_url:
        return jsonify({'status': 'rejected', 'error': f'SSRF Protection: {err_msg}'}), 400

    import yt_dlp
    logs = []
    class CustomLogger:
        def debug(self, msg): logs.append(f"DEBUG: {msg}")
        def info(self, msg): logs.append(f"INFO: {msg}")
        def warning(self, msg): logs.append(f"WARN: {msg}")
        def error(self, msg): logs.append(f"ERROR: {msg}")

    repo_root = os.path.dirname(os.path.abspath(__file__))
    cookies_path = os.path.join(repo_root, 'cookies.txt')
    qjs_path = os.path.join(repo_root, 'bin', 'qjs')

    opts = {
        'logger': CustomLogger(),
        'verbose': True,
        'force_ipv4': True,
        'noplaylist': True,
        'cookiefile': cookies_path if os.path.isfile(cookies_path) and os.path.getsize(cookies_path) > 100 else None,
        'extractor_args': {
            'youtube': {
                'player_client': ['visionos', 'ios', 'android']
            }
        }
    }
    if os.name != 'nt' and os.path.isfile(qjs_path):
        opts['js_runtimes'] = {'quickjs': {'path': qjs_path}}
        try:
            import yt_dlp_ejs
        except ImportError:
            opts['remote_components'] = ['ejs:github']

    result = {}
    try:
        with ssrf_safe_socket():
            with yt_dlp.YoutubeDL(opts) as ydl:
                info = ydl.extract_info(url, download=False)
                result['title'] = info.get('title')
                result['formats_count'] = len(info.get('formats', []))
                result['status'] = 'success'
    except Exception as e:
        result['status'] = 'failed'
        result['exception'] = str(e)

    result['logs'] = logs
    return jsonify(result)

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

    # CSRF Verification for active browser sessions
    csrf_token = request.headers.get('X-CSRFToken') or data.get('csrf_token')
    if session.get('_csrf_token') and not validate_csrf_token(csrf_token):
        return jsonify({'error': 'Security validation failed: Invalid or expired CSRF token. Please refresh the page.'}), 403

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

    # Thread Exhaustion & DoS Guard 1: Verify task exists before keeping SSE stream open
    initial_check = get_progress(task_id)
    if initial_check is None:
        # Grace period for worker thread launch
        for _ in range(2):
            time.sleep(1)
            initial_check = get_progress(task_id)
            if initial_check:
                break
        if initial_check is None:
            return jsonify({'error': 'Task not found or expired'}), 404

    # Thread Exhaustion & DoS Guard 2: Enforce strict concurrency limits per task and per IP
    client_ip = get_client_ip()
    with SSE_STREAM_LOCK:
        if ACTIVE_SSE_BY_TASK.get(task_id, 0) >= MAX_SSE_PER_TASK:
            return jsonify({'error': 'Too many active monitor connections for this task'}), 429
        if ACTIVE_SSE_BY_IP.get(client_ip, 0) >= MAX_SSE_PER_IP:
            return jsonify({'error': 'Too many active monitor connections from your IP. Please close extra tabs.'}), 429

        ACTIVE_SSE_BY_TASK[task_id] = ACTIVE_SSE_BY_TASK.get(task_id, 0) + 1
        ACTIVE_SSE_BY_IP[client_ip] = ACTIVE_SSE_BY_IP.get(client_ip, 0) + 1

    def event_stream():
        max_duration = 300 # 5 minutes maximum stream duration to protect WSGI threads
        start_time = time.time()
        try:
            while True:
                if time.time() - start_time > max_duration:
                    yield f"data: {{\"status\": \"error\", \"error\": \"Connection stream timed out.\"}}\n\n"
                    break

                progress_data = get_progress(task_id)
                if not progress_data:
                    yield f"data: {{\"status\": \"error\", \"error\": \"Task expired.\"}}\n\n"
                    break

                yield f"data: {json.dumps(progress_data)}\n\n"
                if progress_data.get('status') in ['finished', 'error', 'cancelled']:
                    break
                time.sleep(1)
        finally:
            with SSE_STREAM_LOCK:
                if task_id in ACTIVE_SSE_BY_TASK and ACTIVE_SSE_BY_TASK[task_id] > 0:
                    ACTIVE_SSE_BY_TASK[task_id] -= 1
                    if ACTIVE_SSE_BY_TASK[task_id] == 0:
                        del ACTIVE_SSE_BY_TASK[task_id]
                if client_ip in ACTIVE_SSE_BY_IP and ACTIVE_SSE_BY_IP[client_ip] > 0:
                    ACTIVE_SSE_BY_IP[client_ip] -= 1
                    if ACTIVE_SSE_BY_IP[client_ip] == 0:
                        del ACTIVE_SSE_BY_IP[client_ip]

    return Response(event_stream(), mimetype="text/event-stream")

@app.route('/api/cancel/<task_id>', methods=['POST'])
def cancel(task_id):
    # Security: Strict UUID format validation
    try:
        uuid.UUID(task_id)
    except ValueError:
        return jsonify({'error': 'Invalid task ID format'}), 400

    csrf_token = request.headers.get('X-CSRFToken') or request.form.get('csrf_token')
    if session.get('_csrf_token') and not validate_csrf_token(csrf_token):
        return jsonify({'error': 'Security validation failed: Invalid or expired CSRF token'}), 403
        
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
