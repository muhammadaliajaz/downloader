import secrets
import time
import threading
import urllib.parse
from functools import wraps
from flask import session, redirect, url_for, flash, request, abort
from werkzeug.security import generate_password_hash, check_password_hash
from core.db import get_db_connection

# In-memory store for login rate limiting: {identifier: {'count': int, 'first_attempt': float, 'locked_until': float}}
LOGIN_ATTEMPTS = {}
AUTH_LOCK = threading.Lock()

MAX_FAILED_ATTEMPTS = 5
LOCKOUT_DURATION = 300 # 5 minutes lockout

def is_safe_redirect_url(target: str) -> bool:
    """Verifies that redirect destination is strictly on-site to block Open Redirect attacks."""
    if not target:
        return False
    target = target.strip()
    if target.startswith('\\') or target.startswith('//'):
        return False
    parsed = urllib.parse.urlparse(target)
    if parsed.scheme and parsed.scheme not in ('http', 'https'):
        return False
    if parsed.netloc:
        host = request.headers.get('Host', '')
        return parsed.netloc.lower() == host.lower()
    return True

def hash_password(password: str) -> str:
    """Hashes password using werkzeug modern security standards."""
    return generate_password_hash(password)

def verify_password(stored_hash: str, password: str) -> bool:
    """Verifies a plain password against the stored hash."""
    return check_password_hash(stored_hash, password)

def check_login_rate_limit(client_ip: str, username: str = None):
    """
    Checks if client IP or IP+username pair is currently rate-limited/locked out.
    Locks the offending IP, preventing DoS lockout of legitimate users across other IPs.
    Returns (is_allowed: bool, remaining_lockout_seconds: int)
    """
    now = time.time()
    keys_to_check = [f"ip:{client_ip}"]
    if username:
        keys_to_check.append(f"pair:{client_ip}:{username.lower().strip()}")

    with AUTH_LOCK:
        for k in keys_to_check:
            record = LOGIN_ATTEMPTS.get(k)
            if record:
                # Check if locked
                if record.get('locked_until', 0) > now:
                    remaining = int(record['locked_until'] - now)
                    return False, remaining
                # Clean expired records
                if now - record.get('first_attempt', 0) > LOCKOUT_DURATION:
                    del LOGIN_ATTEMPTS[k]

        return True, 0

def record_failed_login(client_ip: str, username: str = None):
    """Records a failed login attempt for the offending IP, locking if threshold reached."""
    now = time.time()
    keys_to_record = [f"ip:{client_ip}"]
    if username:
        keys_to_record.append(f"pair:{client_ip}:{username.lower().strip()}")

    with AUTH_LOCK:
        for k in keys_to_record:
            if k not in LOGIN_ATTEMPTS:
                LOGIN_ATTEMPTS[k] = {'count': 1, 'first_attempt': now, 'locked_until': 0}
            else:
                LOGIN_ATTEMPTS[k]['count'] += 1
                if LOGIN_ATTEMPTS[k]['count'] >= MAX_FAILED_ATTEMPTS:
                    LOGIN_ATTEMPTS[k]['locked_until'] = now + LOCKOUT_DURATION

def reset_login_attempts(client_ip: str, username: str = None):
    """Resets failed attempts upon successful authentication."""
    keys_to_clear = [f"ip:{client_ip}"]
    if username:
        keys_to_clear.append(f"pair:{client_ip}:{username.lower().strip()}")

    with AUTH_LOCK:
        for k in keys_to_clear:
            if k in LOGIN_ATTEMPTS:
                del LOGIN_ATTEMPTS[k]

def login_user(user_dict, remember: bool = False):
    """Logs the user into the current session, rotates security tokens, and sets cookie persistence."""
    session.clear()
    
    # Ensure user has a security stamp in DB for session revocation
    stamp = user_dict['security_stamp'] if 'security_stamp' in user_dict.keys() else None
    if not stamp:
        stamp = secrets.token_hex(16)
        conn = get_db_connection()
        conn.execute("UPDATE users SET security_stamp = ? WHERE id = ?", (stamp, user_dict['id']))
        conn.commit()
        conn.close()

    session['user_id'] = user_dict['id']
    session['username'] = user_dict['username']
    session['email'] = user_dict['email']
    session['role'] = user_dict['role']
    session['security_stamp'] = stamp
    session['logged_in_at'] = time.time()
    session['_csrf_token'] = secrets.token_hex(32)
    
    # Session Persistence:
    # If remember is False, cookie is a pure Session Cookie (browser close = automatic logout)
    # If remember is True, cookie stays active for configured lifetime (6 hours)
    session.permanent = bool(remember)

    # Update last_login in database
    conn = get_db_connection()
    conn.execute("UPDATE users SET last_login = CURRENT_TIMESTAMP WHERE id = ?", (user_dict['id'],))
    conn.commit()
    conn.close()

def logout_user():
    """Logs the current user out."""
    session.clear()

def is_authenticated() -> bool:
    """Checks if a user is currently authenticated in session and verifies session security stamp."""
    user_id = session.get('user_id')
    if not user_id:
        return False
    
    sess_stamp = session.get('security_stamp')
    conn = get_db_connection()
    user = conn.execute("SELECT id, security_stamp FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()
    
    if not user:
        session.clear()
        return False

    # If user security_stamp exists in DB, ensure session matches (revokes on password change)
    if user['security_stamp'] and sess_stamp and user['security_stamp'] != sess_stamp:
        session.clear()
        return False

    return True

def get_current_user():
    """Returns the current logged-in user dictionary or None."""
    user_id = session.get('user_id')
    if not user_id:
        return None
    conn = get_db_connection()
    user = conn.execute("""
        SELECT id, username, email, role, display_name, created_at, last_login, security_stamp,
               mfa_enabled, mfa_secret, mfa_backup_codes, recovery_key_hash
        FROM users WHERE id = ?
    """, (user_id,)).fetchone()
    conn.close()
    return user

def login_required(f):
    """Decorator to require login for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_authenticated():
            conn = get_db_connection()
            user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
            conn.close()
            if user_count == 0:
                return redirect(url_for('admin.setup'))
            flash('Please log in to access this page.', 'warning')
            return redirect(url_for('admin.login', next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def admin_required(f):
    """Decorator to require admin role for a route."""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not is_authenticated():
            flash('Please log in to access this area.', 'warning')
            return redirect(url_for('admin.login', next=request.url))
        if session.get('role') != 'admin':
            abort(403)
        return f(*args, **kwargs)
    return decorated_function

# CSRF Token Utilities
def generate_csrf_token() -> str:
    """Generates and stores a cryptographically secure CSRF token in session."""
    if '_csrf_token' not in session:
        session['_csrf_token'] = secrets.token_hex(32)
    return session['_csrf_token']

def validate_csrf_token(token: str) -> bool:
    """Validates submitted CSRF token against session token."""
    session_token = session.get('_csrf_token')
    if not session_token or not token:
        return False
    return secrets.compare_digest(session_token, token)
