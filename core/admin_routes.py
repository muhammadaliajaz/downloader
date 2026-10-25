import math
import os
import secrets
import re
from datetime import datetime, timezone
from flask import (
    Blueprint, render_template, request, redirect, url_for, flash, 
    session, jsonify, abort, current_app, send_file
)
from core.db import (
    get_db_connection, check_and_publish_scheduled, get_setting, set_setting,
    get_all_settings, log_audit_event, DB_PATH
)
from core.auth import (
    hash_password, verify_password, login_user, logout_user, 
    login_required, admin_required, check_login_rate_limit, 
    record_failed_login, reset_login_attempts, validate_csrf_token,
    get_current_user, is_safe_redirect_url
)
from core.totp import (
    generate_base32_secret, get_totp_code, verify_totp_code,
    generate_qr_code_data_uri, generate_backup_scratch_codes,
    verify_and_consume_backup_code, generate_emergency_recovery_key,
    verify_emergency_recovery_key
)
from core.sanitizer import sanitize_html, slugify, generate_excerpt
from core.media import save_media_file

ADMIN_SLUG = (os.environ.get('ADMIN_SLUG') or 'stellar-vault-786').strip().strip('/')
if not ADMIN_SLUG:
    ADMIN_SLUG = 'stellar-vault-786'

admin_bp = Blueprint('admin', __name__, url_prefix=f'/{ADMIN_SLUG}')

ADMIN_LAST_SCHEDULED_CHECK = 0

@admin_bp.before_request
def check_scheduled():
    """Checks and updates any scheduled articles before admin operations (throttled to 60s)."""
    global ADMIN_LAST_SCHEDULED_CHECK
    import time
    now = time.time()
    if now - ADMIN_LAST_SCHEDULED_CHECK < 60:
        return
    ADMIN_LAST_SCHEDULED_CHECK = now
    try:
        check_and_publish_scheduled()
    except Exception:
        pass

# -------------------------------------------------------------
# 1. SETUP & AUTHENTICATION
# -------------------------------------------------------------

@admin_bp.route('/setup', methods=['GET', 'POST'])
def setup():
    """Initial Administrator Account Setup Wizard (active only if 0 users exist)."""
    conn = get_db_connection()
    user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    
    if user_count > 0:
        conn.close()
        flash('Administrator setup has already been completed.', 'info')
        return redirect(url_for('admin.login'))

    if request.method == 'POST':
        # CSRF check
        if not validate_csrf_token(request.form.get('csrf_token', '')):
            flash('Security token invalid or expired. Please try again.', 'error')
            conn.close()
            return render_template('admin/setup.html')

        username = request.form.get('username', '').strip()
        display_name = request.form.get('display_name', '').strip() or username
        email = request.form.get('email', '').strip().lower()
        password = request.form.get('password', '')
        confirm_password = request.form.get('confirm_password', '')
        site_title = request.form.get('site_title', '').strip()

        if not username or len(username) < 3:
            flash('Username must be at least 3 characters long.', 'error')
        elif not email or '@' not in email:
            flash('Please provide a valid email address.', 'error')
        elif not password or len(password) < 8:
            flash('Password must be at least 8 characters long.', 'error')
        elif password != confirm_password:
            flash('Passwords do not match.', 'error')
        else:
            hashed = hash_password(password)
            stamp = secrets.token_hex(16)
            rec_plain, rec_hash = generate_emergency_recovery_key()
            cursor = conn.cursor()
            cursor.execute('''
                INSERT INTO users (username, display_name, email, password_hash, role, security_stamp, recovery_key_hash)
                VALUES (?, ?, ?, ?, 'admin', ?, ?)
            ''', (username, display_name, email, hashed, stamp, rec_hash))
            conn.commit()

            if site_title:
                set_setting('site_title', site_title)

            # Auto-login newly created admin
            new_user = conn.execute("SELECT * FROM users WHERE id = ?", (cursor.lastrowid,)).fetchone()
            conn.close()
            login_user(new_user, remember=False)
            log_audit_event('ACCOUNT_SETUP', f"Initial admin '{username}' initialized", user_id=new_user['id'], username=username, ip_address=request.remote_addr)
            flash(f'Admin account created! Your Emergency Recovery Key is: {rec_plain}. Save this key safely to reset your password if you ever forget it.', 'success')
            return redirect(url_for('admin.account'))

    conn.close()
    return render_template('admin/setup.html')

@admin_bp.route('/login', methods=['GET', 'POST'])
def login():
    """Secure login with brute-force rate limiting, 2FA prompt, audit logging, and CSRF protection."""
    conn = get_db_connection()
    user_count = conn.execute("SELECT COUNT(*) FROM users").fetchone()[0]
    conn.close()

    if user_count == 0:
        return redirect(url_for('admin.setup'))

    if session.get('user_id'):
        return redirect(url_for('admin.dashboard'))

    client_ip = request.remote_addr or '127.0.0.1'

    if request.method == 'POST':
        username_or_email = request.form.get('username', '').strip()
        password = request.form.get('password', '')
        remember_me = bool(request.form.get('remember_me') or request.form.get('remember'))

        # Rate Limiting check on IP and identifier
        allowed, remaining = check_login_rate_limit(client_ip, username=username_or_email)
        if not allowed:
            log_audit_event('SECURITY_LOCKOUT', f"Account login temporarily locked for identifier '{username_or_email}'", ip_address=client_ip, user_agent=request.headers.get('User-Agent'))
            flash(f'Too many failed attempts. Login temporarily locked. Please wait {remaining} seconds.', 'error')
            return render_template('admin/login.html')

        # CSRF validation
        if not validate_csrf_token(request.form.get('csrf_token', '')):
            log_audit_event('CSRF_FAILURE', f"Invalid CSRF token during login attempt", ip_address=client_ip)
            flash('Security token invalid or expired. Please refresh and try again.', 'error')
            return render_template('admin/login.html')

        if not username_or_email or not password:
            flash('Please enter both username/email and password.', 'error')
            return render_template('admin/login.html')

        conn = get_db_connection()
        user = conn.execute('''
            SELECT * FROM users 
            WHERE username = ? OR email = ?
        ''', (username_or_email, username_or_email.lower())).fetchone()
        conn.close()

        if user and verify_password(user['password_hash'], password):
            reset_login_attempts(client_ip, username=username_or_email)
            
            # Open redirect defense
            next_url = request.args.get('next') or url_for('admin.dashboard')
            if not is_safe_redirect_url(next_url):
                next_url = url_for('admin.dashboard')

            # Check if 2FA is active on account
            if user['mfa_enabled'] and user['mfa_secret']:
                session['2fa_pending_user_id'] = user['id']
                session['2fa_pending_remember'] = remember_me
                session['2fa_pending_next'] = next_url
                log_audit_event('2FA_PROMPT', f"Credentials verified for '{user['username']}', prompting 2FA code", user_id=user['id'], username=user['username'], ip_address=client_ip)
                return redirect(url_for('admin.login_2fa'))

            login_user(user, remember=remember_me)
            log_audit_event('LOGIN_SUCCESS', f"User '{user['username']}' logged in successfully (Remember: {remember_me})", user_id=user['id'], username=user['username'], ip_address=client_ip, user_agent=request.headers.get('User-Agent'))
            flash(f'Welcome back, {user["username"]}!', 'success')
            return redirect(next_url)
        else:
            record_failed_login(client_ip, username=username_or_email)
            log_audit_event('LOGIN_FAILED', f"Failed login attempt for identifier '{username_or_email}'", ip_address=client_ip, user_agent=request.headers.get('User-Agent'))
            flash('Invalid username or password. Please try again.', 'error')

    return render_template('admin/login.html')

@admin_bp.route('/login/2fa', methods=['GET', 'POST'])
def login_2fa():
    """Second-step authentication for accounts with 2FA / TOTP enabled."""
    user_id = session.get('2fa_pending_user_id')
    if not user_id:
        return redirect(url_for('admin.login'))

    conn = get_db_connection()
    user = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    conn.close()

    if not user or not user['mfa_enabled'] or not user['mfa_secret']:
        session.pop('2fa_pending_user_id', None)
        return redirect(url_for('admin.login'))

    client_ip = request.remote_addr or '127.0.0.1'

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token', '')):
            flash('Security token expired. Please try again.', 'error')
            return render_template('admin/login_2fa.html', username=user['username'])

        allowed, remaining = check_login_rate_limit(client_ip, username=user['username'])
        if not allowed:
            flash(f'Too many failed attempts. Locked for {remaining} seconds.', 'error')
            return render_template('admin/login_2fa.html', username=user['username'])

        code_input = request.form.get('totp_code', '').strip()
        is_valid = False
        used_backup = False

        # 1. Try TOTP authenticator code (6 digits, +-2 min clock skew tolerance)
        if verify_totp_code(user['mfa_secret'], code_input, window=4):
            is_valid = True
        # 2. Try single-use backup scratch code (e.g. XXXX-XXXX)
        elif user['mfa_backup_codes']:
            is_valid, updated_json = verify_and_consume_backup_code(user['mfa_backup_codes'], code_input)
            if is_valid:
                used_backup = True
                conn = get_db_connection()
                conn.execute("UPDATE users SET mfa_backup_codes = ? WHERE id = ?", (updated_json, user['id']))
                conn.commit()
                conn.close()

        if is_valid:
            remember_me = session.pop('2fa_pending_remember', False)
            next_url = session.pop('2fa_pending_next', url_for('admin.dashboard'))
            session.pop('2fa_pending_user_id', None)

            reset_login_attempts(client_ip, username=user['username'])
            login_user(user, remember=remember_me)

            method_str = "Emergency Backup Code" if used_backup else "Google Authenticator TOTP"
            log_audit_event('LOGIN_SUCCESS_2FA', f"User '{user['username']}' completed 2FA via {method_str}", user_id=user['id'], username=user['username'], ip_address=client_ip, user_agent=request.headers.get('User-Agent'))
            flash(f'2FA verification successful. Welcome back, {user["username"]}!', 'success')
            return redirect(next_url)
        else:
            record_failed_login(client_ip, username=user['username'])
            log_audit_event('LOGIN_2FA_FAILED', f"Invalid 2FA code entered for user '{user['username']}'", user_id=user['id'], username=user['username'], ip_address=client_ip)
            flash('Invalid 2FA code or backup code. Please try again.', 'error')

    return render_template('admin/login_2fa.html', username=user['username'])

@admin_bp.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    """Emergency Account Recovery via Master Recovery Key."""
    if session.get('user_id'):
        return redirect(url_for('admin.dashboard'))

    client_ip = request.remote_addr or '127.0.0.1'

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token', '')):
            flash('Security token invalid or expired. Please refresh and try again.', 'error')
            return render_template('admin/forgot_password.html')

        username_or_email = request.form.get('username', '').strip()
        recovery_key = request.form.get('recovery_key', '').strip()
        new_password = request.form.get('new_password', '')
        confirm_password = request.form.get('confirm_password', '')

        allowed, remaining = check_login_rate_limit(client_ip, username=username_or_email)
        if not allowed:
            flash(f'Too many attempts. Account locked. Please wait {remaining} seconds.', 'error')
            return render_template('admin/forgot_password.html')

        conn = get_db_connection()
        user = conn.execute(
            "SELECT * FROM users WHERE username = ? OR email = ?",
            (username_or_email, username_or_email.lower())
        ).fetchone()

        if not user or not user['recovery_key_hash']:
            record_failed_login(client_ip, username=username_or_email)
            log_audit_event('RECOVERY_FAILED', f"Recovery attempted with invalid identifier '{username_or_email}'", ip_address=client_ip)
            flash('Invalid account identifier or emergency recovery key.', 'error')
            conn.close()
            return render_template('admin/forgot_password.html')

        if not verify_emergency_recovery_key(user['recovery_key_hash'], recovery_key):
            record_failed_login(client_ip, username=username_or_email)
            log_audit_event('RECOVERY_FAILED', f"Invalid emergency recovery key for user '{user['username']}'", user_id=user['id'], username=user['username'], ip_address=client_ip)
            flash('Invalid emergency recovery key. Please check your backup records.', 'error')
            conn.close()
            return render_template('admin/forgot_password.html')

        if not new_password or len(new_password) < 8:
            flash('New password must be at least 8 characters long.', 'error')
            conn.close()
            return render_template('admin/forgot_password.html')
        elif not re.search(r'[A-Za-z]', new_password) or not re.search(r'[0-9!@#$%^&*(),.?":{}|<>]', new_password):
            flash('New password must contain both letters and at least one number or special symbol.', 'error')
            conn.close()
            return render_template('admin/forgot_password.html')
        elif new_password != confirm_password:
            flash('New password and confirmation do not match.', 'error')
            conn.close()
            return render_template('admin/forgot_password.html')

        # Reset password, rotate security stamp, and generate a FRESH recovery key
        new_hash = hash_password(new_password)
        new_stamp = secrets.token_hex(16)
        new_rec_plain, new_rec_hash = generate_emergency_recovery_key()

        conn.execute("""
            UPDATE users
            SET password_hash = ?, security_stamp = ?, recovery_key_hash = ?,
                mfa_enabled = 0, mfa_secret = NULL, mfa_backup_codes = NULL
            WHERE id = ?
        """, (new_hash, new_stamp, new_rec_hash, user['id']))
        conn.commit()
        conn.close()

        reset_login_attempts(client_ip, username=user['username'])
        log_audit_event('PASSWORD_RECOVERED', f"Password reset via emergency key for user '{user['username']}'. 2FA reset, all sessions revoked.", user_id=user['id'], username=user['username'], ip_address=client_ip)

        flash(f'Password reset successfully! Your NEW Emergency Recovery Key is: {new_rec_plain}. Please store it in a secure location.', 'success')
        return redirect(url_for('admin.login'))

    return render_template('admin/forgot_password.html')

@admin_bp.route('/logout', methods=['GET', 'POST'])
def logout():
    """Secure logout clearing session and logging event."""
    u_id = session.get('user_id')
    u_name = session.get('username')
    logout_user()
    log_audit_event('LOGOUT', f"User '{u_name}' logged out", user_id=u_id, username=u_name, ip_address=request.remote_addr)
    flash('You have been successfully logged out.', 'info')
    return redirect(url_for('admin.login'))

@admin_bp.route('/database/backup', methods=['GET'])
@login_required
@admin_required
def database_backup():
    """Secure on-demand database backup download for server admin."""
    if not os.path.isfile(DB_PATH):
        flash('Database file not found.', 'error')
        return redirect(url_for('admin.account'))
    
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    log_audit_event('DB_BACKUP_DOWNLOADED', f"Full database backup downloaded by '{session.get('username')}'", user_id=session.get('user_id'), username=session.get('username'), ip_address=request.remote_addr)
    return send_file(DB_PATH, as_attachment=True, download_name=f"stellar_cms_backup_{timestamp}.db")

# -------------------------------------------------------------
# 2. DASHBOARD OVERVIEW
# -------------------------------------------------------------

@admin_bp.route('/', strict_slashes=False)
@login_required
def dashboard():
    """Admin dashboard with high-level statistics and recent articles."""
    conn = get_db_connection()
    
    # Metrics
    published_count = conn.execute("SELECT COUNT(*) FROM articles WHERE status = 'published' AND published_at <= CURRENT_TIMESTAMP").fetchone()[0]
    drafts_count = conn.execute("SELECT COUNT(*) FROM articles WHERE status = 'draft'").fetchone()[0]
    scheduled_count = conn.execute("SELECT COUNT(*) FROM articles WHERE status = 'scheduled'").fetchone()[0]
    categories_count = conn.execute("SELECT COUNT(*) FROM categories").fetchone()[0]
    total_views = conn.execute("SELECT COALESCE(SUM(views_count), 0) FROM articles").fetchone()[0]
    media_count = conn.execute("SELECT COUNT(*) FROM media").fetchone()[0]

    # Recent articles
    recent_articles = conn.execute("""
        SELECT a.id, a.title, a.slug, a.status, a.published_at, a.scheduled_for, a.created_at, a.views_count,
               c.name as category_name
        FROM articles a
        LEFT JOIN categories c ON a.category_id = c.id
        ORDER BY a.created_at DESC
        LIMIT 6
    """).fetchall()

    conn.close()

    stats = {
        'published': published_count,
        'drafts': drafts_count,
        'scheduled': scheduled_count,
        'categories': categories_count,
        'views': total_views,
        'media': media_count
    }

    return render_template('admin/dashboard.html', stats=stats, recent_articles=recent_articles, current_user=get_current_user())

# -------------------------------------------------------------
# 3. ARTICLES / POSTS MANAGEMENT
# -------------------------------------------------------------

@admin_bp.route('/posts', strict_slashes=False)
@login_required
def posts_list():
    """Articles management table with search, status filters, category filter, and pagination."""
    page = request.args.get('page', 1, type=int)
    search = request.args.get('q', '').strip()
    status_filter = request.args.get('status', '').strip()
    category_id = request.args.get('category_id', type=int)
    per_page = 15

    conn = get_db_connection()
    base_sql = "FROM articles a LEFT JOIN categories c ON a.category_id = c.id WHERE 1=1"
    params = []

    if search:
        base_sql += " AND (a.title LIKE ? OR a.slug LIKE ? OR a.excerpt LIKE ?)"
        term = f"%{search}%"
        params.extend([term, term, term])

    if status_filter:
        base_sql += " AND a.status = ?"
        params.append(status_filter)

    if category_id:
        base_sql += " AND a.category_id = ?"
        params.append(category_id)

    # Count
    total = conn.execute("SELECT COUNT(*) " + base_sql, params).fetchone()[0]
    total_pages = max(1, math.ceil(total / per_page))
    page = max(1, min(page, total_pages))
    offset = (page - 1) * per_page

    posts = conn.execute(f"""
        SELECT a.id, a.title, a.slug, a.status, a.published_at, a.scheduled_for, a.created_at, a.updated_at, a.views_count,
               a.author_name, a.featured_image, c.name as category_name
        {base_sql}
        ORDER BY a.created_at DESC
        LIMIT ? OFFSET ?
    """, params + [per_page, offset]).fetchall()

    categories = conn.execute("SELECT id, name FROM categories ORDER BY name ASC").fetchall()
    conn.close()

    return render_template(
        'admin/posts_list.html',
        posts=posts,
        categories=categories,
        current_page=page,
        total_pages=total_pages,
        total_posts=total,
        search_query=search,
        selected_status=status_filter,
        selected_category=category_id,
        current_user=get_current_user()
    )

@admin_bp.route('/posts/new', methods=['GET', 'POST'], endpoint='post_new', strict_slashes=False)
@admin_bp.route('/posts/new', methods=['GET', 'POST'], endpoint='post_create', strict_slashes=False)
@login_required
def post_create():
    """Create a new article with rich-text editor, scheduling, and SEO meta drawer."""
    conn = get_db_connection()

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token', '')):
            flash('Invalid security token. Please try again.', 'error')
            conn.close()
            return redirect(url_for('admin.post_create'))

        title = request.form.get('title', '').strip()
        custom_slug = request.form.get('slug', '').strip()
        excerpt = request.form.get('excerpt', '').strip()
        raw_content = request.form.get('content', '')
        category_id = request.form.get('category_id', type=int)
        featured_image = request.form.get('featured_image', '').strip() or None
        featured_image_alt = request.form.get('featured_image_alt', '').strip() or None
        author_name = request.form.get('author_name', session.get('username', 'Admin')).strip()
        status = request.form.get('status', 'draft') # 'draft', 'published', 'scheduled'
        scheduled_for = request.form.get('scheduled_for', '').strip()
        raw_tags = request.form.get('tags', '').strip()

        # Advanced SEO Fields
        seo_title = request.form.get('seo_title', '').strip()
        meta_description = request.form.get('meta_description', '').strip()
        canonical_url = request.form.get('canonical_url', '').strip()
        og_title = request.form.get('og_title', '').strip()
        og_description = request.form.get('og_description', '').strip()
        og_image = request.form.get('og_image', '').strip()
        is_noindex = 1 if request.form.get('is_noindex') else 0

        if not title:
            flash('Article title is required.', 'error')
            categories = conn.execute("SELECT id, name FROM categories ORDER BY name ASC").fetchall()
            conn.close()
            return render_template('admin/post_form.html', categories=categories, post={})

        # Sanitize HTML content
        content = sanitize_html(raw_content)

        # Generate unique slug
        base_slug = slugify(custom_slug) if custom_slug else slugify(title)
        slug = base_slug
        suffix = 1
        while conn.execute("SELECT id FROM articles WHERE slug = ?", (slug,)).fetchone():
            slug = f"{base_slug}-{suffix}"
            suffix += 1

        # Auto-generate excerpt if empty
        if not excerpt:
            excerpt = generate_excerpt(content)

        # Determine published / scheduled timestamps
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        published_at = None
        scheduled_ts = None

        if status == 'published':
            published_at = now_str
        elif status == 'scheduled':
            if scheduled_for:
                try:
                    # Clean ISO format
                    dt = datetime.fromisoformat(scheduled_for.replace('Z', ''))
                    scheduled_ts = dt.strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    scheduled_ts = scheduled_for
            else:
                status = 'draft' # Fallback to draft if no date given

        cursor = conn.cursor()
        cursor.execute('''
            INSERT INTO articles (
                title, slug, excerpt, content, featured_image, featured_image_alt,
                category_id, author_name, status, published_at, scheduled_for,
                seo_title, meta_description, canonical_url, og_title, og_description, og_image, is_noindex
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        ''', (
            title, slug, excerpt, content, featured_image, featured_image_alt,
            category_id, author_name, status, published_at, scheduled_ts,
            seo_title, meta_description, canonical_url, og_title, og_description, og_image, is_noindex
        ))
        article_id = cursor.lastrowid

        # Process Tags
        if raw_tags:
            tag_names = [t.strip() for t in raw_tags.split(',') if t.strip()]
            for t_name in tag_names:
                t_slug = slugify(t_name)
                # Find or insert tag
                tag_row = conn.execute("SELECT id FROM tags WHERE slug = ?", (t_slug,)).fetchone()
                if tag_row:
                    tag_id = tag_row['id']
                else:
                    tag_cur = conn.cursor()
                    tag_cur.execute("INSERT INTO tags (name, slug) VALUES (?, ?)", (t_name, t_slug))
                    tag_id = tag_cur.lastrowid
                conn.execute("INSERT OR IGNORE INTO article_tags (article_id, tag_id) VALUES (?, ?)", (article_id, tag_id))

        conn.commit()
        log_audit_event('ARTICLE_CREATED', f"Article '{title}' (ID: {article_id}) saved as {status.upper()}", user_id=session.get('user_id'), username=session.get('username'), ip_address=request.remote_addr)
        conn.close()

        flash(f'Article "{title}" has been saved successfully as {status.upper()}!', 'success')
        return redirect(url_for('admin.posts_list'))

    categories = conn.execute("SELECT id, name FROM categories ORDER BY name ASC").fetchall()
    all_media = conn.execute("SELECT filename, original_name, filepath FROM media ORDER BY uploaded_at DESC LIMIT 24").fetchall()
    conn.close()

    return render_template(
        'admin/post_form.html',
        categories=categories,
        all_media=all_media,
        post={'author_name': session.get('username', 'Admin'), 'status': 'draft'},
        is_edit=False,
        current_user=get_current_user()
    )

@admin_bp.route('/posts/<int:post_id>/edit', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def post_edit(post_id):
    """Edit existing article."""
    conn = get_db_connection()
    post_row = conn.execute("SELECT * FROM articles WHERE id = ?", (post_id,)).fetchone()
    if not post_row:
        conn.close()
        flash('Article not found.', 'error')
        return redirect(url_for('admin.posts_list'))

    post = dict(post_row)

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token', '')):
            flash('Invalid security token.', 'error')
            conn.close()
            return redirect(url_for('admin.post_edit', post_id=post_id))

        title = request.form.get('title', '').strip()
        custom_slug = request.form.get('slug', '').strip()
        excerpt = request.form.get('excerpt', '').strip()
        raw_content = request.form.get('content', '')
        category_id = request.form.get('category_id', type=int)
        featured_image = request.form.get('featured_image', '').strip() or None
        featured_image_alt = request.form.get('featured_image_alt', '').strip() or None
        author_name = request.form.get('author_name', '').strip() or post['author_name']
        new_status = request.form.get('status', 'draft')
        scheduled_for = request.form.get('scheduled_for', '').strip()
        raw_tags = request.form.get('tags', '').strip()

        # Advanced SEO Fields
        seo_title = request.form.get('seo_title', '').strip()
        meta_description = request.form.get('meta_description', '').strip()
        canonical_url = request.form.get('canonical_url', '').strip()
        og_title = request.form.get('og_title', '').strip()
        og_description = request.form.get('og_description', '').strip()
        og_image = request.form.get('og_image', '').strip()
        is_noindex = 1 if request.form.get('is_noindex') else 0

        if not title:
            flash('Article title is required.', 'error')
            conn.close()
            return redirect(url_for('admin.post_edit', post_id=post_id))

        content = sanitize_html(raw_content)

        # Unique slug verification
        base_slug = slugify(custom_slug) if custom_slug else slugify(title)
        slug = base_slug
        suffix = 1
        while True:
            existing = conn.execute("SELECT id FROM articles WHERE slug = ? AND id != ?", (slug, post_id)).fetchone()
            if not existing:
                break
            slug = f"{base_slug}-{suffix}"
            suffix += 1

        if not excerpt:
            excerpt = generate_excerpt(content)

        # Handle publish/schedule transitions
        now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
        published_at = post.get('published_at')
        scheduled_ts = post.get('scheduled_for')

        if new_status == 'published' and not published_at:
            published_at = now_str
        elif new_status == 'scheduled':
            if scheduled_for:
                try:
                    dt = datetime.fromisoformat(scheduled_for.replace('Z', ''))
                    scheduled_ts = dt.strftime('%Y-%m-%d %H:%M:%S')
                except Exception:
                    scheduled_ts = scheduled_for

        conn.execute('''
            UPDATE articles SET
                title = ?, slug = ?, excerpt = ?, content = ?, featured_image = ?, featured_image_alt = ?,
                category_id = ?, author_name = ?, status = ?, published_at = ?, scheduled_for = ?,
                seo_title = ?, meta_description = ?, canonical_url = ?, og_title = ?, og_description = ?,
                og_image = ?, is_noindex = ?, updated_at = CURRENT_TIMESTAMP
            WHERE id = ?
        ''', (
            title, slug, excerpt, content, featured_image, featured_image_alt,
            category_id, author_name, new_status, published_at, scheduled_ts,
            seo_title, meta_description, canonical_url, og_title, og_description,
            og_image, is_noindex, post_id
        ))

        # Update Tags
        conn.execute("DELETE FROM article_tags WHERE article_id = ?", (post_id,))
        if raw_tags:
            tag_names = [t.strip() for t in raw_tags.split(',') if t.strip()]
            for t_name in tag_names:
                t_slug = slugify(t_name)
                tag_row = conn.execute("SELECT id FROM tags WHERE slug = ?", (t_slug,)).fetchone()
                if tag_row:
                    tag_id = tag_row['id']
                else:
                    tag_cur = conn.cursor()
                    tag_cur.execute("INSERT INTO tags (name, slug) VALUES (?, ?)", (t_name, t_slug))
                    tag_id = tag_cur.lastrowid
                conn.execute("INSERT OR IGNORE INTO article_tags (article_id, tag_id) VALUES (?, ?)", (post_id, tag_id))

        conn.commit()
        log_audit_event('ARTICLE_UPDATED', f"Article '{title}' (ID: {post_id}) updated (Status: {new_status.upper()})", user_id=session.get('user_id'), username=session.get('username'), ip_address=request.remote_addr)
        conn.close()

        flash(f'Article "{title}" updated successfully!', 'success')
        return redirect(url_for('admin.posts_list'))

    # Load tags for post
    post_tags = conn.execute("""
        SELECT t.name FROM tags t
        JOIN article_tags at ON t.id = at.tag_id
        WHERE at.article_id = ?
    """, (post_id,)).fetchall()
    post['tags'] = ', '.join([t['name'] for t in post_tags])

    categories = conn.execute("SELECT id, name FROM categories ORDER BY name ASC").fetchall()
    all_media = conn.execute("SELECT filename, original_name, filepath FROM media ORDER BY uploaded_at DESC LIMIT 24").fetchall()
    conn.close()

    return render_template(
        'admin/post_form.html',
        categories=categories,
        all_media=all_media,
        post=post,
        is_edit=True,
        current_user=get_current_user()
    )

@admin_bp.route('/posts/<int:post_id>/toggle-status', methods=['POST'])
@login_required
def post_toggle_status(post_id):
    """Toggles article between draft and published."""
    if not validate_csrf_token(request.form.get('csrf_token', '')):
        flash('Invalid CSRF token.', 'error')
        return redirect(url_for('admin.posts_list'))

    conn = get_db_connection()
    post = conn.execute("SELECT status, title FROM articles WHERE id = ?", (post_id,)).fetchone()
    if not post:
        conn.close()
        flash('Article not found.', 'error')
        return redirect(url_for('admin.posts_list'))

    new_status = 'draft' if post['status'] == 'published' else 'published'
    now_str = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
    
    conn.execute('''
        UPDATE articles SET status = ?, 
               published_at = CASE WHEN ? = 'published' AND published_at IS NULL THEN ? ELSE published_at END,
               updated_at = CURRENT_TIMESTAMP
        WHERE id = ?
    ''', (new_status, new_status, now_str, post_id))
    conn.commit()
    log_audit_event('ARTICLE_STATUS_TOGGLED', f"Article '{post['title']}' status toggled to {new_status.upper()}", user_id=session.get('user_id'), username=session.get('username'), ip_address=request.remote_addr)
    conn.close()

    flash(f'Article "{post["title"]}" status changed to {new_status.upper()}.', 'success')
    return redirect(url_for('admin.posts_list'))

@admin_bp.route('/posts/<int:post_id>/delete', methods=['POST'])
@login_required
def post_delete(post_id):
    """Deletes an article."""
    if not validate_csrf_token(request.form.get('csrf_token', '')):
        flash('Invalid CSRF token.', 'error')
        return redirect(url_for('admin.posts_list'))

    conn = get_db_connection()
    post = conn.execute("SELECT title FROM articles WHERE id = ?", (post_id,)).fetchone()
    if post:
        conn.execute("DELETE FROM articles WHERE id = ?", (post_id,))
        conn.commit()
        log_audit_event('ARTICLE_DELETED', f"Article '{post['title']}' (ID: {post_id}) deleted", user_id=session.get('user_id'), username=session.get('username'), ip_address=request.remote_addr)
        flash(f'Article "{post["title"]}" deleted.', 'success')
    else:
        flash('Article not found.', 'error')
    conn.close()

    return redirect(url_for('admin.posts_list'))

# -------------------------------------------------------------
# 4. CATEGORIES & TAGS MANAGEMENT
# -------------------------------------------------------------

@admin_bp.route('/categories', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def categories():
    """List and create categories."""
    conn = get_db_connection()

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token', '')):
            flash('Invalid CSRF token.', 'error')
            conn.close()
            return redirect(url_for('admin.categories'))

        name = request.form.get('name', '').strip()
        custom_slug = request.form.get('slug', '').strip()
        description = request.form.get('description', '').strip()

        if not name:
            flash('Category name is required.', 'error')
        else:
            base_slug = slugify(custom_slug) if custom_slug else slugify(name)
            slug = base_slug
            suffix = 1
            while conn.execute("SELECT id FROM categories WHERE slug = ?", (slug,)).fetchone():
                slug = f"{base_slug}-{suffix}"
                suffix += 1

            conn.execute("INSERT INTO categories (name, slug, description) VALUES (?, ?, ?)", (name, slug, description))
            conn.commit()
            flash(f'Category "{name}" created.', 'success')
            conn.close()
            return redirect(url_for('admin.categories'))

    categories_list = conn.execute("""
        SELECT c.*, COUNT(a.id) as post_count
        FROM categories c
        LEFT JOIN articles a ON c.id = a.category_id
        GROUP BY c.id
        ORDER BY c.name ASC
    """).fetchall()
    conn.close()

    return render_template('admin/categories.html', categories=categories_list, current_user=get_current_user())

@admin_bp.route('/categories/<int:cat_id>/delete', methods=['POST'])
@login_required
def category_delete(cat_id):
    """Deletes a category."""
    if not validate_csrf_token(request.form.get('csrf_token', '')):
        flash('Invalid CSRF token.', 'error')
        return redirect(url_for('admin.categories'))

    conn = get_db_connection()
    conn.execute("DELETE FROM categories WHERE id = ?", (cat_id,))
    conn.commit()
    conn.close()
    flash('Category deleted.', 'success')
    return redirect(url_for('admin.categories'))

@admin_bp.route('/tags', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def tags():
    """List and manage tags."""
    conn = get_db_connection()

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token', '')):
            flash('Invalid CSRF token.', 'error')
            conn.close()
            return redirect(url_for('admin.tags'))

        name = request.form.get('name', '').strip()
        if name:
            slug = slugify(name)
            conn.execute("INSERT OR IGNORE INTO tags (name, slug) VALUES (?, ?)", (name, slug))
            conn.commit()
            flash(f'Tag "{name}" added.', 'success')
            conn.close()
            return redirect(url_for('admin.tags'))

    tags_list = conn.execute("""
        SELECT t.*, COUNT(at.article_id) as post_count
        FROM tags t
        LEFT JOIN article_tags at ON t.id = at.tag_id
        GROUP BY t.id
        ORDER BY post_count DESC, t.name ASC
    """).fetchall()
    conn.close()

    return render_template('admin/tags.html', tags=tags_list, current_user=get_current_user())

@admin_bp.route('/tags/<int:tag_id>/delete', methods=['POST'])
@login_required
def tag_delete(tag_id):
    """Deletes a tag."""
    if not validate_csrf_token(request.form.get('csrf_token', '')):
        flash('Invalid CSRF token.', 'error')
        return redirect(url_for('admin.tags'))

    conn = get_db_connection()
    conn.execute("DELETE FROM tags WHERE id = ?", (tag_id,))
    conn.commit()
    conn.close()
    flash('Tag deleted.', 'success')
    return redirect(url_for('admin.tags'))

# -------------------------------------------------------------
# 5. MEDIA LIBRARY & UPLOADS
# -------------------------------------------------------------

@admin_bp.route('/media', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def media_library():
    """Media management gallery with file upload and copy link."""
    conn = get_db_connection()

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token', '')):
            flash('Invalid CSRF token.', 'error')
            conn.close()
            return redirect(url_for('admin.media_library'))

        file = request.files.get('file')
        success, res, media_id = save_media_file(file)
        if success:
            flash('Media file uploaded successfully!', 'success')
        else:
            flash(f'Upload failed: {res}', 'error')
        conn.close()
        return redirect(url_for('admin.media_library'))

    page = request.args.get('page', 1, type=int)
    per_page = 24
    total = conn.execute("SELECT COUNT(*) FROM media").fetchone()[0]
    total_pages = max(1, math.ceil(total / per_page))
    offset = (page - 1) * per_page

    media_items = conn.execute("""
        SELECT * FROM media 
        ORDER BY uploaded_at DESC 
        LIMIT ? OFFSET ?
    """, (per_page, offset)).fetchall()
    conn.close()

    return render_template(
        'admin/media.html', 
        media_items=media_items, 
        current_page=page, 
        total_pages=total_pages,
        total_media=total,
        current_user=get_current_user()
    )

@admin_bp.route('/api/upload', methods=['POST'])
@login_required
def api_upload_media():
    """AJAX file upload endpoint for Quill editor drag & drop and image picker."""
    csrf_token = request.headers.get('X-CSRFToken') or request.form.get('csrf_token')
    if not validate_csrf_token(csrf_token):
        return jsonify({'error': 'CSRF verification failed. Please refresh the page.'}), 403

    file = request.files.get('file') or request.files.get('image')
    if not file:
        return jsonify({'error': 'No file provided in request.'}), 400

    success, url_or_error, media_id = save_media_file(file)
    if success:
        return jsonify({
            'success': True,
            'url': url_or_error,
            'media_id': media_id
        })
    else:
        return jsonify({'error': url_or_error}), 400

@admin_bp.route('/media/<int:media_id>/delete', methods=['POST'])
@login_required
def media_delete(media_id):
    """Deletes media file from storage and database."""
    if not validate_csrf_token(request.form.get('csrf_token', '')):
        flash('Invalid CSRF token.', 'error')
        return redirect(url_for('admin.media_library'))

    conn = get_db_connection()
    row = conn.execute("SELECT * FROM media WHERE id = ?", (media_id,)).fetchone()
    if row:
        fp = row['filepath']
        try:
            if os.path.isfile(fp):
                os.remove(fp)
        except Exception:
            pass
        conn.execute("DELETE FROM media WHERE id = ?", (media_id,))
        conn.commit()
        flash('File deleted from library.', 'success')
    conn.close()

    return redirect(url_for('admin.media_library'))

# -------------------------------------------------------------
# 6. WEBSITE SETTINGS
# -------------------------------------------------------------

@admin_bp.route('/settings', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def settings():
    """Website settings configuration."""
    conn = get_db_connection()

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token', '')):
            flash('Invalid CSRF token.', 'error')
            conn.close()
            return redirect(url_for('admin.settings'))

        editable_keys = [
            'site_title', 'site_tagline', 'site_url', 'site_description',
            'contact_email', 'posts_per_page', 'footer_copyright',
            'twitter_url', 'youtube_url', 'facebook_url', 'instagram_url'
        ]

        for k in editable_keys:
            val = request.form.get(k, '').strip()
            set_setting(k, val)

        u_id = session.get('user_id')
        u_name = session.get('username')
        log_audit_event('SETTINGS_UPDATED', 'Platform and website settings saved', user_id=u_id, username=u_name, ip_address=request.remote_addr)

        flash('Website settings have been saved successfully.', 'success')
        conn.close()
        return redirect(url_for('admin.settings'))

    settings_dict = get_all_settings()
    conn.close()

    return render_template('admin/settings.html', settings=settings_dict, current_user=get_current_user())

# -------------------------------------------------------------
# 7. ACCOUNT & SECURITY MANAGEMENT
# -------------------------------------------------------------

@admin_bp.route('/account', methods=['GET', 'POST'], strict_slashes=False)
@login_required
def account():
    """Account Profile, Password Security, Session Invalidation & Audit Log."""
    current_usr = get_current_user()
    if not current_usr:
        return redirect(url_for('admin.login'))

    conn = get_db_connection()

    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token', '')):
            flash('Invalid or expired security token. Please try again.', 'error')
            conn.close()
            return redirect(url_for('admin.account'))

        form_action = request.form.get('action')

        if form_action == 'update_profile':
            display_name = request.form.get('display_name', '').strip() or current_usr['username']
            email = request.form.get('email', '').strip().lower()
            username = request.form.get('username', '').strip()

            if not username or len(username) < 3:
                flash('Username must be at least 3 characters.', 'error')
            elif not email or '@' not in email:
                flash('Please provide a valid email address.', 'error')
            else:
                # Check for existing username/email collision
                existing = conn.execute(
                    "SELECT id FROM users WHERE (username = ? OR email = ?) AND id != ?",
                    (username, email, current_usr['id'])
                ).fetchone()

                if existing:
                    flash('This username or email is already registered to another user.', 'error')
                else:
                    conn.execute(
                        "UPDATE users SET display_name = ?, username = ?, email = ? WHERE id = ?",
                        (display_name, username, email, current_usr['id'])
                    )
                    conn.commit()
                    session['username'] = username
                    session['email'] = email
                    log_audit_event('PROFILE_UPDATED', f"Admin profile updated (Username: {username}, Email: {email})", user_id=current_usr['id'], username=username, ip_address=request.remote_addr)
                    flash('Account profile updated successfully.', 'success')

            conn.close()
            return redirect(url_for('admin.account', tab='profile'))

        elif form_action == 'change_password':
            current_pwd = request.form.get('current_password', '')
            new_pwd = request.form.get('new_password', '')
            confirm_pwd = request.form.get('confirm_password', '')

            # Fetch fresh user record
            user_rec = conn.execute("SELECT password_hash FROM users WHERE id = ?", (current_usr['id'],)).fetchone()

            if not verify_password(user_rec['password_hash'], current_pwd):
                log_audit_event('PASSWORD_CHANGE_FAILED', 'Incorrect current password provided', user_id=current_usr['id'], username=current_usr['username'], ip_address=request.remote_addr)
                flash('Current password is incorrect.', 'error')
            elif not new_pwd or len(new_pwd) < 8:
                flash('New password must be at least 8 characters long.', 'error')
            elif not re.search(r'[A-Za-z]', new_pwd) or not re.search(r'[0-9!@#$%^&*(),.?":{}|<>]', new_pwd):
                flash('New password must contain both letters and at least one number or special symbol.', 'error')
            elif new_pwd != confirm_pwd:
                flash('New password and confirmation do not match.', 'error')
            elif verify_password(user_rec['password_hash'], new_pwd):
                flash('New password cannot be the same as your current password.', 'error')
            else:
                new_hash = hash_password(new_pwd)
                new_stamp = secrets.token_hex(16)
                conn.execute(
                    "UPDATE users SET password_hash = ?, security_stamp = ? WHERE id = ?",
                    (new_hash, new_stamp, current_usr['id'])
                )
                conn.commit()
                # Update current session security stamp so this session stays active
                session['security_stamp'] = new_stamp
                log_audit_event('PASSWORD_CHANGED', 'Admin account password changed; all other active sessions revoked', user_id=current_usr['id'], username=current_usr['username'], ip_address=request.remote_addr)
                flash('Password changed successfully! All other active sessions have been revoked for your security.', 'success')

            conn.close()
            return redirect(url_for('admin.account', tab='password'))

        elif form_action == 'setup_2fa':
            # Reuse existing pending secret or generate fresh one
            temp_secret = session.get('pending_2fa_secret') or generate_base32_secret()
            session['pending_2fa_secret'] = temp_secret
            qr_uri = generate_qr_code_data_uri(secret_b32=temp_secret, username=current_usr['username'], issuer="StellarStudio")
            audit_logs = conn.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 30").fetchall()
            conn.close()
            return render_template(
                'admin/account.html',
                current_user=get_current_user(),
                audit_logs=audit_logs,
                setup_2fa_secret=temp_secret,
                setup_2fa_qr=qr_uri,
                active_tab='2fa'
            )

        elif form_action == 'confirm_enable_2fa':
            secret = request.form.get('secret', '').strip() or session.get('pending_2fa_secret', '')
            code = request.form.get('totp_code', '').strip()

            # Forgiving +-3 minute clock tolerance window during setup
            if not secret or not code or not verify_totp_code(secret, code, window=6):
                log_audit_event('2FA_ACTIVATION_FAILED', f"Code verification failed for user '{current_usr['username']}'. Input: '{code}'. Server time: {datetime.now().strftime('%H:%M:%S')}", user_id=current_usr['id'], username=current_usr['username'], ip_address=request.remote_addr)
                flash('Invalid 6-digit code. Please verify the code displayed in your authenticator app and try again. (Tip: Ensure your phone clock is set to Automatic Network Time).', 'error')
                qr_uri = generate_qr_code_data_uri(secret_b32=secret, username=current_usr['username'], issuer="StellarStudio")
                audit_logs = conn.execute("SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 30").fetchall()
                conn.close()
                return render_template(
                    'admin/account.html',
                    current_user=get_current_user(),
                    audit_logs=audit_logs,
                    setup_2fa_secret=secret,
                    setup_2fa_qr=qr_uri,
                    active_tab='2fa'
                )
            else:
                session.pop('pending_2fa_secret', None)
                plain_backup_codes, hashed_json = generate_backup_scratch_codes()
                conn.execute("""
                    UPDATE users 
                    SET mfa_enabled = 1, mfa_secret = ?, mfa_backup_codes = ? 
                    WHERE id = ?
                """, (secret, hashed_json, current_usr['id']))
                conn.commit()
                session['generated_backup_codes'] = plain_backup_codes
                log_audit_event('2FA_ACTIVATED', f"Two-Factor Authentication activated for user '{current_usr['username']}'", user_id=current_usr['id'], username=current_usr['username'], ip_address=request.remote_addr)
                flash('Two-Factor Authentication has been successfully enabled! Save your emergency backup codes below.', 'success')

            conn.close()
            return redirect(url_for('admin.account', tab='2fa'))

        elif form_action == 'disable_2fa':
            current_pwd = request.form.get('current_password', '')
            user_rec = conn.execute("SELECT password_hash FROM users WHERE id = ?", (current_usr['id'],)).fetchone()

            if not verify_password(user_rec['password_hash'], current_pwd):
                flash('Incorrect password. 2FA cannot be disabled.', 'error')
            else:
                conn.execute("""
                    UPDATE users 
                    SET mfa_enabled = 0, mfa_secret = NULL, mfa_backup_codes = NULL 
                    WHERE id = ?
                """, (current_usr['id'],))
                conn.commit()
                log_audit_event('2FA_DEACTIVATED', f"Two-Factor Authentication disabled for user '{current_usr['username']}'", user_id=current_usr['id'], username=current_usr['username'], ip_address=request.remote_addr)
                flash('Two-Factor Authentication has been deactivated.', 'info')

            conn.close()
            return redirect(url_for('admin.account', tab='2fa'))

        elif form_action == 'generate_recovery_key':
            current_pwd = request.form.get('current_password', '')
            user_rec = conn.execute("SELECT password_hash FROM users WHERE id = ?", (current_usr['id'],)).fetchone()

            if not verify_password(user_rec['password_hash'], current_pwd):
                flash('Incorrect password. Recovery key cannot be rotated.', 'error')
            else:
                rec_plain, rec_hash = generate_emergency_recovery_key()
                conn.execute("UPDATE users SET recovery_key_hash = ? WHERE id = ?", (rec_hash, current_usr['id']))
                conn.commit()
                session['generated_recovery_key'] = rec_plain
                log_audit_event('RECOVERY_KEY_ROTATED', f"Emergency recovery key rotated for user '{current_usr['username']}'", user_id=current_usr['id'], username=current_usr['username'], ip_address=request.remote_addr)
                flash('New Emergency Recovery Key generated! Please store it in a secure location.', 'success')

            conn.close()
            return redirect(url_for('admin.account', tab='recovery'))

    # Fetch recent security audit logs
    audit_logs = conn.execute(
        "SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT 30"
    ).fetchall()
    conn.close()

    generated_backup_codes = session.pop('generated_backup_codes', None)
    generated_recovery_key = session.pop('generated_recovery_key', None)

    active_tab = request.args.get('tab', '').strip()
    if not active_tab:
        if generated_backup_codes:
            active_tab = '2fa'
        elif generated_recovery_key:
            active_tab = 'recovery'
        else:
            active_tab = 'profile'

    return render_template(
        'admin/account.html',
        current_user=get_current_user(),
        audit_logs=audit_logs,
        generated_backup_codes=generated_backup_codes,
        generated_recovery_key=generated_recovery_key,
        active_tab=active_tab
    )
