import os
import re
import time
import socket
import sqlite3
import threading
from datetime import datetime, timezone

# Load environment variables if python-dotenv is present
try:
    from dotenv import load_dotenv
    load_dotenv()
except Exception:
    pass

# Database directory & fallback SQLite path
DATA_DIR = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'data'))
os.makedirs(DATA_DIR, exist_ok=True)
DB_PATH = os.environ.get('CMS_DB_PATH') or os.path.join(DATA_DIR, 'cms.db')

DB_LOCK = threading.Lock()

def get_database_url():
    """Returns current active PostgreSQL / Supabase connection URL if set."""
    return os.environ.get('DATABASE_URL') or os.environ.get('SUPABASE_DB_URL')

def is_postgres_enabled():
    """Returns True if a valid PostgreSQL/Supabase DATABASE_URL is configured and not running isolated SQLite test."""
    if os.environ.get('CMS_DB_PATH'):
        return False
    url = get_database_url()
    return bool(url and url.strip().startswith(('postgres://', 'postgresql://')))

TABLES_WITH_ID = {'users', 'categories', 'tags', 'articles', 'media', 'audit_logs'}

# Platform Master Default Settings
DEFAULT_SETTINGS = {
    'site_title': 'Stellar Video Downloader & Tech Blog',
    'site_tagline': 'Free 4K Video Downloader, Audio Extractor & Entertainment Hub',
    'site_url': 'https://www.aryplusdownloader.tech',
    'site_description': 'Download HD videos from ARY Plus, YouTube, TikTok, Facebook, and Instagram. Read latest tech guides, drama updates, and media tips.',
    'contact_email': 'support@aryplusdownloader.tech',
    'posts_per_page': '9',
    'footer_copyright': '© 2026 Stellar Studio. All rights reserved.',
    'twitter_url': 'https://twitter.com',
    'youtube_url': 'https://youtube.com',
    'facebook_url': 'https://facebook.com',
    'instagram_url': 'https://instagram.com'
}

# ============================================================================
# PostgreSQL / Supabase Adapters & Connection Pool
# ============================================================================

def _parse_postgres_connection_params(url):
    """
    Intelligently parses PostgreSQL URLs (even with special characters like '@' in password)
    and handles IPv6-only Supabase hosts by automatically routing to IPv4 poolers.
    """
    prefix = 'postgresql://' if url.startswith('postgresql://') else 'postgres://'
    rest = url[len(prefix):]
    query_str = ''
    if '?' in rest:
        rest, query_str = rest.split('?', 1)

    if '@' in rest:
        auth_part, host_part = rest.rsplit('@', 1)
    else:
        auth_part, host_part = '', rest

    user, password = '', ''
    if ':' in auth_part:
        user, password = auth_part.split(':', 1)
    else:
        user = auth_part

    import urllib.parse
    user = urllib.parse.unquote(user)
    password = urllib.parse.unquote(password)

    host, port, dbname = '', 5432, 'postgres'
    if '/' in host_part:
        host_port, dbname = host_part.split('/', 1)
    else:
        host_port = host_part

    if ':' in host_port:
        host, port_str = host_port.split(':', 1)
        try:
            port = int(port_str)
        except ValueError:
            port = 5432
    else:
        host = host_port

    # Supabase direct endpoints (db.<ref>.supabase.co) are IPv6-only worldwide.
    # Heroku dynos and IPv4 networks MUST always route through the IPv4 Supavisor connection pooler.
    if host.startswith('db.') and host.endswith('.supabase.co'):
        proj_ref = host.split('.')[1]
        host = 'aws-0-ap-northeast-2.pooler.supabase.com'
        if not user.startswith('postgres.'):
            user = f'postgres.{proj_ref}'
        port = 5432

    return {
        'host': host,
        'port': port,
        'user': user,
        'password': password,
        'dbname': dbname,
        'sslmode': 'require',
        'connect_timeout': 15
    }

class CompatibleRow(dict):
    """Provides sqlite3.Row-like behavior (key access, index access, dict, ISO timestamp formatting)."""
    def __init__(self, raw_row, description):
        super().__init__()
        self._values = []
        keys = [col[0] for col in description] if description else []
        from datetime import datetime, date
        for i, val in enumerate(raw_row):
            if isinstance(val, (datetime, date)):
                val = val.strftime('%Y-%m-%d %H:%M:%S')
            self._values.append(val)
            if i < len(keys):
                self[keys[i]] = val

    def __getitem__(self, item):
        if isinstance(item, int):
            return self._values[item]
        return super().__getitem__(item)

class PostgresCursorWrapper:
    """Wraps a psycopg2 cursor to provide seamless SQLite compatibility."""
    def __init__(self, raw_cursor):
        self._cursor = raw_cursor
        self.lastrowid = None

    def _wrap_row(self, row):
        if row is None:
            return None
        return CompatibleRow(row, self._cursor.description)

    def __iter__(self):
        for row in self._cursor:
            yield self._wrap_row(row)

    def _prepare_sql(self, sql):
        sql_stripped = sql.strip()

        # 1. Translate INSERT OR IGNORE INTO <table> ... -> INSERT INTO <table> ... ON CONFLICT DO NOTHING
        if re.match(r'^INSERT\s+OR\s+IGNORE\s+INTO\s+', sql_stripped, flags=re.IGNORECASE):
            sql_stripped = re.sub(r'^INSERT\s+OR\s+IGNORE\s+INTO\s+', 'INSERT INTO ', sql_stripped, flags=re.IGNORECASE)
            if 'on conflict' not in sql_stripped.lower():
                sql_stripped = sql_stripped.rstrip(';') + ' ON CONFLICT DO NOTHING'

        # 2. Translate LIKE -> ILIKE for case-insensitive search compatibility
        sql_stripped = re.sub(r'\bLIKE\b', 'ILIKE', sql_stripped)

        # 3. Check for RETURNING id on INSERT to populate cursor.lastrowid
        wants_returning = False
        m_insert = re.match(r'^INSERT\s+INTO\s+([a-zA-Z0-9_]+)', sql_stripped, flags=re.IGNORECASE)
        if m_insert:
            table_name = m_insert.group(1).lower()
            if table_name in TABLES_WITH_ID and 'returning' not in sql_stripped.lower():
                sql_stripped = sql_stripped.rstrip(';') + ' RETURNING id'
                wants_returning = True

        # 4. Convert ? to %s parameter placeholders outside quotes
        parts = []
        in_quote = False
        quote_char = ''
        i = 0
        while i < len(sql_stripped):
            ch = sql_stripped[i]
            if ch in ("'", '"'):
                if not in_quote:
                    in_quote = True
                    quote_char = ch
                elif ch == quote_char:
                    in_quote = False
                parts.append(ch)
            elif ch == '?' and not in_quote:
                parts.append('%s')
            else:
                parts.append(ch)
            i += 1
        return "".join(parts), wants_returning

    def execute(self, sql, params=None):
        final_sql, wants_returning = self._prepare_sql(sql)
        if params is None:
            self._cursor.execute(final_sql)
        else:
            self._cursor.execute(final_sql, params)

        if wants_returning:
            try:
                row = self._cursor.fetchone()
                if row:
                    self.lastrowid = row[0]
            except Exception:
                self.lastrowid = None
        else:
            self.lastrowid = None
        return self

    def executemany(self, sql, params_seq):
        final_sql, _ = self._prepare_sql(sql)
        return self._cursor.executemany(final_sql, params_seq)

    def fetchone(self):
        return self._wrap_row(self._cursor.fetchone())

    def fetchall(self):
        rows = self._cursor.fetchall()
        desc = self._cursor.description
        return [CompatibleRow(r, desc) for r in rows]

    def fetchmany(self, size=None):
        rows = self._cursor.fetchmany(size) if size else self._cursor.fetchmany()
        desc = self._cursor.description
        return [CompatibleRow(r, desc) for r in rows]

    @property
    def rowcount(self):
        return self._cursor.rowcount

    @property
    def description(self):
        return self._cursor.description

    def close(self):
        try:
            self._cursor.close()
        except Exception:
            pass

class PostgresConnectionWrapper:
    """Wraps a psycopg2 connection to mimic sqlite3.Connection behavior with pooling support."""
    def __init__(self, raw_conn, pool=None):
        self._conn = raw_conn
        self._pool = pool
        self._closed = False

    def cursor(self):
        import psycopg2.extras
        return PostgresCursorWrapper(self._conn.cursor(cursor_factory=psycopg2.extras.DictCursor))

    def execute(self, sql, params=None):
        cur = self.cursor()
        cur.execute(sql, params)
        return cur

    def executemany(self, sql, params_seq):
        cur = self.cursor()
        cur.executemany(sql, params_seq)
        return cur

    def commit(self):
        return self._conn.commit()

    def rollback(self):
        return self._conn.rollback()

    def close(self):
        if self._closed:
            return
        self._closed = True
        if self._pool is not None:
            try:
                # Return the connection back to the warm pool for instant reuse
                self._pool.putconn(self._conn)
            except Exception:
                pass
        else:
            try:
                self._conn.close()
            except Exception:
                pass

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type:
            self.rollback()
        else:
            self.commit()

# ============================================================================
# Unified Database Connection Interface with High-Performance Pooling
# ============================================================================

_PG_POOL = None
_PG_POOL_LOCK = threading.Lock()

def _get_pg_pool():
    """Initializes and returns a thread-safe persistent connection pool for Supabase."""
    global _PG_POOL
    if _PG_POOL is None and is_postgres_enabled():
        with _PG_POOL_LOCK:
            if _PG_POOL is None:
                try:
                    from psycopg2.pool import ThreadedConnectionPool
                    params = _parse_postgres_connection_params(get_database_url())
                    _PG_POOL = ThreadedConnectionPool(minconn=1, maxconn=10, **params)
                except Exception as e:
                    print(f"[DATABASE POOL NOTICE] Could not initialize ThreadedConnectionPool: {e}", flush=True)
                    _PG_POOL = None
    return _PG_POOL

def get_db_connection():
    """
    Returns an active database connection:
    - If DATABASE_URL is set -> Warm connection from ThreadedConnectionPool (0ms latency).
    - Otherwise -> Local SQLite connection with Row factory.
    """
    if is_postgres_enabled():
        pool = _get_pg_pool()
        if pool is not None:
            try:
                raw_conn = pool.getconn()
                # Verify socket is alive
                if raw_conn.closed != 0:
                    try:
                        pool.putconn(raw_conn, close=True)
                    except Exception:
                        pass
                    raw_conn = pool.getconn()
                return PostgresConnectionWrapper(raw_conn, pool=pool)
            except Exception as e:
                print(f"[DATABASE POOL NOTICE] getconn failed ({e}), trying direct connection.", flush=True)

        # Fallback to direct connect if pool is full or unavailable
        try:
            import psycopg2
            params = _parse_postgres_connection_params(get_database_url())
            raw_conn = psycopg2.connect(**params)
            return PostgresConnectionWrapper(raw_conn, pool=None)
        except Exception as e:
            print(f"[DATABASE NOTICE] PostgreSQL connection failed: {e}. Falling back to SQLite.", flush=True)

    # Local SQLite Fallback
    db_path = os.environ.get('CMS_DB_PATH') or DB_PATH
    conn = sqlite3.connect(db_path, timeout=30.0, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    return conn

def init_db():
    """Initializes all CMS database tables and default configuration."""
    with DB_LOCK:
        conn = get_db_connection()

        if is_postgres_enabled():
            _init_postgres_db(conn)
        else:
            _init_sqlite_db(conn)

def _init_postgres_db(conn):
    """Initializes PostgreSQL / Supabase schema."""
    cur = conn.cursor()
    schema_sql = '''
    CREATE TABLE IF NOT EXISTS users (
        id SERIAL PRIMARY KEY,
        username VARCHAR(100) UNIQUE NOT NULL,
        display_name VARCHAR(100),
        email VARCHAR(255) UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        role VARCHAR(50) NOT NULL DEFAULT 'admin',
        security_stamp VARCHAR(100),
        mfa_enabled INTEGER DEFAULT 0,
        mfa_secret TEXT,
        mfa_backup_codes TEXT,
        recovery_key_hash TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        last_login TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS categories (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        slug VARCHAR(100) UNIQUE NOT NULL,
        description TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS tags (
        id SERIAL PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        slug VARCHAR(100) UNIQUE NOT NULL,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS articles (
        id SERIAL PRIMARY KEY,
        title VARCHAR(255) NOT NULL,
        slug VARCHAR(255) UNIQUE NOT NULL,
        excerpt TEXT,
        content TEXT NOT NULL,
        featured_image TEXT,
        featured_image_alt VARCHAR(255),
        category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
        author_name VARCHAR(100) NOT NULL DEFAULT 'Admin',
        status VARCHAR(50) NOT NULL DEFAULT 'draft',
        published_at TIMESTAMP,
        scheduled_for TIMESTAMP,
        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
        seo_title VARCHAR(255),
        meta_description TEXT,
        canonical_url TEXT,
        og_title VARCHAR(255),
        og_description TEXT,
        og_image TEXT,
        is_noindex INTEGER DEFAULT 0,
        views_count INTEGER DEFAULT 0
    );

    CREATE INDEX IF NOT EXISTS idx_articles_slug ON articles(slug);
    CREATE INDEX IF NOT EXISTS idx_articles_status_pub ON articles(status, published_at);
    CREATE INDEX IF NOT EXISTS idx_categories_slug ON categories(slug);

    CREATE TABLE IF NOT EXISTS article_tags (
        article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
        tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
        PRIMARY KEY (article_id, tag_id)
    );

    CREATE TABLE IF NOT EXISTS settings (
        key VARCHAR(100) PRIMARY KEY,
        value TEXT
    );

    CREATE TABLE IF NOT EXISTS media (
        id SERIAL PRIMARY KEY,
        filename VARCHAR(255) NOT NULL,
        original_name VARCHAR(255) NOT NULL,
        filepath TEXT NOT NULL,
        file_size BIGINT NOT NULL,
        mime_type VARCHAR(100) NOT NULL,
        uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );

    CREATE TABLE IF NOT EXISTS audit_logs (
        id SERIAL PRIMARY KEY,
        user_id INTEGER,
        username VARCHAR(100),
        action VARCHAR(100) NOT NULL,
        details TEXT,
        ip_address VARCHAR(100),
        user_agent TEXT,
        created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);
    CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);
    '''
    cur._cursor.execute(schema_sql)

    # Seed Default Settings
    for k, v in DEFAULT_SETTINGS.items():
        cur.execute('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT (key) DO NOTHING', (k, v))

    # Seed initial categories if none exist
    cur.execute('SELECT COUNT(*) FROM categories')
    if cur.fetchone()[0] == 0:
        sample_cats = [
            ('Video Downloading', 'video-downloading', 'Comprehensive guides and tutorials on downloading videos and extracting audio.'),
            ('ARY Plus Dramas', 'ary-plus-dramas', 'Updates, episode guides, and streaming tips for Pakistani television dramas.'),
            ('Tech & Social Media', 'tech-social-media', 'Latest social media tips, video format guides, and technology insights.'),
            ('Tutorials & How-To', 'tutorials-how-to', 'Step-by-step how-to tutorials for mobile and desktop media management.')
        ]
        cur.executemany('INSERT INTO categories (name, slug, description) VALUES (?, ?, ?)', sample_cats)

    # Seed initial admin if specified in env
    cur.execute('SELECT COUNT(*) FROM users')
    if cur.fetchone()[0] == 0:
        env_user = os.environ.get('ADMIN_USERNAME')
        env_pwd = os.environ.get('ADMIN_PASSWORD')
        if env_user and env_pwd:
            from core.auth import hash_password
            from core.totp import generate_emergency_recovery_key
            import secrets
            rec_plain, rec_hash = generate_emergency_recovery_key()
            cur.execute('''
                INSERT INTO users (username, display_name, email, password_hash, role, security_stamp, recovery_key_hash)
                VALUES (?, ?, ?, ?, 'admin', ?, ?)
            ''', (env_user, env_user, os.environ.get('ADMIN_EMAIL', f'{env_user}@stellar.tech'), hash_password(env_pwd), secrets.token_hex(16), rec_hash))

    conn.commit()
    conn.close()

def _init_sqlite_db(conn):
    """Initializes local SQLite schema."""
    cursor = conn.cursor()

    # 1. Users Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL COLLATE NOCASE,
            display_name TEXT,
            email TEXT UNIQUE NOT NULL COLLATE NOCASE,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'admin',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            last_login TIMESTAMP
        );
    ''')
    for col_def in [
        "display_name TEXT",
        "security_stamp TEXT",
        "mfa_enabled INTEGER DEFAULT 0",
        "mfa_secret TEXT",
        "mfa_backup_codes TEXT",
        "recovery_key_hash TEXT"
    ]:
        try:
            cursor.execute(f"ALTER TABLE users ADD COLUMN {col_def};")
        except Exception:
            pass

    # 2. Categories Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS categories (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            slug TEXT UNIQUE NOT NULL COLLATE NOCASE,
            description TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ''')

    # 3. Tags Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS tags (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            slug TEXT UNIQUE NOT NULL COLLATE NOCASE,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ''')

    # 4. Articles Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS articles (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            title TEXT NOT NULL,
            slug TEXT UNIQUE NOT NULL COLLATE NOCASE,
            excerpt TEXT,
            content TEXT NOT NULL,
            featured_image TEXT,
            featured_image_alt TEXT,
            category_id INTEGER REFERENCES categories(id) ON DELETE SET NULL,
            author_name TEXT NOT NULL DEFAULT 'Admin',
            status TEXT NOT NULL DEFAULT 'draft',
            published_at TIMESTAMP,
            scheduled_for TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            seo_title TEXT,
            meta_description TEXT,
            canonical_url TEXT,
            og_title TEXT,
            og_description TEXT,
            og_image TEXT,
            is_noindex INTEGER DEFAULT 0,
            views_count INTEGER DEFAULT 0
        );
    ''')

    cursor.execute('CREATE INDEX IF NOT EXISTS idx_articles_slug ON articles(slug);')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_articles_status_pub ON articles(status, published_at);')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_categories_slug ON categories(slug);')

    # 5. Article Tags Junction Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS article_tags (
            article_id INTEGER NOT NULL REFERENCES articles(id) ON DELETE CASCADE,
            tag_id INTEGER NOT NULL REFERENCES tags(id) ON DELETE CASCADE,
            PRIMARY KEY (article_id, tag_id)
        );
    ''')

    # 6. Settings Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS settings (
            key TEXT PRIMARY KEY,
            value TEXT
        );
    ''')

    # 7. Media Uploads Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS media (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            original_name TEXT NOT NULL,
            filepath TEXT NOT NULL,
            file_size INTEGER NOT NULL,
            mime_type TEXT NOT NULL,
            uploaded_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ''')

    # 8. Security & Admin Audit Logs Table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS audit_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_id INTEGER,
            username TEXT,
            action TEXT NOT NULL,
            details TEXT,
            ip_address TEXT,
            user_agent TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    ''')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);')
    cursor.execute('CREATE INDEX IF NOT EXISTS idx_audit_logs_created ON audit_logs(created_at);')

    # Seed Default Settings if empty
    for k, v in DEFAULT_SETTINGS.items():
        cursor.execute('INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)', (k, v))

    # Seed initial categories if none exist
    cursor.execute('SELECT COUNT(*) FROM categories')
    if cursor.fetchone()[0] == 0:
        sample_cats = [
            ('Video Downloading', 'video-downloading', 'Comprehensive guides and tutorials on downloading videos and extracting audio.'),
            ('ARY Plus Dramas', 'ary-plus-dramas', 'Updates, episode guides, and streaming tips for Pakistani television dramas.'),
            ('Tech & Social Media', 'tech-social-media', 'Latest social media tips, video format guides, and technology insights.'),
            ('Tutorials & How-To', 'tutorials-how-to', 'Step-by-step how-to tutorials for mobile and desktop media management.')
        ]
        cursor.executemany('INSERT INTO categories (name, slug, description) VALUES (?, ?, ?)', sample_cats)

    # Seed initial admin if specified in env
    cursor.execute('SELECT COUNT(*) FROM users')
    if cursor.fetchone()[0] == 0:
        env_user = os.environ.get('ADMIN_USERNAME')
        env_pwd = os.environ.get('ADMIN_PASSWORD')
        if env_user and env_pwd:
            from core.auth import hash_password
            from core.totp import generate_emergency_recovery_key
            import secrets
            rec_plain, rec_hash = generate_emergency_recovery_key()
            cursor.execute('''
                INSERT INTO users (username, display_name, email, password_hash, role, security_stamp, recovery_key_hash)
                VALUES (?, ?, ?, ?, 'admin', ?, ?)
            ''', (env_user, env_user, os.environ.get('ADMIN_EMAIL', f'{env_user}@stellar.tech'), hash_password(env_pwd), secrets.token_hex(16), rec_hash))

    conn.commit()
    conn.close()

# ============================================================================
# Application Helper Functions
# ============================================================================

_LAST_SCHEDULE_CHECK = 0
_SCHEDULE_LOCK = threading.Lock()

def check_and_publish_scheduled(force=False):
    """
    Checks for articles whose scheduled publishing time has arrived
    and transitions them from 'scheduled' to 'published'.
    In PostgreSQL production, throttled to at most once per 60s to eliminate request latency.
    """
    global _LAST_SCHEDULE_CHECK
    now = time.time()
    if is_postgres_enabled() and not force and (now - _LAST_SCHEDULE_CHECK < 60):
        return 0

    with _SCHEDULE_LOCK:
        if is_postgres_enabled() and not force and (now - _LAST_SCHEDULE_CHECK < 60):
            return 0
        _LAST_SCHEDULE_CHECK = now
        with DB_LOCK:
            conn = get_db_connection()
            cursor = conn.cursor()
            now_iso = datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S')
            cursor.execute('''
                UPDATE articles
                SET status = 'published',
                    published_at = COALESCE(scheduled_for, CURRENT_TIMESTAMP),
                    updated_at = CURRENT_TIMESTAMP
                WHERE status = 'scheduled'
                  AND scheduled_for IS NOT NULL
                  AND scheduled_for <= ?
            ''', (now_iso,))
            updated_count = cursor.rowcount
            if updated_count and updated_count > 0:
                conn.commit()
            conn.close()
            return updated_count or 0

def prewarm_database_pool():
    """Pre-warms the Supabase connection pool asynchronously on application startup."""
    if is_postgres_enabled():
        t = threading.Thread(target=_get_pg_pool, daemon=True)
        t.start()

_SETTINGS_CACHE = None
_SETTINGS_CACHE_TIME = 0
_SETTINGS_LOCK = threading.Lock()

def get_setting(key, default=''):
    """Fetches a setting value by key instantly from cache, falling back to DEFAULT_SETTINGS."""
    settings = get_all_settings()
    return settings.get(key, DEFAULT_SETTINGS.get(key, default))

def get_all_settings():
    """Returns all settings as a dict with full defaults, cached in-memory for 60 seconds (0ms latency)."""
    global _SETTINGS_CACHE, _SETTINGS_CACHE_TIME
    now = time.time()
    if _SETTINGS_CACHE is not None and (now - _SETTINGS_CACHE_TIME < 60):
        return dict(_SETTINGS_CACHE)

    with _SETTINGS_LOCK:
        if _SETTINGS_CACHE is not None and (now - _SETTINGS_CACHE_TIME < 60):
            return dict(_SETTINGS_CACHE)

        settings_dict = {}
        try:
            conn = get_db_connection()
            rows = conn.execute('SELECT key, value FROM settings').fetchall()
            conn.close()
            settings_dict = {r['key']: r['value'] for r in rows}
        except Exception as e:
            pass
        # Ensure all defaults are present
        for k, v in DEFAULT_SETTINGS.items():
            if k not in settings_dict or not settings_dict[k]:
                settings_dict[k] = v
        _SETTINGS_CACHE = settings_dict
        _SETTINGS_CACHE_TIME = now
        return dict(settings_dict)

def set_setting(key, value):
    """Sets or updates a setting value and invalidates settings cache."""
    global _SETTINGS_CACHE
    with DB_LOCK:
        conn = get_db_connection()
        conn.execute('INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = ?', (key, value, value))
        conn.commit()
        conn.close()
    _SETTINGS_CACHE = None

def log_audit_event(action, details='', user_id=None, username=None, ip_address=None, user_agent=None):
    """Logs administrative & security actions to audit_logs table."""
    try:
        with DB_LOCK:
            conn = get_db_connection()
            conn.execute('''
                INSERT INTO audit_logs (user_id, username, action, details, ip_address, user_agent)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (user_id, username, action, str(details)[:500], ip_address or '127.0.0.1', str(user_agent or '')[:250]))
            conn.commit()
            conn.close()
    except Exception as e:
        print("Audit logging notice:", e)
