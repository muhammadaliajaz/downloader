import unittest
import os
import errno

# Isolate unit tests to a dedicated local test database
TEST_DB_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), 'data', 'test_cms.db'))
os.environ['CMS_DB_PATH'] = TEST_DB_PATH
os.environ.pop('DATABASE_URL', None)
os.environ.pop('SUPABASE_DB_URL', None)
os.environ['ADMIN_SLUG'] = 'admin'

import json
import io
from app import app
from core.db import get_db_connection, init_db, check_and_publish_scheduled, set_setting, get_setting
from core.auth import generate_csrf_token, verify_password, check_login_rate_limit, record_failed_login, reset_login_attempts
from core.sanitizer import sanitize_html, slugify
from core.media import save_media_file

class TestSecureAdminAndCMS(unittest.TestCase):
    def setUp(self):
        app.config['TESTING'] = True
        app.config['WTF_CSRF_ENABLED'] = False
        self.client = app.test_client()
        init_db()

    def test_01_public_routes(self):
        """Verify all requested public pages exist and respond 200."""
        routes = [
            '/',
            '/blog/',
            '/about/',
            '/contact/',
            '/privacy/',
            '/terms/',
            '/disclaimer/',
            '/robots.txt',
            '/sitemap.xml'
        ]
        for route in routes:
            res = self.client.get(route)
            self.assertEqual(res.status_code, 200, f"Route {route} failed with status {res.status_code}")

    def test_02_html_sanitization(self):
        """Verify rich-text sanitizer strips malicious XSS payload while preserving safe tags."""
        dirty = '<p>Hello <b>world</b><script>alert(1)</script><img src="x" onerror="alert(2)"><a href="javascript:steal()">Link</a></p>'
        clean = sanitize_html(dirty)
        self.assertNotIn('<script>', clean)
        self.assertNotIn('onerror', clean)
        self.assertNotIn('javascript:', clean)
        self.assertIn('<b>world</b>', clean)

    def test_03_admin_setup_and_auth(self):
        """Verify secure admin setup, password hashing, and authentication."""
        conn = get_db_connection()
        conn.execute("DELETE FROM users")
        conn.commit()
        conn.close()

        # With 0 users, /admin/ must redirect to setup
        res = self.client.get('/admin/', follow_redirects=False)
        self.assertEqual(res.status_code, 302)
        self.assertIn('/admin/setup', res.headers['Location'])

        # Create admin user within test client session
        with self.client:
            self.client.get('/admin/setup')
            with self.client.session_transaction() as sess:
                sess['_csrf_token'] = 'test_token_123'

            setup_data = {
                'csrf_token': 'test_token_123',
                'username': 'superadmin',
                'display_name': 'Senior Editor',
                'email': 'admin@stellar.tech',
                'password': 'ComplexPassword123!',
                'confirm_password': 'ComplexPassword123!'
            }
            res = self.client.post('/admin/setup', data=setup_data, follow_redirects=True)
            self.assertEqual(res.status_code, 200)

        # Check DB - password must NEVER be plaintext
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = 'superadmin'").fetchone()
        conn.close()
        self.assertIsNotNone(user)
        self.assertNotEqual(user['password_hash'], 'ComplexPassword123!')
        self.assertTrue(verify_password(user['password_hash'], 'ComplexPassword123!'))

        # Log out before testing login endpoint
        self.client.get('/admin/logout')

        # Log in with wrong password
        with self.client:
            self.client.get('/admin/login')
            with self.client.session_transaction() as sess:
                sess['_csrf_token'] = 'test_token_123'
            login_res = self.client.post('/admin/login', data={
                'csrf_token': 'test_token_123',
                'username': 'superadmin',
                'password': 'WrongPassword'
            }, follow_redirects=True)
            self.assertIn(b'Invalid username or password', login_res.data)

        # Log in with correct password
        with self.client:
            self.client.get('/admin/login')
            with self.client.session_transaction() as sess:
                sess['_csrf_token'] = 'test_token_123'
            login_ok = self.client.post('/admin/login', data={
                'csrf_token': 'test_token_123',
                'username': 'superadmin',
                'password': 'ComplexPassword123!'
            }, follow_redirects=True)
            self.assertIn(b'Dashboard', login_ok.data)

    def test_04_article_lifecycle_and_seo(self):
        """Verify full article CRUD: title, slug, excerpt, tags, category, SEO meta, and published status."""
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = 'superadmin'").fetchone()
        if not user:
            from core.auth import hash_password
            conn.execute("INSERT INTO users (username, display_name, password_hash, email, role) VALUES (?, ?, ?, ?, ?)",
                         ('superadmin', 'Senior Editor', hash_password('ComplexPassword123!'), 'admin@stellar.tech', 'admin'))
            conn.commit()
            user = conn.execute("SELECT * FROM users WHERE username = 'superadmin'").fetchone()
        cat = conn.execute("SELECT id FROM categories LIMIT 1").fetchone()
        conn.close()

        with self.client:
            self.client.get('/admin/posts/new')
            with self.client.session_transaction() as sess:
                sess['user_id'] = user['id']
                sess['username'] = user['username']
                sess['role'] = user['role']
                sess['display_name'] = user['display_name']
                sess['_csrf_token'] = 'test_token_123'

            post_data = {
                'csrf_token': 'test_token_123',
                'title': 'How to Download 4K YouTube Videos Fast',
                'slug': 'how-to-download-4k-youtube-videos-fast',
                'excerpt': 'A comprehensive guide to high-definition video extraction.',
                'content': '<p>Here is the full guide with <strong>tips</strong> and tricks.</p>',
                'category_id': cat['id'],
                'featured_image': '/static/uploads/test.png',
                'featured_image_alt': '4K Video Download Guide Thumbnail',
                'author_name': 'Senior Editor',
                'status': 'published',
                'tags': 'YouTube, 4K, Guides',
                'seo_title': 'Best 4K Video Downloader Guide (2026)',
                'meta_description': 'Learn how to extract 4K 60FPS video streams securely with 32x CDN speed.',
                'canonical_url': 'https://aryplusdownloader.tech/blog/how-to-download-4k-youtube-videos-fast',
                'og_title': '4K YouTube Download Guide',
                'og_description': 'Fastest way to get 4K MP4 videos.',
                'og_image': '/static/uploads/test.png'
            }
            res = self.client.post('/admin/posts/new', data=post_data, follow_redirects=True)
            self.assertEqual(res.status_code, 200)

        # Public access test: visitor visits /blog/how-to-download-4k-youtube-videos-fast
        visitor = app.test_client()
        pub_res = visitor.get('/blog/how-to-download-4k-youtube-videos-fast')
        self.assertEqual(pub_res.status_code, 200)
        self.assertIn(b'How to Download 4K YouTube Videos Fast', pub_res.data)
        self.assertIn(b'Best 4K Video Downloader Guide (2026)', pub_res.data)
        self.assertIn(b'Senior Editor', pub_res.data)

        # Check sitemap includes this article
        sitemap_res = visitor.get('/sitemap.xml')
        self.assertEqual(sitemap_res.status_code, 200)
        self.assertIn(b'how-to-download-4k-youtube-videos-fast', sitemap_res.data)

        # Test Category & Tag archives
        cat_archive = visitor.get('/category/ary-plus-dramas')
        self.assertEqual(cat_archive.status_code, 200)

        tag_archive = visitor.get('/tag/youtube')
        self.assertEqual(tag_archive.status_code, 200)

    def test_05_scheduled_publishing(self):
        """Verify scheduled publishing engine transitions article to published when time passes."""
        conn = get_db_connection()
        conn.execute("DELETE FROM articles WHERE slug = 'scheduled-post-auto'")
        conn.execute("""
            INSERT INTO articles (title, slug, content, status, scheduled_for, created_at)
            VALUES ('Scheduled Post', 'scheduled-post-auto', '<p>Test</p>', 'scheduled', '2026-01-01 00:00:00', CURRENT_TIMESTAMP)
        """)
        conn.commit()
        conn.close()

        # Run scheduled checker
        check_and_publish_scheduled()

        conn = get_db_connection()
        post = conn.execute("SELECT status, published_at FROM articles WHERE slug = 'scheduled-post-auto'").fetchone()
        conn.close()

        self.assertEqual(post['status'], 'published')
        self.assertIsNotNone(post['published_at'])

    def test_06_draft_privacy_and_noindex(self):
        """Verify draft posts are private from visitors and noindex posts are excluded from sitemap."""
        conn = get_db_connection()
        conn.execute("DELETE FROM articles WHERE slug IN ('draft-secret-post', 'noindex-private-guide')")
        conn.execute("""
            INSERT INTO articles (title, slug, content, status, created_at)
            VALUES ('Draft Secret', 'draft-secret-post', '<p>Secret content</p>', 'draft', CURRENT_TIMESTAMP)
        """)
        conn.execute("""
            INSERT INTO articles (title, slug, content, status, is_noindex, published_at, created_at)
            VALUES ('Noindex Guide', 'noindex-private-guide', '<p>Unlisted content</p>', 'published', 1, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
        """)
        conn.commit()
        conn.close()

        visitor = app.test_client()
        # Draft must return 404 (redirect to /blog/)
        draft_res = visitor.get('/blog/draft-secret-post')
        self.assertNotEqual(draft_res.status_code, 200)

        # Noindex post is accessible directly with noindex meta tag
        noindex_res = visitor.get('/blog/noindex-private-guide')
        self.assertEqual(noindex_res.status_code, 200)
        self.assertIn(b'noindex, nofollow', noindex_res.data)

        # Sitemap MUST NOT include noindex post
        sitemap_res = visitor.get('/sitemap.xml')
        self.assertNotIn(b'noindex-private-guide', sitemap_res.data)

    def test_07_media_upload_security(self):
        """Verify media upload rejects executable/script files and accepts valid image magic bytes."""
        class DummyFile:
            def __init__(self, filename, data):
                self.filename = filename
                self._data = data
            def read(self, n=-1):
                return self._data[:n] if n != -1 else self._data
            def seek(self, offset, whence=0):
                pass
            def tell(self):
                return len(self._data)
            def save(self, target):
                with open(target, 'wb') as f:
                    f.write(self._data)

        # 1. Reject malicious PHP / script disguised as PNG
        malicious = DummyFile('shell.php.png', b'<?php phpinfo(); ?>')
        success, err, _ = save_media_file(malicious)
        self.assertFalse(success)
        self.assertIn('File content does not match', err)

        # 2. Accept valid PNG magic bytes (89 50 4E 47 0D 0A 1A 0A)
        png_data = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4'
        valid_png = DummyFile('sample.png', png_data)
        success, url, media_id = save_media_file(valid_png)
        self.assertTrue(success)
        self.assertTrue(url.startswith('/static/uploads/'))

    def test_08_brute_force_rate_limiting(self):
        """Verify login brute-force rate limiter blocks IP after 5 failed attempts."""
        test_ip = '198.51.100.42'
        reset_login_attempts(test_ip)

        for _ in range(4):
            record_failed_login(test_ip)
            allowed, _ = check_login_rate_limit(test_ip)
            self.assertTrue(allowed)

        # 5th attempt locks the IP
        record_failed_login(test_ip)
        allowed, remaining = check_login_rate_limit(test_ip)
        self.assertFalse(allowed)
        self.assertGreater(remaining, 0)

        # Cleanup
        reset_login_attempts(test_ip)

    def test_09_settings_management(self):
        """Verify settings can be updated and retrieved."""
        set_setting('site_title', 'Stellar Media Hub 2026')
        val = get_setting('site_title')
        self.assertEqual(val, 'Stellar Media Hub 2026')

    def test_10_account_security_and_sync(self):
        """Verify Account & Security route, profile update, password change, audit logging, and web sync."""
        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = 'superadmin'").fetchone()
        if not user:
            from core.auth import hash_password
            conn.execute("INSERT INTO users (username, display_name, password_hash, email, role) VALUES (?, ?, ?, ?, ?)",
                         ('superadmin', 'Senior Editor', hash_password('ComplexPassword123!'), 'admin@stellar.tech', 'admin'))
            conn.commit()
            user = conn.execute("SELECT * FROM users WHERE username = 'superadmin'").fetchone()
        conn.close()

        # 1. Verify /admin/account renders for authenticated admin
        with self.client:
            self.client.get('/admin/account')
            with self.client.session_transaction() as sess:
                sess['user_id'] = user['id']
                sess['username'] = user['username']
                sess['role'] = user['role']
                sess['display_name'] = user['display_name']
                sess['security_stamp'] = user['security_stamp']
                sess['_csrf_token'] = 'test_token_123'

            res = self.client.get('/admin/account')
            self.assertEqual(res.status_code, 200)
            self.assertIn(b'Account & System Security', res.data)
            self.assertIn(b'Audit Trail', res.data)

            # 2. Update profile
            profile_res = self.client.post('/admin/account', data={
                'csrf_token': 'test_token_123',
                'action': 'update_profile',
                'username': 'superadmin',
                'display_name': 'Chief Executive Editor',
                'email': 'chief@stellar.tech'
            }, follow_redirects=True)
            self.assertEqual(profile_res.status_code, 200)

            conn = get_db_connection()
            updated_user = conn.execute("SELECT display_name, email FROM users WHERE id = ?", (user['id'],)).fetchone()
            conn.close()
            self.assertEqual(updated_user['display_name'], 'Chief Executive Editor')
            self.assertEqual(updated_user['email'], 'chief@stellar.tech')

            # 3. Change password with strong password
            pwd_res = self.client.post('/admin/account', data={
                'csrf_token': 'test_token_123',
                'action': 'change_password',
                'current_password': 'ComplexPassword123!',
                'new_password': 'BrandNewSecurePassword999!',
                'confirm_password': 'BrandNewSecurePassword999!'
            }, follow_redirects=True)
            self.assertEqual(pwd_res.status_code, 200)
            self.assertIn(b'Password changed successfully', pwd_res.data)

            # 4. Verify audit log entry exists
            conn = get_db_connection()
            log_entry = conn.execute("SELECT * FROM audit_logs WHERE action = 'PASSWORD_CHANGED'").fetchone()
            conn.close()
            self.assertIsNotNone(log_entry)

            # 5. Verify settings sync to homepage (/)
            set_setting('site_title', 'Apex Video Downloader')
            home_res = self.client.get('/')
            self.assertEqual(home_res.status_code, 200)
            self.assertIn(b'Apex Video Downloader', home_res.data)

    def test_11_two_factor_auth_and_recovery(self):
        """Verify 2FA TOTP activation, login prompt, backup scratch codes, emergency password recovery, and endpoint lockdown."""
        from core.totp import generate_base32_secret, get_totp_code, generate_emergency_recovery_key, verify_emergency_recovery_key
        
        # 1. Test Endpoint Security Lockdown
        visitor = app.test_client()
        health_res = visitor.get('/api/health')
        self.assertEqual(health_res.status_code, 200)
        health_data = json.loads(health_res.data)
        self.assertEqual(health_data.get('status'), 'healthy')
        # Ensure NO sensitive server internals or cookies paths are exposed
        self.assertNotIn('cookies_path', health_data)
        self.assertNotIn('has_cookies_txt', health_data)
        self.assertNotIn('qjs_size', health_data)

        # /api/debug_ytdlp must reject unauthenticated visitor
        debug_res = visitor.get('/api/debug_ytdlp')
        self.assertIn(debug_res.status_code, [302, 401, 403])

        # 2. Test 2FA Activation on Account
        secret = generate_base32_secret()
        valid_totp = get_totp_code(secret)

        conn = get_db_connection()
        user = conn.execute("SELECT * FROM users WHERE username = 'superadmin'").fetchone()
        conn.close()

        with self.client:
            self.client.get('/admin/account')
            with self.client.session_transaction() as sess:
                sess['user_id'] = user['id']
                sess['username'] = user['username']
                sess['role'] = user['role']
                sess['security_stamp'] = user['security_stamp']
                sess['_csrf_token'] = 'test_token_123'

            # Activate 2FA
            activate_res = self.client.post('/admin/account', data={
                'csrf_token': 'test_token_123',
                'action': 'confirm_enable_2fa',
                'secret': secret,
                'totp_code': valid_totp
            }, follow_redirects=True)
            self.assertEqual(activate_res.status_code, 200)
            self.assertIn(b'Two-Factor Authentication has been successfully enabled', activate_res.data)

        # Verify DB updated
        conn = get_db_connection()
        user_mfa = conn.execute("SELECT mfa_enabled, mfa_secret, mfa_backup_codes, recovery_key_hash FROM users WHERE id = ?", (user['id'],)).fetchone()
        conn.close()
        self.assertEqual(user_mfa['mfa_enabled'], 1)
        self.assertEqual(user_mfa['mfa_secret'], secret)
        self.assertIsNotNone(user_mfa['mfa_backup_codes'])

        # 3. Test 2FA Step-up Login Flow
        self.client.get('/admin/logout')
        with self.client:
            self.client.get('/admin/login')
            with self.client.session_transaction() as sess:
                sess['_csrf_token'] = 'test_token_123'

            # Step 1: Submit valid password -> redirects to 2FA prompt
            step1_res = self.client.post('/admin/login', data={
                'csrf_token': 'test_token_123',
                'username': 'superadmin',
                'password': 'BrandNewSecurePassword999!'
            }, follow_redirects=False)
            self.assertEqual(step1_res.status_code, 302)
            self.assertIn('/admin/login/2fa', step1_res.headers['Location'])

            # Step 2: Submit invalid TOTP -> rejects
            with self.client.session_transaction() as sess:
                sess['_csrf_token'] = 'test_token_123'
            fail_2fa = self.client.post('/admin/login/2fa', data={
                'csrf_token': 'test_token_123',
                'totp_code': '999999'
            }, follow_redirects=True)
            self.assertIn(b'Invalid 2FA code', fail_2fa.data)

            # Step 3: Submit valid TOTP -> logs in successfully!
            now_code = get_totp_code(secret)
            with self.client.session_transaction() as sess:
                sess['_csrf_token'] = 'test_token_123'
            success_2fa = self.client.post('/admin/login/2fa', data={
                'csrf_token': 'test_token_123',
                'totp_code': now_code
            }, follow_redirects=True)
            self.assertIn(b'Dashboard', success_2fa.data)

        # 4. Test Emergency Forgot-Password Recovery Key Flow
        # Generate new recovery key
        rec_plain, rec_hash = generate_emergency_recovery_key()
        conn = get_db_connection()
        conn.execute("UPDATE users SET recovery_key_hash = ? WHERE id = ?", (rec_hash, user['id']))
        conn.commit()
        conn.close()

        self.client.get('/admin/logout')
        with self.client:
            self.client.get('/admin/forgot-password')
            with self.client.session_transaction() as sess:
                sess['_csrf_token'] = 'test_token_123'

            rec_res = self.client.post('/admin/forgot-password', data={
                'csrf_token': 'test_token_123',
                'username': 'superadmin',
                'recovery_key': rec_plain,
                'new_password': 'RecoveredEmergencyPassword123#',
                'confirm_password': 'RecoveredEmergencyPassword123#'
            }, follow_redirects=True)
            self.assertEqual(rec_res.status_code, 200)
            self.assertIn(b'Password reset successfully', rec_res.data)

        # Verify new password works and 2FA was cleanly reset for emergency access
        conn = get_db_connection()
        rec_user = conn.execute("SELECT password_hash, mfa_enabled FROM users WHERE id = ?", (user['id'],)).fetchone()
        conn.close()
        self.assertTrue(verify_password(rec_user['password_hash'], 'RecoveredEmergencyPassword123#'))
        self.assertEqual(rec_user['mfa_enabled'], 0)

    def test_12_full_security_suite(self):
        """Comprehensive verification of OWASP security headers, SSRF defenses, CSRF guards, and SVG XXE stripping."""
        from core.security import validate_url
        from core.media import sanitize_svg_content

        # 1. Verify OWASP Secure Headers & Hardened CSP
        res = self.client.get('/')
        self.assertEqual(res.headers.get('X-Frame-Options'), 'DENY')
        self.assertEqual(res.headers.get('X-Content-Type-Options'), 'nosniff')
        csp = res.headers.get('Content-Security-Policy', '')
        self.assertIn("default-src 'self'", csp)
        self.assertIn("object-src 'none'", csp)
        self.assertIn("base-uri 'self'", csp)
        self.assertIn("connect-src 'self'", csp)
        self.assertIn("form-action 'self'", csp)
        self.assertEqual(res.headers.get('Server'), 'Protected')

        # 2. SSRF Guard: Verify blocked destinations
        blocked_urls = [
            'http://127.0.0.1/admin',
            'http://localhost:5000/api',
            'http://169.254.169.254/latest/meta-data/',
            'http://instance-data/latest',
            'http://192.168.1.1/router',
            'http://10.0.0.1/',
            'http://172.16.0.1/',
            'http://[::1]/',
            'http://metadata.google.internal/'
        ]
        for b_url in blocked_urls:
            valid, err = validate_url(b_url)
            self.assertFalse(valid, f"URL '{b_url}' was expected to be blocked but passed!")

        # 3. SVG XXE & Stored XSS defense
        malicious_svg = b'''<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>
<svg xmlns="http://www.w3.org/2000/svg" onload="alert('xss')">
  <foreignObject width="100" height="100"><body xmlns="http://www.w3.org/1999/xhtml"><script>alert(1)</script></body></foreignObject>
  <a href="javascript:alert(2)"><text y="20">&xxe;</text></a>
</svg>'''
        sanitized_svg = sanitize_svg_content(malicious_svg).decode('utf-8')
        self.assertNotIn('<!DOCTYPE', sanitized_svg)
        self.assertNotIn('<!ENTITY', sanitized_svg)
        self.assertNotIn('onload=', sanitized_svg)
        self.assertNotIn('<foreignObject', sanitized_svg)
        self.assertNotIn('javascript:', sanitized_svg)

        # 4. Obfuscated script scheme evasion in rich-text sanitizer
        dirty_markup = '<a href="jav&#x09;ascript:alert(1)">Click</a>'
        clean_markup = sanitize_html(dirty_markup)
        self.assertNotIn('javascript:', clean_markup)

        # 5. CSRF defense on /api/download
        with self.client:
            self.client.get('/')
            with self.client.session_transaction() as sess:
                sess['_csrf_token'] = 'legit_token_777'

            # Request with invalid token must be rejected with 403
            bad_res = self.client.post('/api/download', json={
                'url': 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
                'csrf_token': 'wrong_token'
            })
            self.assertEqual(bad_res.status_code, 403)

            # Request with valid X-CSRFToken header passes CSRF verification
            # (Note: it may return a validation or download error for dummy url, but NOT 403 CSRF failure)
            good_res = self.client.post('/api/download', 
                headers={'X-CSRFToken': 'legit_token_777'},
                json={
                    'url': 'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
                    'format': 'mp4',
                    'quality': '720'
                }
            )
            self.assertNotEqual(good_res.status_code, 403)

    def test_13_audit_remediation(self):
        """Verifies all remediation for confirmed critical/high audit issues."""
        from core.security import validate_url
        from core.media import is_allowed_file
        from core.auth import check_login_rate_limit, record_failed_login, reset_login_attempts
        import socket
        from unittest.mock import patch

        # 1. SECRET_KEY must NOT be the compromised static key
        compromised_static_key = b'\x1f\xa4\x8e\xd9\x84\xce\x9a\xf4\x92;\xa3\xfc\xe8\x9f\xb4\xd2\xbd\x98\x11\xa3\x99\xfb\x9e\x7f\x80\xb1\xe4\xd3\x17\xd2\xca\xe5'
        self.assertNotEqual(app.secret_key, compromised_static_key)
        self.assertTrue(len(app.secret_key) >= 32)

        # 2. SSRF DNS resolver unexpected error MUST fail closed
        with patch('socket.getaddrinfo', side_effect=Exception("Simulated unexpected resolver network error")):
            is_valid, err = validate_url("https://some-unresolvable-domain.org/test")
            self.assertFalse(is_valid)
            self.assertIn("Domain security resolution failed", err)

        # 3. /api/debug_ytdlp SSRF protection: rejects internal URLs
        conn = get_db_connection()
        admin_row = conn.execute("SELECT id, security_stamp FROM users WHERE username = 'superadmin'").fetchone()
        conn.close()

        with self.client:
            # Login as admin in session
            with self.client.session_transaction() as sess:
                sess['user_id'] = admin_row['id']
                sess['role'] = 'admin'
                sess['security_stamp'] = admin_row['security_stamp']
            
            # Attacking internal URL
            diag_res = self.client.get('/api/debug_ytdlp?url=http://127.0.0.1/admin')
            self.assertEqual(diag_res.status_code, 400)
            diag_data = json.loads(diag_res.data)
            self.assertIn('SSRF Protection', diag_data.get('error', ''))

        # 4. SSE /api/status/<task_id> DoS thread exhaustion defense: unknown task returns 404
        bogus_uuid = "12345678-1234-5678-1234-567812345678"
        status_res = self.client.get(f'/api/status/{bogus_uuid}')
        self.assertEqual(status_res.status_code, 404)
        status_data = json.loads(status_res.data)
        self.assertIn('Task not found', status_data.get('error', ''))

        # 5. SVG upload disallowance: SVG files are completely rejected
        self.assertFalse(is_allowed_file("malicious.svg"))
        self.assertFalse(is_allowed_file("malicious.SVG"))
        self.assertTrue(is_allowed_file("safe_image.png"))
        self.assertTrue(is_allowed_file("safe_image.webp"))

        # 6. Login lockout DoS defense: attacker IP locked, legitimate user from different IP remains allowed
        attacker_ip = "198.51.100.44"
        admin_ip = "203.0.113.88"
        target_user = "targetadmin"

        reset_login_attempts(attacker_ip, username=target_user)
        reset_login_attempts(admin_ip, username=target_user)

        # Attacker fails 5 times
        for _ in range(5):
            record_failed_login(attacker_ip, username=target_user)

        # Attacker IP is now locked
        attacker_allowed, _ = check_login_rate_limit(attacker_ip, username=target_user)
        self.assertFalse(attacker_allowed)

        # Legitimate admin on admin_ip is NOT locked out by attacker's attempts!
        admin_allowed, _ = check_login_rate_limit(admin_ip, username=target_user)
        self.assertTrue(admin_allowed)

        # 7. Vary: Cookie header on admin routes
        admin_page_res = self.client.get('/admin/login')
        self.assertEqual(admin_page_res.headers.get('Vary'), 'Cookie')

        # 8. HTTPS Redirection on public domains (e.g. aryplusdownloader.tech)
        http_pub_res = self.client.get('/', headers={
            'Host': 'www.aryplusdownloader.tech',
            'X-Forwarded-Proto': 'http'
        }, follow_redirects=False)
        self.assertEqual(http_pub_res.status_code, 301)
        self.assertTrue(http_pub_res.headers.get('Location', '').startswith('https://www.aryplusdownloader.tech'))

        # 9. Strict-Transport-Security (HSTS) on public domains
        https_pub_res = self.client.get('/', headers={
            'Host': 'www.aryplusdownloader.tech',
            'X-Forwarded-Proto': 'https'
        })
        self.assertIn('max-age=31536000', https_pub_res.headers.get('Strict-Transport-Security', ''))

        # 10. Health endpoint leak prevention: No internal paths, versions, or cookie details exposed
        health_res = self.client.get('/api/health')
        self.assertEqual(health_res.status_code, 200)
        health_json = json.loads(health_res.data)
        self.assertEqual(health_json.get('status'), 'healthy')
        self.assertNotIn('/app/vendor', str(health_json))
        self.assertNotIn('ffmpeg', str(health_json))
        self.assertNotIn('cookie', str(health_json).lower())
        self.assertNotIn('qjs', str(health_json).lower())

    def test_14_defense_in_depth(self):
        """Verifies SSRF socket interceptor, proxy spoofing defense, dynamic cookie security, SSE throttling, and CSP nonces."""
        from core.security import ssrf_safe_socket
        from core.downloader import PROGRESS_CACHE, CACHE_LOCK
        from app import ACTIVE_SSE_BY_IP, SSE_STREAM_LOCK
        import socket
        import time

        # 1. ssrf_safe_socket blocks private IPs at the socket level
        with ssrf_safe_socket():
            with self.assertRaises(socket.error):
                socket.create_connection(('127.0.0.1', 80))
            with self.assertRaises(socket.error):
                socket.create_connection(('169.254.169.254', 80))

            # HTTP transports may bypass create_connection and call socket.connect
            # directly when following redirects. Guard the actual socket call too.
            guarded_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                with self.assertRaisesRegex(socket.error, 'SSRF Guard'):
                    guarded_sock.connect(('127.0.0.1', 1))
            finally:
                guarded_sock.close()

            guarded_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                self.assertEqual(guarded_sock.connect_ex(('127.0.0.1', 1)), errno.EACCES)
            finally:
                guarded_sock.close()

            # Exercise urllib3's lower-level connection path used by redirect handling.
            import urllib3.util.connection as urllib3_connection
            with self.assertRaisesRegex(socket.error, 'SSRF Guard'):
                urllib3_connection.create_connection(('127.0.0.1', 1), timeout=0.2)

            # Exercise ThreadPoolExecutor thread-inheritance (used by yt-dlp concurrent fragments)
            import concurrent.futures
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as executor:
                def worker_check():
                    guarded_s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    try:
                        guarded_s.connect(('127.0.0.1', 1))
                        return False
                    except socket.error as e:
                        return "SSRF Guard" in str(e)
                    finally:
                        guarded_s.close()
                fut = executor.submit(worker_check)
                self.assertTrue(fut.result(), "Worker thread in ThreadPoolExecutor did not inherit SSRF guard!")

        # 1b. SSRF Concurrency Isolation: Interleaved concurrent threads cannot disable or race each other's guards
        import threading
        concurrency_errors = []
        def worker(is_guarded, thread_id):
            try:
                for _ in range(5):
                    if is_guarded:
                        with ssrf_safe_socket():
                            try:
                                socket.create_connection(('127.0.0.1', 80))
                                concurrency_errors.append(f"Thread {thread_id} failed to block SSRF inside guard!")
                            except socket.error as e:
                                if "SSRF Guard" not in str(e):
                                    concurrency_errors.append(f"Unexpected error in thread {thread_id}: {e}")
                    time.sleep(0.005)
            except Exception as ex:
                concurrency_errors.append(f"Thread {thread_id} crashed: {ex}")

        threads = [threading.Thread(target=worker, args=(i % 2 == 0, i)) for i in range(10)]
        for t in threads: t.start()
        for t in threads: t.join()
        self.assertEqual(concurrency_errors, [], f"SSRF concurrency race detected: {concurrency_errors}")

        # 2. Proxy Header Spoofing Defense: Untrusted proxy cannot bypass HTTPS redirect by injecting X-Forwarded-Proto
        untrusted_spoof_res = self.client.get('/', headers={
            'Host': 'www.aryplusdownloader.tech',
            'X-Forwarded-Proto': 'https' # Spoofed header
        }, follow_redirects=False)
        # Because TRUST_PROXY is not enabled, the untrusted header is ignored and connection redirects to HTTPS!
        self.assertEqual(untrusted_spoof_res.status_code, 301)
        self.assertTrue(untrusted_spoof_res.headers.get('Location', '').startswith('https://www.aryplusdownloader.tech'))

        # 3. Dynamic Session Cookie Security: Automatically enforces Secure cookie flag on public domain
        self.client.get('/', headers={'Host': 'www.aryplusdownloader.tech'})
        self.assertTrue(app.config['SESSION_COOKIE_SECURE'])

        # 4. SSE Concurrency Throttling: Blocks DoS attempts beyond max streams per IP
        test_tid = "99999999-9999-9999-9999-999999999999"
        with CACHE_LOCK:
            PROGRESS_CACHE[test_tid] = {'status': 'processing', 'progress': 50, 'timestamp': time.time()}

        # Simulate 3 active streams already consuming slots for IP 127.0.0.1
        with SSE_STREAM_LOCK:
            ACTIVE_SSE_BY_IP['127.0.0.1'] = 3

        # 4th connection attempt MUST be throttled with HTTP 429
        throttled_res = self.client.get(f'/api/status/{test_tid}')
        self.assertEqual(throttled_res.status_code, 429)
        self.assertIn('Too many active monitor connections', throttled_res.data.decode('utf-8'))

        # Reset active stream counter
        with SSE_STREAM_LOCK:
            ACTIVE_SSE_BY_IP['127.0.0.1'] = 0

        # 5. CSP Nonce in HTTP Header and Template HTML & Hardened script-src
        home_res = self.client.get('/')
        csp_header = home_res.headers.get('Content-Security-Policy', '')
        self.assertIn("nonce-", csp_header)
        self.assertIn('nonce="', home_res.data.decode('utf-8'))
        script_src = [part for part in csp_header.split(';') if 'script-src' in part][0]
        self.assertNotIn("'unsafe-inline'", script_src)
        self.assertNotIn("'unsafe-eval'", script_src)

        # 6. Anti-Indexing X-Robots-Tag Header & Meta Tag
        login_res = self.client.get('/admin/login')
        self.assertEqual(login_res.headers.get('X-Robots-Tag'), 'noindex, nofollow, noarchive, nosnippet')
        self.assertIn('content="noindex, nofollow, noarchive, nosnippet"', login_res.data.decode('utf-8'))

        # 7. Robots.txt Security Directives
        robots_res = self.client.get('/robots.txt')
        self.assertEqual(robots_res.status_code, 200)
        self.assertIn('Disallow: /admin/', robots_res.data.decode('utf-8'))
        self.assertIn('Disallow: /api/', robots_res.data.decode('utf-8'))
        self.assertIn('Disallow: /downloads/', robots_res.data.decode('utf-8'))

    def test_featured_image_upload_and_removal(self):
        """Validates that featured images can be uploaded via AJAX endpoint, assigned to articles, and removed."""
        import io
        from core.auth import hash_password

        conn = get_db_connection()
        conn.execute("DELETE FROM articles WHERE title = ?", ('Article With Featured Image',))
        user = conn.execute("SELECT * FROM users WHERE username = 'superadmin'").fetchone()
        if not user:
            conn.execute("INSERT INTO users (username, display_name, password_hash, email, role) VALUES (?, ?, ?, ?, ?)",
                         ('superadmin', 'Senior Editor', hash_password('ComplexPassword123!'), 'admin@stellar.tech', 'admin'))
        conn.commit()
        user = conn.execute("SELECT * FROM users WHERE username = 'superadmin'").fetchone()
        conn.close()

        # 1. Login as admin
        with self.client:
            with self.client.session_transaction() as sess:
                sess['user_id'] = user['id']
                sess['username'] = user['username']
                sess['role'] = user['role']
                sess['display_name'] = user['display_name']
                sess['_csrf_token'] = 'test_token_123'

            # 2. Upload valid PNG image via /admin/api/upload
            png_bytes = b'\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR\x00\x00\x00\x01\x00\x00\x00\x01\x08\x06\x00\x00\x00\x1f\x15c4\x00\x00\x00\nIDATx\x9cc\x00\x01\x00\x00\x05\x00\x01\r\n-\xb4\x00\x00\x00\x00IEND\xaeB`\x82'
            data = {
                'file': (io.BytesIO(png_bytes), 'featured_test.png'),
                'csrf_token': 'test_token_123'
            }
            res = self.client.post('/admin/api/upload', data=data, content_type='multipart/form-data')
            self.assertEqual(res.status_code, 200)
            res_json = res.get_json()
            self.assertTrue(res_json.get('success'))
            uploaded_url = res_json.get('url')
            self.assertTrue(uploaded_url.startswith('/static/uploads/'))

            # 3. Create post with featured image
            create_data = {
                'csrf_token': 'test_token_123',
                'title': 'Article With Featured Image',
                'content': '<p>Article body content</p>',
                'status': 'published',
                'featured_image': uploaded_url,
                'featured_image_alt': 'Test alt description'
            }
            create_res = self.client.post('/admin/posts/new', data=create_data, follow_redirects=True)
            self.assertEqual(create_res.status_code, 200)

            # Check post in DB
            conn = get_db_connection()
            post_row = conn.execute("SELECT * FROM articles WHERE title = ?", ('Article With Featured Image',)).fetchone()
            self.assertIsNotNone(post_row)
            post_id = post_row['id']
            self.assertEqual(post_row['featured_image'], uploaded_url)
            self.assertEqual(post_row['featured_image_alt'], 'Test alt description')
            conn.close()

            # 4. Remove featured image by updating post with empty featured_image
            edit_data = {
                'csrf_token': 'test_token_123',
                'title': 'Article With Featured Image',
                'content': '<p>Article body content</p>',
                'status': 'published',
                'featured_image': '',  # Removed!
                'featured_image_alt': ''
            }
            edit_res = self.client.post(f'/admin/posts/{post_id}/edit', data=edit_data, follow_redirects=True)
            self.assertEqual(edit_res.status_code, 200)

            # Check post in DB has featured_image cleared (None / NULL)
            conn = get_db_connection()
            updated_post = conn.execute("SELECT * FROM articles WHERE id = ?", (post_id,)).fetchone()
            self.assertIsNone(updated_post['featured_image'])
            conn.close()

    def test_16_uploads_path_traversal_and_malformed_ports(self):
        """
        Verify:
        1. /static/uploads/ blocks path traversal attacks (%2e%2e%2f, ../../, etc.) and returns 404.
        2. /static/uploads/ refuses to serve non-image files (.py, .env, .db, .txt).
        3. URLs with malformed ports return 400 (not 500) and are safely rejected by validate_url.
        """
        from core.security import validate_url

        # 1. Path traversal attacks on static uploads
        traversal_attempts = [
            '/static/uploads/%2e%2e%2f%2e%2e%2fapp.py',
            '/static/uploads/../../app.py',
            '/static/uploads/%2e%2e%2f%2e%2e%2f%2e%2e%2f.env',
            '/static/uploads/..%2f..%2fapp.py',
            '/static/uploads/%2e%2e%2fcore/db.py',
            '/static/uploads/%2e%2e%2fProcfile',
            '/static/uploads/%2e%2e%2frequirements.txt',
        ]
        for path in traversal_attempts:
            res = self.client.get(path)
            self.assertEqual(res.status_code, 404, f"Path traversal succeeded on {path} with status {res.status_code}")
            # Ensure Python source code or env content is NEVER returned
            self.assertNotIn(b'Flask(__name__)', res.data)
            self.assertNotIn(b'SECRET_KEY', res.data)

        # 2. Malformed port handling in validate_url and /api/download
        malformed_urls = [
            "http://example.com:abc",
            "http://example.com:999999",
            "http://example.com:-1",
            "http://example.com:0",
            "http://[::1]:999999",
            "https://example.com:invalidport/video",
        ]
        for m_url in malformed_urls:
            valid, err = validate_url(m_url)
            self.assertFalse(valid, f"Malformed port URL was marked valid: {m_url}")

            # Must return 400 Bad Request, NEVER 500 Internal Server Error
            api_res = self.client.post('/api/download', json={'url': m_url, 'format': 'mp4', 'quality': '720'})
            self.assertEqual(api_res.status_code, 400, f"Malformed URL {m_url} returned status {api_res.status_code}")
            self.assertIn('error', api_res.get_json())

    def test_17_security_hardening_and_role_authorization(self):
        """
        Validates:
        1. Role authorization: non-admin roles (editor/viewer) receive 403 Forbidden on privileged routes.
        2. 2FA setup audit log does NOT leak entered TOTP authentication codes.
        3. Rate-limiting headers on /api/download responses.
        """
        # 1. Create a non-admin user
        from core.auth import hash_password
        from core.db import get_db_connection
        conn = get_db_connection()
        conn.execute(
            "INSERT INTO users (username, display_name, password_hash, email, role) VALUES (?, ?, ?, ?, ?)",
            ('test_editor', 'Editor', hash_password('EditorPass1234!'), 'editor@example.com', 'editor')
        )
        conn.commit()
        editor_row = conn.execute("SELECT id, username, email FROM users WHERE username = 'test_editor'").fetchone()
        conn.close()

        # Log in as non-admin editor
        with self.client.session_transaction() as sess:
            sess['user_id'] = editor_row['id']
            sess['username'] = editor_row['username']
            sess['email'] = editor_row['email']
            sess['role'] = 'editor'
            sess['_csrf_token'] = 'test_token'

        # Verify privileged routes reject non-admin with 403 Forbidden
        privileged_endpoints = ['/admin/', '/admin/posts', '/admin/settings', '/admin/media', '/admin/categories']
        for ep in privileged_endpoints:
            res = self.client.get(ep)
            self.assertEqual(res.status_code, 403, f"Non-admin gained access to {ep} with status {res.status_code}")

        # 2. Verify failed 2FA code is NEVER leaked into audit_logs table
        fake_secret = 'JBSWY3DPEHPK3PXP'
        secret_code = '999888'
        conn = get_db_connection()
        admin_row = conn.execute("SELECT id, username FROM users WHERE role = 'admin' LIMIT 1").fetchone()
        conn.close()
        admin_id = admin_row['id'] if admin_row else 1
        admin_name = admin_row['username'] if admin_row else 'admin'

        with self.client.session_transaction() as sess:
            sess['user_id'] = admin_id
            sess['username'] = admin_name
            sess['role'] = 'admin'
            sess['_csrf_token'] = 'test_token'

        res = self.client.post('/admin/account', data={
            'form_action': 'confirm_enable_2fa',
            'secret': fake_secret,
            'totp_code': secret_code,
            'csrf_token': 'test_token'
        })
        # Check audit log in DB
        conn = get_db_connection()
        audit_rows = conn.execute("SELECT details FROM audit_logs WHERE action = '2FA_ACTIVATION_FAILED'").fetchall()
        conn.close()
        for row in audit_rows:
            self.assertNotIn(secret_code, row['details'], "Entered 2FA TOTP code was found in audit log details!")

        # 3. Verify /api/download returns security and concurrency headers
        api_res = self.client.post('/api/download', json={'url': 'https://www.youtube.com/watch?v=aqz-KE-bpKQ', 'format': 'mp4', 'quality': '720', 'csrf_token': 'test_token'})
        self.assertIn('X-Concurrency-Limit', api_res.headers)
        self.assertEqual(api_res.headers.get('X-Concurrency-Limit'), '5')

if __name__ == '__main__':
    unittest.main()

