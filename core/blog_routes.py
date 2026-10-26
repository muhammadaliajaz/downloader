import math
import os
from flask import Blueprint, render_template, request, abort, Response, current_app, flash, redirect, url_for
from core.db import get_db_connection, check_and_publish_scheduled, get_setting
from core.sanitizer import calculate_reading_time
from core.security import check_rate_limit
from core.auth import validate_csrf_token

blog_bp = Blueprint('blog', __name__)

BLOG_LAST_SCHEDULED_CHECK = 0

@blog_bp.before_request
def trigger_scheduled_publish():
    """Silently transitions any due scheduled articles to published status (throttled to 60s)."""
    global BLOG_LAST_SCHEDULED_CHECK
    import time
    now = time.time()
    if now - BLOG_LAST_SCHEDULED_CHECK < 60:
        return
    BLOG_LAST_SCHEDULED_CHECK = now
    try:
        check_and_publish_scheduled()
    except Exception:
        pass

@blog_bp.route('/blog/', endpoint='index', strict_slashes=False)
@blog_bp.route('/blog/', endpoint='blog_index', strict_slashes=False)
def blog_index():
    """Blog homepage with article cards, categories, search, and pagination."""
    page = request.args.get('page', 1, type=int)
    search_query = request.args.get('q', '').strip()
    category_slug = request.args.get('category', '').strip()

    try:
        per_page = int(get_setting('posts_per_page', 9))
    except Exception:
        per_page = 9

    conn = get_db_connection()
    
    # Base query for published articles
    base_sql = """
        FROM articles a
        LEFT JOIN categories c ON a.category_id = c.id
        WHERE a.status = 'published' AND a.published_at <= CURRENT_TIMESTAMP
    """
    params = []

    if search_query:
        base_sql += " AND (a.title LIKE ? OR a.excerpt LIKE ? OR a.content LIKE ?)"
        term = f"%{search_query}%"
        params.extend([term, term, term])

    if category_slug:
        base_sql += " AND c.slug = ?"
        params.append(category_slug)

    # Count total articles
    count_sql = "SELECT COUNT(*) " + base_sql
    total_articles = conn.execute(count_sql, params).fetchone()[0]
    total_pages = max(1, math.ceil(total_articles / per_page))
    page = max(1, min(page, total_pages))
    offset = (page - 1) * per_page

    # Fetch articles
    articles_sql = f"""
        SELECT a.id, a.title, a.slug, a.excerpt, a.content, a.featured_image, a.featured_image_alt,
               a.author_name, a.published_at, a.updated_at, a.views_count,
               c.name as category_name, c.slug as category_slug
        {base_sql}
        ORDER BY a.published_at DESC
        LIMIT ? OFFSET ?
    """
    articles_raw = conn.execute(articles_sql, params + [per_page, offset]).fetchall()

    articles = []
    for row in articles_raw:
        art = dict(row)
        art['reading_time'] = calculate_reading_time(art.get('content', ''))
        articles.append(art)

    # Fetch categories with article count
    categories = conn.execute("""
        SELECT c.name, c.slug, COUNT(a.id) as post_count
        FROM categories c
        LEFT JOIN articles a ON a.category_id = c.id AND a.status = 'published' AND a.published_at <= CURRENT_TIMESTAMP
        GROUP BY c.id
        ORDER BY post_count DESC, c.name ASC
    """).fetchall()

    # Fetch featured / latest hero post if on page 1 with no search
    featured_post = None
    if page == 1 and not search_query and not category_slug and articles:
        featured_post = articles[0]

    site_settings = {
        'site_title': get_setting('site_title', 'ARY PLUS DOWNLOADER'),
        'site_tagline': get_setting('site_tagline', 'Free Video Downloader & Tech Insights'),
        'site_description': get_setting('site_description', 'High-quality guides, tech tips, and streaming insights.'),
        'canonical_url': request.base_url
    }

    conn.close()

    return render_template(
        'blog/index.html',
        articles=articles,
        featured_post=featured_post,
        categories=categories,
        current_page=page,
        total_pages=total_pages,
        total_articles=total_articles,
        search_query=search_query,
        selected_category=category_slug,
        site_settings=site_settings
    )

@blog_bp.route('/blog/<slug>/', endpoint='post_detail', strict_slashes=False)
@blog_bp.route('/blog/<slug>/', endpoint='article_detail', strict_slashes=False)
def article_detail(slug):
    """Public single article view with full rich-text content, author, SEO tags, and related articles."""
    conn = get_db_connection()
    
    # Query article
    article_row = conn.execute("""
        SELECT a.*, c.name as category_name, c.slug as category_slug
        FROM articles a
        LEFT JOIN categories c ON a.category_id = c.id
        WHERE a.slug = ?
    """, (slug,)).fetchone()

    if not article_row:
        conn.close()
        abort(404)

    article = dict(article_row)

    # Check status: if not published, block unless preview flag is set from admin session
    from flask import session
    is_admin = bool(session.get('user_id'))
    is_published = (article['status'] == 'published' and article.get('published_at'))
    
    if not is_published and not is_admin:
        conn.close()
        abort(404)

    # Increment view counter silently if not admin preview
    if is_published:
        conn.execute("UPDATE articles SET views_count = views_count + 1 WHERE id = ?", (article['id'],))
        conn.commit()

    article['reading_time'] = calculate_reading_time(article.get('content', ''))

    # Fetch tags for this article
    tags = conn.execute("""
        SELECT t.name, t.slug
        FROM tags t
        JOIN article_tags at ON t.id = at.tag_id
        WHERE at.article_id = ?
        ORDER BY t.name ASC
    """, (article['id'],)).fetchall()

    # Fetch related articles from same category
    related_articles = []
    if article.get('category_id'):
        related_raw = conn.execute("""
            SELECT a.title, a.slug, a.excerpt, a.content, a.featured_image, a.published_at,
                   c.name as category_name, c.slug as category_slug
            FROM articles a
            LEFT JOIN categories c ON a.category_id = c.id
            WHERE a.category_id = ? AND a.id != ? AND a.status = 'published' AND a.published_at <= CURRENT_TIMESTAMP
            ORDER BY a.published_at DESC
            LIMIT 3
        """, (article['category_id'], article['id'])).fetchall()
        for r in related_raw:
            rel = dict(r)
            rel['reading_time'] = calculate_reading_time(rel.get('content', ''))
            related_articles.append(rel)

    # Recent articles fallback if no related in category
    if not related_articles:
        recent_raw = conn.execute("""
            SELECT a.title, a.slug, a.excerpt, a.content, a.featured_image, a.published_at,
                   c.name as category_name, c.slug as category_slug
            FROM articles a
            LEFT JOIN categories c ON a.category_id = c.id
            WHERE a.id != ? AND a.status = 'published' AND a.published_at <= CURRENT_TIMESTAMP
            ORDER BY a.published_at DESC
            LIMIT 3
        """, (article['id'],)).fetchall()
        for r in recent_raw:
            rel = dict(r)
            rel['reading_time'] = calculate_reading_time(rel.get('content', ''))
            related_articles.append(rel)

    site_settings = {
        'site_title': get_setting('site_title', 'ARY PLUS DOWNLOADER'),
        'site_url': get_setting('site_url', 'https://www.aryplusdownloader.tech'),
    }

    conn.close()

    return render_template(
        'blog/post.html',
        article=article,
        tags=tags,
        related_articles=related_articles,
        site_settings=site_settings,
        is_preview=(not is_published and is_admin)
    )

@blog_bp.route('/category/<slug>/', strict_slashes=False)
def category_archive(slug):
    """Archive page for articles filed under a specific category."""
    page = request.args.get('page', 1, type=int)
    per_page = 9

    conn = get_db_connection()
    category = conn.execute("SELECT * FROM categories WHERE slug = ?", (slug,)).fetchone()
    if not category:
        conn.close()
        abort(404)

    # Count articles in category
    total_articles = conn.execute("""
        SELECT COUNT(*) FROM articles
        WHERE category_id = ? AND status = 'published' AND published_at <= CURRENT_TIMESTAMP
    """, (category['id'],)).fetchone()[0]

    total_pages = max(1, math.ceil(total_articles / per_page))
    page = max(1, min(page, total_pages))
    offset = (page - 1) * per_page

    articles_raw = conn.execute("""
        SELECT a.id, a.title, a.slug, a.excerpt, a.content, a.featured_image, a.featured_image_alt,
               a.author_name, a.published_at, a.views_count,
               c.name as category_name, c.slug as category_slug
        FROM articles a
        JOIN categories c ON a.category_id = c.id
        WHERE a.category_id = ? AND a.status = 'published' AND a.published_at <= CURRENT_TIMESTAMP
        ORDER BY a.published_at DESC
        LIMIT ? OFFSET ?
    """, (category['id'], per_page, offset)).fetchall()

    articles = []
    for r in articles_raw:
        art = dict(r)
        art['reading_time'] = calculate_reading_time(art.get('content', ''))
        articles.append(art)

    all_categories = conn.execute("""
        SELECT c.name, c.slug, COUNT(a.id) as post_count
        FROM categories c
        LEFT JOIN articles a ON a.category_id = c.id AND a.status = 'published' AND a.published_at <= CURRENT_TIMESTAMP
        GROUP BY c.id
        ORDER BY post_count DESC
    """).fetchall()

    conn.close()

    return render_template(
        'blog/category.html',
        category=category,
        articles=articles,
        all_categories=all_categories,
        current_page=page,
        total_pages=total_pages,
        total_articles=total_articles
    )

@blog_bp.route('/tag/<slug>/', strict_slashes=False)
def tag_archive(slug):
    """Archive page for articles tagged with a specific tag."""
    page = request.args.get('page', 1, type=int)
    per_page = 9

    conn = get_db_connection()
    tag = conn.execute("SELECT * FROM tags WHERE slug = ?", (slug,)).fetchone()
    if not tag:
        conn.close()
        abort(404)

    # Count articles with tag
    total_articles = conn.execute("""
        SELECT COUNT(a.id)
        FROM articles a
        JOIN article_tags at ON a.id = at.article_id
        WHERE at.tag_id = ? AND a.status = 'published' AND a.published_at <= CURRENT_TIMESTAMP
    """, (tag['id'],)).fetchone()[0]

    total_pages = max(1, math.ceil(total_articles / per_page))
    page = max(1, min(page, total_pages))
    offset = (page - 1) * per_page

    articles_raw = conn.execute("""
        SELECT a.id, a.title, a.slug, a.excerpt, a.content, a.featured_image, a.featured_image_alt,
               a.author_name, a.published_at, a.views_count,
               c.name as category_name, c.slug as category_slug
        FROM articles a
        JOIN article_tags at ON a.id = at.article_id
        LEFT JOIN categories c ON a.category_id = c.id
        WHERE at.tag_id = ? AND a.status = 'published' AND a.published_at <= CURRENT_TIMESTAMP
        ORDER BY a.published_at DESC
        LIMIT ? OFFSET ?
    """, (tag['id'], per_page, offset)).fetchall()

    articles = []
    for r in articles_raw:
        art = dict(r)
        art['reading_time'] = calculate_reading_time(art.get('content', ''))
        articles.append(art)

    conn.close()

    return render_template(
        'blog/tag.html',
        tag=tag,
        articles=articles,
        current_page=page,
        total_pages=total_pages,
        total_articles=total_articles
    )

# Static public pages
@blog_bp.route('/about/', strict_slashes=False)
def about_page():
    return render_template('pages/about.html', site_title=get_setting('site_title'))

@blog_bp.route('/contact/', methods=['GET', 'POST'], strict_slashes=False)
def contact_page():
    if request.method == 'POST':
        if not validate_csrf_token(request.form.get('csrf_token', '')):
            flash('Security token invalid or expired. Please refresh and try again.', 'error')
            return render_template('pages/contact.html', site_title=get_setting('site_title'))

        client_ip = request.remote_addr or '127.0.0.1'
        allowed, retry_after = check_rate_limit(client_ip)
        if not allowed:
            flash('Too many messages sent. Please wait a minute and try again.', 'error')
            return render_template('pages/contact.html', site_title=get_setting('site_title'))

        name = request.form.get('name', '').strip()
        email = request.form.get('email', '').strip()
        message = request.form.get('message', '').strip()
        
        if not name or not email or not message:
            flash('Please fill in all required fields.', 'error')
        else:
            flash('Thank you for reaching out! Your message has been received.', 'success')
            return redirect(url_for('blog.contact_page'))

    return render_template('pages/contact.html', site_title=get_setting('site_title'), contact_email=get_setting('contact_email'))

@blog_bp.route('/privacy/', strict_slashes=False)
def privacy_page():
    return render_template('pages/privacy.html', site_title=get_setting('site_title'))

@blog_bp.route('/terms/', strict_slashes=False)
def terms_page():
    return render_template('pages/terms.html', site_title=get_setting('site_title'))

@blog_bp.route('/disclaimer/', strict_slashes=False)
def disclaimer_page():
    return render_template('pages/disclaimer.html', site_title=get_setting('site_title'))

# SEO Sitemap & Robots
@blog_bp.route('/sitemap.xml')
def sitemap_xml():
    """Generates dynamic XML sitemap containing all published articles, categories, and public pages."""
    conn = get_db_connection()
    site_url = get_setting('site_url', 'https://www.aryplusdownloader.tech').rstrip('/')

    articles = conn.execute("""
        SELECT slug, updated_at, published_at
        FROM articles
        WHERE status = 'published' AND published_at <= CURRENT_TIMESTAMP AND is_noindex = 0
        ORDER BY published_at DESC
    """).fetchall()

    categories = conn.execute("SELECT slug FROM categories").fetchall()
    conn.close()

    xml_lines = [
        '<?xml version="1.0" encoding="UTF-8"?>',
        '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'
    ]

    # Public static pages
    static_routes = [
        ('/', '1.0', 'daily'),
        ('/blog/', '0.9', 'daily'),
        ('/about/', '0.7', 'monthly'),
        ('/contact/', '0.7', 'monthly'),
        ('/privacy/', '0.5', 'monthly'),
        ('/terms/', '0.5', 'monthly'),
        ('/disclaimer/', '0.5', 'monthly'),
    ]

    for path, prio, freq in static_routes:
        xml_lines.append(f"  <url><loc>{site_url}{path}</loc><changefreq>{freq}</changefreq><priority>{prio}</priority></url>")

    # Category pages
    for c in categories:
        xml_lines.append(f"  <url><loc>{site_url}/category/{c['slug']}/</loc><changefreq>weekly</changefreq><priority>0.7</priority></url>")

    # Published articles
    for a in articles:
        lastmod = (a['updated_at'] or a['published_at'] or '').split()[0]
        mod_tag = f"<lastmod>{lastmod}</lastmod>" if lastmod else ""
        xml_lines.append(f"  <url><loc>{site_url}/blog/{a['slug']}/</loc>{mod_tag}<changefreq>weekly</changefreq><priority>0.8</priority></url>")

    xml_lines.append('</urlset>')
    return Response('\n'.join(xml_lines), mimetype='application/xml')

@blog_bp.route('/robots.txt')
def robots_txt():
    """Standard search engine directives."""
    site_url = get_setting('site_url', 'https://www.aryplusdownloader.tech').rstrip('/')
    content = f"""User-agent: *
Allow: /
Disallow: /admin/
Disallow: /api/
Disallow: /downloads/

Sitemap: {site_url}/sitemap.xml
"""
    return Response(content, mimetype='text/plain')
