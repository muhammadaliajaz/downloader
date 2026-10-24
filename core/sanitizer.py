import re
import html
from html.parser import HTMLParser
from urllib.parse import urlparse

# Allowed HTML elements for rich text content
ALLOWED_TAGS = {
    'p', 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'br', 'hr',
    'strong', 'b', 'em', 'i', 'u', 's', 'strike',
    'ul', 'ol', 'li', 'blockquote', 'pre', 'code',
    'a', 'img', 'table', 'thead', 'tbody', 'tfoot', 'tr', 'th', 'td',
    'div', 'span', 'figure', 'figcaption'
}

# Allowed attributes per tag
ALLOWED_ATTRIBUTES = {
    'a': {'href', 'title', 'target', 'rel', 'class'},
    'img': {'src', 'alt', 'title', 'width', 'height', 'class', 'loading'},
    'table': {'class'},
    'div': {'class'},
    'span': {'class'},
    'pre': {'class'},
    'code': {'class'},
    'h1': {'class', 'id'},
    'h2': {'class', 'id'},
    'h3': {'class', 'id'},
    'h4': {'class', 'id'},
    'p': {'class'},
    'blockquote': {'class'}
}

DISALLOWED_SCHEMES = {'javascript', 'vbscript', 'data'}

class HTMLSanitizerParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.result = []

    def handle_starttag(self, tag, attrs):
        tag_lower = tag.lower()
        if tag_lower not in ALLOWED_TAGS:
            return # Skip tag completely

        cleaned_attrs = []
        allowed_attrs = ALLOWED_ATTRIBUTES.get(tag_lower, set())
        
        for attr_name, attr_val in attrs:
            attr_lower = attr_name.lower()
            if attr_lower.startswith('on'):
                continue # Block JS event handlers like onclick, onerror

            if attr_lower in allowed_attrs or attr_lower.startswith('data-'):
                if attr_lower in {'href', 'src'}:
                    # Validate URL protocol and block obfuscated schemes (e.g. java\tscript:)
                    val_clean = re.sub(r'[\s\x00-\x1f]', '', (attr_val or '').lower())
                    if any(val_clean.startswith(f"{ds}:") for ds in DISALLOWED_SCHEMES):
                        continue # Drop malicious URI schemes
                    parsed = urlparse(attr_val.strip())
                    scheme = parsed.scheme.lower()
                    if scheme in DISALLOWED_SCHEMES:
                        continue # Drop malicious URI schemes
                    # Automatically ensure external links have noopener noreferrer
                    if tag_lower == 'a':
                        cleaned_attrs.append(('rel', 'noopener noreferrer'))

                cleaned_attrs.append((attr_name, html.escape(attr_val or '', quote=True)))

        attr_str = ' '.join(f'{k}="{v}"' for k, v in cleaned_attrs)
        if attr_str:
            self.result.append(f'<{tag_lower} {attr_str}>')
        else:
            self.result.append(f'<{tag_lower}>')

    def handle_endtag(self, tag):
        tag_lower = tag.lower()
        if tag_lower in ALLOWED_TAGS and tag_lower not in {'img', 'br', 'hr'}:
            self.result.append(f'</{tag_lower}>')

    def handle_data(self, data):
        self.result.append(html.escape(data))

    def handle_entityref(self, name):
        self.result.append(f'&{name};')

    def handle_charref(self, name):
        self.result.append(f'&#{name};')

def sanitize_html(raw_html: str) -> str:
    """Sanitizes raw rich text HTML to prevent Stored XSS."""
    if not raw_html:
        return ''
    
    # Strip any direct script/style tags including content first
    cleaned = re.sub(r'<(script|style|iframe|object|embed)[^>]*>.*?</\1>', '', raw_html, flags=re.DOTALL | re.IGNORECASE)
    
    parser = HTMLSanitizerParser()
    parser.feed(cleaned)
    parser.close()
    return ''.join(parser.result)

def strip_tags(html_text: str) -> str:
    """Strips all HTML tags to return plain text."""
    if not html_text:
        return ''
    return re.sub(r'<[^>]*?>', '', html_text).strip()

def slugify(text: str) -> str:
    """Converts a title into a clean, URL-safe slug."""
    if not text:
        return 'post'
    text = text.strip().lower()
    # Replace non-word characters with hyphen
    text = re.sub(r'[^\w\s-]', '', text)
    text = re.sub(r'[\s_-]+', '-', text)
    text = text.strip('-')
    return text[:120] or 'post'

def calculate_reading_time(html_content: str) -> str:
    """Estimates reading time based on 200 words per minute."""
    plain = strip_tags(html_content)
    words = len(plain.split())
    minutes = max(1, round(words / 200))
    return f"{minutes} min read"

def generate_excerpt(html_content: str, max_chars: int = 160) -> str:
    """Generates a clean text excerpt from HTML content."""
    plain = strip_tags(html_content)
    plain = re.sub(r'\s+', ' ', plain)
    if len(plain) <= max_chars:
        return plain
    # Cut off cleanly at the last space
    truncated = plain[:max_chars].rsplit(' ', 1)[0]
    return f"{truncated}..."
