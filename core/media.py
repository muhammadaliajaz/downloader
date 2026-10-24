import os
import uuid
import re
from werkzeug.utils import secure_filename
from core.db import get_db_connection

UPLOAD_FOLDER = os.path.abspath(os.path.join(os.path.dirname(os.path.dirname(__file__)), 'static', 'uploads'))
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# 5 MB Max File Size for Media Uploads
MAX_IMAGE_SIZE = 5 * 1024 * 1024 

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'webp', 'gif'}
ALLOWED_MIME_TYPES = {
    'image/jpeg': {'jpg', 'jpeg'},
    'image/png': {'png'},
    'image/webp': {'webp'},
    'image/gif': {'gif'}
}

def is_allowed_file(filename: str) -> bool:
    """Validates file extension."""
    if '.' not in filename:
        return False
    ext = filename.rsplit('.', 1)[1].lower()
    return ext in ALLOWED_EXTENSIONS

def validate_image_bytes(file_stream, ext: str) -> bool:
    """Verifies image magic header bytes against the claimed extension."""
    pos = file_stream.tell()
    header = file_stream.read(32)
    file_stream.seek(pos) # Reset stream position

    if ext in ['jpg', 'jpeg']:
        return header.startswith(b'\xff\xd8\xff')
    elif ext == 'png':
        return header.startswith(b'\x89PNG\r\n\x1a\n')
    elif ext == 'gif':
        return header.startswith(b'GIF87a') or header.startswith(b'GIF89a')
    elif ext == 'webp':
        return header.startswith(b'RIFF') and b'WEBP' in header[:16]
    elif ext == 'svg':
        # Text/XML check for SVG
        try:
            head_str = header.decode('utf-8', errors='ignore').lower()
            return '<?xml' in head_str or '<svg' in head_str
        except Exception:
            return False
    return False

def sanitize_svg_content(content_bytes: bytes) -> bytes:
    """Strips executable JS, XXE entities, and embedded HTML from SVG to prevent Stored XSS/XXE."""
    text = content_bytes.decode('utf-8', errors='ignore')
    # Strip script tags
    text = re.sub(r'<\s*script\b[^>]*>.*?<\s*/\s*script\s*>', '', text, flags=re.DOTALL | re.IGNORECASE)
    # Strip on* event handlers (e.g. onload=, onclick=, onerror=)
    text = re.sub(r'\bon\w+\s*=\s*(["\'][^"\']*["\']|[^\s>]+)', '', text, flags=re.IGNORECASE)
    # Strip javascript: and data: URIs in href and xlink:href
    text = re.sub(r'(href|xlink:href)\s*=\s*["\']\s*(javascript|data):[^"\']*["\']', 'href="#"', text, flags=re.IGNORECASE)
    # Strip foreignObject (which allows arbitrary embedded HTML/XSS inside SVG)
    text = re.sub(r'<\s*foreignObject\b[^>]*>.*?<\s*/\s*foreignObject\s*>', '', text, flags=re.DOTALL | re.IGNORECASE)
    # Strip DOCTYPE and ENTITY to block XML External Entity (XXE) attacks
    text = re.sub(r'<!DOCTYPE[^>]*(\[.*?\])?>', '', text, flags=re.DOTALL | re.IGNORECASE)
    text = re.sub(r'<!ENTITY[^>]*>', '', text, flags=re.IGNORECASE)
    # Strip xml-stylesheet
    text = re.sub(r'<\?xml-stylesheet[^>]*\?>', '', text, flags=re.IGNORECASE)
    return text.encode('utf-8')

def save_media_file(file_storage):
    """
    Saves an uploaded media file safely to disk and registers it in the media table.
    Returns (success: bool, url_or_error: str, media_id: int)
    """
    if not file_storage or not file_storage.filename:
        return False, "No file selected.", None

    orig_name = file_storage.filename.strip()
    if not is_allowed_file(orig_name):
        return False, "Invalid file format. Allowed formats: PNG, JPG, JPEG, WEBP, GIF (SVG is disallowed for security).", None

    ext = orig_name.rsplit('.', 1)[1].lower()

    # Size check
    file_storage.seek(0, os.SEEK_END)
    size = file_storage.tell()
    file_storage.seek(0)
    
    if size > MAX_IMAGE_SIZE:
        return False, f"File size exceeds 5MB limit ({size / (1024*1024):.1f}MB uploaded).", None

    if size < 10:
        return False, "Uploaded file is empty or corrupted.", None

    # Magic byte verification
    if not validate_image_bytes(file_storage, ext):
        return False, "File content does not match the image extension signature.", None

    # Generate safe unique filename
    safe_base = secure_filename(orig_name.rsplit('.', 1)[0])
    safe_base = re.sub(r'[^a-zA-Z0-9_-]', '', safe_base)[:30] or 'image'
    unique_name = f"{safe_base}_{uuid.uuid4().hex[:10]}.{ext}"
    target_path = os.path.join(UPLOAD_FOLDER, unique_name)

    try:
        if ext == 'svg':
            file_storage.seek(0)
            raw = file_storage.read()
            cleaned = sanitize_svg_content(raw)
            with open(target_path, 'wb') as f:
                f.write(cleaned)
        else:
            file_storage.save(target_path)
    except Exception as e:
        return False, f"Failed to save file: {str(e)}", None

    # Mime type detection
    mime_type = getattr(file_storage, 'mimetype', None) or f"image/{ext}"
    public_url = f"/static/uploads/{unique_name}"

    # Register in DB
    conn = get_db_connection()
    cursor = conn.cursor()
    cursor.execute('''
        INSERT INTO media (filename, original_name, filepath, file_size, mime_type)
        VALUES (?, ?, ?, ?, ?)
    ''', (unique_name, orig_name, public_url, size, mime_type))
    conn.commit()
    media_id = cursor.lastrowid
    conn.close()

    return True, public_url, media_id
