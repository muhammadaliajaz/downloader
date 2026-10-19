import re
import urllib.parse
import requests

def is_tiktok_url(url):
    """Checks whether the given URL or identifier is a TikTok video."""
    if not url or not isinstance(url, str):
        return False
    u = url.strip().lower()
    if any(domain in u for domain in ['tiktok.com', 'tiktokv.com', 'douyin.com']):
        return True
    # Pure numeric ID (15 to 22 digits)
    if re.match(r'^\d{15,22}$', url.strip()):
        return True
    return False

def normalize_tiktok_url(url):
    """Converts raw TikTok IDs or short links into a standard canonical URL."""
    clean = url.strip()
    if re.match(r'^\d{15,22}$', clean):
        return f"https://www.tiktok.com/@user/video/{clean}"
    if clean.startswith(('tiktok.com/', 'www.tiktok.com/', 'vm.tiktok.com/', 'vt.tiktok.com/')):
        return f"https://{clean}"
    return clean

def extract_tiktok_stream(url, format_type='mp4'):
    """
    Directly extracts watermark-free MP4 stream or MP3 audio from TikTok
    via the high-speed TikWM JSON engine with zero bot challenges.
    Falls back gracefully to None if network or API is unavailable.
    """
    try:
        canonical_url = normalize_tiktok_url(url)
        encoded_url = urllib.parse.quote(canonical_url, safe=':/?=&')
        api_url = f"https://www.tikwm.com/api/?url={encoded_url}"
        
        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Accept': 'application/json'
        }
        
        resp = requests.get(api_url, headers=headers, timeout=6)
        if resp.status_code != 200:
            return None
        
        data_json = resp.json()
        if data_json.get('code') == 0 and data_json.get('data'):
            d = data_json['data']
            
            # Select stream based on requested format
            if format_type == 'mp3' and d.get('music'):
                stream = d.get('music')
            else:
                stream = d.get('play') or d.get('wmplay')
            
            if stream:
                # Ensure stream URL is absolute
                if stream.startswith('//'):
                    stream = 'https:' + stream
                elif stream.startswith('/'):
                    stream = 'https://www.tikwm.com' + stream

                return {
                    'stream_url': stream,
                    'title': (d.get('title') or 'TikTok Video').strip(),
                    'thumbnail': d.get('cover') or d.get('origin_cover'),
                    'duration': d.get('duration', 0),
                    'author': d.get('author', {}).get('nickname', 'TikTok Creator')
                }
    except Exception as e:
        print(f"[TikTok Extractor] Direct extraction notice: {e}")
    
    return None
