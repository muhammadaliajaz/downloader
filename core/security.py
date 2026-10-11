import urllib.parse
import ipaddress
import os
import time
import threading
from collections import defaultdict

# In-memory storage for IP rate limiting
IP_REQUEST_LOG = defaultdict(list)
RATE_LIMIT_LOCK = threading.Lock()

# Rate limit settings: Max 10 download requests per 60 seconds per IP
MAX_REQUESTS_PER_MINUTE = 10
WINDOW_SECONDS = 60

# Max server-wide active concurrent downloads (prevents DoS RAM exhaustion)
MAX_CONCURRENT_DOWNLOADS = 5
ACTIVE_DOWNLOADS_COUNT = 0
ACTIVE_LOCK = threading.Lock()

def check_rate_limit(client_ip):
    """
    Checks if client IP has exceeded the allowed download request rate limit.
    Returns (allowed: bool, retry_after: int)
    """
    now = time.time()
    with RATE_LIMIT_LOCK:
        # Periodic garbage collection for inactive IPs (every ~100 requests)
        if len(IP_REQUEST_LOG) > 200:
            stale_ips = [ip for ip, timestamps in IP_REQUEST_LOG.items() if not timestamps or (now - timestamps[-1] > 3600)]
            for ip in stale_ips:
                del IP_REQUEST_LOG[ip]

        # Prune requests older than window
        IP_REQUEST_LOG[client_ip] = [t for t in IP_REQUEST_LOG[client_ip] if now - t < WINDOW_SECONDS]
        
        if len(IP_REQUEST_LOG[client_ip]) >= MAX_REQUESTS_PER_MINUTE:
            oldest_request = IP_REQUEST_LOG[client_ip][0]
            retry_after = int(WINDOW_SECONDS - (now - oldest_request)) + 1
            return False, retry_after
        
        IP_REQUEST_LOG[client_ip].append(now)
        return True, 0

def acquire_concurrency_slot():
    """Attempts to acquire an active download slot. Returns True if successful."""
    global ACTIVE_DOWNLOADS_COUNT
    with ACTIVE_LOCK:
        if ACTIVE_DOWNLOADS_COUNT >= MAX_CONCURRENT_DOWNLOADS:
            return False
        ACTIVE_DOWNLOADS_COUNT += 1
        return True

def release_concurrency_slot():
    """Releases an active download slot."""
    global ACTIVE_DOWNLOADS_COUNT
    with ACTIVE_LOCK:
        if ACTIVE_DOWNLOADS_COUNT > 0:
            ACTIVE_DOWNLOADS_COUNT -= 1

def validate_url(url):
    """
    Strictly validates input URLs to prevent SSRF, local network scanning, 
    and arbitrary scheme execution attacks.
    """
    if not url or not isinstance(url, str):
        return False, "URL is required"
    
    url = url.strip()
    if len(url) > 2048:
        return False, "URL length exceeds maximum limit of 2048 characters"

    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        return False, "Invalid URL structure"

    if parsed.scheme.lower() not in ['http', 'https']:
        return False, "Only HTTP and HTTPS URLs are permitted"

    hostname = parsed.hostname
    if not hostname:
        return False, "Invalid URL hostname"

    hostname = hostname.lower()

    # Block local loopback and internal hostname patterns
    blocked_hosts = ['localhost', 'loopback', 'local']
    if any(h == hostname or hostname.endswith('.' + h) for h in blocked_hosts):
        return False, "Access to local network destinations is prohibited"

    # Check if hostname is an IP address and block private/reserved IPs
    try:
        ip = ipaddress.ip_address(hostname)
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
            return False, "Access to private or internal IP addresses is prohibited"
    except ValueError:
        # Domain name - resolve IP via DNS to prevent DNS Rebinding / nip.io spoofing
        try:
            import socket
            resolved_addrs = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            for addr_info in resolved_addrs:
                ip_str = addr_info[4][0]
                resolved_ip = ipaddress.ip_address(ip_str)
                if resolved_ip.is_private or resolved_ip.is_loopback or resolved_ip.is_link_local or resolved_ip.is_reserved or resolved_ip.is_multicast:
                    return False, "Target domain resolves to a prohibited internal IP address"
        except Exception:
            # If DNS resolution fails, allow yt-dlp to handle or fail naturally
            pass

    return True, None

def is_safe_filepath(file_path, base_directory):
    """
    Prevents Path Traversal attacks by confirming that target file path 
    is strictly located within the designated downloads directory.
    """
    if not file_path or not os.path.isabs(file_path):
        return False
    
    target_abs = os.path.abspath(file_path)
    base_abs = os.path.abspath(base_directory)
    
    # Common prefix check with separator to prevent path prefix matching attacks
    return os.path.commonpath([target_abs, base_abs]) == base_abs
