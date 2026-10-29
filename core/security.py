import urllib.parse
import ipaddress
import errno
import os
import time
import threading
import socket
import tempfile
from contextlib import contextmanager
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

# Restricted non-HTTP service ports to prevent SSRF port scanning
ALLOWED_PORTS = {80, 443, 8080, 8443}

def check_rate_limit(client_ip):
    """
    Checks if client IP has exceeded the allowed download request rate limit.
    Returns (allowed: bool, retry_after: int)
    """
    if not client_ip:
        client_ip = '127.0.0.1'

    now = time.time()
    with RATE_LIMIT_LOCK:
        # Periodic garbage collection for inactive IPs
        if len(IP_REQUEST_LOG) > 300:
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

TASK_LOCK_DIR = os.path.join(tempfile.gettempdir(), 'ytdl_concurrency_locks')
try:
    os.makedirs(TASK_LOCK_DIR, exist_ok=True)
except Exception:
    pass

def _prune_stale_concurrency_locks():
    now = time.time()
    try:
        if os.path.isdir(TASK_LOCK_DIR):
            for fname in os.listdir(TASK_LOCK_DIR):
                if fname.endswith('.lock'):
                    fpath = os.path.join(TASK_LOCK_DIR, fname)
                    if os.path.isfile(fpath) and (now - os.path.getmtime(fpath) > 360):
                        try:
                            os.remove(fpath)
                        except Exception:
                            pass
    except Exception:
        pass

def acquire_concurrency_slot(task_id: str = None) -> bool:
    """
    Attempts to acquire an active download slot.
    Cross-worker & cross-instance safe: verifies both in-memory counter
    and shared filesystem lock directory.
    """
    global ACTIVE_DOWNLOADS_COUNT
    with ACTIVE_LOCK:
        _prune_stale_concurrency_locks()
        
        active_fs_locks = 0
        try:
            if os.path.isdir(TASK_LOCK_DIR):
                active_fs_locks = len([f for f in os.listdir(TASK_LOCK_DIR) if f.endswith('.lock')])
        except Exception:
            active_fs_locks = 0

        effective_count = max(ACTIVE_DOWNLOADS_COUNT, active_fs_locks)
        if effective_count >= MAX_CONCURRENT_DOWNLOADS:
            return False

        ACTIVE_DOWNLOADS_COUNT += 1
        if task_id:
            try:
                lock_file = os.path.join(TASK_LOCK_DIR, f"{task_id}.lock")
                with open(lock_file, 'w', encoding='utf-8') as f:
                    f.write(str(time.time()))
            except Exception:
                pass
        return True

def release_concurrency_slot(task_id: str = None):
    """Releases an active download slot from in-memory and shared lock directory."""
    global ACTIVE_DOWNLOADS_COUNT
    with ACTIVE_LOCK:
        if ACTIVE_DOWNLOADS_COUNT > 0:
            ACTIVE_DOWNLOADS_COUNT -= 1
        if task_id:
            try:
                lock_file = os.path.join(TASK_LOCK_DIR, f"{task_id}.lock")
                if os.path.isfile(lock_file):
                    os.remove(lock_file)
            except Exception:
                pass

def is_prohibited_ip(ip):
    """
    Comprehensive verification against all private, loopback, link-local,
    reserved, multicast, and carrier-grade NAT address spaces.
    """
    # Unpack IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1 -> 127.0.0.1)
    if hasattr(ip, 'ipv4_mapped') and ip.ipv4_mapped:
        ip = ip.ipv4_mapped

    if (
        ip.is_private or
        ip.is_loopback or
        ip.is_link_local or
        ip.is_reserved or
        ip.is_multicast or
        ip.is_unspecified
    ):
        return True

    # Carrier Grade NAT (RFC 6598) & IETF Protocol/Benchmark Assignments
    try:
        if ip.version == 4:
            if ip in ipaddress.ip_network('100.64.0.0/10'):
                return True
            if ip in ipaddress.ip_network('192.0.0.0/24'):
                return True
            if ip in ipaddress.ip_network('198.18.0.0/15'):
                return True
    except Exception:
        pass

    return False

def validate_url(url):
    """
    Strictly validates input URLs to prevent SSRF, DNS rebinding, internal port
    scanning, local network probing, and CRLF / command injection.
    """
    if not url or not isinstance(url, str):
        return False, "URL is required"
    
    url = url.strip()
    if len(url) > 2048:
        return False, "URL length exceeds maximum limit of 2048 characters"

    # Block control characters, CR, LF, and null bytes (Prevents CRLF / HTTP Smuggling)
    if any(c in url for c in ['\r', '\n', '\0', '\t']):
        return False, "URL contains illegal control characters"

    try:
        parsed = urllib.parse.urlparse(url)
        if not parsed.scheme or parsed.scheme.lower() not in ['http', 'https']:
            return False, "Only HTTP and HTTPS URLs are permitted"

        # Accessing hostname or port on malformed URLs (e.g. invalid port characters or out of range)
        # raises ValueError in urllib.parse. Catching ValueError here prevents uncaught 500 crashes.
        hostname = parsed.hostname
        if not hostname:
            return False, "Invalid URL hostname"

        hostname = hostname.lower().strip()

        # Port restriction: Block non-standard or dangerous services
        port = parsed.port
        if port is not None and port not in ALLOWED_PORTS:
            return False, f"Target port {port} is prohibited. Only standard web ports (80, 443, 8080, 8443) are allowed."
    except (ValueError, TypeError) as e:
        return False, f"Malformed URL port or structure: {str(e)}"
    except Exception:
        return False, "Invalid URL structure"

    # Block local loopback and internal hostname patterns
    blocked_hosts = ['localhost', 'loopback', 'local', 'internal', 'intranet', 'instance-data', 'metadata', 'localdomain', 'onion']
    if any(h == hostname or hostname.endswith('.' + h) for h in blocked_hosts):
        return False, "Access to local or internal network destinations is prohibited"

    # Check if hostname is directly an IP address
    try:
        ip = ipaddress.ip_address(hostname)
        if is_prohibited_ip(ip):
            return False, "Access to private, loopback, or reserved IP addresses is prohibited"
    except ValueError:
        # Hostname is a domain name: Resolve via DNS to verify target IP address
        try:
            resolved_addrs = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
            if not resolved_addrs:
                return False, "Target domain could not be resolved"
            
            for addr_info in resolved_addrs:
                ip_str = addr_info[4][0]
                resolved_ip = ipaddress.ip_address(ip_str)
                if is_prohibited_ip(resolved_ip):
                    return False, "Target domain resolves to a prohibited internal or reserved IP address"
        except socket.gaierror:
            # If domain cannot be resolved via DNS, reject it to prevent blind SSRF
            return False, "Target domain name does not exist or could not be resolved"
        except Exception as e:
            # Strictly fail-closed on any unexpected DNS, network, or resolver error
            return False, f"Domain security resolution failed: {str(e)}"

    return True, None

def is_safe_filepath(file_path, base_directory):
    """
    Prevents Path Traversal attacks by confirming that target file path 
    is strictly located within the designated base directory.
    Canonicalizes paths, resolves symlinks, and rejects base directory itself.
    """
    if not file_path or not base_directory:
        return False
    try:
        target_abs = os.path.realpath(os.path.abspath(file_path))
        base_abs = os.path.realpath(os.path.abspath(base_directory))
        return os.path.commonpath([target_abs, base_abs]) == base_abs and target_abs != base_abs
    except Exception:
        return False

# ============================================================================
# Thread-Isolated SSRF Protection with DNS Rebinding Defense (IP Pinning)
# ============================================================================

_SSRF_TLS = threading.local()
_ORIGINAL_CREATE_CONNECTION = socket.create_connection
_ORIGINAL_SOCKET_CONNECT = socket.socket.connect
_ORIGINAL_SOCKET_CONNECT_EX = socket.socket.connect_ex
_HOOK_LOCK = threading.Lock()
_HOOK_INSTALLED = False

_DNS_CACHE = {}
_DNS_CACHE_LOCK = threading.Lock()
_DNS_CACHE_TTL = 300 # 5 minutes cache

def _get_cached_addrinfo(host, port, family=socket.AF_UNSPEC):
    """
    High-performance in-memory DNS cache:
    Eliminates blocking getaddrinfo roundtrips on repeated video fragment connections,
    and sorts addresses to prioritize IPv4 (AF_INET) for maximum line-rate download speed.
    """
    now = time.time()
    cache_key = (host, port, family)
    with _DNS_CACHE_LOCK:
        if cache_key in _DNS_CACHE:
            ts, addrs = _DNS_CACHE[cache_key]
            if now - ts < _DNS_CACHE_TTL:
                return addrs

    addrs = socket.getaddrinfo(host, port, family, socket.SOCK_STREAM)
    # Sort addresses to prioritize IPv4 (AF_INET) to prevent IPv6 timeout penalties
    addrs.sort(key=lambda x: 0 if x[0] == socket.AF_INET else 1)

    with _DNS_CACHE_LOCK:
        if len(_DNS_CACHE) > 500:
            _DNS_CACHE.clear()
        _DNS_CACHE[cache_key] = (now, addrs)
    return addrs

def _validate_socket_destination(sock, address):
    """Validate the actual address passed to a socket connect call.

    HTTP libraries may bypass ``socket.create_connection`` and call
    ``socket.socket.connect`` directly (notably while following redirects).
    Checking the resolved sockaddr at this layer closes that gap.
    """
    if not getattr(_SSRF_TLS, 'active', False):
        return address

    if sock.family not in (socket.AF_INET, socket.AF_INET6):
        raise socket.error("SSRF Guard: Non-IP socket destinations are prohibited")

    if not isinstance(address, tuple) or len(address) < 2:
        raise socket.error("SSRF Guard: Invalid socket destination")

    host, port = address[0], address[1]
    try:
        ip = ipaddress.ip_address(host.split('%', 1)[0] if isinstance(host, str) else host)
    except ValueError:
        # Some callers pass a hostname directly to socket.connect. Resolve it
        # once, reject mixed public/private answers, then pin to the sockaddr.
        try:
            addrs = _get_cached_addrinfo(host, port, sock.family)
        except OSError as exc:
            raise socket.error(f"SSRF Guard: Domain resolution failed: {exc}")

        if not addrs:
            raise socket.error("SSRF Guard: Domain could not be resolved")

        safe_sockaddrs = []
        for af, _socktype, _proto, _canonname, sockaddr in addrs:
            resolved_ip = ipaddress.ip_address(sockaddr[0].split('%', 1)[0])
            if is_prohibited_ip(resolved_ip):
                raise socket.error(f"SSRF Guard: Prohibited resolved IP destination {resolved_ip}")
            if af == sock.family:
                safe_sockaddrs.append(sockaddr)

        if not safe_sockaddrs:
            raise socket.error("SSRF Guard: No compatible safe address was resolved")
        return safe_sockaddrs[0]

    if is_prohibited_ip(ip):
        raise socket.error(f"SSRF Guard: Prohibited IP destination {ip}")
    return address

def _safe_socket_connect(sock, address):
    return _ORIGINAL_SOCKET_CONNECT(sock, _validate_socket_destination(sock, address))

def _safe_socket_connect_ex(sock, address):
    try:
        address = _validate_socket_destination(sock, address)
    except OSError as exc:
        return exc.errno or errno.EACCES
    return _ORIGINAL_SOCKET_CONNECT_EX(sock, address)

def _safe_thread_start(self, *args, **kwargs):
    """
    Ensures that any worker threads spawned by yt-dlp, ThreadPoolExecutor, or HTTP transports
    automatically inherit the SSRF security context of their parent thread.
    """
    if getattr(_SSRF_TLS, 'active', False):
        orig_run = self.run
        def guarded_run(*r_args, **r_kwargs):
            _SSRF_TLS.active = True
            try:
                return orig_run(*r_args, **r_kwargs)
            finally:
                _SSRF_TLS.active = False
        self.run = guarded_run
    return _ORIGINAL_THREAD_START(self, *args, **kwargs)

_ORIGINAL_THREAD_START = threading.Thread.start

def _safe_create_connection(address, timeout=socket._GLOBAL_DEFAULT_TIMEOUT, source_address=None, **kwargs):
    """
    Thread-safe connection hook that pins to verified safe IP addresses.
    Only acts when active on the current thread (_SSRF_TLS.active is True).
    Blocks DNS rebinding by connecting directly to the validated IP, not the hostname.
    """
    if not getattr(_SSRF_TLS, 'active', False):
        if source_address:
            return _ORIGINAL_CREATE_CONNECTION(address, timeout, source_address=source_address, **kwargs)
        return _ORIGINAL_CREATE_CONNECTION(address, timeout, **kwargs)

    host, port = address[0], address[1]

    # 1. Direct IP Check
    try:
        ip = ipaddress.ip_address(host)
        if is_prohibited_ip(ip):
            raise socket.error(f"SSRF Guard: Prohibited IP destination {ip}")
        # Pin directly to verified IP
        if source_address:
            return _ORIGINAL_CREATE_CONNECTION((str(ip), port), timeout, source_address=source_address, **kwargs)
        return _ORIGINAL_CREATE_CONNECTION((str(ip), port), timeout, **kwargs)
    except ValueError:
        pass

    # 2. Hostname Resolution with DNS Rebinding Defense (IP Pinning)
    try:
        addrs = _get_cached_addrinfo(host, port, socket.AF_UNSPEC)
        if not addrs:
            raise socket.gaierror(f"SSRF Guard: Domain {host} could not be resolved")

        # Verify all resolved IPs first (reject immediately if dual-homed to private IP)
        safe_addrs = []
        for addr in addrs:
            ip_str = addr[4][0]
            ip = ipaddress.ip_address(ip_str)
            if is_prohibited_ip(ip):
                raise socket.error(f"SSRF Guard: Prohibited resolved IP destination {ip} for {host}")
            safe_addrs.append(addr)
    except socket.gaierror as e:
        raise socket.error(f"SSRF Guard: Domain resolution error for {host}: {str(e)}")

    # 3. Connect to the validated socket addresses directly (prevents secondary DNS rebinding lookup)
    last_err = None
    for af, socktype, proto, canonname, sa in safe_addrs:
        sock = None
        try:
            sock = socket.socket(af, socktype, proto)
            if timeout is not socket._GLOBAL_DEFAULT_TIMEOUT:
                sock.settimeout(timeout)
            if source_address:
                sock.bind(source_address)
            sock.connect(sa)
            return sock
        except socket.error as err:
            last_err = err
            if sock is not None:
                sock.close()

    if last_err is not None:
        raise last_err
    raise socket.error(f"SSRF Guard: Unable to connect to verified addresses for {host}")

def _install_ssrf_socket_hook():
    global _HOOK_INSTALLED
    with _HOOK_LOCK:
        if not _HOOK_INSTALLED:
            socket.create_connection = _safe_create_connection
            socket.socket.connect = _safe_socket_connect
            socket.socket.connect_ex = _safe_socket_connect_ex
            threading.Thread.start = _safe_thread_start

            # 1. urllib3 connection hook (used by requests and yt-dlp)
            try:
                import urllib3.util.connection as u3_conn
                orig_u3_create = u3_conn.create_connection
                def _safe_u3_create(address, *args, **kwargs):
                    if getattr(_SSRF_TLS, 'active', False):
                        host = address[0]
                        try:
                            ip = ipaddress.ip_address(host.split('%', 1)[0] if isinstance(host, str) else host)
                            if is_prohibited_ip(ip):
                                raise socket.error(f"SSRF Guard: Prohibited IP destination {ip}")
                        except ValueError:
                            pass
                    return orig_u3_create(address, *args, **kwargs)
                u3_conn.create_connection = _safe_u3_create
            except (ImportError, AttributeError):
                pass

            # 2. requests redirect hook (stops redirects at HTTP protocol layer)
            try:
                import requests.sessions
                orig_res_redir = requests.sessions.Session.resolve_redirects
                def _safe_resolve_redirects(self, resp, req, *args, **kwargs):
                    for r in orig_res_redir(self, resp, req, *args, **kwargs):
                        if getattr(_SSRF_TLS, 'active', False):
                            t_url = getattr(r, 'url', None)
                            if t_url:
                                valid, err = validate_url(t_url)
                                if not valid:
                                    raise requests.exceptions.InvalidURL(f"SSRF Guard: Blocked redirect to prohibited destination: {err}")
                        yield r
                requests.sessions.Session.resolve_redirects = _safe_resolve_redirects
            except (ImportError, AttributeError):
                pass

            # 3. urllib.request redirect hook
            try:
                import urllib.request
                orig_urllib_redir = urllib.request.HTTPRedirectHandler.redirect_request
                def _safe_urllib_redirect(self, req, fp, code, msg, headers, newurl):
                    if getattr(_SSRF_TLS, 'active', False):
                        valid, err = validate_url(newurl)
                        if not valid:
                            raise urllib.error.HTTPError(newurl, 400, f"SSRF Guard: Blocked redirect to prohibited destination: {err}", headers, fp)
                    return orig_urllib_redir(self, req, fp, code, msg, headers, newurl)
                urllib.request.HTTPRedirectHandler.redirect_request = _safe_urllib_redirect
            except (ImportError, AttributeError):
                pass

            _HOOK_INSTALLED = True

# Install hook permanently at module load time
_install_ssrf_socket_hook()

@contextmanager
def ssrf_safe_socket():
    """
    Context manager that activates thread-isolated SSRF protection for the current thread and child workers.
    - Completely eliminates concurrency races (each thread has its own isolated flag).
    - Prevents DNS rebinding by pinning outbound sockets directly to verified IP addresses.
    - Preserves TLS SNI and HTTP Host headers for full HTTPS/CDN compatibility.
    - Proactively blocks redirect bypasses at both socket and HTTP layers.
    """
    _install_ssrf_socket_hook()
    prev_state = getattr(_SSRF_TLS, 'active', False)
    _SSRF_TLS.active = True
    try:
        yield
    finally:
        _SSRF_TLS.active = prev_state


