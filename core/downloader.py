import yt_dlp
import shutil
import os
import threading
import re
import time
import tempfile

from core.ary_extractor import extract_ary_stream, is_ary_url
from core.tiktok_extractor import extract_tiktok_stream, is_tiktok_url, normalize_tiktok_url
from core.security import release_concurrency_slot, is_safe_filepath

PROGRESS_CACHE = {}
CANCEL_EVENTS = {}
CACHE_LOCK = threading.Lock()
CANCEL_LOCK = threading.Lock()

class CancelledError(Exception):
    """Custom exception to signal download cancellation."""
    pass

def _prune_cache():
    """Remove cache entries older than 2 hours."""
    now = time.time()
    to_delete = []
    with CACHE_LOCK:
        for tid, data in PROGRESS_CACHE.items():
            if now - data.get('timestamp', 0) > 7200: # 2 hours
                to_delete.append(tid)
        for tid in to_delete:
            del PROGRESS_CACHE[tid]

def get_progress(task_id):
    return PROGRESS_CACHE.get(task_id)

def cancel_download(task_id):
    with CANCEL_LOCK:
        if task_id in CANCEL_EVENTS:
            CANCEL_EVENTS[task_id].set()
            return True
    return False

def download_task(task_id, url, format_type, quality, download_dir):
    _prune_cache()
    
    # Initialize Cancel Event
    cancel_event = threading.Event()
    with CANCEL_LOCK:
        CANCEL_EVENTS[task_id] = cancel_event

    with CACHE_LOCK:
        PROGRESS_CACHE[task_id] = {
            'status': 'processing', 
            'progress': 0, 
            'timestamp': time.time()
        }

    # ARY Plus / ARY Zap Native Direct Stream Extractor
    target_url = url
    ary_title = None
    ary_thumbnail = None
    
    if is_ary_url(url):
        try:
            with CACHE_LOCK:
                if task_id in PROGRESS_CACHE:
                    PROGRESS_CACHE[task_id]['title'] = "Connecting to ARY Plus CDN..."
            
            stream_info = extract_ary_stream(url)
            if stream_info and stream_info.get('video_url'):
                target_url = stream_info['video_url']
                ary_title = stream_info.get('title')
                ary_thumbnail = stream_info.get('thumbnail')
                with CACHE_LOCK:
                    if task_id in PROGRESS_CACHE:
                        PROGRESS_CACHE[task_id].update({
                            'title': ary_title or "ARY Plus Video",
                            'thumbnail': ary_thumbnail
                        })
        except Exception as e:
            print("ARY Extractor fallback notice:", e)

    # TikTok Direct Stream Extractor (Watermark-free, zero bot block)
    tiktok_title = None
    tiktok_thumbnail = None
    is_tiktok = is_tiktok_url(url)
    
    if is_tiktok:
        try:
            with CACHE_LOCK:
                if task_id in PROGRESS_CACHE:
                    PROGRESS_CACHE[task_id]['title'] = "Connecting to TikTok high-speed CDN..."
            
            tiktok_info = extract_tiktok_stream(url, format_type)
            if tiktok_info and tiktok_info.get('stream_url'):
                target_url = tiktok_info['stream_url']
                tiktok_title = tiktok_info.get('title')
                tiktok_thumbnail = tiktok_info.get('thumbnail')
                with CACHE_LOCK:
                    if task_id in PROGRESS_CACHE:
                        PROGRESS_CACHE[task_id].update({
                            'title': tiktok_title or "TikTok Video",
                            'thumbnail': tiktok_thumbnail
                        })
            else:
                target_url = normalize_tiktok_url(url)
        except Exception as e:
            print("TikTok Extractor fallback notice:", e)

    if not target_url.startswith('http://') and not target_url.startswith('https://'):
        target_url = f"ytsearch1:{url}"

    def my_hook(d):
        # Check for cancellation
        if cancel_event.is_set():
            raise CancelledError("User requested cancellation")

        # DoS Defense: Abort downloads exceeding 2 GB to protect server disk space
        MAX_ALLOWED_BYTES = 2 * 1024 * 1024 * 1024 # 2 GB
        dl_bytes = d.get('downloaded_bytes') or 0
        tot_bytes = d.get('total_bytes') or d.get('total_bytes_estimate') or 0
        if dl_bytes > MAX_ALLOWED_BYTES or tot_bytes > MAX_ALLOWED_BYTES:
            raise CancelledError("Download exceeded the maximum allowed size limit of 2 GB.")

        ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
        
        def clean_ansi(text):
            if not text: return "N/A"
            return ansi_escape.sub('', text).strip()

        if d['status'] == 'downloading':
            try:
                percent_str = clean_ansi(d.get('_percent_str', '0%'))
                clean_percent = percent_str.replace('%', '').strip()
                progress = float(clean_percent)
            except Exception:
                progress = 0
            
            PROGRESS_CACHE[task_id] = {
                'status': 'downloading',
                'progress': progress,
                'speed': clean_ansi(d.get('_speed_str', 'N/A')),
                'eta': clean_ansi(d.get('_eta_str', 'N/A')),
                'total_size': clean_ansi(d.get('_total_bytes_str') or d.get('_total_bytes_estimate_str') or 'N/A'),
                'downloaded': clean_ansi(d.get('_downloaded_bytes_str', 'N/A')),
                'timestamp': time.time()
            }
        elif d['status'] == 'finished':
            with CACHE_LOCK:
                if task_id in PROGRESS_CACHE:
                    PROGRESS_CACHE[task_id].update({'status': 'converting', 'timestamp': time.time()})

    # Detect ffmpeg executable location (if installed)
    def get_ffmpeg_path():
        path = shutil.which('ffmpeg')
        if path:
            return path
        common_paths = [
            "/usr/bin/ffmpeg",
            "/usr/local/bin/ffmpeg",
            "/app/vendor/ffmpeg/ffmpeg",
            "/app/vendor/ffmpeg/bin/ffmpeg",
            r"C:\Program Files\ffmpeg\bin\ffmpeg.exe",
            r"C:\Program Files\Gyan\ffmpeg\bin\ffmpeg.exe",
        ]
        local_app_data = os.environ.get('LOCALAPPDATA', '')
        if local_app_data:
            winget_dir = os.path.join(local_app_data, 'Microsoft', 'WinGet', 'Packages')
            if os.path.isdir(winget_dir):
                for root, _, files in os.walk(winget_dir):
                    if 'ffmpeg.exe' in files:
                        common_paths.append(os.path.join(root, 'ffmpeg.exe'))
                        break

        for p in common_paths:
            if os.path.isfile(p):
                return p
        return None
    ffmpeg_path = get_ffmpeg_path()
    if ffmpeg_path:
        os.environ['FFMPEG_BINARY'] = ffmpeg_path

    # Detect Node.js runtime for YouTube challenge solving
    def get_node_path():
        path = shutil.which('node')
        if path:
            return path
        common = [
            "/app/.apt/usr/bin/node",
            "/usr/bin/node",
            "/usr/local/bin/node",
            "/app/bin/node",
            r"C:\Program Files\nodejs\node.exe",
            r"C:\Program Files (x86)\nodejs\node.exe"
        ]
        for p in common:
            if os.path.isfile(p):
                return p
        return None

    node_path = get_node_path()

    is_ary = is_ary_url(url) or is_ary_url(target_url)

    ydl_opts = {
        'outtmpl': os.path.join(download_dir, f'{task_id}_%(title)s.%(ext)s'),
        'progress_hooks': [my_hook],
        'quiet': True,
        'no_warnings': True,
        'noplaylist': True,
        'cachedir': False,
        'force_ipv4': True,
        'youtube_include_dash_manifest': False,
        'youtube_include_hls_manifest': False,
        'retries': 5,
        'fragment_retries': 5,
        'skip_unavailable_fragments': True,
        'keep_fragments': False,
        'file_access_retries': 3,
        'extractor_retries': 3,
        'socket_timeout': 15,
        'nocheckcertificate': True,
        'postprocessor_args': {
            'ffmpeg': ['-threads', '0', '-preset', 'ultrafast']
        }
    }

    if ffmpeg_path:
        ydl_opts['ffmpeg_location'] = ffmpeg_path

    if node_path:
        ydl_opts['js_runtimes'] = {'node': {'path': node_path}}
        ydl_opts['remote_components'] = ['ejs:github']

    if is_ary:
        ydl_opts['http_headers'] = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Referer': 'https://aryplus.tv/',
            'Origin': 'https://aryplus.tv'
        }
        # 8 concurrent fragments gives max CDN throughput without socket drops
        ydl_opts['concurrent_fragments'] = 8
        ydl_opts['buffersize'] = 2097152
        ydl_opts['hls_prefer_native'] = True
    elif is_tiktok:
        ydl_opts['http_headers'] = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Referer': 'https://www.tiktok.com/',
        }
        ydl_opts['concurrent_fragments'] = 4
    else:
        ydl_opts['concurrent_fragments'] = 6
    task_cookiefile = None
    repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    
    def is_valid_netscape(file_path):
        try:
            if not os.path.isfile(file_path) or os.path.getsize(file_path) < 15:
                return False
            with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                head = f.read(500)
                return ('# Netscape' in head or '.youtube.com' in head) and '\t' in head
        except Exception:
            return False

    # Check environment variable YOUTUBE_COOKIES, but ONLY write if it is genuine Netscape format
    env_cookie_file = os.path.join(tempfile.gettempdir(), 'env_youtube_cookies.txt')
    raw_cookies = os.environ.get('YOUTUBE_COOKIES', '').strip()
    if raw_cookies:
        decoded_cookies = None
        try:
            import base64
            b64_candidate = base64.b64decode(raw_cookies).decode('utf-8', errors='ignore')
            if ('youtube.com' in b64_candidate or '# Netscape' in b64_candidate) and '\t' in b64_candidate:
                decoded_cookies = b64_candidate
        except Exception:
            pass

        if not decoded_cookies:
            if '\\n' in raw_cookies:
                raw_cookies = raw_cookies.replace('\\n', '\n').replace('\\t', '\t')
            if ('youtube.com' in raw_cookies or '# Netscape' in raw_cookies) and '\t' in raw_cookies:
                decoded_cookies = raw_cookies

        if decoded_cookies:
            try:
                with open(env_cookie_file, 'w', encoding='utf-8') as f:
                    f.write(decoded_cookies)
            except Exception as e:
                print("Notice writing cookies from env:", e)

    possible_cookie_paths = [
        os.path.join(repo_root, 'www.youtube.com_cookies.txt'),
        os.path.join(repo_root, 'cookies.txt'),
        '/app/www.youtube.com_cookies.txt',
        '/app/cookies.txt',
        os.path.join(os.getcwd(), 'www.youtube.com_cookies.txt'),
        os.path.join(os.getcwd(), 'cookies.txt'),
        env_cookie_file
    ]
    
    task_cookiefile = None
    has_cookies = False
    for cp in possible_cookie_paths:
        if is_valid_netscape(cp):
            try:
                task_cookiefile = os.path.join(tempfile.gettempdir(), f"yt_cookies_{task_id}.txt")
                shutil.copyfile(cp, task_cookiefile)
                ydl_opts['cookiefile'] = task_cookiefile
            except Exception:
                ydl_opts['cookiefile'] = cp
            has_cookies = True
            break

    # YouTube Cloud Engine:
    # 1. 'visionos' uses native Apple HLS (.m3u8) manifests which completely bypass:
    #    - Cloud datacenter bot challenges ("Sign in to confirm you're not a bot")
    #    - SABR encrypted streaming experiments
    #    - Web player JavaScript 'n' challenge requirements
    # 2. 'web' leverages authenticated cookies
    # 3. 'tv' and 'android' serve as supplemental stream fallbacks
    ydl_opts['extractor_args'] = {
        'youtube': {
            'player_client': ['visionos', 'web', 'tv', 'android']
        }
    }

    if format_type == 'mp3':
        ydl_opts.update({
            'format': 'bestaudio/best',
            'postprocessors': [{
                'key': 'FFmpegExtractAudio',
                'preferredcodec': 'mp3',
                'preferredquality': '192',
            }],
        })
    else:
        ydl_opts['merge_output_format'] = 'mp4'
        if quality == 'best':
            ydl_opts['format'] = 'bestvideo+bestaudio/best'
        elif quality.isdigit():
            height = quality
            ydl_opts['format'] = f'bestvideo[height<={height}]+bestaudio/bestvideo+bestaudio/best'
        else:
            ydl_opts['format'] = 'bestvideo[height<=720]+bestaudio/bestvideo+bestaudio/best'
        
    try:
        # Store metadata as soon as we get it
        metadata = {}
        
        def pre_download_hook(d):
            # Capture title/thumbnail immediately when info is available
            if d.get('info_dict') and not metadata.get('captured'):
                info = d['info_dict']
                metadata['title'] = info.get('title', 'Unknown Video')
                metadata['thumbnail'] = info.get('thumbnail')
                metadata['captured'] = True
                # Update cache immediately so UI shows preview
                with CACHE_LOCK:
                    if task_id in PROGRESS_CACHE:
                        PROGRESS_CACHE[task_id].update({
                            'title': metadata['title'],
                            'thumbnail': metadata['thumbnail'],
                            'timestamp': time.time()
                        })
        
        # Add the hook to get early metadata
        original_hooks = ydl_opts.get('progress_hooks', [])
        ydl_opts['progress_hooks'] = [pre_download_hook] + original_hooks
        
        with yt_dlp.YoutubeDL(ydl_opts) as ydl:
            info = ydl.extract_info(target_url, download=True)
            
            # Handle playlist/search result dictionary
            if info.get('_type') == 'playlist' or 'entries' in info:
                entries = info.get('entries') or []
                if entries:
                    info_target = entries[0]
                else:
                    raise Exception("No video stream found for the requested ARY link.")
            else:
                info_target = info
            
            # Use captured metadata or fallback to info target
            title = ary_title or tiktok_title or metadata.get('title') or info_target.get('title', 'Video')
            thumbnail = ary_thumbnail or tiktok_thumbnail or metadata.get('thumbnail') or info_target.get('thumbnail')
            
            # Locate the actual downloaded media file on disk
            actual_filepath = None
            
            # 1. Check requested_downloads tracked by yt_dlp
            for source_dict in [info, info_target]:
                for rd in source_dict.get('requested_downloads', []):
                    fp = rd.get('filepath')
                    if fp and os.path.isfile(fp):
                        actual_filepath = fp
                        break
                if actual_filepath:
                    break

            # 2. Check standard prepare_filename if not found in requested_downloads
            if not actual_filepath or not os.path.isfile(actual_filepath):
                prep_fn = ydl.prepare_filename(info_target)
                if format_type == 'mp3':
                    prep_fn = os.path.splitext(prep_fn)[0] + '.mp3'
                if os.path.isfile(prep_fn):
                    actual_filepath = prep_fn

            # 3. Resilient directory scan for the unique task_id prefix
            if not actual_filepath or not os.path.isfile(actual_filepath):
                for f in os.listdir(download_dir):
                    if f.startswith(f"{task_id}_") and not (f.endswith('.part') or f.endswith('.temp') or f.endswith('.ytdl')):
                        candidate = os.path.join(download_dir, f)
                        if os.path.isfile(candidate):
                            actual_filepath = candidate
                            break

            if not actual_filepath or not os.path.isfile(actual_filepath):
                raise Exception("Download failed: Resulting media file was not found on server.")

            # Sanitize title and rename to clean safe file name
            safe_title = re.sub(r'[\\/*?:"<>|]', "", title).strip() or "video"
            safe_title = re.sub(r'\s+', ' ', safe_title)[:80]
            _, actual_ext = os.path.splitext(actual_filepath)
            
            desired_filename = os.path.join(download_dir, f"{task_id}_{safe_title}{actual_ext}")
            final_filepath = actual_filepath
            if os.path.abspath(actual_filepath) != os.path.abspath(desired_filename):
                try:
                    if os.path.exists(desired_filename):
                        os.remove(desired_filename)
                    os.rename(actual_filepath, desired_filename)
                    final_filepath = desired_filename
                except Exception as e:
                    print("Rename notice:", e)
                    final_filepath = actual_filepath

            # Security: Path Traversal Defense
            if not is_safe_filepath(final_filepath, download_dir):
                if os.path.exists(final_filepath):
                    try:
                        os.remove(final_filepath)
                    except Exception:
                        pass
                raise Exception("Target path traversal blocked.")

            # Security: Validate file extension against allowed media extensions
            allowed_exts = ['.mp4', '.mp3', '.m4a', '.webm', '.mkv', '.avi', '.mov', '.flv']
            _, ext = os.path.splitext(final_filepath)
            if ext.lower() not in allowed_exts:
                if os.path.exists(final_filepath):
                    os.remove(final_filepath)
                raise Exception("Downloaded file type is not an allowed media format.")

            with CACHE_LOCK:
                PROGRESS_CACHE[task_id] = {
                    'status': 'finished',
                    'filepath': final_filepath,
                    'filename': os.path.basename(final_filepath),
                    'task_id': task_id,
                    'timestamp': time.time(),
                    'title': title,
                    'thumbnail': thumbnail
                }
    except CancelledError:
        with CACHE_LOCK:
            PROGRESS_CACHE[task_id] = {
                'status': 'cancelled',
                'timestamp': time.time()
            }
        # Cleanup partial files
        for f in os.listdir(download_dir):
            if f.startswith(task_id) and (f.endswith('.part') or f.endswith('.temp')):
                try:
                    os.remove(os.path.join(download_dir, f))
                except:
                    pass
    except Exception as e:
        err_msg = str(e)
        # Security: Mask internal server directory paths from error messages
        err_msg = re.sub(r'[A-Za-z]:\\[^\s<]+', '[Server Path]', err_msg)
        err_msg = re.sub(r'/(?:[a-zA-Z0-9_\-\.]+/)+[a-zA-Z0-9_\-\.]+', '[Server Path]', err_msg)
        
        if is_ary_url(url):
            if 'DRM' in err_msg:
                err_msg = 'This ARY stream is protected by DRM encryption.<br><span class="block mt-2 font-semibold text-white">👉 <strong>Solution:</strong> Paste the video link directly from <a href="https://www.youtube.com/@ARYDigitalasia" target="_blank" rel="noopener" class="underline text-yellow-400 hover:text-white font-black">ARY Digital Official YouTube Channel</a> to download in Full HD!</span>'
            elif 'Unsupported URL' in err_msg or 'extractor' in err_msg.lower():
                err_msg = 'Unable to extract stream from this ARY link. Please verify the episode URL from aryplus.tv.'
        with CACHE_LOCK:
            PROGRESS_CACHE[task_id] = {
                'status': 'error', 
                'error': err_msg,
                'timestamp': time.time()
            }
    finally:
        if task_cookiefile and os.path.exists(task_cookiefile):
            try:
                os.remove(task_cookiefile)
            except Exception:
                pass
        # Release server concurrency slot
        release_concurrency_slot()
        # Final cleanup of the event
        with CANCEL_LOCK:
            if task_id in CANCEL_EVENTS:
                del CANCEL_EVENTS[task_id]

def start_download_thread(task_id, url, format_type, quality, download_dir):
    thread = threading.Thread(target=download_task, args=(task_id, url, format_type, quality, download_dir))
    thread.daemon = True
    thread.start()
