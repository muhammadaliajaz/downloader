import yt_dlp
import shutil
import os
import threading
import re
import time

from core.ary_extractor import extract_ary_stream_sync
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
    
    if any(domain in url.lower() for domain in ['aryplus.tv', 'aryzap.com']):
        try:
            with CACHE_LOCK:
                if task_id in PROGRESS_CACHE:
                    PROGRESS_CACHE[task_id]['title'] = "Connecting to ARY Plus CDN..."
            
            stream_info = extract_ary_stream_sync(url)
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
            r"C:\Program Files\nodejs\node.exe",
            r"C:\Program Files (x86)\nodejs\node.exe"
        ]
        for p in common:
            if os.path.isfile(p):
                return p
        return None

    node_path = get_node_path()

    is_ary = any(domain in url.lower() for domain in ['aryplus.tv', 'aryzap.com', 'vod.aryzap.com'])

    ydl_opts = {
        'outtmpl': os.path.join(download_dir, f'{task_id}_%(title)s.%(ext)s'),
        'progress_hooks': [my_hook],
        'quiet': True,
        'no_warnings': True,
        'noplaylist': True,
        'cachedir': False,
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
        ydl_opts['extractor_args'] = {
            'youtube': {
                'player_client': ['web', 'ios', 'android']
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
        if quality == 'best':
            ydl_opts['format'] = 'bestvideo+bestaudio/best'
        elif quality.isdigit():
            height = quality
            # Direct resolution match for both HLS sub-playlists and standard videos
            ydl_opts['format'] = f'bestvideo[height<={height}]+bestaudio/best[height<={height}]/best'
        else:
            ydl_opts['format'] = 'bestvideo[height<=720]+bestaudio/best[height<=720]/best'
        
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
            
            expected_filename = ydl.prepare_filename(info_target)
            if format_type == 'mp3':
                expected_filename = os.path.splitext(expected_filename)[0] + '.mp3'
            
            # Security: Path Traversal Defense
            if not is_safe_filepath(expected_filename, download_dir):
                if os.path.exists(expected_filename):
                    try:
                        os.remove(expected_filename)
                    except Exception:
                        pass
                raise Exception("Target path traversal blocked.")

            # Security: Validate file extension against allowed media extensions
            allowed_exts = ['.mp4', '.mp3', '.m4a', '.webm', '.mkv', '.avi', '.mov', '.flv']
            _, ext = os.path.splitext(expected_filename)
            if ext.lower() not in allowed_exts:
                if os.path.exists(expected_filename):
                    os.remove(expected_filename)
                raise Exception("Downloaded file type is not an allowed media format.")

            with CACHE_LOCK:
                PROGRESS_CACHE[task_id] = {
                    'status': 'finished',
                    'filepath': expected_filename,
                    'filename': os.path.basename(expected_filename),
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
        
        if any(domain in url.lower() for domain in ['aryplus.tv', 'aryzap.com', 'arydigital']):
            if 'Unsupported URL' in err_msg or 'DRM' in err_msg or 'extractor' in err_msg.lower():
                err_msg = 'ARY Plus web pages use DRM encryption.<br><span class="block mt-2 font-semibold text-white">👉 <strong>Solution:</strong> Paste the video link directly from <a href="https://www.youtube.com/@ARYDigitalasia" target="_blank" rel="noopener" class="underline text-yellow-400 hover:text-white font-black">ARY Digital Official YouTube Channel</a> to download in Full HD!</span>'
        with CACHE_LOCK:
            PROGRESS_CACHE[task_id] = {
                'status': 'error', 
                'error': err_msg,
                'timestamp': time.time()
            }
    finally:
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
