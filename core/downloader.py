import yt_dlp
import shutil
import os
import threading
import re
import time

from core.ary_extractor import extract_ary_stream_sync
from core.security import release_concurrency_slot

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

    if not target_url.startswith('http://') and not target_url.startswith('https://'):
        target_url = f"ytsearch1:{url}"

    def my_hook(d):
        # Check for cancellation
        if cancel_event.is_set():
            raise CancelledError("User requested cancellation")

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

    ydl_opts = {
        'outtmpl': os.path.join(download_dir, f'{task_id}_%(title)s.%(ext)s'),
        'progress_hooks': [my_hook],
        'quiet': True,
        'no_warnings': True,
        'noplaylist': True,
        'cachedir': False,                    # Skip disk cache lookup for speed
        'youtube_include_dash_manifest': False, # Skip extra manifest queries
        'youtube_include_hls_manifest': False,
        'extractor_args': {
            'youtube': {
                'player_client': ['ios', 'android', 'web']
            }
        },
        # ULTRA-FAST SPEED OPTIMIZATIONS
        'concurrent_fragments': 32,           # 32 Multi-Threaded Concurrent Streams
        'buffersize': 4194304,                # 4 MB Memory Buffer
        'http_chunk_size': 10485760,          # 10 MB Chunk Transfers
        'hls_use_mpegts': True,               # Ultra fast HLS stream processing
        'hls_prefer_native': True,            # Multi-fragment native HLS downloader
        'retries': 3,                         # Fast retries
        'fragment_retries': 3,                # Fast fragment retries
        'skip_unavailable_fragments': True,   # Skip broken fragments immediately
        'keep_fragments': False,              # Clean up temporary fragments instantly
        'file_access_retries': 2,             # Fast file access retries
        'extractor_retries': 2,               # Fast extractor retries
        'socket_timeout': 10,                 # 10 sec socket timeout for instant failover
        'nocheckcertificate': True,           # Skip SSL cert verification overhead
        'http_headers': {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
            'Referer': 'https://aryplus.tv/',
            'Origin': 'https://aryplus.tv'
        },
        'postprocessor_args': {
            'ffmpeg': ['-threads', '0', '-preset', 'ultrafast']
        }
    }
    
    if ffmpeg_path:
        ydl_opts['ffmpeg_location'] = ffmpeg_path

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
            # Best available quality
            ydl_opts.update({
                'format': 'best[ext=mp4]/best/bestvideo+bestaudio',
            })
        elif quality.isdigit():
            # Specific height quality (e.g. 720p) - optimized for both HLS streams and standard mp4
            height = quality
            ydl_opts.update({
                'format': f'best[height<={height}][ext=mp4]/best[height<={height}]/bestvideo[height<={height}]+bestaudio/best',
            })
        else:
            ydl_opts.update({
                'format': 'best[height<=720]/best[ext=mp4]/best',
            })
        
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
            title = ary_title or metadata.get('title') or info_target.get('title', 'ARY Plus Video')
            thumbnail = ary_thumbnail or metadata.get('thumbnail') or info_target.get('thumbnail')
            
            expected_filename = ydl.prepare_filename(info_target)
            if format_type == 'mp3':
                expected_filename = os.path.splitext(expected_filename)[0] + '.mp3'
            
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
