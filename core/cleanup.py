import os
import time
from apscheduler.schedulers.background import BackgroundScheduler

from core.security import is_safe_filepath

def cleanup_job(download_dir, max_age_minutes=30):
    now = time.time()
    if not os.path.exists(download_dir):
        return
        
    for filename in os.listdir(download_dir):
        # Ignore hidden files
        if filename.startswith('.'):
            continue
            
        filepath = os.path.join(download_dir, filename)
        if os.path.isfile(filepath) and is_safe_filepath(filepath, download_dir):
            file_mtime = os.path.getmtime(filepath)
            file_age = now - file_mtime
            
            # Protect active partial downloads modified within last 10 minutes
            if (filename.endswith('.part') or filename.endswith('.ytdl')) and (now - file_mtime < 600):
                continue

            if file_age > max_age_minutes * 60:
                try:
                    os.remove(filepath)
                except Exception:
                    pass

def start_cleanup_scheduler(download_dir):
    scheduler = BackgroundScheduler()
    # Run the cleanup job every 10 minutes
    scheduler.add_job(cleanup_job, 'interval', minutes=10, args=[download_dir])
    scheduler.start()
