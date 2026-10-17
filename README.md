# ⚡Steller Studio

![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)
![Flask Framework](https://img.shields.io/badge/framework-Flask_3.0-green.svg)
![Playwright Support](https://img.shields.io/badge/headless-Playwright_Interception-purple.svg)
![Speed Optimizations](https://img.shields.io/badge/concurrency-32_Threads-orange.svg)
![License](https://img.shields.io/badge/license-MIT-brightgreen.svg)

A high-performance, full-stack web application designed for seamless video & audio downloads from **ARY Plus (`aryplus.tv`)**, YouTube, and universal media platforms. Features multi-threaded parallel fragment downloading, direct headless CDN stream interception, default 720p HD fast encoding, and background automatic cache cleanup.

---

## ✨ Key Features

- **🎬 Native ARY Plus Direct Extractor**: Uses headless browser interception (Playwright / Edge / Chrome) to extract authenticated `.m3u8` HLS streams directly from `vod.aryzap.com` CDN without DRM restrictions.
- **🚀 32-Thread Multi-Stream Acceleration**: Powered by multi-threaded chunk downloading (32 parallel fragments, 4 MB memory buffer, 10 MB HTTP chunk transfers).
- **📺 720p HD Default Quality**: Defaults to 720p HD (~300MB per episode), delivering 800% faster download speeds compared to 1080p uncompressed master streams.
- **🎵 Universal Audio & Video Conversion**: Supports MP4 video downloads and high-quality MP3 audio extraction via FFmpeg post-processing (`-threads 0 -preset ultrafast`).
- **🔄 Auto Browser Engine Fallback**: Automatically leverages pre-installed Microsoft Edge or Google Chrome on Windows if Playwright Chromium binaries are not downloaded.
- **🎨 Glassmorphic Modern UI**: Responsive dark-mode interface with live real-time progress bars, speed metrics, ETA timers, and 1-click drama shortcuts.
- **🛡️ Live Production Security**: Hardened with SSRF protection, IP rate limiting, server concurrency caps, path traversal guards, UUID strict parsing, and HTTP security response headers.
- **🧹 Automatic Cache Cleanup**: Background scheduler automatically removes completed download files older than 30 minutes to save disk space.

---

## 📁 Repository Architecture

```
downloader/
├── app.py                      # Flask web server & REST API endpoints
├── Procfile                    # Web deployment manifest
├── requirements.txt            # Python dependency specifications
├── setup.bat                   # 1-Click Windows initial setup script
├── run.bat                     # 1-Click Windows application launcher
├── README.md                   # Application documentation
├── core/                       # Core engine modules
│   ├── ary_extractor.py        # ARY Plus authenticated CDN stream interceptor
│   ├── downloader.py           # Multi-threaded yt-dlp & FFmpeg engine
│   └── cleanup.py              # Background cache pruning scheduler
├── static/                     # Frontend static assets
│   ├── css/
│   │   └── style.css           # Glassmorphic Tailwind-inspired styling
│   └── js/
│       └── main.js             # Event listeners & AJAX polling engine
├── templates/
│   └── index.html              # HTML5 application interface
└── downloads/                  # Temporary storage for active downloads
```

---

## ⚡ Quick Start Guide (Windows)

### Prerequisites

1. **Python 3.8+**: Download from [python.org](https://www.python.org/downloads/)  
   *(⚠️ **Crucial**: Check **"Add python.exe to PATH"** during installation).*
2. **FFmpeg**: Open PowerShell as Administrator and run:
   ```cmd
   winget install Gyan.FFmpeg
   ```

---

### Option A: 1-Click Batch Setup (Recommended)

1. Double-click **`setup.bat`** (installs required Python packages automatically).
2. Double-click **`run.bat`** to start the application.
3. Open your browser and navigate to:  
   👉 **`http://localhost:5000`**

---

### Option B: Manual Command Line Setup

Open Command Prompt (CMD) in the project root folder and execute:

```cmd
# 1. Install dependencies
pip install -r requirements.txt

# 2. Launch the web application
python app.py
```

---

## ⚙️ Performance & Acceleration Tuning

The downloader engine (`core/downloader.py`) is pre-configured with high-throughput parameters:

| Parameter | Value | Description |
| :--- | :--- | :--- |
| `concurrent_fragments` | `32` | 32 parallel HTTP connections for HLS `.m3u8` streams |
| `buffersize` | `4 MB` | 4,194,304 bytes memory buffer |
| `http_chunk_size` | `10 MB` | 10,485,760 bytes chunk size |
| `hls_use_mpegts` | `True` | Direct TS stream decoding acceleration |
| `hls_prefer_native` | `True` | Native multi-fragment HLS downloader |
| `ffmpeg_args` | `-threads 0 -preset ultrafast` | Maximize CPU core usage during audio/video conversion |

---


## ❓ Frequently Asked Questions (FAQ)

<details>
<summary><b>Q: Why is Playwright required for ARY Plus?</b></summary>
<p>ARY Plus uses Firebase authenticated JWT API endpoints (<code>be.aryplus.tv/api/cdn/ep/</code>). Playwright executes the React web page script headlessly to intercept the CDN stream link seamlessly.</p>
</details>

<details>
<summary><b>Q: What if 'playwright' executable command is missing on another laptop?</b></summary>
<p>You don't need to run <code>playwright install</code> manually. The extractor automatically detects pre-installed <b>Microsoft Edge</b> or <b>Google Chrome</b> on Windows.</p>
</details>

<details>
<summary><b>Q: Where are downloaded files saved?</b></summary>
<p>Files are initially stored in the <code>downloads/</code> folder and downloaded straight through your web browser upon completion.</p>
</details>

---

## 📜 License

Distributed under the MIT License. See `LICENSE` for details.
