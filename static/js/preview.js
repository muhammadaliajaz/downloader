/**
 * Modern Human-Crafted SaaS Video Downloader Frontend Logic
 */
document.addEventListener('DOMContentLoaded', () => {
    // Core Elements
    const form = document.getElementById('downloadForm');
    const urlInput = document.getElementById('videoUrl');
    const submitBtn = document.getElementById('submitBtn');
    const pasteBtn = document.getElementById('pasteBtn');
    const clearBtn = document.getElementById('clearBtn');
    const platformIndicator = document.getElementById('platformIndicator');
    const platformName = document.getElementById('platformName');
    const platformIcon = document.getElementById('platformIcon');
    
    // Format and Quality selectors
    const formatBtnVideo = document.getElementById('formatBtnVideo');
    const formatBtnAudio = document.getElementById('formatBtnAudio');
    const qualitySelect = document.getElementById('qualitySelect');
    const qualityHelpText = document.getElementById('qualityHelpText');
    let selectedFormat = 'mp4';
    
    // Status & Progress Dashboard
    const dashboardCard = document.getElementById('dashboardCard');
    const previewThumbnail = document.getElementById('previewThumbnail');
    const previewTitle = document.getElementById('previewTitle');
    const previewPlatformBadge = document.getElementById('previewPlatformBadge');
    const statusPill = document.getElementById('statusPill');
    const statusPillText = document.getElementById('statusPillText');
    const progressBar = document.getElementById('progressBar');
    const progressPercent = document.getElementById('progressPercent');
    const metricSpeed = document.getElementById('metricSpeed');
    const metricDownloaded = document.getElementById('metricDownloaded');
    const metricEta = document.getElementById('metricEta');
    const cancelBtn = document.getElementById('cancelBtn');
    
    // Result & Error areas
    const successCard = document.getElementById('successCard');
    const downloadFinalBtn = document.getElementById('downloadFinalBtn');
    const resetDownloadBtn = document.getElementById('resetDownloadBtn');
    const errorCard = document.getElementById('errorCard');
    const errorMessage = document.getElementById('errorMessage');
    
    let currentEventSource = null;
    let activeTaskId = null;
    const initialSubmitHtml = submitBtn.innerHTML;

    // Platform detection patterns
    const platforms = [
        {
            name: 'ARY Plus / Zap',
            icon: 'fa-solid fa-tv text-rose-500',
            pattern: /(aryplus\.tv|aryzap\.com)/i,
            tag: 'Official ARY CDN'
        },
        {
            name: 'YouTube',
            icon: 'fa-brands fa-youtube text-red-500',
            pattern: /(youtube\.com|youtu\.be)/i,
            tag: 'YouTube Stream'
        },
        {
            name: 'Instagram',
            icon: 'fa-brands fa-instagram text-pink-500',
            pattern: /instagram\.com/i,
            tag: 'Insta Reels'
        },
        {
            name: 'TikTok',
            icon: 'fa-brands fa-tiktok text-cyan-400',
            pattern: /tiktok\.com/i,
            tag: 'TikTok Video'
        },
        {
            name: 'Facebook',
            icon: 'fa-brands fa-facebook text-blue-500',
            pattern: /(facebook\.com|fb\.watch)/i,
            tag: 'Facebook Watch'
        },
        {
            name: 'X (Twitter)',
            icon: 'fa-brands fa-x-twitter text-slate-200',
            pattern: /(twitter\.com|x\.com)/i,
            tag: 'X Video'
        }
    ];

    function detectPlatform(url) {
        if (!url || url.trim() === '') {
            platformIndicator.classList.add('opacity-0');
            clearBtn.classList.add('hidden');
            return null;
        }

        clearBtn.classList.remove('hidden');
        
        for (const p of platforms) {
            if (p.pattern.test(url)) {
                platformIcon.className = p.icon;
                platformName.textContent = p.name;
                platformIndicator.classList.remove('opacity-0');
                return p;
            }
        }

        // Generic web link
        platformIcon.className = 'fa-solid fa-globe text-emerald-400';
        platformName.textContent = 'Universal Video';
        platformIndicator.classList.remove('opacity-0');
        return null;
    }

    // Input events
    urlInput.addEventListener('input', (e) => {
        detectPlatform(e.target.value);
    });

    // Paste from clipboard button
    if (pasteBtn && navigator.clipboard) {
        pasteBtn.addEventListener('click', async () => {
            try {
                const text = await navigator.clipboard.readText();
                if (text) {
                    urlInput.value = text.trim();
                    detectPlatform(urlInput.value);
                    urlInput.focus();
                    
                    // Visual feedback
                    const originalIcon = pasteBtn.innerHTML;
                    pasteBtn.innerHTML = '<i class="fa-solid fa-check text-emerald-400 text-xs"></i>';
                    setTimeout(() => {
                        pasteBtn.innerHTML = originalIcon;
                    }, 1200);
                }
            } catch (err) {
                console.log('Clipboard permission not granted:', err);
                urlInput.focus();
            }
        });
    }

    // Clear input button
    clearBtn.addEventListener('click', () => {
        urlInput.value = '';
        detectPlatform('');
        urlInput.focus();
    });

    // Format toggle buttons (Video vs Audio)
    formatBtnVideo.addEventListener('click', () => {
        selectedFormat = 'mp4';
        formatBtnVideo.classList.add('bg-rose-600', 'text-white', 'shadow-lg', 'shadow-rose-950/40');
        formatBtnVideo.classList.remove('text-slate-400', 'hover:text-slate-200');
        
        formatBtnAudio.classList.remove('bg-rose-600', 'text-white', 'shadow-lg', 'shadow-rose-950/40');
        formatBtnAudio.classList.add('text-slate-400', 'hover:text-slate-200');

        // Re-enable quality dropdown
        qualitySelect.disabled = false;
        qualitySelect.classList.remove('opacity-50', 'cursor-not-allowed');
        qualitySelect.innerHTML = `
            <option value="720" selected>720p HD (Fast &amp; Recommended • ~300 MB)</option>
            <option value="1080">1080p Full HD (Original Master • High Bitrate)</option>
            <option value="480">480p SD (Data Saver)</option>
            <option value="360">360p Low (Mobile Friendly)</option>
        `;
        qualityHelpText.textContent = "720p HD delivers optimum 8x speed via 32-stream multi-threading.";
    });

    formatBtnAudio.addEventListener('click', () => {
        selectedFormat = 'mp3';
        formatBtnAudio.classList.add('bg-rose-600', 'text-white', 'shadow-lg', 'shadow-rose-950/40');
        formatBtnAudio.classList.remove('text-slate-400', 'hover:text-slate-200');
        
        formatBtnVideo.classList.remove('bg-rose-600', 'text-white', 'shadow-lg', 'shadow-rose-950/40');
        formatBtnVideo.classList.add('text-slate-400', 'hover:text-slate-200');

        // Update dropdown for audio
        qualitySelect.disabled = true;
        qualitySelect.classList.add('opacity-75', 'cursor-not-allowed');
        qualitySelect.innerHTML = `
            <option value="best" selected>MP3 Audio (192 kbps High Quality Stereo)</option>
        `;
        qualityHelpText.textContent = "Audio will be extracted and converted into high-bitrate MP3 via FFmpeg.";
    });

    // Quick chips filler
    window.fillAndFocus = function(urlText, preferredQuality = '720') {
        urlInput.value = urlText;
        detectPlatform(urlText);
        
        if (selectedFormat === 'mp4' && qualitySelect) {
            qualitySelect.value = preferredQuality;
        }
        
        urlInput.scrollIntoView({ behavior: 'smooth', block: 'center' });
        urlInput.focus();
    };

    // Cancel download listener
    cancelBtn.addEventListener('click', async () => {
        if (!activeTaskId) return;
        
        cancelBtn.disabled = true;
        cancelBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin text-xs"></i> Cancelling...';
        
        try {
            await fetch(`/api/cancel/${activeTaskId}`, { method: 'POST' });
        } catch (err) {
            console.error('Cancel request error:', err);
        }

        if (currentEventSource) currentEventSource.close();
        resetDashboard();
    });

    function resetDashboard() {
        dashboardCard.classList.add('hidden');
        successCard.classList.add('hidden');
        errorCard.classList.add('hidden');
        submitBtn.disabled = false;
        submitBtn.innerHTML = initialSubmitHtml;
        activeTaskId = null;
    }

    if (resetDownloadBtn) {
        resetDownloadBtn.addEventListener('click', () => {
            resetDashboard();
            urlInput.value = '';
            detectPlatform('');
            urlInput.focus();
        });
    }

    // Form submission
    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        const url = urlInput.value.trim();
        if (!url) {
            urlInput.focus();
            return;
        }

        const quality = qualitySelect ? qualitySelect.value : '720';

        // Reset UI states
        errorCard.classList.add('hidden');
        successCard.classList.add('hidden');
        dashboardCard.classList.remove('hidden');
        
        // Scroll to dashboard smoothly
        dashboardCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

        submitBtn.disabled = true;
        submitBtn.innerHTML = '<i class="fa-solid fa-circle-notch fa-spin text-lg"></i> Connecting to CDN...';
        
        cancelBtn.disabled = false;
        cancelBtn.innerHTML = '<i class="fa-solid fa-xmark text-xs"></i> Cancel';
        
        // Initial dashboard indicators
        statusPill.className = 'px-2.5 py-1 rounded-full text-xs font-semibold bg-rose-500/10 text-rose-400 border border-rose-500/20';
        statusPillText.textContent = 'Connecting...';
        progressBar.style.width = '3%';
        progressPercent.textContent = '0%';
        metricSpeed.textContent = '-- MB/s';
        metricDownloaded.textContent = '0 MB / -- MB';
        metricEta.textContent = 'Calculating...';
        previewTitle.textContent = 'Extracting media streams...';
        previewThumbnail.src = 'data:image/svg+xml;utf8,<svg xmlns="http://www.w3.org/2000/svg" width="160" height="90" viewBox="0 0 160 90"><rect width="160" height="90" fill="%231a1d29"/><text x="50%" y="50%" dominant-baseline="middle" text-anchor="middle" fill="%2364748b" font-family="sans-serif" font-size="10">Loading Preview</text></svg>';

        try {
            const response = await fetch('/api/download', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    url: url,
                    format: selectedFormat,
                    quality: quality
                })
            });

            const data = await response.json();

            if (!response.ok) {
                throw new Error(data.error || 'Server rejected download request.');
            }

            activeTaskId = data.task_id;
            listenToProgress(activeTaskId);

        } catch (err) {
            showError(err.message || 'Failed to initialize stream extraction.');
        }
    });

    function listenToProgress(taskId) {
        if (currentEventSource) currentEventSource.close();
        
        currentEventSource = new EventSource(`/api/status/${taskId}`);

        currentEventSource.onmessage = (event) => {
            try {
                const data = JSON.parse(event.data);
                
                // Update Metadata preview if available
                if (data.title && previewTitle.textContent !== data.title) {
                    previewTitle.textContent = data.title;
                }
                if (data.thumbnail && previewThumbnail.src !== data.thumbnail) {
                    previewThumbnail.src = data.thumbnail;
                }

                if (data.status === 'processing') {
                    statusPillText.textContent = 'Connecting to Stream...';
                    metricSpeed.textContent = 'Connecting';
                    metricEta.textContent = 'Negotiating';
                }
                else if (data.status === 'downloading') {
                    const percent = Math.min(Math.max(data.progress || 0, 0), 100);
                    progressBar.style.width = `${percent}%`;
                    progressPercent.textContent = `${percent.toFixed(0)}%`;
                    
                    statusPill.className = 'px-2.5 py-1 rounded-full text-xs font-semibold bg-emerald-500/10 text-emerald-400 border border-emerald-500/20';
                    statusPillText.textContent = 'Downloading (32 Streams)';
                    
                    metricSpeed.textContent = data.speed || '-- MB/s';
                    metricDownloaded.textContent = `${data.downloaded || '0 MB'} / ${data.total_size || 'N/A'}`;
                    metricEta.textContent = data.eta ? `${data.eta} left` : 'Calculating...';
                }
                else if (data.status === 'converting') {
                    progressBar.style.width = '100%';
                    progressPercent.textContent = '100%';
                    statusPill.className = 'px-2.5 py-1 rounded-full text-xs font-semibold bg-amber-500/10 text-amber-400 border border-amber-500/20';
                    statusPillText.textContent = 'Processing Media Audio/Video...';
                    metricSpeed.textContent = 'Finalizing';
                    metricEta.textContent = 'Almost ready';
                }
                else if (data.status === 'finished') {
                    currentEventSource.close();
                    handleComplete(taskId, data);
                }
                else if (data.status === 'error') {
                    currentEventSource.close();
                    showError(data.error || 'Download failed due to stream timeout.');
                }
                else if (data.status === 'cancelled') {
                    currentEventSource.close();
                    resetDashboard();
                }
            } catch (e) {
                console.error('Error parsing status stream:', e);
            }
        };

        currentEventSource.onerror = () => {
            currentEventSource.close();
            showError('Connection to server lost. Please check your network and retry.');
        };
    }

    function handleComplete(taskId, data) {
        dashboardCard.classList.add('hidden');
        successCard.classList.remove('hidden');
        successCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

        downloadFinalBtn.href = `/api/files/${taskId}`;
        
        // Show friendly title
        const successTitle = document.getElementById('successFileTitle');
        if (successTitle && data.title) {
            successTitle.textContent = data.title;
        }

        submitBtn.disabled = false;
        submitBtn.innerHTML = initialSubmitHtml;
    }

    function showError(msg) {
        dashboardCard.classList.add('hidden');
        successCard.classList.add('hidden');
        errorCard.classList.remove('hidden');
        errorMessage.innerHTML = msg;
        
        errorCard.scrollIntoView({ behavior: 'smooth', block: 'nearest' });

        submitBtn.disabled = false;
        submitBtn.innerHTML = initialSubmitHtml;
        activeTaskId = null;
    }

    // Interactive Accordion FAQ
    const faqButtons = document.querySelectorAll('.faq-toggle');
    faqButtons.forEach(btn => {
        btn.addEventListener('click', () => {
            const content = btn.nextElementSibling;
            const icon = btn.querySelector('.faq-icon');
            const isOpen = content.classList.contains('open');

            // Close all
            document.querySelectorAll('.faq-content').forEach(c => c.classList.remove('open'));
            document.querySelectorAll('.faq-icon').forEach(i => i.classList.remove('rotate-180'));

            if (!isOpen) {
                content.classList.add('open');
                if (icon) icon.classList.add('rotate-180');
            }
        });
    });
});
