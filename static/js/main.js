document.addEventListener('DOMContentLoaded', () => {
    const form = document.getElementById('downloadForm');
    const urlInput = document.getElementById('videoUrl');
    const submitBtn = document.getElementById('submitBtn');
    
    // Status UI elements
    const statusContainer = document.getElementById('statusContainer');
    const statusSpinner = document.getElementById('statusSpinner');
    const statusText = document.getElementById('statusText');
    const statusSubtext = document.getElementById('statusSubtext');
    const statusPercentage = document.getElementById('statusPercentage');
    
    // Progress Bar elements
    const progressWrapper = document.getElementById('progressWrapper');
    const progressBar = document.getElementById('progressBar');
    
    // Action areas
    const errorArea = document.getElementById('errorArea');
    const errorText = document.getElementById('errorText');
    const cancelWrapper = document.getElementById('cancelWrapper');
    const cancelBtn = document.getElementById('cancelBtn');

    let currentEventSource = null;
    let activeTaskId = null;

    const formatRadios = document.querySelectorAll('input[name="format"]');
    const qualityWrapper = document.getElementById('qualityWrapper');

    formatRadios.forEach(radio => {
        radio.addEventListener('change', (e) => {
            if (e.target.value === 'mp3') {
                qualityWrapper.style.opacity = '0.5';
                qualityWrapper.style.pointerEvents = 'none';
            } else {
                qualityWrapper.style.opacity = '1';
                qualityWrapper.style.pointerEvents = 'auto';
            }
        });
    });

    cancelBtn.addEventListener('click', async () => {
        if (!activeTaskId) return;
        
        cancelBtn.disabled = true;
        cancelBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin mr-2"></i> Clearing...';
        
        try {
            await fetch(`/api/cancel/${activeTaskId}`, { method: 'POST' });
            if (currentEventSource) currentEventSource.close();
            
            // Full Reset (Clear)
            urlInput.value = '';
            statusContainer.classList.add('opacity-0');
            setTimeout(() => {
                statusContainer.classList.add('hidden');
                cancelWrapper.classList.add('hidden');
                document.getElementById('previewWrapper').classList.add('hidden');
            }, 300);

            resetFormBtn();
            activeTaskId = null;
        } catch (err) {
            console.error('Clear failed', err);
        }
    });

    form.addEventListener('submit', async (e) => {
        e.preventDefault();
        
        const url = urlInput.value.trim();
        const format = document.querySelector('input[name="format"]:checked').value;
        const quality = document.getElementById('qualitySelect').value;
        
        if (!url) return;

        // Reset UI
        submitBtn.disabled = true;
        const btnOriginalText = submitBtn.innerHTML;
        submitBtn.innerHTML = '<i class="fa-solid fa-spinner fa-spin"></i>';
        
        statusContainer.classList.remove('hidden');
        // Slight delay for transition
        setTimeout(() => {
            statusContainer.classList.remove('opacity-0');
        }, 10);
        
        // Reset old states
        downloadArea.classList.add('hidden');
        downloadArea.classList.remove('flex');
        errorArea.classList.add('hidden');
        progressWrapper.classList.remove('hidden');
        statusPercentage.classList.remove('hidden');
        
        statusSpinner.innerHTML = '<i class="fa-solid fa-circle-notch text-indigo-500 animate-spin text-xl"></i>';
        
        updateStatusUI('Connecting', 'Fetching video info...', 0);

        try {
            const response = await fetch('/api/download', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({ url, format, quality })
            });

            if (!response.ok) {
                const data = await response.json();
                throw new Error(data.error || 'Server error');
            }

            const { task_id } = await response.json();
            activeTaskId = task_id;
            cancelWrapper.classList.remove('hidden');
            cancelBtn.disabled = false;
            cancelBtn.innerHTML = '<i class="fa-solid fa-xmark group-hover:rotate-90 transition-transform"></i> Abort Extraction';
            
            listenForStatus(task_id, btnOriginalText);

        } catch (error) {
            showError(error.message);
            resetFormBtn(btnOriginalText);
        }
    });

    function listenForStatus(taskId, btnOriginalText) {
        if (currentEventSource) currentEventSource.close();
        
        currentEventSource = new EventSource(`/api/status/${taskId}`);
        
        currentEventSource.onmessage = (event) => {
            const data = JSON.parse(event.data);
            
            // Handle Preview Data
            if (data.title || data.thumbnail) {
                const previewWrapper = document.getElementById('previewWrapper');
                const videoTitle = document.getElementById('videoTitle');
                const videoThumbnail = document.getElementById('videoThumbnail');
                
                if (data.title) videoTitle.textContent = data.title;
                if (data.thumbnail) videoThumbnail.src = data.thumbnail;
                
                if (previewWrapper.classList.contains('hidden')) {
                    previewWrapper.classList.remove('hidden');
                    previewWrapper.classList.add('flex');
                }
            }

            // Show lightning badge for speed indication
            const lightningBadge = document.getElementById('lightningBadge');
            
            if (data.status === 'processing') {
                updateStatusUI('Initializing', 'Preparing download...', 0);
                if (lightningBadge) lightningBadge.classList.add('hidden');
            } 
            else if (data.status === 'downloading') {
                const percent = data.progress || 0;
                const speed = data.speed || 'N/A';
                const eta = data.eta || 'N/A';
                const total = data.total_size || 'N/A';
                const downloaded = data.downloaded || 'N/A';
                // Show lightning badge
                if (lightningBadge) lightningBadge.classList.remove('hidden');
                // If title is available but download just started (0%), show "Starting download..."
                const subtext = (percent === 0 && data.title) 
                    ? `Starting download... • ${data.title.substring(0, 40)}${data.title.length > 40 ? '...' : ''}`
                    : `${downloaded} / ${total} • ${speed} • ${eta} left`;
                updateStatusUI('Downloading', subtext, percent);
            }
            else if (data.status === 'converting') {
                updateStatusUI('Finalizing', 'Running high-quality merge...', 100);
            }
            else if (data.status === 'finished') {
                currentEventSource.close();
                cancelWrapper.classList.add('hidden');
                if (lightningBadge) lightningBadge.classList.add('hidden');
                showSuccess(taskId);
                resetFormBtn(btnOriginalText);
                activeTaskId = null;
            }
            else if (data.status === 'error') {
                currentEventSource.close();
                cancelWrapper.classList.add('hidden');
                if (lightningBadge) lightningBadge.classList.add('hidden');
                showError(data.error);
                resetFormBtn(btnOriginalText);
                activeTaskId = null;
            }
            else if (data.status === 'cancelled') {
                 currentEventSource.close();
                 cancelWrapper.classList.add('hidden');
                 if (lightningBadge) lightningBadge.classList.add('hidden');
                 activeTaskId = null;
            }
        };

        currentEventSource.onerror = (err) => {
            currentEventSource.close();
            showError('Lost connection to server.');
            resetFormBtn(btnOriginalText);
        };
    }

    function updateStatusUI(title, subtext, percentage) {
        statusText.textContent = title;
        statusSubtext.textContent = subtext;
        
        const p = Math.min(Math.max(percentage, 0), 100);
        progressBar.style.width = `${p}%`;
        statusPercentage.textContent = `${p.toFixed(0)}%`;
    }

    function showSuccess(taskId) {
        statusText.textContent = 'Complete';
        statusSubtext.textContent = 'File is ready for download.';
        statusPercentage.textContent = '100%';
        progressBar.style.width = '100%';
        
        statusSpinner.innerHTML = '<i class="fa-solid fa-check text-green-500 text-xl"></i>';
        statusSpinner.classList.remove('animate-spin');

        downloadArea.classList.remove('hidden');
        downloadArea.classList.add('flex');
        downloadLink.href = `/api/files/${taskId}`;
    }

    function showError(message) {
        statusText.textContent = 'Extraction Notice';
        statusSubtext.textContent = 'Supported Download Source Required';
        
        statusSpinner.innerHTML = '<i class="fa-solid fa-circle-info text-amber-400 text-xl"></i>';
        statusSpinner.classList.remove('animate-spin');
        
        progressWrapper.classList.add('hidden');
        statusPercentage.classList.add('hidden');
        errorArea.classList.remove('hidden');
        errorText.innerHTML = message;
    }

    function resetFormBtn(originalText) {
        submitBtn.disabled = false;
        submitBtn.innerHTML = originalText || `<span>INITIALIZE EXTRACTION</span><i class="fa-solid fa-bolt-lightning text-yellow-400"></i>`;
    }

    window.quickFill = function(query) {
        urlInput.value = query;
        urlInput.focus();
    };
});
