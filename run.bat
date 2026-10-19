@echo off
echo ===================================================
echo   Starting Stellar Video Downloader...
echo ===================================================

if exist .\venv\Scripts\activate.bat (
    call .\venv\Scripts\activate.bat
)
python app.py
pause
