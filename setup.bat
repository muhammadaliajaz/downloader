@echo off
echo ===================================================
echo   Stellar Video Downloader - Initial Setup
echo ===================================================

echo [1/3] Creating Virtual Environment...
python -m venv venv

echo [2/3] Activating Virtual Environment...
call .\venv\Scripts\activate

echo [3/3] Installing Required Packages...
pip install -r requirements.txt

echo ===================================================
echo Setup Completed Successfully! 
echo Now run "run.bat" or double-click run.bat to start.
echo ===================================================
pause
