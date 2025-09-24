@echo off
echo Starting FileSplitterBot with Progress Tracker...
cd /d "%~dp0"
call venv\Scripts\activate.bat

echo Starting Electron Progress Tracker...
start "Unicorn Tracker" cmd /k "cd unicorn-electron && npm start"

echo Waiting 3 seconds...
timeout /t 3 /nobreak > nul

echo Launching Discord bot...
python main.py
pause