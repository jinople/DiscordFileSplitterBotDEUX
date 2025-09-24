@echo off

echo Starting Princess Unicorn Progress Tracker...
echo.

echo Changing to electron directory...
cd /d "%~dp0unicorn-electron"

echo.
echo Launching Electron app...
npm start