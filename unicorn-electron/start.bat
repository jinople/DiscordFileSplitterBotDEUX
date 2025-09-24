@echo off

echo Starting Princess Unicorn Progress Tracker...
echo.

echo Current directory: %cd%
echo.

echo Checking for node_modules...
if not exist "node_modules\" (
    echo Installing dependencies first...
    npm install
    echo.
)

echo Launching Electron app...
npm start

pause