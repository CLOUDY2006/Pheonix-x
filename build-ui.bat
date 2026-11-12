@echo off
cd /d "%~dp0frontend"
call npm install
call npm run build
echo.
echo Done. Start the app with: node server\index.js
pause
