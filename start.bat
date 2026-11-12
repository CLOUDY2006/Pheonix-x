@echo off
setlocal
cd /d "%~dp0"
where node >nul 2>nul || (echo.& echo  Node.js 22.13 or newer is required: https://nodejs.org  (choose the LTS "Windows Installer")& echo.& pause & exit /b 1)
for /f "tokens=1,2 delims=." %%a in ('node -p "process.versions.node"') do (set NMAJ=%%a& set NMIN=%%b)
if %NMAJ% LSS 22 (echo  Node %NMAJ%.%NMIN% is too old. Install Node 22.13+ from https://nodejs.org & pause & exit /b 1)
if not exist .env copy .env.example .env >nul
if not exist data mkdir data
echo  Starting PHOENIX X ... (first start in PRODUCTION mode asks you to create the admin account in the browser)
start "" http://localhost:3000
node --disable-warning=ExperimentalWarning server\index.js
pause
