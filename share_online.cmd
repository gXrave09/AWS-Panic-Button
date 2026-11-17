@echo off
title AWS Incident Response - Public Online Share
cd /d "%~dp0"

echo ============================================================
echo 🌐 AWS Panic Button - Public Online Sharing
echo    Connected to Account: 7117-3301-6743
echo    Target Bucket: confidential-company-data-2503a52928
echo ============================================================
echo.

:: 1. Start the Python server in a separate window
echo [1/2] Starting Incident Response Server...
start "AWS Panic Button Server" cmd /k "python backend\mock_server.py"

timeout /t 3 >nul

:: 2. Check for cloudflared, otherwise use npx localtunnel
echo.
echo [2/2] Creating Public Shareable Link...
echo ============================================================
echo Copy the link below and share it with your team / evaluators!
echo (Keep this window open to keep the link active)
echo ============================================================
echo.

where cloudflared >nul 2>&1
if %ERRORLEVEL% equ 0 (
    cloudflared tunnel --url http://localhost:8080
) else (
    echo Starting tunnel via localtunnel...
    npx localtunnel --port 8080
)

pause
