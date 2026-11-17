@echo off
title Incident Response Server & EC2 LAN Bridge
cd /d "%~dp0"

echo ============================================================
echo ⚡ Incident Response Panic Button ^& EC2 Network Bridge
echo ============================================================
echo.
echo Checking Wi-Fi IP address...
for /f "tokens=2 delims=:" %%a in ('ipconfig ^| findstr /c:"IPv4 Address"') do (
    set IP=%%a
    goto :found_ip
)
:found_ip
set IP=%IP: =%
echo PC Wi-Fi IP: %IP%
echo.
echo 📱 To connect from mobile Termux:
echo    ssh -p 9345 root@%IP%
echo    (Password: root)
echo.
echo 🖥️ Web Console:
echo    http://localhost:8080  or  http://localhost:8000
echo.
echo Starting server...
echo (NOTE: Keep this window open while using the application)
echo.
python backend\mock_server.py
if %ERRORLEVEL% neq 0 (
    py backend\mock_server.py
)
pause
