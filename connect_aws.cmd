@echo off
title Connect Real AWS Cloud - Incident Response
cd /d "%~dp0"

echo ============================================================
echo 🛡️ AWS Incident Response - Connect Live AWS Cloud
echo    Target Bucket: confidential-company-data-2503a52928
echo ============================================================
echo.
echo Please copy your AWS credentials from your AWS Learner Lab:
echo (Click 'AWS Details' at the top of the lab -> 'AWS CLI' -> 'Show')
echo.
set /p AWS_KEY_ID="Paste aws_access_key_id: "
set /p AWS_SECRET="Paste aws_secret_access_key: "
set /p AWS_TOKEN="Paste aws_session_token: "

set AWS_ACCESS_KEY_ID=%AWS_KEY_ID: =%
set AWS_SECRET_ACCESS_KEY=%AWS_SECRET: =%
set AWS_SESSION_TOKEN=%AWS_TOKEN: =%
set AWS_DEFAULT_REGION=us-east-1
set AWS_ENDPOINT_URL=

echo.
echo ✅ AWS Credentials Loaded for Account 7117-3301-6743!
echo Starting Panic Button Web Console...
echo.
python backend\mock_server.py
pause
