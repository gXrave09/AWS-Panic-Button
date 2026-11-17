@echo off
title Publish to GitHub - AWS Panic Button
cd /d "%~dp0"

echo ============================================================
echo 🚀 Creating GitHub Repository: AWS-Panic-Button
echo ============================================================
echo.

:: 1. Check GitHub Authentication
echo Checking GitHub authentication...
gh auth status >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo.
    echo [Step 1] Your GitHub token is expired or not logged in.
    echo Authorizing GitHub CLI in your web browser...
    echo (Press Enter and enter the one-time code in your browser)
    echo.
    gh auth login -h github.com -p https -w
)

echo.
echo [Step 2] Creating repository 'AWS-Panic-Button' on your GitHub...
gh repo create "AWS-Panic-Button" --public --description "Automated Multi-Service Incident Response Panic Button for AWS" --source=. --remote=my-github --push

if %ERRORLEVEL% equ 0 (
    echo.
    echo ============================================================
    echo 🎉 SUCCESS! Your project is live on GitHub!
    echo ============================================================
) else (
    echo.
    echo ℹ️ Trying standard git push...
    git add .
    git commit -m "Initial commit: AWS Incident Response Panic Button"
    git branch -M main
    git push -u my-github main
)

pause
