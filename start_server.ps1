# Starts the Incident Response Server and EC2 LAN Bridge
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $ScriptDir

$wifiIp = (Get-NetIPAddress -AddressFamily IPv4 -InterfaceAlias "*Wi-Fi*" -ErrorAction SilentlyContinue).IPAddress
if (-not $wifiIp) {
    $wifiIp = "10.2.8.24"
}

Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "⚡ Incident Response Server & EC2 Mobile Bridge" -ForegroundColor Cyan
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host "PC Wi-Fi IP: $wifiIp" -ForegroundColor Yellow
Write-Host ""
Write-Host "📱 Connect from Mobile Termux:" -ForegroundColor Green
Write-Host "   ssh -p 9345 root@$wifiIp" -ForegroundColor White
Write-Host "   (Password: root)" -ForegroundColor Gray
Write-Host ""
Write-Host "🖥️ Web Console:" -ForegroundColor Green
Write-Host "   http://localhost:8080  or  http://localhost:8000" -ForegroundColor White
Write-Host "   (Keep this window open while using the app)" -ForegroundColor Yellow
Write-Host "============================================================" -ForegroundColor Cyan
Write-Host ""

python backend\mock_server.py
