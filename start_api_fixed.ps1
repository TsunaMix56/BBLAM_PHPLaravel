$ErrorActionPreference = "Stop"

# Ensure we're in the correct directory
$targetDir = "d:\BBLAM_PHPLaravel\BBLAM_PHPLaravel"
Set-Location $targetDir

# Verify we're in the right place
$currentDir = Get-Location
Write-Host "Current Directory: $currentDir" -ForegroundColor Yellow

# Check if api.php exists
if (-not (Test-Path "api.php")) {
    Write-Host "ERROR: api.php not found in current directory!" -ForegroundColor Red
    Get-ChildItem | Where-Object { $_.Name -like "*.php" } | ForEach-Object { Write-Host "Found: $($_.Name)" }
    exit 1
}

Write-Host "✅ api.php found (Size: $((Get-Item api.php).Length) bytes)" -ForegroundColor Green

# Stop any running PHP processes
Get-Process -Name "php" -ErrorAction SilentlyContinue | Stop-Process -Force
Start-Sleep -Seconds 1

Write-Host ""
Write-Host "🚀 Starting BBLAM JWT API Server..." -ForegroundColor Green
Write-Host "📍 Directory: $currentDir" -ForegroundColor Gray  
Write-Host "🌐 URL: http://localhost:8000" -ForegroundColor Cyan
Write-Host "🔒 Features: JWT + SQL Server + Fallback" -ForegroundColor Yellow
Write-Host "===========================================" -ForegroundColor White

# Start the server using the full path to api.php
$apiPath = Join-Path $currentDir "api.php"
Write-Host "Starting with: C:\php\php.exe -S localhost:8000 $apiPath" -ForegroundColor Gray

& "C:\php\php.exe" -S localhost:8000 $apiPath