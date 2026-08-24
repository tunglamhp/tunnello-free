$ErrorActionPreference = 'Stop'
$deploy = Split-Path -Parent $MyInvocation.MyCommand.Path
Set-Location $deploy

if (-not (Get-Command docker -ErrorAction SilentlyContinue)) {
    Write-Host 'Docker Desktop is required. Install it, then double-click this file again.'
    Read-Host 'Press Enter to close'
    exit 1
}

if (-not (Test-Path '.env')) {
    Copy-Item '.env.example' '.env'
    Write-Host 'Created deploy/.env with public port 443 (clean URLs).'
    Write-Host 'Edit DDNS_DOMAIN and choose a certificate source, then run this file again.'
    Start-Process notepad.exe (Join-Path $deploy '.env')
    Read-Host 'Press Enter after configuring .env'
}

docker compose up -d --build
Write-Host 'Tunello is running. Open the URL in DDNS_BASE_URL, then finish /setup.'
Read-Host 'Press Enter to close'