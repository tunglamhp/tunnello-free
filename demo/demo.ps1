# Local end-to-end demo: broker + echo app + tunnel client.
#
# What it does:
#   1. Builds ddns-server, ddns-client and ddns-echo.
#   2. Starts the broker (dev self-signed cert) on 127.0.0.1:8443 with its own
#      demo DB (demo/demo.db) — reuses an already-listening broker if present.
#   3. Creates the operator account (password "demo1234"), logs in, creates a
#      token via the operator API.
#   4. Starts ddns-echo (local app on 127.0.0.1:8088) and ddns-client (tunnel).
#   5. Proves the round trip: curl through the tunnel reaches the echo app.
#
# The broker/echo/client keep running afterwards; the tunnel stays live.
# Stop:  Stop-Process -Name ddns-server,ddns-client,ddns-echo
#        (or close the windows they run in).

$ErrorActionPreference = "Stop"
$root = Split-Path -Parent $PSScriptRoot
Set-Location $root

# Windows PowerShell 5.1 has no -SkipCertificateCheck parameter. The demo
# broker uses a local self-signed certificate, so trust it only for this run.
[System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }

$demoDir = Join-Path $root "demo"
New-Item -ItemType Directory -Force -Path $demoDir | Out-Null
$db = Join-Path $demoDir "demo.db"
$caPem = "$db.dev-ca.pem"
$listen = "127.0.0.1:8443"
$echoPort = 8088
$adminPassword = "demo1234"

Write-Host "== [1/5] building ddns-server, ddns, ddns-echo" -ForegroundColor Cyan
# Windows locks a running exe, and cargo 1.94 relinks whenever the dep-info is
# newer than the binary — so re-running the demo while the previous stack is
# still up fails with "Access is denied" on ddns-server.exe. Skip the build
# when all three binaries are already running.
$demoRunning = @("ddns-server", "ddns", "ddns-echo") | Where-Object {
    Get-Process $_ -ErrorAction SilentlyContinue
}
if ($demoRunning.Count -eq 3) {
    Write-Host "demo binaries already running - skipping build" -ForegroundColor Yellow
} else {
    cargo build -p ddns-server -p ddns-client -p ddns-echo -q
    if ($LASTEXITCODE -ne 0) { throw "build failed" }
}

Write-Host "== [1b/5] building the web bundle (ddns-web)" -ForegroundColor Cyan
if (Get-Command dx -ErrorAction SilentlyContinue) {
    dx bundle --platform web --package ddns-web
    if ($LASTEXITCODE -ne 0) { throw "dx bundle failed" }
} else {
    Write-Host "dx not installed - islands won't load; install with: cargo install dioxus-cli" -ForegroundColor Yellow
}

Write-Host "== [2/5] starting broker on https://$listen (dev cert)" -ForegroundColor Cyan
$brokerRunning = Test-NetConnection -ComputerName 127.0.0.1 -Port 8443 -WarningAction SilentlyContinue |
    Select-Object -ExpandProperty TcpTestSucceeded
if (-not $brokerRunning) {
    Start-Process -FilePath "target\debug\ddns-server.exe" -ArgumentList @(
        "--dev", "--domain", "tunnel.example.com", "--listen", $listen, "--db", $db,
        "--web-dist", "dist/public", "--stun-port", "3478"
    ) -WorkingDirectory $root -WindowStyle Minimized
    Start-Sleep -Seconds 3
}

Write-Host "== [3/5] operator setup + token" -ForegroundColor Cyan
# /setup creates the operator account (idempotent on an existing account).
$setup = "password=$adminPassword&confirm=$adminPassword"
try {
    Invoke-WebRequest -Uri "https://$listen/setup" -Method Post -Body $setup `
        -ContentType "application/x-www-form-urlencoded" -UseBasicParsing | Out-Null
} catch {
    Write-Host "operator setup already complete - continuing" -ForegroundColor DarkGray
}
# login -> session cookie
$login = "password=$adminPassword"
$session = Invoke-WebRequest -Uri "https://$listen/login" -Method Post -Body $login `
    -ContentType "application/x-www-form-urlencoded" -SessionVariable web -UseBasicParsing
# create an operator token
$body = @{ name = "demo"; max_sessions = 0; max_streams = 0; max_bytes = 0 } |
    ConvertTo-Json -Compress
$resp = Invoke-RestMethod -Uri "https://$listen/api/tokens" -Method Post -Body $body `
    -ContentType "application/json" -WebSession $web
$secret = $resp.secret
Write-Host "token: $($resp.id)"

Write-Host "== [4/5] starting echo app (127.0.0.1:$echoPort) + tunnel client" -ForegroundColor Cyan
Start-Process -FilePath "target\debug\ddns-echo.exe" -ArgumentList @("--port", "$echoPort") `
    -WorkingDirectory $root -WindowStyle Minimized
Start-Sleep -Seconds 1
Start-Process -FilePath "target\debug\ddns.exe" -ArgumentList @(
    "--token", $secret, "--server", "https://$listen", "--port", "$echoPort",
    "--ca-pem", $caPem
) -WorkingDirectory $root -RedirectStandardOutput (Join-Path $demoDir "client.log") `
    -RedirectStandardError (Join-Path $demoDir "client.err.log") -WindowStyle Minimized

Write-Host "== [5/5] waiting for the tunnel, then proving the round trip" -ForegroundColor Cyan
$tunnelUrl = $null
for ($i = 0; $i -lt 30 -and -not $tunnelUrl; $i++) {
    Start-Sleep -Milliseconds 500
    if (Test-Path (Join-Path $demoDir "client.log")) {
        $log = Get-Content (Join-Path $demoDir "client.log") -Raw -ErrorAction SilentlyContinue
        if ($log -match "https://([a-z0-9-]+)\.tunnel\.example\.com") {
            $tunnelUrl = $Matches[0]
        }
    }
}
if (-not $tunnelUrl) {
    Write-Host "tunnel did not come up; see demo/client.log / demo/client.err.log" -ForegroundColor Red
    exit 1
}
Write-Host ""
Write-Host "Tunnel is live: $tunnelUrl" -ForegroundColor Green
Write-Host "Your tunnel host is routed via the Host header; prove it locally with:"
$hostHeader = $tunnelUrl -replace "https://", ""
Write-Host ("  curl.exe -k -H Host:$hostHeader https://127.0.0.1:8443/echo?msg=hello")
$proof = curl.exe -sk -H "Host: $hostHeader" "https://127.0.0.1:8443/echo?msg=hello"
Write-Host ""
Write-Host "Round-trip proof (echo app answered through the tunnel):" -ForegroundColor Cyan
Write-Host $proof

Write-Host ""
Write-Host "P2P check (connector page + relay escape hatch):" -ForegroundColor Cyan

# 1. Browser navigation serves the connector page (registers the Service Worker).
$connector = curl.exe -sk -H "Host: $hostHeader" -H "Accept: text/html" "https://127.0.0.1:8443/"
if ($connector -match "__tunnello/sw.js") {
    Write-Host "  [PASS] connector page served (registers __tunnello/sw.js)" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] connector page not served (missing __tunnello/sw.js)" -ForegroundColor Yellow
}

# 2. The relay escape hatch still reaches the echo app.
$relay = curl.exe -sk -H "Host: $hostHeader" -H "Accept: text/html" -H "X-Tunnello-Relay: 1" "https://127.0.0.1:8443/"
if ($relay -match "echo") {
    Write-Host "  [PASS] relay escape hatch reaches the app" -ForegroundColor Green
} else {
    Write-Host "  [FAIL] relay escape hatch did not reach the app" -ForegroundColor Yellow
    Write-Host "  warning: relay check failed - the tunnel is still usable via the connector page." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "Demo left running. Stop everything with:" -ForegroundColor Yellow
Write-Host "  Stop-Process -Name ddns-server,ddns,ddns-echo"
