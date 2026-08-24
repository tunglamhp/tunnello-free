# Client guide — Windows, Linux & macOS

`ddns` is a single static binary (~7 MB). Pick your platform below: download the
pre-built client from **https://<your-broker>/downloads**, or build it yourself.

After installing, every platform runs the same command:

```sh
ddns --token <SECRET> --server https://<broker-host> --port 8080
```

The broker prints your public URL, e.g.
`https://myapp.tunnel.example.com → http://127.0.0.1:8080`.

---

## 1. Windows 10/11 (x86_64, arm64)

### Install

**Option A — PowerShell one-liner** (downloads `ddns.exe` into the current folder):

```powershell
Invoke-WebRequest https://<broker>/download/ddns-x86_64-pc-windows-msvc.exe -OutFile ddns.exe
```

**Option B — manual**: grab `ddns.exe` from `/downloads`, put it in a folder
that is on your `PATH` (e.g. `C:\Tools\`).

### Optional — install into PATH permanently

```powershell
mkdir $env:USERPROFILE\bin -Force
Move-Item .\ddns.exe $env:USERPROFILE\bin\ddns.exe
[Environment]::SetEnvironmentVariable("Path", $env:Path + ";$env:USERPROFILE\bin", "User")
```

Open a new terminal afterwards so the updated `PATH` takes effect.

### Run at login (Task Scheduler)

```powershell
$action  = New-ScheduledTaskAction -Execute "$env:USERPROFILE\bin\ddns.exe" `
           -Argument "--token SECRET --server https://broker.example.com --port 8080"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask -TaskName "Tunello client" -Action $action -Trigger $trigger
```

### Firewall note

Windows Defender may prompt on first run ("Allow access") — click **Allow** for
private networks; the client only makes outbound connections.

---

## 2. Linux (x86_64, arm64)

### Install — one line (recommended)

```sh
curl -fsSL https://<broker>/install.sh | sh
```

The script detects your architecture, downloads the static musl binary to
`/usr/local/bin/ddns`, and prints next steps.

### Manual install

```sh
sudo curl -fsSL "https://<broker>/download/ddns-x86_64-unknown-linux-musl" \
     -o /usr/local/bin/ddns && sudo chmod +x /usr/local/bin/ddns
```

### Run as a systemd service (auto-start + auto-restart)

```ini
# /etc/systemd/system/tunnello.service
[Unit]
Description=Tunello client
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/ddns --token SECRET --server https://broker.example.com --port 8080
Restart=always
RestartSec=5
User=youruser

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl daemon-reload
sudo systemctl enable --now tunnello
journalctl -u tunnello -f        # follow logs
```

---

## 3. macOS (Apple Silicon & Intel)

### Install

```sh
ARCH=$(uname -m | sed 's/x86_64/x86_64/;s/arm64/aarch64/')
curl -fsSL "https://<broker>/download/ddns-${ARCH}-apple-darwin" -o /usr/local/bin/ddns \
  && sudo chmod +x /usr/local/bin/ddns
```

(For Intel Macs `uname -m` returns `x86_64`; on Apple Silicon it returns `arm64`,
mapped above to `aarch64`.)

### Gatekeeper note

macOS may warn about an unidentified developer binary:

```sh
xattr -d com.apple.quarantine /usr/local/bin/ddns
```

### Run at login (launchd)

Save as `~/Library/LaunchAgents/com.tunello.client.plist`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN"
 "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>ProgramArguments</key><array>
    <string>/usr/local/bin/ddns</string>
    <string>--token</string><string>SECRET</string>
    <string>--server</string><string>https://broker.example.com</string>
    <string>--port</string><string>8080</string>
  </array>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
</dict></plist>
```

```sh
launchctl load ~/Library/LaunchAgents/com.tunello.client.plist
```

---

## 4. P2P quick connect (`ddns connect`)

All platforms also ship the native visitor helper — connect straight to any
running tunnel over WebRTC (no browser):

```sh
ddns connect https://myapp.tunnel.example.com
# → Forwarding TCP 127.0.0.1:PORT → myapp (P2P)
```

Point your SSH/RDP/database client at `127.0.0.1:PORT`. If hole-punching fails,
the helper prints the relay address and exits.

---

## 5. Troubleshooting

| Symptom | Fix |
|---|---|
| `reconnecting…` loops forever | Broker unreachable or token disabled — check the dashboard **Tokens** page |
| TLS error on first connect | Pass `--ca-pem <broker-ca.pem>` when the broker runs with a self-signed/dev cert |
| macOS blocks execution | `xattr -d com.apple.quarantine <path-to-ddns>` |
| Port already in use | Another process owns the local port — pick another `--port` |
| Client exits with `token rejected` | Token was deleted/disabled — mint a new one on the dashboard |
