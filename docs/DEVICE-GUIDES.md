# Device Guides

Step-by-step guides for exposing common devices and platforms through
Tunello. Each guide assumes you have a token from the operator dashboard.

---

## Raspberry Pi

The most popular use case: expose SSH, a camera stream, or Home Assistant
running on a Raspberry Pi behind CGNAT.

### Setup

```sh
# Download the client (arm64):
curl -fsSL "https://<broker>/download/ddns-aarch64-unknown-linux-musl" \
  -o /usr/local/bin/ddns && chmod +x /usr/local/bin/ddns

# Create a systemd service:
sudo tee /etc/systemd/system/tunnello.service > /dev/null <<'UNIT'
[Unit]
Description=Tunello tunnel client
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/ddns --token YOUR_TOKEN --server https://<broker> --port 8080
Restart=always
RestartSec=5
User=pi

[Install]
WantedBy=multi-user.target
UNIT

sudo systemctl daemon-reload
sudo systemctl enable --now tunnello
```

### Common Pi services to expose

| Service | Port | Command flag |
|---|---|---|
| SSH | 22 | `--tcp 22` |
| Home Assistant | 8123 | `--port 8123` |
| Pi Camera (motionEye) | 8765 | `--port 8765` |
| Pi-hole admin | 80 | `--port 80` |
| Samba file share | 445 | `--tcp 445` |

---

## Synology / QNAP NAS

Expose DSM web UI, File Station, or specific shared folders.

### Docker method (recommended)

```yaml
# docker-compose.yml on your NAS:
version: "3"
services:
  tunnello:
    image: rust:slim
    command: >
      sh -c "curl -fsSL https://<broker>/download/ddns-x86_64-unknown-linux-musl -o /bin/ddns &&
             chmod +x /bin/ddns &&
             ddns --token YOUR_TOKEN --server https://<broker> --port 5000"
    network_mode: host
    restart: always
```

### Binary method (SSH into NAS)

```sh
# For Intel NAS:
wget "https://<broker>/download/ddns-x86_64-unknown-linux-musl" -O /usr/local/bin/ddns
chmod +x /usr/local/bin/ddns

# For ARM NAS:
wget "https://<broker>/download/ddns-aarch64-unknown-linux-musl" -O /usr/local/bin/ddns
chmod +x /usr/local/bin/ddns

# Run in background:
nohup ddns --token YOUR_TOKEN --server https://<broker> --port 5000 &
```

| Service | Port | Command flag |
|---|---|---|
| DSM Web UI | 5000/5001 | `--port 5000` |
| File Station | 5000 | same as DSM |
| Surveillance Station | 5001 | `--port 5001` |
| Plex | 32400 | `--port 32400` |

---

## Windows PC (RDP / file share)

Expose Remote Desktop or SMB file sharing.

### RDP setup

```powershell
# Enable RDP (run as Administrator):
Set-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value 0

# Download and run the client:
Invoke-WebRequest https://<broker>/download/ddns-x86_64-pc-windows-msvc.exe -OutFile ddns.exe
.\ddns.exe --token YOUR_TOKEN --server https://<broker> --tcp 3389
```

### Auto-start at login (Task Scheduler)

```powershell
$action = New-ScheduledTaskAction -Execute "C:\Tools\ddns.exe" `
  -Argument "--token YOUR_TOKEN --server https://<broker> --tcp 3389"
$trigger = New-ScheduledTaskTrigger -AtLogOn
Register-ScheduledTask "Tunello RDP" -Action $action -Trigger $trigger -RunLevel Highest
```

---

## macOS (Screen Sharing / file share)

```sh
# Install:
ARCH=$(uname -m | sed 's/x86_64/x86_64/;s/arm64/aarch64/')
curl -fsSL "https://<broker>/download/ddns-${ARCH}-apple-darwin" \
  -o /usr/local/bin/ddns && sudo chmod +x /usr/local/bin/ddns

# Screen Sharing uses port 5900:
ddns --token YOUR_TOKEN --server https://<broker> --tcp 5900
```

---

## Docker container

Expose any container's published port.

```sh
# Find the published port:
docker port <container-name>

# Tunnel it (use --network host so ddns can reach the container directly):
docker run --rm --network host -v ./ddns:/bin/ddns alpine/sh -c "
  wget -q https://<broker>/download/ddns-x86_64-unknown-linux-musl -O /bin/ddns &&
  chmod +x /bin/ddns &&
  ddns --token YOUR_TOKEN --server https://<broker> --port <container-port>
"
```

---

## Home Assistant

```yaml
# Add to configuration.yaml or use a shell_command:
shell_command:
  tunnello: >-
    ddns --token YOUR_TOKEN --server https://<broker> --port 8123
```

Or run as a Home Assistant add-on via Docker Compose alongside HA.
See the Raspberry Pi section for systemd setup if running HA on a Pi.

---

## Multiple services on one device

Run multiple tunnels with different ports using one token:

```sh
# HTTP service:
ddns --token TOKEN --server https://<broker> --port 3000

# TCP service (separate process, separate token recommended):
ddns --token TOKEN2 --server https://<broker> --tcp 22
```

The operator dashboard shows all active sessions grouped by token.

UDP services can also go P2P: `ddns connect <sub> --udp 53` (no broker UDP
port required — datagrams ride the WebRTC data channel).

---

## Full-tunnel exit node (advanced)

Turn your device's default traffic through a tunnel (WireGuard data plane):

```sh
ddns up <sub> --exit-node     # admin required (routes + firewall)
ddns up --cleanup             # remove stale rules after a crash
```

The tunnel owner must run the client with `--allow-exit`. Free edition:
on/off with safe defaults (kill-switch, DNS via tunnel, IPv6 blocked,
180-day key rotation). Platform checklists (nftables audit, DNS-leak test,
PMTU) live in the operator docs.
