# Service Templates

Pre-configured tunnel profiles for common services. Pick a template, replace
the placeholder values with your own, and run the command.

Each template shows: the local service port, the tunnel command to run, and
how to connect from outside.

---

## SSH (port 22)

Expose a Linux/Mac SSH server.

```sh
# On the server running SSH:
ddns --token <SECRET> --server https://<broker> --tcp 22

# From outside, connect via P2P helper:
ddns connect https://<sub>.<domain>
ssh user@127.0.0.1 -p <forwarded-port>

# Or via relay (public URL):
ssh -o ProxyCommand="openssl s_client -connect <sub>.<domain>:443" user@<sub>.<domain>
```

---

## RDP — Windows Remote Desktop (port 3389)

Expose a Windows Remote Desktop server.

```sh
# On the Windows machine running RDP:
ddns.exe --token <SECRET> --server https://<broker> --tcp 3389

# From outside, connect via P2P helper on another machine:
ddns connect https://<sub>.<domain>
# Then open mstsc.exe → connect to 127.0.0.1:<forwarded-port>
```

---

## VNC (port 5900)

Expose a VNC remote desktop server (TightVNC, TigerVNC, RealVNC).

```sh
ddns --token <SECRET> --server https://<broker> --tcp 5900
```

---

## MySQL / MariaDB (port 3306)

Expose a database for secure remote administration.

```sh
ddns --token <SECRET> --server https://<broker> --tcp 3306

# Connect remotely via P2P helper:
mysql -h 127.0.0.1 -P <forwarded-port> -u admin -p
```

---

## PostgreSQL (port 5432)

```sh
ddns --token <SECRET> --server https://<broker> --tcp 5432

psql -h 127.0.0.1 -p <forwarded-port> -U postgres
```

---

## Home Assistant (port 8123)

Expose your Home Assistant web UI.

```sh
ddns --token <SECRET> --server https://<broker> --port 8123

# Access from anywhere:
open https://<sub>.<domain>
```

---

## Plex Media Server (port 32400)

Expose Plex web UI for remote access behind CGNAT.

```sh
ddns --token <SECRET> --server https://<broker> --port 32400

open https://<sub>.<domain>/web
```

---

## MQTT Broker (port 1883)

Expose an MQTT broker (Mosquitto, EMQX) for IoT devices.

```sh
ddns --token <SECRET> --server https://<broker> --tcp 1883

mosquitto_pub -h 127.0.0.1 -p <forwarded-port> -t "sensors/temp" -m "22.5"
```

---

## Web Server (port 80 or 3000/8000/5000)

Expose any HTTP(S) web application.

```sh
ddns --token <SECRET> --server https://<broker> --port 3000

open https://<sub>.<domain>
```

---

## Docker container port

Expose a specific Docker container's published port.

```sh
# Find the published port:
docker port <container-name>

# Tunnel it:
ddns --token <SECRET> --server https://<broker> --port <published-port>
```
