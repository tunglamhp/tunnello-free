<p align="center">
  <img src="docs/logo.svg" alt="Tunello" width="96"/>
</p>

<h1 align="center">Tunello Free</h1>

<p align="center"><em>Self-hosted tunnel service. One command on your VPS, one line on your laptop.</em></p>

<p align="center">
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue" alt="MIT"/></a>
  <a href="https://github.com/tunglamhp/tunnello-free/releases"><img src="https://img.shields.io/github/v/release/tunglamhp/tunnello-free" alt="Release"/></a>
  <img src="https://img.shields.io/badge/version-0.11.0-6f42c1" alt="version 0.11.0"/>
</p>

```
visitor ──https──▶ Tunello broker ◀──wss── ddns-client ──http/tcp──▶ your local app
```

## 1. Cài broker lên VPS (Ubuntu, 1 lệnh)

SSH vào VPS, chạy:

```bash
curl -sSL https://raw.githubusercontent.com/tunglamhp/tunnello-free/main/install-server.sh | bash
```

Script tự cài Docker (nếu thiếu), clone repo, chạy `deploy.sh`, in ra URL + bước `/setup` đầu tiên. Mở URL đó trên trình duyệt → tạo tài khoản operator.

Nâng cấp sau này: `cd /opt/tunnello/deploy && bash deploy.sh --update`.


Phần mới nhất (xem CHANGELOG):
- **ACME DNS-01** — đặt `DDNS_ACME_PROVIDER=cloudflare|porkbun` (kèm credentials trong `deploy/.env`): broker tự ghi TXT `_acme-challenge` và cấp một chứng chỉ Let's Encrypt cho apex + `*.domain` — mọi tunnel hostname đều có HTTPS, tự gia hạn, không cần mở cổng.
- **`deploy.sh` preflight** — tự kiểm tra DNS (apex + wildcard) và mở firewall (ufw/firewalld); tắt bằng `DDNS_SKIP_DNS_CHECK=1` / `DDNS_SKIP_FIREWALL=1`.

## 2. Cài client trên máy muốn expose

Vào dashboard → **Tokens** → tạo token → **Quickstart** → copy đúng lệnh cho máy của bạn:

- **Linux / macOS**:
  ```bash
  curl -sSL "https://<broker>/install.sh?code=sc_xxx&port=8080" | sh
  ```
- **Windows (PowerShell)**:
  ```powershell
  irm "https://<broker>/install.ps1?code=sc_xxx&port=8080" | iex
  ```

Lệnh này tự tải binary `ddns`, cài vào PATH, mở tunnel trỏ về service cục bộ (`localhost:8080`). Tunnel URL hiện ngay cuối output.

Khách hàng cũng có thể tự đăng ký tại `https://<broker>/portal` rồi vào portal lấy lệnh Quickstart cho mình.

## 3. Xong

Truy cập tunnel URL trên trình duyệt — thấy app cục bộ của bạn, ai cũng truy cập được qua HTTPS.

---

## Free edition boundary

Các tính năng thuộc miễn phí/public:
- `ddns-proto`, `ddns-client`, `ddns-server` core tunneling, `/connect`, `/install.sh`, `/download/{file}`

Các tính năng chỉ giữ private:
- `ddns-billing`, payments, plans/subscriptions UI, token packs, portal payments

---

## Cập nhật

```bash
# Server
cd /opt/tunnello/deploy && bash deploy.sh --update

# Client
ddns update           # tự tải binary mới từ GitHub Releases
```

## Cấu hình nâng cao & khắc phục sự cố

Xem **[MANUAL.md](MANUAL.md)** — cổng STUN, biến môi trường, dashboard pages, dev mode, build từ source, kiến trúc, gỡ lỗi.

## Thay đổi theo phiên bản

Xem **[CHANGELOG.md](CHANGELOG.md)** — các bản phát hành và thay đổi gần nhất.

## Giấy phép

[MIT](LICENSE)
