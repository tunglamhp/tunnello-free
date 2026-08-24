# Hướng dẫn cài đặt & quản lý DDNS Broker trên VPS (Ubuntu 24.04 / 26.04)

> Dành cho **chủ hệ thống / operator**. Khách hàng dùng file `GUIDE-KHACH-HANG.md`.
> DDNS Broker = nền tảng tunnel tự lưu trữ: khách hàng chạy client `ddns` tại chỗ,
> truy cập dịch vụ local của họ qua tên miền cố định `https://<slug>.<domain-cua-ban>`.

---

## 1. Chuẩn bị (bắt buộc)

| Thứ | Yêu cầu |
|---|---|
| VPS | Ubuntu 24.04 hoặc 26.04, tối thiểu 1 vCPU / 1 GB RAM (nên 2 GB), public IP |
| Domain | Bạn kiểm soát DNS, ví dụ `tunnel.example.com` |
| DNS | Bản ghi `A` (hoặc AAAA) trỏ **cả 2** về IP VPS: |
| | `tunnel.example.com` → IP VPS (dashboard, chứng chỉ ACME) |
| | `*.tunnel.example.com` → IP VPS (mọi tunnel của khách) |
| Firewall | Mở cổng **443/tcp** mặc định (HTTPS + WSS — URL sạch không hiện port) và **3478/udp** (STUN P2P). Chỉ mở **8443/tcp** khi bạn đặt `DDNS_PUBLIC_PORT=8443` (443 bận); **51821/udp** khi bật WireGuard; **80** nếu bật HTTP-01/redirect |
| Swap | VPS 1 GB RAM nên thêm swap 1–2 GB trước khi build (build Rust tốn RAM) |

Cài DNS **trước**, để bản ghi lan truyền (vài phút → vài giờ tùy DNS).

---

## 2. Cài đặt một cú nhấp chuột (one-click)

Cả thư mục `deploy/` này là một gói tự chứa. Đưa nó lên VPS (dùng `scp`, `rsync`, hoặc clone repo), rồi chạy **một lệnh duy nhất**:

```bash
# tùy chọn A — gửi thư mục deploy/ lên VPS từ máy bạn:
scp -r deploy/ root@IP-VPS:/opt/ddns-deploy/

# tùy chọn B — clone repo rồi vào deploy/:
git clone <URL-repo-cua-ban> /opt/ddns && cd /opt/ddns/deploy
```

Trên VPS:

```bash
cd /opt/ddns-deploy
./deploy.sh
```

Script sẽ tự động (khi chạy bằng `root`):

1. **Tự cài container engine + Compose plugin** nếu chưa có (qua `get.docker.com`; tắt bằng `DDNS_INSTALL_DOCKER=0`).
2. Hỏi **domain** và **nguồn chứng chỉ** (1 = PEM tĩnh, 2 = ACME (chứng chỉ tự động), 3 = dev — không dùng ở production).
3. Ghi `deploy/.env` (chmod 600, chứa bí mật — **không commit**).
4. Clone mã nguồn (nếu chưa có checkout), build image, khởi động stack `broker` + `redis`.
5. In ra các bước lần chạy đầu.

> Chạy **không tương tác** (cho CI/script): cung cấp trước env, ví dụ
> `DDNS_DOMAIN=tunnel.example.com DDNS_ACME_EMAIL=admin@example.com ./deploy.sh`
> (hoặc đặt `DDNS_CERT=/certs/fullchain.pem DDNS_KEY=/certs/privkey.pem` + đặt file PEM vào `deploy/certs/`).

### 2.1. Nguồn chứng chỉ — chọn đúng 1

1. **PEM tĩnh (khuyên dùng)** — đặt `fullchain.pem` + `privkey.pem` vào `deploy/certs/` (mount read-only). Gia hạn ngoài (certbot, CA của bạn) rồi `docker compose restart broker`.
2. **ACME (chứng chỉ tự động) TLS-ALPN-01** — set `DDNS_ACME_EMAIL`; broker tự cấp + tự gia hạn cho **apex**. (Wildcard cần DNS-01 — chưa hỗ trợ; nếu cần wildcard hãy dùng PEM tĩnh.)

> ACME account/certificate cache được lưu trong `/data/acme_cache` trên volume
> `broker-data`, nên vẫn tồn tại sau khi container restart/rebuild. Hãy backup
> volume này cùng với SQLite DB.
3. `DDNS_DEV=1` — cert tự ký, **chỉ test**.

### 2.2. Lần chạy đầu — bảo mật ngay

```bash
# mở dashboard:
#   https://tunnel.example.com/setup   → đặt mật khẩu admin (8–128 ký tự, argon2)
#   sau đó: https://tunnel.example.com/ → đăng nhập
```

Vào **Settings** (`/settings`) và làm:

- **Security** → bật **TOTP 2FA**; đặt **session TTL**; thêm IP của bạn vào **dashboard IP allowlist** (CIDR; trống = cho tất cả — hãy đặt).
- **Alerts** → webhook URL + secret (sự kiện ký HMAC `X-DDNS-Signature`) và/hoặc email alert.
- **Defaults** → giới hạn token mặc định cho token mới.

---

## 2.3. Chạy tại nhà với IP động (bridge mode, không VPS)

Khả thi khi modem chuyển **bridge mode** để router nhà nhận **public IPv4 động**
(không CGNAT — kiểm tra: `curl -4 -s https://api.ipify.org` không được thuộc
`100.64.0.0/10` hay `10.0.0.0/8`). Toàn bộ thiết kế giữ nguyên (P2P, STUN 3478).

1. **Modem bridge mode** → router nhà tự PPPoE (lấy user/pass từ ISP) → WAN là IP công khai động.
2. **Port forwarding trên router**: `443/tcp` + `3478/udp` → máy chạy broker.
   Kiểm tra ISP có chặn inbound 80/443 không (nếu chặn: đổi `DDNS_PUBLIC_PORT` — URL sẽ hiện port).
3. **DDNS bằng API Porkbun** — `deploy/ddns-porkbun.sh` (đi kèm repo):
   ```bash
   cp deploy/ddns-porkbun.sh /opt/ddns-deploy/
   cp deploy/systemd/ddns-porkbun.{service,timer} /etc/systemd/system/
   # thêm vào deploy/.env (hoặc environment):
   #   DDNS_PORKBUN_API_KEY=...   DDNS_PORKBUN_SECRET=...   (porkbun.com/account/api)
   #   DDNS_PORKBUN_HOSTS="tunnel.example.com *.tunnel.example.com"
   systemctl daemon-reload && systemctl enable --now ddns-porkbun.timer
   ```
   Timer chạy mỗi 5 phút: IP đổi → cập nhật A record apex + wildcard (TTL 300).
   Kiểm tra thủ công: `/opt/ddns-deploy/ddns-porkbun.sh --dry-run`.
4. **Wildcard TLS** — project ACME chỉ làm apex TLS-ALPN-01, tunnel cần wildcard:
   cấp ngoài bằng **certbot + plugin dns-porkbun** (DNS-01, dùng chung API key):
   ```bash
   sudo apt install certbot python3-certbot-dns-porkbun
   sudo certbot certonly --dns-porkbun --dns-porkbun-credentials /etc/porkbun.ini \
     -d tunnel.example.com -d '*.tunnel.example.com'
   # copy fullchain.pem + privkey.pem vào deploy/certs/ (đặt DDNS_CERT/DDNS_KEY)
   # gia hạn: certbot renew + docker compose restart broker (xem README §Certificates)
   ```
5. **Khi IP đổi**: DNS cập nhật ≤ ~5 phút → client tự reconnect (backoff 1–30s);
   phiên WebRTC P2P đang sống bị đứt → visitor reload là nối lại (rơi relay rồi P2P lại).

> Lưu ý: mất điện/mạng nhà = dịch vụ chết tạm; không có SLA như VPS.
> Nếu ISP không cho bridge/IP công khai → dùng Oracle Cloud Always Free
> (4 OCPU/24 GB, $0) hoặc Cloudflare Tunnel (relay-only, mất P2P).

## 2.4. Failover: home chính + VPS backup (chạy song hành)

Khi home server tắt/mất mạng, **VPS backup tự tiếp quản** trong ~5–10 phút
(phát hiện 3 lần fail × 60s + DNS TTL 300s). Cả hai broker cài song song;
DNS Porkbun là công tắc.

**Vai trò:**
- **Home (primary):** broker chạy bình thường; mỗi 5 phút đẩy snapshot SQLite
  (`.backup` qua sqlite3 trong container alpine) + certs sang VPS.
- **VPS (backup):** monitor health-check `https://<home-ip>/install.sh` trực
  tiếp (qua `--resolve`, không qua DNS). Home chết ≥ 3 lần liên tiếp →
  restore snapshot mới nhất → `docker compose up -d` → trỏ DNS (apex +
  wildcard) về IP VPS. Home hồi → trỏ DNS về home → tắt stack VPS.

**Cài home (`deploy/failover/home-push-backup.sh`):**
```bash
cp deploy/failover/home-push-backup.sh /opt/ddns-deploy/
cp deploy/failover/systemd/home-push-backup.{service,timer} /etc/systemd/system/
# deploy/.env: DDNS_VPS_SSH=root@<vps-ip>  DDNS_VOLUME=<tên volume thật>
ssh-copy-id root@<vps-ip>          # 1 lần: key home -> VPS
systemctl daemon-reload && systemctl enable --now home-push-backup.timer
```

**Cài VPS (`deploy/failover/vps-monitor.sh`):**
```bash
# deploy/.env trên VPS: DDNS_HOME_IP, DDNS_VPS_IP, DDNS_DOMAIN,
# DDNS_PORKBUN_API_KEY/SECRET + các biến failover
cp deploy/failover/vps-monitor.sh /opt/ddns-deploy/
cp deploy/failover/systemd/vps-monitor.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now vps-monitor
```

**Kiểm tra:** `vps-monitor.sh --once` (1 lượt), `--force-to-vps` / `--force-to-home`
(đảo tay); `ddns-porkbun.sh get` (xem DNS đang trỏ đâu).

**Giới hạn (nói thẳng):** mất tối đa ~5 phút dữ liệu mới nhất (giữa 2 lần push);
session đang sống bị đứt khi đảo → client tự reconnect (backoff) tới broker
đang trỏ; token/plan/code dùng được từ snapshot cuối; phiên P2P cần visitor
reload. VPS lúc thường **không chạy stack** (chỉ monitor) — bật khi failover,
tắt khi home hồi.

## 3. Cấu hình tùy chọn (deploy/.env)

| Biến | Ý nghĩa |
|---|---|
| `DDNS_DOMAIN` | Tên miền apex (bắt buộc) |
| `DDNS_CERT` / `DDNS_KEY` | Đường dẫn PEM trong container (`/certs/...`) |
| `DDNS_ACME_EMAIL` | Email ACME (nguồn cert #2) |
| `DDNS_HTTP_LISTEN=0.0.0.0:80` | Bật listener HTTP (301→HTTPS + HTTP-01) |
| `DDNS_MAX_SESSIONS` | Giới hạn session đồng thời (mặc định 256) |
| `DDNS_BASE_URL` | URL ngoài dùng trong email (xác minh/reset) |
| `DDNS_REDIS_URL` | Mặc định `redis://redis:6379` (rate limit + hot counter). Đặt **trống** (`DDNS_REDIS_URL=`) để chạy SQLite-only — **giữ nguyên service redis** (broker `depends_on` nó), chỉ bỏ URL. Bộ nhớ đệm chết → fail-open, không chặn traffic |
| `DDNS_SMTP_*` | SMTP cho email xác minh/reset/cảnh báo (thiếu → chỉ log link ở dev) |

Sửa xong chạy lại: `./deploy.sh --update`.

---

## 4. Quản lý hàng ngày

```bash
cd /opt/ddns-deploy            # thư mục deploy/

./deploy.sh --update           # cập nhật: git pull + rebuild + restart

docker compose ps              # trạng thái (broker phải "healthy", redis "healthy")
docker compose logs -f broker  # log theo thời gian thực
docker compose logs --tail 200 broker   # 200 dòng cuối

# khởi động lại broker (vd sau khi thay cert PEM):
docker compose restart broker
```

### Backup & restore (QUAN TRỌNG — dữ liệu nằm trong volume `broker-data`)

```bash
# backup (dừng ngắn để snapshot nhất quán):
docker compose stop
docker run --rm -v ddns_broker-data:/data -v $PWD:/backup \
  alpine tar czf /backup/ddns-data-$(date +%F).tar.gz -C /data .
docker compose start

# restore:
docker compose stop
docker run --rm -v ddns_broker-data:/data -v $PWD:/backup \
  alpine sh -c 'rm -rf /data/* && tar xzf /backup/ddns-data-YYYY-MM-DD.tar.gz -C /data'
docker compose start
```

> Volume tên dạng `<project>_broker-data` (mặc định `ddns_broker-data` nếu chạy từ `deploy/`).
> Kiểm tra tên chính xác bằng `docker volume ls`.

### Giám sát

- **Healthcheck**: `/install.sh` được poll 30s (compose healthcheck).
- **Metrics**: `https://tunnel.example.com/metrics` (cần session operator; text exposition `ddns_*`). Scrape ví dụ:

```yaml
scrape_configs:
  - job_name: ddns-broker
    metrics_path: /metrics
    scheme: https
    bearer_token: <chuỗi-cookie-session-operator>   # hoặc dùng basic auth proxy
    static_configs: [{ targets: ["tunnel.example.com"] }]
```

---

## 5. Vận hành bán hàng (những gì khách thấy)

| Trang | Dùng cho |
|---|---|
| `https://domain/portal/signup` | Khách đăng ký tài khoản |
| `https://domain/portal/login` | Khách đăng nhập, tự quản lý |
| Portal → API keys | Tạo API key (`ddns_...`, hiện 1 lần), truy cập `/api/v1/*` |
| `/plans`, `/codes` (operator) | Sửa giới hạn gói; mã kích hoạt |
| `/tokens`, `/tunnels`, `/domains` (operator) | Token, tunnel profile, kích hoạt apex + hướng dẫn DNS |

---

## 6. Ứng phó lạm dụng (abuse response)

Khi nhận **báo cáo lạm dụng** (phishing, malware, spam…), xử lý theo trình tự sau:

1. **Nhận báo cáo** — ghi lại slug/URL/domain của tunnel bị tố cáo (vd `https://<slug>.tunnel.example.com`).
2. **Xác định tài khoản** — dashboard hiển thị `Peer IP` của kết nối client trực tiếp trong session list. Dùng slug/token để xác định tài khoản trong SQLite (`/data/ddns.db`, volume `broker-data`):

   ```sql
   SELECT account_id FROM tunnels WHERE subdomain = '<slug>';   -- từ slug báo cáo
   SELECT owner_id   FROM tokens  WHERE id        = 't-xxxx';   -- từ token id (dạng t-xxxx)
   ```

   Chạy tạm trong container (image broker không cài `sqlite3`): `docker run --rm -v ddns_broker-data:/data alpine sh -c 'apk add --no-cache sqlite >/dev/null 2>&1 && sqlite3 /data/ddns.db'` — thay `ddns_broker-data` bằng tên volume thật (`docker volume ls`).
3. **Ngăn chặn ngay** (đúng thứ tự — kill trước, vì Suspend không tự ngắt session đang chạy):
   - **Kill session** — nút kill trên dashboard (ngắt ngay kết nối đang chạy).
   - **Suspend** — vào `/clients/{id}` → **Suspend** (hạ gói về Free/trial-hết hạn, chặn đăng ký tiếp; **không** tự đóng session đang chạy — đã xử lý ở bước kill).
   - **Vô hiệu hóa token** — vào `/tokens`, disable token vi phạm.
   - **Xóa tunnel profile** — nếu cần (chặn đăng ký lại slug đó).
4. **Điều tra** — bằng chứng sẵn có: `Peer IP` trên session đang sống, `usage_daily` theo tài khoản (băng thông/request theo ngày) và lịch sử biến động token (`token_movements`). Peer IP là địa chỉ socket trực tiếp mà broker nhìn thấy; nếu đi qua reverse proxy, đó có thể là IP proxy và cần đối chiếu log proxy.
5. **Kiểm soát chủ động đã có sẵn**:
   - Rate limit theo gói (`rate_limit_rpm`) — **cần Redis**: chế độ SQLite-only (bỏ `DDNS_REDIS_URL`) không có enforcement rpm, cố ý fail-open (không chặn traffic).
   - Hạn mức băng thông tháng (`bandwidth_monthly`).
   - Cảnh báo mềm ở **80% / 95%** hạn mức.
   - **Cắt cứng** khi hết token (từ chối đăng ký tunnel mới, đóng session đang chạy).
   - Per-tunnel auth: basic auth, bearer key, IP whitelist (CIDR) — cấu hình trong tunnel editor.
6. **Lưu ý pháp lý** — chỉ thu thập tối thiểu (usage theo tài khoản + biến động token); broker **không** ghi IP client hay nội dung traffic. Có quy trình **xác minh trước khi khóa tài khoản** để tránh khóa nhầm (vd khách bị mạo danh / token bị chiếm).

---

## 7. Xử lý sự cố

| Triệu chứng | Nguyên nhân / cách xử lý |
|---|---|
| Healthcheck fail | `docker compose logs broker`; thường do cổng 443 chưa mở trên firewall, hoặc cert sai |
| Visitor "no such tunnel" | Apex chưa kích hoạt (`/domains`), client chưa connect, hoặc DNS wildcard chưa trỏ về VPS |
| Khách nhận 429 | Rate limit theo plan (`rate_limit_rpm`); thử sau `Retry-After`; tăng hạn mức hoặc override |
| Khách nhận 402 / token rejected | Token hết → nạp token (cổng thanh toán) hoặc operator `Credit tokens` |
| Client "slug occupied" (`NoSubdomainAvailable`) | Tên slug cố định đang bị session khác chiếm; chờ hoặc đổi slug |
| Cổng 443 bận | Đổi `DDNS_PUBLIC_PORT=8443` trong `deploy/.env` (URL sẽ hiện `:8443`); cổng trong container vẫn là 443 |
| Bộ nhớ đệm không lên | `docker compose ps` — redis phải healthy trước (depends_on service_healthy) |
| Cert hết hạn (PEM tĩnh) | Thay file trong `deploy/certs/` → `docker compose restart broker` |

---

## 8. Nâng cấp từ bản cũ

```bash
cd /opt/ddns-deploy
./deploy.sh --update     # pull mã mới + rebuild + restart (giữ nguyên .env và volume)
```

Không có migration thủ công — schema tự nâng qua `ensure_columns` khi khởi động. Bản ghi cũ không bị truy thu token (hạn mức tháng bắt đầu từ lần metering đầu tiên sau khi nâng cấp).

---

## 9. Tham chiếu

- `README.md` — tổng quan kiến trúc + cấu trúc container.
- `GUIDE-KHACH-HANG.md` — hướng dẫn cho khách (gửi file này cho họ).
- `MANUAL.md` (trong repo) — tài liệu kỹ thuật đầy đủ: §4 dashboard/portal, §5 REST API, §6 Operations, §7 Admin.
