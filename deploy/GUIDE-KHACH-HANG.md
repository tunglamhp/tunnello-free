# Hướng dẫn sử dụng DDNS Tunnel — dành cho khách hàng

> DDNS là dịch vụ **tunnel** giúp bạn công khai dịch vụ đang chạy trên máy của mình
> (web server, API, SSH...) ra internet qua một địa chỉ cố định:
> **`https://<slug>.<ten-mien>`** — không cần IP tĩnh, không cần mở port trên router,
> không cần thuê VPS riêng. Bạn chỉ cần chạy một chương trình nhỏ (`ddns`) trên máy
> có dịch vụ.

---

## 1. Đăng ký tài khoản

1. Mở trang: **`https://<ten-mien>/portal/signup`**
   (thay `<ten-mien>` bằng domain của dịch vụ, ví dụ `https://tunnel.example.com/portal/signup`).
2. Nhập email + mật khẩu (8 ký tự trở lên), xác minh email theo link được gửi.
3. Đăng nhập tại **`https://<ten-mien>/portal/login`**.

Sau khi đăng nhập, bạn tự quản lý mọi thứ tại **portal**: tạo token, xem hạn mức,
mua thêm token, nâng cấp gói, tạo API key — không cần liên hệ người vận hành.

---

## 2. Cài đặt chương trình `ddns` (client)

### Linux (x86_64 / aarch64)

Một lệnh (thay `https://<ten-mien>` bằng domain thật):

```bash
DDNS_SERVER=https://<ten-mien> curl -fsSL https://<ten-mien>/install.sh | sh
# tạo file ./ddns trong thư mục hiện tại
```

Hoặc tải tay: `https://<ten-mien>/download/ddns-x86_64-unknown-linux-musl`
(rename thành `ddns`, `chmod +x ddns`). Kiểm tra: `./ddns --help`.

### macOS / Windows

- **macOS**: tải `https://<ten-mien>/download/ddns-x86_64-apple-darwin` (hoặc `...-aarch64-apple-darwin` trên Apple Silicon).
- **Windows**: tải `https://<ten-mien>/download/ddns-x86_64-pc-windows-msvc.exe` và đổi tên thành `ddns.exe`.
- Nếu file tương ứng chưa có trên trang download, liên hệ người vận hành để họ bổ sung bản build cho nền tảng của bạn.

---

## 3. Tạo tunnel token

1. Đăng nhập portal → mục **Tokens** (hoặc từ Overview).
2. Bấm **Create token**, đặt tên (vd `web-server`), chọn giới hạn (session / stream / dung lượng / thời hạn).
3. **Sao chép ngay chuỗi bí mật** dạng `tok_...` — nó chỉ hiển thị **một lần**.
   Token này là "chìa khóa" kết nối; ai có nó đều mở được tunnel của bạn — giữ kín.

> Token tạo từ **portal** thuộc tài khoản của bạn và chịu hạn mức gói (số tunnel,
> băng thông, tốc độ request). Token do operator tạo (dashboard) là token riêng,
> không tính vào tài khoản.

---

## 4. Chạy tunnel

### HTTP web service (ví dụ web server local cổng 8080)

```bash
./ddns --token tok_XXXXXXXX --server https://<ten-mien> --port 8080
```

Xong — truy cập dịch vụ của bạn qua:

```
https://<slug>. <ten-mien>
```

(chương trình in ra địa chỉ đầy đủ khi kết nối thành công, ví dụ `https://drowsy-fox-4d.tunnel.example.com`).

### Nhiều dịch vụ / địa chỉ đích linh hoạt

```bash
# forward nhiều scheme cùng lúc:
./ddns --token tok_XXX --server https://<ten-mien> \
       --local http://127.0.0.1:8080 \
       --local tcp://127.0.0.1:5432

# TCP trực tiếp (ví dụ SSH cổng 22):
./ddns --token tok_XXX --server https://<ten-mien> --tcp 22
```

Các tùy chọn chính:

| Tùy chọn | Ý nghĩa |
|---|---|
| `--token` | Token kết nối (bắt buộc) |
| `--server` | URL broker (mặc định `https://tunnel.example.com`) |
| `--port N` | Cổng HTTP local để forward |
| `--tcp N` | Cổng TCP local để forward |
| `--local URL` | Đích dạng `http://host:port` hoặc `tcp://host:port` (lặp được) |
| `--ca-pem FILE` | CA tùy chỉnh nếu broker dùng CA riêng |

> Chạy nền lâu dài trên Linux: `nohup ./ddns ... > ddns.log 2>&1 &` hoặc cấu hình
> systemd (dịch vụ `ddns.service` với `Restart=always`).

---

## 4b. Kết nối trong 1 phút — Quickstart (một dòng lệnh)

Sau khi đã đăng ký và tạo token + tunnel, cách nhanh nhất để mở tunnel là dùng nút
**Quickstart** trên trang **Tunnels** của portal:

1. **Đăng ký** tài khoản (§1) rồi đăng nhập portal.
2. **Tạo token** (§3), sau đó tạo tunnel ở mục **Tunnels** (nhập cổng local, vd `8080`).
3. Bấm nút **Quickstart** ở dòng tunnel vừa tạo.
4. **Sao chép** dòng lệnh hiện ra và dán vào terminal trên máy đang chạy dịch vụ:

```bash
curl -sSL "https://<ten-mien>/install.sh?code=sc_XXX&port=8080" | sh
```

Lệnh này tự cài client và mở tunnel với token + cổng của chính bạn — token bí mật
`tok_...` không bao giờ lộ ra ngoài. Mã `sc_...` dùng **một lần**, hết hạn sau
**7 ngày**; làm mới trang Quickstart để nhận mã mới.

---

## 5. Tự quản lý tài khoản (portal)

| Mục | Chức năng |
|---|---|
| **Overview** | Đồng hồ token (số dư, hạn mức tháng, % đã dùng, mốc cảnh báo 80%/95%), trạng thái từng tunnel đang chạy (live gauges 5s) |
| **Tokens** | Tạo / vô hiệu hóa / xóa token |
| **API keys** | Tạo API key (`ddns_...`, hiện 1 lần) để gọi API `/api/v1/*` |
| **Mua thêm token** | Nút "Buy 100k tokens — $5" trên Overview (nếu operator đã bật cổng thanh toán) — dùng khi sắp hết hạn mức |

**API** (dùng API key, header `Authorization: Bearer ddns_...`):

```
GET  /api/v1/me              → thông tin tài khoản + gói + số dư token
GET  /api/v1/tokens          → số dư + lịch sử token
GET  /api/v1/tunnels         → danh sách tunnel + số liệu trực tiếp
GET  /api/v1/usage?since=    → series usage theo ngày
```

---

## 6. Hạn mức & cách tính token

- **1 token = 1 MiB dữ liệu truyền qua tunnel HOẶC 100 request** (quy đổi theo gói).
- Mỗi tháng tài khoản được cộng hạn mức theo gói (gói Free có hạn mức thấp, gói Pro cao hơn, gói Business không giới hạn).
- Khi dùng tới **80% / 95%** hạn mức tháng, hệ thống gửi email/cảnh báo.
- Khi **hết token**: tunnel bị ngắt, đăng ký tunnel mới bị từ chối cho tới khi bạn **mua thêm token** hoặc nâng cấp gói.
- Rate limit: số request/phút theo gói; vượt quá nhận `429` kèm `Retry-After` (thử lại sau N giây).

---

## 7. Xử lý sự cố thường gặp

| Vấn đề | Cách xử lý |
|---|---|
| `error: token rejected` / không kết nối được | Sai token (kiểm tra lại `tok_...`), token đã bị xóa/vô hiệu hóa, hoặc tài khoản hết token (xem §6) |
| Nhận `429 Too Many Requests` | Vượt tốc độ request của gói; chờ `Retry-After` giây rồi thử lại |
| Trang truy cập báo "no such tunnel" | Client chưa kết nối (xem log client) hoặc slug không đúng |
| `slug is occupied` (NoSubdomainAvailable) | Slug đang bị phiên khác dùng; ngắt phiên cũ hoặc đợi vài phút |
| Tunnel hay bị ngắt | Kiểm tra mạng, tường lửa local, hoặc hạn mức token sắp cạn; chạy client với `Restart=always` |
| Không nhận được email xác minh | Kiểm tra thư rác; hoặc liên hệ operator (SMTP có thể chưa cấu hình) |

Cần hỗ trợ thêm? Liên hệ người vận hành dịch vụ (chủ hệ thống) kèm: tên tài khoản, token ID, và nội dung log client.
