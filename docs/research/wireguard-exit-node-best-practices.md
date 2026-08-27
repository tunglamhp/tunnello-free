# WireGuard Exit Node — Best Practices Bảo Mật (Enterprise)

> Nghiên cứu phục vụ Phase "Exit Node" (`ddns up --exit-node`). Mục tiêu: tổng hợp
> best practices đã được xác minh từ nguồn chính thống để builder và verifier đối chiếu.
> Mỗi mục: khuyến nghị ngắn gọn + link nguồn. Không thay đổi code.

**Nguồn chính:** [WireGuard official](https://www.wireguard.com/) ·
[Arch Wiki — WireGuard](https://wiki.archlinux.org/title/WireGuard) ·
[wg-quick(8)](https://man.archlinux.org/man/wg-quick.8) ·
[Tailscale docs](https://tailscale.com/kb) · [Gentoo Wiki — WireGuard/Examples](https://wiki.gentoo.org/wiki/WireGuard/Examples)

---

## 1. Server-side (exit node)

### 1.1 nftables: NAT + Forward rules an toàn

WireGuard kernel **không tự NAT và không đụng bảng routing** — exit node phải tự cấu hình
forwarding + NAT ([Gentoo Wiki](https://wiki.gentoo.org/wiki/WireGuard/Examples)).

Ruleset mẫu (thay `eth0` = WAN interface, `10.200.200.0/24` = subnet tunnel):

```nft
table inet wg-exit {
    chain forward {
        type filter hook forward priority 0; policy drop;

        # Chỉ forward lưu lượng có nguồn từ subnet tunnel ra WAN
        iifname "wg0" ip saddr 10.200.200.0/24 oifname "eth0" ct state new,established accept

        # Cho phép reply quay về tunnel (stateful)
        iifname "eth0" oifname "wg0" ct state established,related accept

        # Mặc định: DROP mọi thứ khác — không bao giờ mở WAN→LAN hay wg0→LAN
    }

    chain postrouting {
        type nat hook postrouting priority 100;
        oifname "eth0" ip saddr 10.200.200.0/24 masquerade
        # IP tĩnh: dùng snat thay masquerade (nhanh hơn, giữ connection tracking ổn định)
    }
}
```

Điểm cần nhớ:

- **`policy drop` ở forward** là kill-switch mặc định của server: khi `wg0` down,
  rule `iifname "wg0"` không match gì → không có lưu lượng nào bị forward lộ.
- **Không forward WAN→LAN**: chỉ chấp nhận `ct state established,related`. Đây là
  biên giới chống open-relay hai chiều.
- Arch Wiki dùng iptables tương đương (`iptables -A FORWARD -i %i -j ACCEPT`,
  `MASQUERADE`) trong `PostUp/PostDown` của `wg-quick`
  ([nguồn](https://wiki.archlinux.org/title/WireGuard#Server_configuration)).
  nftables native tốt hơn cho production vì một bảng `inet` xử lý cả v4+v6 atomically.

### 1.2 Anti-spoofing

- **Cryptokey routing của WireGuard đã lọc source ở tầng protocol**: packet giải mã từ
  peer X chỉ được chấp nhận nếu `ip saddr` nằm trong `AllowedIPs` của peer X; ngược lại
  bị drop âm thầm. Đây là cơ chế built-in — **đặt `AllowedIPs = <ip-peer>/32` chặt trên
  server**, không bao giờ `/24` hay `0.0.0.0/0` cho peer client
  ([Arch Wiki — server config](https://wiki.archlinux.org/title/WireGuard#Server_configuration),
  [wireguard.com — conceptual overview](https://www.wireguard.com/#cryptokey-routing)).
- **Defense-in-depth ở nftables**: rule `iifname "wg0" ip saddr 10.200.200.0/24` ở §1.1
  lặp lại ràng buộc prefix ngay cả khi ai đó cấu hình sai `AllowedIPs`.
- Bật **reverse path filtering** trên server (`sysctl net.ipv4.conf.all.rp_filter=1`)
  để kernel drop packet có route ngược không hợp lý.

### 1.3 Key rotation & PSK

- **Pre-shared key (PSK) cho mỗi cặp peer, KHÔNG tái sử dụng**: thêm lớp symmetric
  (ChaCha20-Poly1305 mix vào Noise IK) với mục đích **post-quantum resistance**
  (`wg genpsk`, umask 0077)
  ([Arch Wiki — Key generation](https://wiki.archlinux.org/title/WireGuard#Key_generation)).
- **Rotation thủ công, zero-downtime** — không cần restart tunnel:
  ```bash
  wg set wg0 peer <pubkey> preshared-key <(wg genpsk)   # atomic, handshake kế tiếp dùng PSK mới
  ```
- **Chính sách expiry kiểu Tailscale**: key mặc định hết hạn sau **180 ngày** (tùy chỉnh
  1–180 ngày); thiết bị hết hạn mất kết nối cho đến khi re-authenticate; chỉ disable
  expiry cho server/IoT khó tiếp cận
  ([Tailscale — Key expiry](https://tailscale.com/docs/features/access-control/key-expiry)).
  Áp dụng cho ddns: broker track ngày cấp key/ticket của visitor và ép re-issue định kỳ.
- Private key của server nên lưu mã hóa (TPM-bound nếu có): `systemd-creds encrypt`
  hoặc `pass`, load qua `PostUp`/`PrivateKey = @credential`
  ([Arch Wiki — Store private keys encrypted](https://wiki.archlinux.org/title/WireGuard#Store_private_keys_in_encrypted_form_(wg-quick))).
- Handshake key của phiên WireGuard tự xoay mỗi **~2 phút** theo giao thức (Noise
  transport key update) — đây là lý do WireGuard có forward secrecy tự nhiên; việc
  rotation ở trên là về identity/PSK dài hạn, không phải session key.

### 1.4 Peer management tự động

- **Thêm/xóa peer không ngắt kết nối đang hoạt động**:
  ```bash
  wg syncconf wg0 <(wg-quick strip wg0)     # apply conf mới, giữ nguyên session
  ```
  ([man wg-quick(8)](https://man.archlinux.org/man/wg-quick.8#EXAMPLES),
  [Arch Wiki — Reload peer configuration](https://wiki.archlinux.org/title/WireGuard#Reload_peer_(server)_configuration)).
  Tránh `wg-quick down/up` (rớt mọi flow).
- Đặt `SaveConfig = false` (mặc định) khi peer được quản lý bằng script/API — tránh
  config file bị ghi đè bởi trạng thái runtime.
- **Mỗi peer một dòng `[Peer]` với `/32` riêng**; xóa peer = `wg set wg0 peer <pubkey> remove`.
- Tooling tham khảo: `wg_tool` / `wireguird` liệt kê trong
  [Arch Wiki](https://wiki.archlinux.org/title/WireGuard#Command-line_tools);
  Firezone/wg-easy là các panel phổ biến (không bắt buộc).
- Endpoint DDNS đổi IP: WireGuard **không re-resolve DNS** — cần cron chạy
  `reresolve-dns.sh` mỗi ~30 giây
  ([Arch Wiki — Endpoint with changing IP](https://wiki.archlinux.org/title/WireGuard#Endpoint_with_changing_IP)).
  Với ddns đây chính là use case cốt lõi của project.

### 1.5 Kill-switch phía server

Server-side kill-switch = đảm bảo **không có lưu lượng nào rời server ngoài đường hầm
khi tunnel chưa sẵn sàng**:

1. `policy drop` ở chain forward (§1.1) — khi `wg0` không tồn tại, rule `iifname "wg0"`
   match nothing → toàn bộ forward bị drop.
2. Gắn ruleset với vòng đời interface bằng `PostUp/PostDown` (hoặc nftables table riêng
   được load/unload cùng `wg-quick`) để không dư rule mồ côi sau crash.
3. Không bao giờ đặt rule NAT/forward broad (`masquerade` không kèm `ip saddr`).

---

## 2. Client-side (visitor / full-tunnel)

### 2.1 Route mặc định qua WireGuard

- Cách chuẩn: `AllowedIPs = 0.0.0.0/0, ::/0` ở `[Peer]`; wg-quick tự setup policy routing
  ([Arch Wiki — Routing all traffic](https://wiki.archlinux.org/title/WireGuard#Routing_all_traffic_over_WireGuard)).
- **Cơ chế bên dưới (quan trọng để hiểu và tự implement)** — wg-quick dùng fwmark +
  bảng route riêng thay vì ghi đè default route:
  ```bash
  ip route add default dev wg0 table 51820
  wg set wg0 fwmark 51820
  ip rule add not fwmark 51820 table 51820 pref 32764
  ip rule add table main suppress_prefixlength 0      # vẫn truy cập được LAN
  ```
  Lợi thế: **endpoint roaming** — packet ciphertext của chính WireGuard mang fwmark nên
  đi qua main table, không cần route exception tĩnh cho endpoint IP
  ([wireguard.com/netns — Improved Rule-based Routing](https://www.wireguard.com/netns/#improved-rule-based-routing)).
- Phương án thay thế "0.0.0.0/1 + 128.0.0.0/1" (2 route cụ thể hơn default) cũng hợp lệ,
  nhưng DHCP daemon hay ghi đè — kém bền hơn fwmark
  ([wireguard.com/netns — Classic Solutions](https://www.wireguard.com/netns/#the-classic-solutions)).

### 2.2 DNS leak prevention

- Dùng directive `DNS = <tunnel-ip>` trong `[Interface]`: wg-quick gọi
  `resolvconf -a tun.%i -m 0 -x` (metric 0 = ưu tiên cao nhất) và trả lại cấu hình cũ khi
  teardown ([man wg-quick(8)](https://man.archlinux.org/man/wg-quick.8#CONFIGURATION)).
- **Resolver phải là địa chỉ tunnel IP của peer**, không phải IP LAN thật của nó — nếu
  không query sẽ thoát ra ngoài tunnel và fail/leak
  ([Arch Wiki — DNS](https://wiki.archlinux.org/title/WireGuard#DNS)).
- **Block port 53/853 ngoài tunnel** ở firewall client (rule kill-switch §2.3 đã phủ vì
  nó chặn mọi egress không-mark, gồm cả DNS). Kiểm tra leak: `curl https://dnsleaktest.com`
  hoặc so sánh resolver qua `resolvectl status` trước/sau khi up.
- Lưu ý: wg-quick không hỗ trợ đánh dấu interface DNS là *private* qua resolvconf —
  mọi query hệ điều hành đều đi vào tunnel DNS, kể cả search domain. Đây là hành vi
  mong muốn cho full-tunnel.
- IPv6: nếu tunnel chỉ có v4 mà client còn IPv6, **IPv6 sẽ leak**. Giải pháp enterprise:
  block IPv6 egress khi tunnel up (cách Tailscale v1: "block rather than leak").

### 2.3 Kill-switch (fwmark / policy routing)

Kill-switch chính thức từ tác giả WireGuard, nằm ngay man page
([wg-quick(8) EXAMPLES](https://man.archlinux.org/man/wg-quick.8#EXAMPLES)):

```ini
PostUp   = iptables -I OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT
PreDown  = iptables -D OUTPUT ! -o %i -m mark ! --mark $(wg show %i fwmark) -m addrtype ! --dst-type LOCAL -j REJECT
```

Cơ chế: mọi packet **OUTPUT không ra interface wg0, không mang fwmark của tunnel, và
không phải loopback/local** → REJECT. Kết quả: khi tunnel chết, máy không thể rò rỉ
traffic ra mạng vật lý (DHCP vẫn sống vì PF_PACKET socket bypass netfilter — chấp nhận được).

Nâng cao nhất — **network namespace isolation**
([wireguard.com/netns](https://www.wireguard.com/netns/)): đưa toàn bộ physical interfaces
vào netns `physical`, giữ `wg0` làm interface duy nhất trong netns mặc định. Ứng dụng
thường **không nhìn thấy** eth0/wlan0 — không thể leak kể cả khi firewall lỗi.

Lưu ý vận hành: systemd-networkd ≥253 reset routing policy khi resume khỏi sleep —
khiến mất kill-switch và lộ public IP; cần `ManageForeignRoutingPolicyRules=no` trong
`/etc/systemd/networkd.conf`
([Arch Wiki — Troubleshooting](https://wiki.archlinux.org/title/WireGuard#Connection_lost_after_sleep_using_systemd-networkd)).

### 2.4 MTU

| Bối cảnh | MTU khuyến nghị | Nguồn |
|---|---|---|
| wg-quick mặc định (auto-detect từ endpoint/default route) | thường ra **1420** | [wg-quick(8)](https://man.archlinux.org/man/wg-quick.8#CONFIGURATION) |
| PPPoE (WAN MTU 1492) | **1412** | suy ra từ công thức dưới |
| Đường bất định / relayed / chống PMTU blackhole | **1280** (IPv6 minimum MTU) | [tailscale issue #3836](https://github.com/tailscale/tailscale/issues/3836) — Tailscale dùng 1280 |

- Công thức: `1500 − 20(inner IP) − 8(UDP) − 32(WG data-plane header+tag) − 20~40(outer IP)` → 1420 với outer IPv4.
- **Khuyến nghị thực tế**: bắt đầu 1420; nếu thấy throughput tụt đột ngột hoặc TCP
  hang (PMTU blackhole), hạ 1380 rồi 1280. Luôn set `MTU =` tường minh trong config —
  auto-detect có thể nhảy khi restart interface.
- boringtun/TUN user-space (data plane thực tế của ddns-free): MSS do stack quảng cáo = `MTU − 40`
  (IPv6) — kiểm soát MTU ở TUN là đủ, không cần clamp MSS kernel. Bản free cố định
  1420; bản private cho phép override 1412 (PPPoE) / 1280 (PMTU blackhole).

---

## 3. Mapping sang design của tunnello/ddns

Spec hiện tại: `docs/superpowers/specs/2026-08-26-exit-node-wireguard-design.md`. ddns chạy
**WireGuard data plane** qua `boringtun` (userspace) ở client visitor, và NAT ở exit qua
`nftables` (không tự viết TCP/IP stack — đã bỏ hướng smoltcp). Các best practices trên map:

| Best practice | Áp dụng cho ddns |
|---|---|
| Cryptokey routing / AllowedIPs /32 | Tương đương: broker enforce `want_exit` per-session (§3.Exit-1 spec) — access control ở control plane |
| `policy drop` forward | Visitor kill-switch (§7 spec) đã đúng hướng; bổ sung: exit bridge chỉ dial từ flow hợp lệ, refuse RFC1918/loopback (§8 SSRF row — đã có) |
| DNS qua tunnel IP + block :53 ngoài tunnel | Spec §6: DNS proxy `10.111.0.1` + kill-switch block non-TUN egress — khớp §2.2 |
| fwmark/policy-routing kill-switch | Spec §7 Linux: `iptables OUTPUT mark !0x539 DROP` — đúng mô hình wg-quick fwmark; cân nhắc thêm sweep stale-rule (đã có trong spec §7) |
| MTU 1420→1280 | Spec chọn 1384 (margin cho DTLS/SCTP) — nằm giữa 1420 và 1280, hợp lý; verify bằng test PMTU |
| Key rotation 90–180 ngày | Broker nên track tuổi key/tunnel và ép re-auth định kỳ (chưa thấy trong spec — gap tiềm năng) |
| Block-IPv6-rather-than-leak | Spec §6 đã chọn đúng posture này |

## 4. Checklist verifier

- [ ] Tunnel down → `curl ifconfig.me` từ visitor **fail/không trả IP thật** (kill-switch hoạt động)
- [ ] `dig +short whoami.akamai.net` trả resolver của tunnel, không phải ISP (no DNS leak)
- [ ] Ping `8.8.8.8` khi tunnel down → timeout, không fallback
- [ ] Server: `nft list ruleset` — forward chain có `policy drop`, không có rule WAN→LAN new-state
- [ ] Thêm/xóa peer lúc đang transfer → flow không đứt (`wg syncconf`)
- [ ] MTU: transfer lớn (nc/dd) không treo; `ping -M do -s <payload>` xác nhận PMTU
