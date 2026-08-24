# Building `ddns` from source

The ddns client compiles to a single static binary.

## Quick build

```sh
cargo build --release -p ddns-client
```

The binary is at `target/release/ddns` (or `ddns.exe` on Windows).

## Linux static builds (musl)

For fully static binaries that run on any Linux kernel ≥ 2.6.x:

```sh
# Install musl targets (once)
rustup target add x86_64-unknown-linux-musl
rustup target add aarch64-unknown-linux-musl

# Build
cargo build --release -p ddns-client --target x86_64-unknown-linux-musl
cargo build --release -p ddns-client --target aarch64-unknown-linux-musl
```

Binary paths:
- `target/x86_64-unknown-linux-musl/release/ddns`
- `target/aarch64-unknown-linux-musl/release/ddns`

## Expected binary size

Release builds are **4–6 MB** (stripped). The binary includes:

- `tokio` async runtime
- `rustls` + `webpki-roots` for TLS
- `tokio-tungstenite` for WebSocket
- `serde`/`serde_json` for protocol serialization

## Install script

Users can install with a one-liner that fetches the correct binary for their platform:

```sh
curl -fsSL https://<server>/install.sh | sh
```

The script detects OS and architecture, then downloads `https://<server>/download/ddns-<target-triple>` where `<target-triple>` is one of:

- `x86_64-unknown-linux-musl`
- `aarch64-unknown-linux-musl`
- `x86_64-apple-darwin`
- `aarch64-apple-darwin`
- `x86_64-pc-windows-msvc`

(The `/download/{file}` route serves files from the broker's `download_dir`, named `ddns-<target-triple>`; see the broker task 5.)

The `<server>` URL defaults to `https://tunnel.example.com` and can be overridden with `DDNS_SERVER`.
