# syntax=docker/dockerfile:1
# ddns tunnel broker — production image.
#
# Build:   docker build -f deploy/Dockerfile -t ddns-broker:latest .
# Run:     see deploy/README.md or docker compose up -d in deploy/.
#
# Multi-stage:
#   builder — release build of ddns-server (glibc; rusqlite is bundled) and a
#             static-musl ddns client for the broker's /download endpoint.
#   web     — dx bundle of the dioxus ddns-web crate (wasm), layer-cached.
#   runtime — debian-slim, non-root (drops privileges via setpriv), TLS CA
#             bundle for ACME, wget for the compose healthcheck.

FROM rust:1.94-slim AS builder
RUN apt-get update \
    && apt-get install -y --no-install-recommends musl-tools \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add x86_64-unknown-linux-musl
WORKDIR /build

# Dependency layer cache: manifests first, sources after.
COPY Cargo.toml Cargo.lock ./
COPY crates/ddns-proto/Cargo.toml crates/ddns-proto/Cargo.toml
COPY crates/ddns-client/Cargo.toml crates/ddns-client/Cargo.toml
COPY crates/ddns-server/Cargo.toml crates/ddns-server/Cargo.toml
COPY crates/ddns-echo/Cargo.toml crates/ddns-echo/Cargo.toml
COPY crates/ddns-web/Cargo.toml crates/ddns-web/Cargo.toml
RUN mkdir -p crates/ddns-proto/src crates/ddns-client/src crates/ddns-server/src \
      crates/ddns-echo/src crates/ddns-web/src \
    && printf '// placeholder\n' > crates/ddns-proto/src/lib.rs \
    && printf '// placeholder\n' > crates/ddns-client/src/lib.rs \
    && printf '// placeholder\n' > crates/ddns-server/src/lib.rs \
    && printf 'fn main() {}\n' > crates/ddns-echo/src/main.rs \
    && printf '// placeholder\n' > crates/ddns-web/src/lib.rs \
    && cargo fetch

COPY crates/ ./crates/

# Broker binary (default glibc target).
RUN cargo build --release --bin ddns-server

# Static client binary for /download — install.sh fetches ddns-x86_64-unknown-linux-musl.
ENV CC_x86_64_unknown_linux_musl=musl-gcc
RUN cargo build --release --bin ddns --target x86_64-unknown-linux-musl \
    && cp target/x86_64-unknown-linux-musl/release/ddns \
       target/release/ddns-x86_64-unknown-linux-musl

FROM rust:1.94-slim AS web
RUN apt-get update \
    && apt-get install -y --no-install-recommends pkg-config libssl-dev \
    && rm -rf /var/lib/apt/lists/* \
    && rustup target add wasm32-unknown-unknown \
    && cargo install dioxus-cli --version 0.7.10 --locked
WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY crates/ ./crates/
RUN dx bundle --platform web --package ddns-web --release

FROM debian:trixie-slim AS runtime
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates wget util-linux \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --system --create-home --uid 10001 ddns

COPY --from=builder /build/target/release/ddns-server /usr/local/bin/ddns-server
COPY --from=builder /build/target/release/ddns-x86_64-unknown-linux-musl \
    /opt/ddns/downloads/ddns-x86_64-unknown-linux-musl
COPY --from=web --chown=ddns:ddns /build/dist/public /opt/ddns/web/public
COPY deploy/entrypoint.sh /usr/local/bin/docker-entrypoint.sh
RUN chmod +x /usr/local/bin/docker-entrypoint.sh

# Persistent state: SQLite DB + client download dir.
VOLUME /data
EXPOSE 443 80

ENTRYPOINT ["/usr/local/bin/docker-entrypoint.sh"]
