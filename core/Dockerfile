# Build context: repository root (needs tools/ and core/).

# 1) Pinned ProjectDiscovery binaries, SHA-256 verified (installer from SWOT).
FROM python:3.13-slim-bookworm AS tools
WORKDIR /build
COPY tools/install_tools.py tools/versions.json tools/
RUN python tools/install_tools.py --dest /opt/asi-tools --only naabu httpx tlsx nuclei

# 2) Rust build. Dependencies are cached in a separate layer.
FROM rust:1-bookworm AS builder
WORKDIR /src
COPY core/Cargo.toml core/Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release && rm -rf src
COPY core/migrations ./migrations
COPY core/src ./src
RUN touch src/main.rs && cargo build --release

# 3) Runtime: nmap from Debian + verified PD tools, non-root.
FROM debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends nmap libpcap0.8 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 asi
COPY --from=tools /opt/asi-tools /opt/asi-tools
COPY --from=builder /src/target/release/asi-core /usr/local/bin/asi-core
ENV ASI_TOOLS_DIR=/opt/asi-tools ASI_BIND=0.0.0.0:8000 RUST_LOG=info
USER asi
EXPOSE 8000
HEALTHCHECK --interval=20s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1
CMD ["asi-core"]
