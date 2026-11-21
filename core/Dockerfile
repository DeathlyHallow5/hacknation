# Base images come from Docker Hub; when its anonymous pull limit is hit (HTTP 429), build with
# ASI_BASE_REGISTRY=mirror.gcr.io/library (Google's public Docker Hub cache).
ARG BASE_REGISTRY=docker.io/library
# Build context: repository root (needs tools/ and core/).

# 1) Pinned ProjectDiscovery binaries, SHA-256 verified (installer from SWOT).
FROM ${BASE_REGISTRY}/python:3.13-slim-bookworm AS tools
WORKDIR /build
COPY tools/install_tools.py tools/versions.json tools/
RUN python tools/install_tools.py --dest /opt/asi-tools --only naabu httpx tlsx nuclei

# 2) Rust build. Dependencies are cached in a separate layer.
FROM ${BASE_REGISTRY}/rust:1-bookworm AS builder
WORKDIR /src
COPY core/Cargo.toml core/Cargo.lock ./
RUN mkdir src && echo 'fn main() {}' > src/main.rs && cargo build --release && rm -rf src
COPY core/migrations ./migrations
COPY core/signatures ./signatures
COPY core/src ./src
RUN touch src/main.rs && cargo build --release

# 3) Runtime: nmap from Debian + verified PD tools, non-root.
FROM ${BASE_REGISTRY}/debian:bookworm-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends nmap libpcap0.8 ca-certificates curl \
    && rm -rf /var/lib/apt/lists/* \
    && useradd --create-home --uid 10001 asi
# nmap -sV also runs the NSE "version" scripts (vmware-version: POST /sdk, http-trane-info:
# /evox/about, ...): requests that look like exploit probing in the targets' logs. ASI needs
# only the version probes, so those scripts are not shipped.
RUN cd /usr/share/nmap/scripts && grep -l 'categories *= *{[^}]*"version"' *.nse | xargs -r rm -f     && nmap --script-updatedb >/dev/null
COPY --from=tools /opt/asi-tools /opt/asi-tools
COPY --from=builder /src/target/release/asi-core /usr/local/bin/asi-core
ENV ASI_TOOLS_DIR=/opt/asi-tools ASI_BIND=0.0.0.0:8000 RUST_LOG=info
USER asi
EXPOSE 8000
HEALTHCHECK --interval=20s --timeout=5s --start-period=20s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8000/api/health || exit 1
CMD ["asi-core"]
