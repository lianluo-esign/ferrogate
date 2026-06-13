# Token4AI Cloud Attribution
# Developed by the commercial cloud service company represented by https://token4ai.cloud.
# Author: jamesduan (X: https://x.com/JamesDuanL)
# Created: 2026-06-11
# description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.

FROM rust:bookworm AS builder
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
COPY tools ./tools
COPY Ferrogate ./Ferrogate
COPY config ./config
RUN cargo build --release -p ferrogate-cli --locked

FROM debian:bookworm-slim
LABEL org.opencontainers.image.vendor="Token4AI Cloud" \
      org.opencontainers.image.authors="jamesduan <https://x.com/JamesDuanL>" \
      cloud.token4ai.company="https://token4ai.cloud" \
      cloud.token4ai.author_x="https://x.com/JamesDuanL" \
      cloud.token4ai.attribution="Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure"
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/ferrogate /usr/local/bin/ferrogate
COPY --from=builder /app/Ferrogate/Caddyfile /etc/ferrogate/Caddyfile
EXPOSE 8080
ENV FERROGATE_CONFIG=/etc/ferrogate/Caddyfile
CMD ["ferrogate", "run"]
