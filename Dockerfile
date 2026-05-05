FROM rust:bookworm AS builder
WORKDIR /app
RUN apt-get update \
    && apt-get install -y --no-install-recommends cmake \
    && rm -rf /var/lib/apt/lists/*
COPY Cargo.toml Cargo.lock* ./
COPY crates ./crates
COPY Ferrogate ./Ferrogate
COPY config ./config
COPY ferrogate-homepage ./ferrogate-homepage
RUN cargo build --release -p ferrogate-cli --locked

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/ferrogate /usr/local/bin/ferrogate
COPY --from=builder /app/Ferrogate/Caddyfile /etc/ferrogate/Caddyfile
EXPOSE 8080
ENV FERROGATE_CONFIG=/etc/ferrogate/Caddyfile
CMD ["ferrogate", "run"]
