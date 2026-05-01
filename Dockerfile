FROM rust:1.78-bookworm AS builder
WORKDIR /app
COPY Cargo.toml Cargo.lock* ./
COPY src ./src
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/ferrogate /usr/local/bin/ferrogate
EXPOSE 8080
ENV FERROGATE_CONFIG=/etc/ferrogate/ferrogate.toml
CMD ["ferrogate", "serve"]
