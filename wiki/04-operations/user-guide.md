---
title: User guide
---

# User guide

## Install from source

```bash
git clone https://github.com/lianluo-esign/ferrogate.git
cd ferrogate
cargo build --release
```

## Run locally

```bash
cargo run -- serve
```

## Use a custom config

```bash
cargo run -- --config ./config/ferrogate.example.toml check
cargo run -- --config ./config/ferrogate.example.toml serve
```

## Docker

```bash
docker build -t ferrogate .
docker run --rm -p 8080:8080 ferrogate
```
