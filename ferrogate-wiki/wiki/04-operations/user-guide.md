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
cargo run -- run --config Ferrogate/Caddyfile
```

## Use a custom config

```bash
cargo run -- validate --config ./config/ferrogate.example.toml
cargo run -- reload --config ./config/ferrogate.example.toml
cargo run -- run --config ./config/ferrogate.example.toml
```

`reload` 当前会校验候选配置并输出 snapshot id；运行中平滑切换将在 P2 后续任务中接入 Pingora runtime。

`Ferrogate/Caddyfile` 中的全局 `admin localhost:2019` 会进入 typed config。运行中的 `/admin/status` 会返回当前配置 snapshot，便于后续验证 reload 是否生效。

## OpenAI-compatible MVP status

当前 P3 已支持 `GET /v1/models`，并且 `/v1/chat/completions` 已完成 API key 鉴权、租户上下文、模型 allowlist、logical model 到 provider model 的 request planning 和非流式 HTTP upstream dispatch。`stream=true` 的 SSE 转发、HTTPS provider dispatch、usage 提取和 Provider 错误归一化仍在后续 P3 切片中完成。

## Docker

```bash
docker build -t ferrogate .
docker run --rm -p 8080:8080 ferrogate
```
