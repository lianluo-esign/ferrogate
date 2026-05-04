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

`reload` CLI 默认会校验候选配置并输出 snapshot id，不会替换运行中监听器。若提供 `--admin-url http://127.0.0.1:8080 --admin-token "$FERROGATE_ADMIN_TOKEN"`，CLI 会把候选 TOML/Caddyfile 提交到运行中的 `POST /admin/v1/config/reload`，并输出 `valid`、`committed`、`mode`、active/candidate snapshot 和错误信息。运行中的管理 API 也可直接接收 `config_toml`、`config_caddyfile`，或 `source = "file"` 以重新读取当前 `ferrogate run --config` 的配置文件。validate 响应会返回 `reload_mode`、`listener_reload_required` 和 `reload_reason`，用于在执行 reload 前判断候选配置是否需要 listener 级路径。当候选配置不改变 `listen` 与 TLS listener 设置时，会以 process-local 方式替换新请求使用的 routes、upstreams、providers、models、api_keys 和 policies；监听地址/TLS 变更可通过 `ferrogate reload --config <candidate> --graceful-upgrade` 启动新进程并向旧进程发送 `SIGQUIT`，由 Pingora 通过 `graceful_upgrade_sock` 完成 FD transfer。FerroGate 已透传 Pingora graceful upgrade 的 `graceful_upgrade_pid_file`、`graceful_upgrade_sock` 和 `graceful_upgrade_sock_retries`。

`Ferrogate/Caddyfile` 中的全局 `admin localhost:2019` 会进入 typed config。运行中的 `/admin/status` 会返回当前配置 snapshot，便于后续验证 reload 是否生效。

## Production self-hosting

See [[04-operations/self-hosting-runbook|Self-hosting runbook]] for the current P8 deployment guide. It covers:

- binary and Docker deployment
- manual TLS listener configuration
- Provider/API key environment variables
- Admin health checks and metrics
- graceful shutdown settings
- request/token limits
- capacity planning and incident response

## OpenAI-compatible API status

当前已支持 `GET /v1/models`，并且 `/v1/chat/completions` 已完成 API key 鉴权、租户上下文、模型 allowlist、logical model 到 provider model 的 request planning、HTTP/HTTPS provider dispatch、非流式和 `stream=true` SSE response forwarding、usage 提取、Provider 错误归一化、fallback、熔断、超时重试、Token 预算预留/结算与计费事件记录。

## Docker

```bash
docker build -t ferrogate .
docker run --rm -p 8080:8080 ferrogate
```
