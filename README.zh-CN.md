# FerroGate

**语言：** [English](README.md) | 简体中文

FerroGate 是一个基于 Cloudflare Pingora 构建的开源 Rust API 网关和 AI 网关。它为团队提供一个可自托管的 LLM 流量控制点，覆盖路由、虚拟 API Key、供应商适配、策略检查、Token 用量计费、可观测性、Admin API 和自动 HTTPS。

该项目也是 [Token4AI Cloud](https://token4ai.cloud) 背后的开源网关基础。

## FerroGate 提供什么

- **Pingora 网关运行时**：支持 HTTP 反向代理、路由匹配、上游池、路径和 Header 重写、请求 ID、Trace ID、流式响应、优雅关闭，以及监听器级别的优雅升级。
- **OpenAI 兼容 AI API**：支持 `GET /v1/models` 和 `POST /v1/chat/completions`，包含非流式与 SSE 流式转发。
- **供应商适配器**：支持 OpenAI-compatible API、OpenAI、Anthropic、Gemini、Grok/xAI 和 Azure OpenAI。
- **模型注册表与 fallback 路由**：支持逻辑模型名、供应商模型映射、优先级 fallback、加权 fallback、租户可见性，以及供应商 allow/deny 控制。
- **Caddy 风格配置兼容**：通过解析 `Ferrogate/Caddyfile` 支持熟悉的反向代理路由、匹配器、TLS、日志和网关设置，同时也支持结构化 TOML 配置。
- **虚拟 API Key 与策略检查**：支持哈希 Key、租户上下文、Scope、禁用或过期 Key、模型和供应商白名单/黑名单、最小化 deny-rule 策略评估、请求频率限制和 Token 预算。
- **Token 用量与计费事件**：优先使用供应商返回的 usage；缺失时由网关估算；并提供面向生产 AI 网关的请求预留与结算流程。
- **可观测性**：包括结构化请求日志、计费事件、用量聚合、Prometheus 指标、请求/Trace ID 传播，以及 OTLP/HTTP metrics/logs/traces 导出。
- **Admin API 与 Dashboard**：查看网关状态、供应商、模型、API Key、租户、策略、请求日志、计费事件、用量聚合、审计事件、供应商健康状态、配置验证和进程内 reload。
- **自动 HTTPS**：支持手动 TLS、ACME HTTP-01，以及内置 Cloudflare provider 的 ACME DNS-01。ACME provider 凭据从 FerroGate 配置文件读取，不依赖环境变量或 Python 脚本。
- **供应链与安全门禁**：包含格式化、clippy、锁定元数据、高置信度密钥扫描、cargo-deny、cargo-audit 和 GitHub Actions。

## 当前状态

开源网关代码库的 MVP 与生产可用性实现切片已经完成。

已完成端到端验证：

- 基于 Pingora 的 HTTP 反向代理运行时。
- OpenAI 兼容 AI 网关路径。
- 供应商适配器与 fallback 路由。
- 虚拟 API Key 鉴权、策略检查、频率限制和 Token 预算处理。
- 请求日志、计费事件、用量聚合、指标和 OTLP 规划。
- Admin API、静态 Dashboard、配置验证和进程内 reload。
- 手动 TLS、ACME HTTP-01 和 ACME DNS-01。
- 在真实 Let's Encrypt staging 与 production 环境中完成 HTTP-01 和 Cloudflare DNS-01 的签发验证。

仍有意留作下一阶段生产工作的范围：

- API Key、租户、策略、计费、请求日志和审计日志的持久化存储实现。当前运行时状态主要由配置和内存 repository 驱动。
- 完整 Admin API CRUD 控制面。
- 后台 ACME 续期与热证书 reload。当前 ACME 行为是在启动时签发或复用证书。
- 内置 Cloudflare provider 和通用外部 hook 边界之外的更多 DNS provider。

## 仓库结构

```text
crates/
  ferrogate-cli             CLI、Pingora 运行时接线、网关 handler
  ferrogate-config          Caddyfile/TOML 配置模型与解析器
  ferrogate-providers       AI 供应商适配器与模型注册表
  ferrogate-auth            租户与 RBAC 领域模型
  ferrogate-policy          策略决策模型与引擎
  ferrogate-storage         Repository trait 与内存存储
  ferrogate-billing         Token 用量、成本与计费事件模型
  ferrogate-observability   指标、span 与 exporter 契约
  ferrogate-runtime         Reload 与运行时生命周期状态机
config/                     TOML 示例配置
Ferrogate/Caddyfile          默认 Caddyfile 风格开发配置
scripts/security-check.sh    本地安全与供应链门禁
```

## 快速开始

前置条件：

- 与 workspace `rust-version` 兼容的 Rust toolchain。
- `cmake`、`g++`、`make` 和 `pkg-config`，用于 Pingora 原生压缩依赖链。

运行默认开发网关：

```bash
cargo run -- run --config Ferrogate/Caddyfile
```

验证配置：

```bash
cargo run -- validate --config Ferrogate/Caddyfile
cargo run -- validate --config config/ferrogate.example.toml
```

探测网关：

```bash
curl http://127.0.0.1:8080/healthz
curl http://127.0.0.1:8080/proxy/httpbin/get
curl -H 'Authorization: Bearer dev-secret' http://127.0.0.1:8080/v1/models
```

发送 OpenAI 兼容 chat 请求：

```bash
curl -X POST http://127.0.0.1:8080/v1/chat/completions \
  -H 'Authorization: Bearer dev-secret' \
  -H 'Content-Type: application/json' \
  -d '{"model":"fast-chat","messages":[{"role":"user","content":"hello"}]}'
```

打开 Admin Dashboard：

```text
http://127.0.0.1:8080/admin
```

## 配置

FerroGate 默认加载 `Ferrogate/Caddyfile`。同时也支持 TOML，用于结构化自托管和测试。

```bash
ferrogate run --config Ferrogate/Caddyfile
ferrogate run --config /etc/ferrogate/ferrogate.toml
```

### Caddyfile 示例

```caddyfile
:8080 {
    log

    respond /healthz "ok" 200

    ai_gateway {
        provider openai {
            kind openai-compatible
            base_url https://api.openai.com/v1
            api_key {env.OPENAI_API_KEY}
        }

        model fast-chat -> openai:gpt-4o-mini {
            capabilities chat streaming
            input_price_per_1m 0.15
            output_price_per_1m 0.60
        }

        api_key key_dev {
            key {$FERROGATE_DEV_KEY}
            scopes models.read chat.completions admin.read
            allowed_models fast-chat
            allowed_providers openai
            request_limit_per_minute 60
            monthly_token_budget 1000000
        }
    }

    route /v1/* {
        reverse_proxy https://api.openai.com {
            header_up Authorization "Bearer {env.OPENAI_API_KEY}"
        }
    }
}
```

### TOML 示例

```toml
listen = "0.0.0.0:8080"

[admin]
listen = "127.0.0.1:2019"

[reliability]
provider_circuit_breaker_failure_threshold = 3
provider_circuit_breaker_cooldown_secs = 30
provider_dispatch_timeout_secs = 10
provider_dispatch_max_retries = 1
graceful_shutdown_grace_period_secs = 3
graceful_shutdown_timeout_secs = 15

[[providers]]
name = "openai"
kind = "openai-compatible"
base_url = "https://api.openai.com/v1"
api_key_env = "OPENAI_API_KEY"

[[models]]
name = "fast-chat"
provider = "openai"
provider_model = "gpt-4o-mini"
capabilities = ["chat", "streaming"]
input_price_per_1m = "0.15"
output_price_per_1m = "0.60"

[[api_keys]]
id = "dev"
key = "dev-secret"
scopes = ["models.read", "chat.completions", "admin.read"]
allowed_models = ["fast-chat"]
allowed_providers = ["openai"]
request_limit_per_minute = 60
monthly_token_budget = 1000000
```

生产环境建议使用 `ferrogate hash-key` 生成的 `key_hash`，不要使用明文开发 Key。

```bash
ferrogate hash-key --secret 'your-client-secret'
```

## 自动 HTTPS

FerroGate 支持手动 TLS 证书和启动时 ACME 证书签发。

### 手动 TLS

```toml
[tls]
enabled = true
cert_path = "/etc/ferrogate/certs/fullchain.pem"
key_path = "/etc/ferrogate/certs/privkey.pem"
http2 = true
```

### ACME HTTP-01

HTTP-01 要求公网可以访问 80 端口完成 challenge，并通过 443 端口提供 HTTPS 服务。

```toml
listen = "0.0.0.0:443"

[tls]
enabled = true
http2 = true

[tls.acme]
enabled = true
domains = ["api.example.com"]
email = "ops@example.com"
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
terms_agreed = true
challenge = "http-01"
http_challenge_listen = "0.0.0.0:80"
storage_dir = "/var/lib/ferrogate/acme-http"
```

### 使用内置 Cloudflare 的 ACME DNS-01

DNS-01 不要求公网开放 80 端口，并且是签发 wildcard 证书的必需方式。Cloudflare 凭据配置在 FerroGate 配置文件中。

```toml
listen = "0.0.0.0:443"

[tls]
enabled = true
http2 = true

[tls.acme]
enabled = true
domains = ["api.example.com"]
email = "ops@example.com"
directory_url = "https://acme-v02.api.letsencrypt.org/directory"
terms_agreed = true
challenge = "dns-01"
storage_dir = "/var/lib/ferrogate/acme-dns"
dns_provider = "cloudflare"
dns_config = { api_token = "cf-token", zone_name = "example.com" }
dns_propagation_delay_secs = 30
```

Caddyfile 风格 DNS-01：

```caddyfile
api.example.com {
    tls {
        issuer acme {
            email ops@example.com
        }
        storage /var/lib/ferrogate/acme-dns
        dns cloudflare {
            api_token cf-token
            zone_name example.com
        }
    }
}
```

FerroGate 还保留了供应商中立的外部 hook 边界，用于尚未内置的 DNS provider。Hook 会收到一个权限为 0600 的 JSON payload 文件路径，调用形式如下：

```text
<hook> <set|cleanup> <payload-json-path>
```

## Reload

只验证并输出 reload 报告：

```bash
ferrogate reload --config Ferrogate/Caddyfile
```

通过正在运行的 Admin API 进行进程内 reload：

```bash
ferrogate reload \
  --config Ferrogate/Caddyfile \
  --admin-url http://127.0.0.1:8080 \
  --admin-token "$FERROGATE_ADMIN_TOKEN"
```

通过 Pingora graceful upgrade 进行监听器级别 reload：

```bash
ferrogate reload --config Ferrogate/Caddyfile --graceful-upgrade
```

只有当 listen socket 和 TLS listener 指纹不变时，才使用进程内 reload。监听器或 TLS 变更需要 graceful upgrade。

## Admin API

常用端点：

```text
GET  /admin/v1/status
GET  /admin/v1/providers
GET  /admin/v1/provider-health
GET  /admin/v1/models
GET  /admin/v1/api-keys
GET  /admin/v1/tenants
GET  /admin/v1/policies
GET  /admin/v1/request-logs
GET  /admin/v1/billing-events
GET  /admin/v1/usage-aggregates
GET  /admin/v1/audit-events
POST /admin/v1/config/validate
POST /admin/v1/config/reload
GET  /metrics
GET  /admin
```

配置了 API Key 时，读端点需要 `admin.read`。配置验证和 reload 需要 `admin.write`。

## Docker

稳定版本使用日期版本号，例如 `v2026.05.05`。

拉取 GitHub Packages 发布镜像，并挂载配置运行：

```bash
docker pull ghcr.io/lianluo-esign/ferrogate:v2026.05.05

docker run --rm \
  -p 8080:8080 \
  -v "$PWD/config/ferrogate.example.toml:/etc/ferrogate/ferrogate.toml:ro" \
  -e FERROGATE_CONFIG=/etc/ferrogate/ferrogate.toml \
  ghcr.io/lianluo-esign/ferrogate:v2026.05.05
```

开发 Docker 改动时，可以构建本地镜像：

```bash
docker build -t ferrogate .
```

如需自动 HTTPS，发布相关端口并挂载 ACME 存储：

```bash
docker run --rm \
  -p 80:80 \
  -p 443:443 \
  -v /etc/ferrogate/ferrogate.toml:/etc/ferrogate/ferrogate.toml:ro \
  -v /var/lib/ferrogate/acme:/var/lib/ferrogate/acme \
  -e FERROGATE_CONFIG=/etc/ferrogate/ferrogate.toml \
  ghcr.io/lianluo-esign/ferrogate:v2026.05.05
```

## 质量与安全

提交前运行本地门禁：

```bash
./scripts/security-check.sh
```

严格模式需要安装 cargo-deny 和 cargo-audit：

```bash
FERROGATE_SECURITY_REQUIRE_TOOLS=1 ./scripts/security-check.sh
```

安装供应链工具：

```bash
cargo install cargo-deny --version 0.19.4 --locked
cargo install cargo-audit --version 0.22.1 --locked
```

安全门禁会运行：

- `cargo fmt --check`
- `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- `cargo metadata --locked`
- 高置信度密钥扫描
- `cargo deny check licenses bans sources`
- `cargo audit`

已知剩余 audit 警告记录在 `.cargo/audit.toml` 和开发计划中。这些警告当前来自 Pingora 的传递依赖，并与 FerroGate 直接代码分开跟踪。

## 文档

- 项目路线图：[`docs/roadmap.md`](docs/roadmap.md)
- 性能测试指南：[`docs/performance-testing.md`](docs/performance-testing.md)
- TOML 示例配置：[`config/ferrogate.example.toml`](config/ferrogate.example.toml)
- 默认 Caddyfile 风格配置：[`Ferrogate/Caddyfile`](Ferrogate/Caddyfile)

内部开发计划笔记维护在产品仓库之外。

## 贡献

1. 保持变更小而可 review。
2. 遵循现有 Rust 模块边界和 Caddyfile adapter 风格。
3. 提 PR 前运行 `./scripts/security-check.sh`。
4. 当行为、配置、运维或架构发生变化时，同步更新公开产品文档。
5. 不要提交供应商密钥、ACME token、私钥或生成的证书。

## License

基于 Apache License, Version 2.0 授权。详见 [LICENSE](LICENSE)。
