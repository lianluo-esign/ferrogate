# FerroGate

**语言：** [English](README.md) | 简体中文

FerroGate 是一个基于 Cloudflare Pingora 构建的开源 Rust API 网关和 AI 网关。它为团队提供一个可自托管的 LLM 流量控制点，覆盖路由、虚拟 API Key、供应商适配、exact-match 响应缓存、MCP 工具执行、策略检查、Token 用量计费、可观测性、Admin API、集群运维和自动 HTTPS。

该项目也是 [Token4AI Cloud](https://token4ai.cloud) 背后的开源网关基础。

## FerroGate 提供什么

- **Pingora 网关运行时**：支持 HTTP 反向代理、路由匹配、上游池、路径和 Header 重写、请求 ID、Trace ID、流式响应、优雅关闭，以及监听器级别的优雅升级。
- **OpenAI 兼容 AI API**：支持 `GET /v1/models`、`POST /v1/chat/completions` 和 `POST /v1/responses`，包含非流式与 SSE 流式转发。
- **供应商适配器**：支持 OpenAI-compatible API、OpenAI、Azure OpenAI、OpenRouter、Anthropic、Gemini 和 Grok/xAI。
- **模型注册表与 fallback 路由**：支持逻辑模型名、供应商模型映射、优先级 fallback、加权 fallback、最低成本、最低延迟、balanced routing、租户可见性，以及供应商 allow/deny 控制。
- **Exact-match AI 响应缓存**：支持非流式请求缓存，并提供全局、模型、API Key 级别启用控制。缓存键包含租户上下文、路由、逻辑模型、供应商路由/模型和规范化请求体。
- **MCP Gateway**：通过 `ferrogate-mcp` 作为 MCP host/client，支持 streamable HTTP、SSE 和 stdio server session，启动时执行 `initialize` 与 `tools/list`，以 `serverName-toolName` 暴露工具，执行默认 deny-by-default，并接入策略目标、Admin 可见性、健康检查、重连和 `POST /v1/mcp/tool/execute`。
- **Agentic Lite 扩展面**：支持内置 request hook、tool provider、event sink、`GET /v1/tools`、`POST /v1/tools/execute`、Admin tool session 视图和审计事件。
- **Caddy 风格配置兼容**：通过解析 `Ferrogate/Caddyfile` 支持熟悉的反向代理路由、匹配器、TLS、日志和网关设置，同时也支持结构化 TOML 配置。
- **虚拟 API Key 与策略检查**：支持哈希 Key、租户上下文、Scope、禁用或过期 Key、模型和供应商白名单/黑名单、最小化 deny-rule 策略评估、请求频率限制和 Token 预算。
- **Token 用量与计费事件**：优先使用供应商返回的 usage；缺失时由网关估算；并提供面向生产 AI 网关的请求预留与结算流程。
- **可观测性**：包括结构化请求日志、计费事件、可配置 in-memory retention、用量聚合、供应商健康、缓存指标、MCP 工具指标、Prometheus 指标、请求/Trace ID 传播，以及 OTLP/HTTP metrics/logs/traces 导出。
- **Admin API 与 Dashboard**：查看网关状态、供应商、模型、API Key、租户、策略、请求日志、计费事件、用量聚合、审计事件、供应商健康状态、扩展、工具、MCP server、配置验证、进程内 reload 和节点 drain/readiness。
- **集群运维**：支持多节点部署的节点身份、共享文件控制面状态、Redis 请求/Token 计数器、状态、readiness 和 drain 语义。
- **自动 HTTPS**：支持手动 TLS、ACME HTTP-01、内置 Cloudflare provider 的 ACME DNS-01、续期调度，以及需要监听器级 TLS reload 时的 graceful-upgrade handoff。ACME provider 凭据从 FerroGate 配置文件读取，不依赖环境变量或 Python 脚本。
- **供应链与安全门禁**：包含格式化、clippy、锁定元数据、高置信度密钥扫描、cargo-deny、cargo-audit 和 GitHub Actions。

## 当前状态

开源网关实现已经覆盖自托管第一版生产切片需要的核心 API 网关、AI 网关、治理、工具执行、可观测性、TLS 和集群运维能力。

已完成端到端验证：

- 基于 Pingora 的 HTTP 反向代理运行时。
- OpenAI 兼容 Chat Completions 和 Responses API 路径。
- 供应商适配器，以及 priority、weighted、cost、latency、balanced 路由。
- 虚拟 API Key 鉴权、策略检查、频率限制和 Token 预算处理。
- 非流式 AI 请求的 exact-match 响应缓存。
- Agentic Lite tools 和 MCP gateway 执行，并经过鉴权、策略、计费、审计和指标链路。
- 请求日志、计费事件、用量聚合、供应商健康、缓存指标、MCP 工具指标、Prometheus 和 OTLP 导出。
- Admin API、API Key 和 policy CRUD、静态 Dashboard、配置验证、进程内 reload、status、readiness 和 drain。
- 手动 TLS、ACME HTTP-01、ACME DNS-01、续期调度和监听器级 graceful upgrade handoff。
- 集群身份、共享文件状态、Redis 计数器、readiness 和 drain runbook。
- 在真实 Let's Encrypt staging 与 production 环境中完成 HTTP-01 和 Cloudflare DNS-01 的签发验证。

仍有意留作下一阶段生产工作的范围：

- API Key、租户、策略、计费、请求日志、审计日志和多节点控制面状态的 durable database-backed 存储实现。当前运行时状态主要由配置、共享文件状态、Redis 计数器和内存 repository 驱动。
- 当前 API key、policy、配置验证、reload 和 drain 资源之外的完整 Admin API 写控制面。
- Semantic/vector cache matching。当前已实现的缓存是 exact-match。
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
  ferrogate-mcp             MCP host/client 管理器与工具执行桥接
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

发送 OpenAI 兼容 Responses API 请求：

```bash
curl -X POST http://127.0.0.1:8080/v1/responses \
  -H 'Authorization: Bearer dev-secret' \
  -H 'Content-Type: application/json' \
  -d '{"model":"fast-chat","input":"hello"}'
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

[telemetry]
access_log = "error"
access_log_sample_rate = 100
access_log_error_rate_limit_per_sec = 100

[metering]
export_enabled = false
export_endpoint = "https://api.token4ai.cloud/v1/metering/events"
# export_token_env = "FERROGATE_METERING_TOKEN"

[storage]
request_log_retention_records = 10000
audit_event_retention_records = 10000
billing_event_retention_records = 10000
admin_list_default_limit = 100
admin_list_max_limit = 1000

[cache]
enabled = true
mode = "exact_match"
ttl_secs = 300
max_records = 1000

[reliability]
provider_circuit_breaker_failure_threshold = 3
provider_circuit_breaker_cooldown_secs = 30
provider_dispatch_timeout_secs = 10
provider_dispatch_max_retries = 1
provider_response_body_max_bytes = 16777216
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
cache_enabled = true

[[api_keys]]
id = "dev"
key = "dev-secret"
scopes = ["models.read", "tools.read", "tools.execute", "chat.completions", "responses.create", "admin.read"]
allowed_models = ["fast-chat"]
allowed_providers = ["openai", "mcp:github"]
request_limit_per_minute = 60
monthly_token_budget = 1000000
cache_enabled = true

[[mcp_servers]]
name = "github"
transport = "streamable_http"
url = "http://127.0.0.1:9000/mcp"
auth_type = "headers"
tools_to_execute = ["search"]
tools_to_auto_execute = ["search"]
tool_include = ["search"]
timeout_ms = 3000

[[mcp_servers.headers]]
name = "Authorization"
value_env = "GITHUB_MCP_TOKEN"

[[policies]]
name = "deny dev MCP search"
effect = "deny"
enabled = false
api_key_ids = ["dev"]
models = ["mcp_tool:github-search"]
providers = ["mcp:github"]
message = "MCP search is blocked for this key"
```

第一版缓存模式是 `exact_match`。FerroGate 只缓存非流式 AI 响应，并要求租户上下文、路由、逻辑模型、供应商路由/模型和规范化 JSON 请求体完全一致。Semantic/vector cache matching 不属于当前第一版。

`[[mcp_servers]]` 让 FerroGate 成为 MCP host/client。每个 server 会在启动或 reload 时建立长连接 session，执行 `initialize` 与 `tools/list`，并在后台做健康检查。工具名以 `serverName-toolName` 暴露，例如上面的 server 会暴露 `github-search`。执行默认 deny-by-default：每个 server 必须声明 `tools_to_execute`，并且 `POST /v1/mcp/tool/execute` 仍然经过网关鉴权、策略、计费和可观测性链路。策略目标使用 `models = ["mcp_tool:github-search"]` 和 `providers = ["mcp:github"]`。

生产环境建议使用 `ferrogate hash-key` 生成的 `key_hash`，不要使用明文开发 Key。

```bash
ferrogate hash-key --secret 'your-client-secret'
```

多节点集群模式下，设置 `cluster.counter_backend = "redis"` 和 `cluster.redis_url` 可以让 API Key 请求频率限制和 Token 预算预留/结算在多个网关副本之间一致。Redis 计数器是 fail-closed：计数后端不可用时，受治理保护的 AI 请求会返回治理后端错误，而不是降级成单进程计数器。

完整的 Kubernetes-first、但不限定 Kubernetes 的集群部署契约，包括 readiness、drain、共享状态、Redis 计数器和非 Kubernetes 路径，见 [Cluster Deployment](docs/cluster-deployment.md)。

### OpenRouter Provider

OpenRouter 是一等 provider kind，复用 OpenAI 兼容的 Chat Completions 和 Responses API dispatch 路径。

```toml
[[providers]]
name = "openrouter"
kind = "openrouter"
base_url = "https://openrouter.ai/api/v1"
api_key_env = "OPENROUTER_API_KEY"
openrouter_http_referer = "https://example.com"
openrouter_x_title = "Example FerroGate"

[[models]]
name = "router-chat"
provider = "openrouter"
provider_model = "openai/gpt-4o-mini"
capabilities = ["chat", "streaming"]
```

可选的 `openrouter_http_referer` 和 `openrouter_x_title` 会作为 `HTTP-Referer` 和 `X-Title` header 发送给上游。它们不是客户端 API Key，也不能替代 `api_key_env`。

Caddyfile 风格 provider 配置支持同样字段：

```caddyfile
ai_gateway {
    provider openrouter {
        kind openrouter
        base_url https://openrouter.ai/api/v1
        api_key {env.OPENROUTER_API_KEY}
        openrouter_http_referer https://example.com
        openrouter_x_title Example FerroGate
    }

    model router-chat -> openrouter:openai/gpt-4o-mini {
        capabilities chat streaming
    }
}
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
renewal_window_secs = 2592000
renewal_check_interval_secs = 43200
renewal_retry_interval_secs = 1800
auto_graceful_reload = true
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
renewal_window_secs = 2592000
renewal_check_interval_secs = 43200
renewal_retry_interval_secs = 1800
auto_graceful_reload = true
```

Caddyfile 风格 DNS-01：

```caddyfile
api.example.com {
    tls {
        issuer acme {
            email ops@example.com
        }
        storage /var/lib/ferrogate/acme-dns
        renewal_window_secs 2592000
        renewal_check_interval_secs 43200
        renewal_retry_interval_secs 1800
        auto_graceful_reload true
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

启用 ACME 后，FerroGate 会在启动证书签发或从缓存加载后启动后台续期循环。当 leaf 证书进入 `renewal_window_secs` 窗口时开始续期；失败会记录并在 `renewal_retry_interval_secs` 后重试；当前证书过期时间和最近一次续期结果会暴露在 `GET /admin/v1/status`。

当前 Pingora runtime 使用 Rustls listener。续期后的证书文件需要 listener-level reload 才会被新的 TLS handshake 使用。如果 `auto_graceful_reload = true`，并且配置了 `reliability.graceful_upgrade_pid_file` 与 `reliability.graceful_upgrade_sock`，FerroGate 会在成功续期后触发 graceful-upgrade reload 路径。否则 Admin status 会报告 `reload_required: true` 和 `reload_mode: "listener-level-required"`，由 operator 执行 `ferrogate reload --graceful-upgrade`。

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
GET  /v1/models
GET  /v1/tools
POST /v1/tools/execute
POST /v1/mcp/tool/execute
POST /v1/chat/completions
POST /v1/responses
GET  /admin/v1/status
GET  /admin/v1/providers
GET  /admin/v1/provider-health
GET  /admin/v1/extensions
GET  /admin/v1/tools
GET  /admin/v1/mcp-servers
GET  /admin/v1/tool-sessions/{session_id}
GET  /admin/v1/models
GET  /admin/v1/api-keys
GET  /admin/v1/api-keys/{id}
POST /admin/v1/api-keys
PUT  /admin/v1/api-keys/{id}
DELETE /admin/v1/api-keys/{id}
GET  /admin/v1/tenants
GET  /admin/v1/policies
GET  /admin/v1/policies/{name}
POST /admin/v1/policies
PUT  /admin/v1/policies/{name}
DELETE /admin/v1/policies/{name}
GET  /admin/v1/request-logs
GET  /admin/v1/metering-events
GET  /admin/v1/billing-events
GET  /admin/v1/usage-aggregates
GET  /admin/v1/audit-events
POST /admin/v1/config/validate
POST /admin/v1/config/reload
GET  /admin/v1/drain
POST /admin/v1/drain
DELETE /admin/v1/drain
GET  /metrics
GET  /admin
```

配置了 API Key 时，读端点需要 `admin.read`。工具列表需要 `tools.read`，显式工具执行需要 `tools.execute`，Chat Completions 需要 `chat.completions`，Responses API 请求需要 `responses.create`，配置验证和 reload 需要 `admin.write`。

## Docker

稳定版本使用日期版本号，例如 `v2026.06.06`。

拉取 GitHub Packages 发布镜像，并挂载配置运行：

```bash
docker pull ghcr.io/lianluo-esign/ferrogate:v2026.06.06

docker run --rm \
  -p 8080:8080 \
  -v "$PWD/config/ferrogate.example.toml:/etc/ferrogate/ferrogate.toml:ro" \
  -e FERROGATE_CONFIG=/etc/ferrogate/ferrogate.toml \
  ghcr.io/lianluo-esign/ferrogate:v2026.06.06
```

开发 Docker 改动时，可以构建本地镜像：

```bash
docker build -t ferrogate .
```

如果运行两个或更多 Docker、VM、ECS/Fargate、Nomad 或 Kubernetes 副本，请跟随集群部署 runbook，而不是只依赖 Docker 保证网关状态一致性。Docker 只运行进程；FerroGate cluster mode 负责共享状态 revision、readiness、drain 和分布式计数器。

如需自动 HTTPS，发布相关端口并挂载 ACME 存储：

```bash
docker run --rm \
  -p 80:80 \
  -p 443:443 \
  -v /etc/ferrogate/ferrogate.toml:/etc/ferrogate/ferrogate.toml:ro \
  -v /var/lib/ferrogate/acme:/var/lib/ferrogate/acme \
  -e FERROGATE_CONFIG=/etc/ferrogate/ferrogate.toml \
  ghcr.io/lianluo-esign/ferrogate:v2026.06.06
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
- 集群部署指南：[`docs/cluster-deployment.md`](docs/cluster-deployment.md)
- Admin API OpenAPI：[`docs/openapi/admin-api.openapi.json`](docs/openapi/admin-api.openapi.json)
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
