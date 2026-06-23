<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-06-11
  description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
-->

# FerroGate

**语言：** [English](README.md) | 简体中文

FerroGate 是一个基于 Cloudflare Pingora 构建的开源 Rust API 网关和 AI
网关。它为团队提供一个可自托管的 AI 流量控制点，覆盖 OpenAI 兼容 API、
供应商路由、虚拟 API Key、策略检查、Token 计量、MCP/工具执行、显式 agent
run、WASM 沙箱化 agent 执行、可观测性、Admin API、集群运维和自动 HTTPS。

该项目也是 [Token4AI Cloud](https://token4ai.cloud) 背后的开源网关基础。

更完整的能力清单和当前实现状态见
[`docs/product-overview.zh-CN.md`](docs/product-overview.zh-CN.md)。

## 核心能力

- **OpenAI 兼容网关：** `GET /v1/models`、`POST /v1/chat/completions` 和
  `POST /v1/responses`，支持非流式和 SSE 流式转发。
- **供应商编排：** OpenAI-compatible API、OpenAI、Azure OpenAI、OpenRouter、
  Anthropic、Gemini、Grok/xAI，支持逻辑模型和 fallback 路由。
- **治理能力：** 虚拟 API Key、scope、租户上下文、allow/deny 规则、请求频率
  限制、Token 预算和 exact-match 响应缓存。
- **Agent 与工具流量：** MCP host/client、原生 `POST /v1/mcp` JSON-RPC 入口、
  显式 `POST /v1/agent-runs`、受治理的工具执行、插件注册、可选 WASM 沙箱执行和
  审计事件。
- **运维可见性：** 请求日志、usage/metering 事件、供应商健康、缓存/工具指标、
  agent run timeline、Prometheus、OTLP 导出、Admin API 和 Dashboard。
- **生产运维：** durable control-plane storage、analytics warehouse、reload/drain
  readiness、集群计数器、Docker、Kubernetes manifests、Helm chart 和 ACME HTTPS。

## 快速开始

前置条件：

- 与 workspace `rust-version` 兼容的 Rust toolchain。
- `cmake`、`g++`、`make` 和 `pkg-config`，用于 Pingora 原生依赖链。

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

发送 Responses API 请求：

```bash
curl -X POST http://127.0.0.1:8080/v1/responses \
  -H 'Authorization: Bearer dev-secret' \
  -H 'Content-Type: application/json' \
  -d '{"model":"fast-chat","input":"hello"}'
```

打开本地 Dashboard：

```text
http://127.0.0.1:8080/admin
```

## Agentic Gateway

FerroGate 支持显式 agent 流量，但不会把所有 AI 请求都变成 agent loop。普通
Chat Completions 和 Responses 请求保持原有行为；agent 执行需要通过
`POST /v1/agent-runs` 和运维侧 `[agent_runtime]` 配置显式开启。

已实现的 agentic gateway 能力包括：

- 带 max-turn 和 timeout 限制的有界 agent run。
- 默认 provider、外部进程 provider、以及基于 Wasmtime 的可配置 WASM provider。
- 默认拒绝的 WASM 执行边界，带 fuel/timeout 限制，没有默认 WASI、网络或文件系统
  权限；可显式开启 `ferrogate.log`、`ferrogate.state_get`、
  `ferrogate.state_set` 和 `ferrogate.tool_dispatch` host ABI。
- agent run 和 WASM host ABI 发起的工具调用仍走统一 gateway 治理链路：auth、
  scope、policy、approval、billing 和 audit evidence。
- durable `agent_run` / `agent_run_event` 记录，以及
  `GET /admin/v1/agent-runs` 和 `GET /admin/v1/agent-runs/{run_id}` timeline，
  用于查看 request、billing、audit、tool 和 run-event 证据。

## 配置

FerroGate 默认加载 `Ferrogate/Caddyfile`，也支持结构化 TOML 和 YAML 配置。

```bash
ferrogate run --config Ferrogate/Caddyfile
ferrogate run --config config/ferrogate.example.toml
```

最小 Caddyfile 风格 AI 网关配置：

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
        }

        api_key key_dev {
            key {$FERROGATE_DEV_KEY}
            scopes models.read chat.completions responses.create admin.read
            allowed_models fast-chat
            allowed_providers openai
        }
    }
}
```

主要配置入口：

- 默认开发配置：[`Ferrogate/Caddyfile`](Ferrogate/Caddyfile)
- 完整 TOML 示例：[`config/ferrogate.example.toml`](config/ferrogate.example.toml)
- Durable storage：[`docs/durable-storage.md`](docs/durable-storage.md)
- Analytics warehouse：[`docs/analytics-warehouse.md`](docs/analytics-warehouse.md)
- 集群部署：[`docs/cluster-deployment.md`](docs/cluster-deployment.md)

生产客户端密钥建议使用哈希形式：

```bash
ferrogate hash-key --secret 'your-client-secret'
```

## 核心模块

```text
crates/
  ferrogate-cli             CLI、Pingora runtime 接线、gateway handlers
  ferrogate-config          Caddyfile/TOML/YAML 配置模型与解析器
  ferrogate-providers       AI 供应商适配器与模型注册表
  ferrogate-auth            独立租户与 RBAC REST API 服务
  ferrogate-policy          策略决策模型与引擎
  ferrogate-storage         Repository trait 与控制面存储边界
  ferrogate-billing         Token usage metering 模型与本地事件保留
  ferrogate-observability   Metrics、spans、exporter contracts
  ferrogate-runtime         Reload、lifecycle、有界 agent harness、WASM sandbox
  ferrogate-mcp             MCP host/client 管理器与工具执行桥接
```

## Docker 与部署

使用已发布镜像并挂载配置：

```bash
docker run --rm \
  -p 8080:8080 \
  -v "$PWD/config/ferrogate.example.toml:/etc/ferrogate/ferrogate.toml:ro" \
  -e FERROGATE_CONFIG=/etc/ferrogate/ferrogate.toml \
  ghcr.io/lianluo-esign/ferrogate:<tag>
```

开发镜像内容时本地构建：

```bash
docker build -t ferrogate .
```

Kubernetes 示例和可选 Helm chart 分别位于
[`deploy/kubernetes/`](deploy/kubernetes/) 和 [`charts/ferrogate/`](charts/ferrogate/)。
验证命令：

```bash
scripts/check-kubernetes-examples.sh
helm template ferrogate charts/ferrogate
```

## Admin API

OpenAPI 3.1 文档位于
[`docs/openapi/admin-api.openapi.json`](docs/openapi/admin-api.openapi.json)。

常用 runtime 和 admin 入口：

```text
GET  /v1/models
POST /v1/chat/completions
POST /v1/responses
POST /v1/agent-runs
GET  /v1/tools
POST /v1/tools/execute
POST /v1/mcp
POST /v1/mcp/tool/execute
GET  /admin/v1/agent-runs
GET  /admin/v1/agent-runs/{run_id}
GET  /admin/v1/status
GET  /admin/v1/providers
GET  /admin/v1/provider-health
GET  /admin/v1/request-logs
GET  /admin/v1/metering-events
GET  /admin/v1/usage-aggregates
POST /admin/v1/config/validate
POST /admin/v1/config/reload
GET  /metrics
GET  /admin
```

## 质量与安全

提交前运行本地门禁：

```bash
./scripts/security-check.sh
```

严格模式需要 cargo-deny 和 cargo-audit：

```bash
FERROGATE_SECURITY_REQUIRE_TOOLS=1 ./scripts/security-check.sh
```

更轻量的本地检查：

```bash
cargo fmt --all -- --check
cargo metadata --locked --format-version=1
python3 scripts/check-openapi.py
git diff --check
```

## 文档

- 产品概览与状态：[`docs/product-overview.zh-CN.md`](docs/product-overview.zh-CN.md)
- Agent framework 兼容性：[`docs/agent-framework-compatibility.md`](docs/agent-framework-compatibility.md)
- Durable storage：[`docs/durable-storage.md`](docs/durable-storage.md)
- Analytics warehouse：[`docs/analytics-warehouse.md`](docs/analytics-warehouse.md)
- 集群部署：[`docs/cluster-deployment.md`](docs/cluster-deployment.md)
- Auth service contract：[`docs/auth-service-contract.md`](docs/auth-service-contract.md)
- 性能测试：[`docs/performance-testing.md`](docs/performance-testing.md)
- Roadmap：[`docs/roadmap.md`](docs/roadmap.md)

## 贡献

FerroGate 的协作模式默认面向人类维护者和 AI 编码代理共同开发。最好的贡献是
可 review、可测试、可从运维视角解释的 issue-linked 小切片。

适合参与的方向：

- Provider adapter、模型注册表、路由策略、fallback 和 streaming 正确性。
- Policy、虚拟 API Key、rate limit、token budget、metering、audit 和 request log 证据。
- MCP gateway、Agentic Lite tools、OpenAI-compatible client 兼容性和 agent framework 示例。
- Admin API、Dashboard 可见性、OpenAPI schema、配置校验、reload 行为和集群运维。
- 让已实现 runtime 路径真正可在生产使用的文档、示例和 runbook。

工作流：

1. 从 GitHub issue 开始。
2. 编辑前定义 end-to-end 证明：operator input、runtime path、failure behavior、
   admin/log/metric evidence 和聚焦回归测试。
3. 行为放回所属 crate，避免横跨边界的大重写。
4. Patch 保持窄、typed、可回滚，并尽量不新增依赖。
5. PR 写清验证命令和已知缺口。

AI agent 自主选 issue 和执行开发时，遵循
[`docs/dynamic-workflow.md`](docs/dynamic-workflow.md)。

## License

基于 Apache License, Version 2.0 授权。详见 [LICENSE](LICENSE)。
