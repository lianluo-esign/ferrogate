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
网关。它为团队提供一个可自托管的 AI 流量控制点：OpenAI 兼容与 Anthropic
原生 API、多供应商路由、虚拟 API Key、策略检查、由独立计费服务结算的
Token 计量、MCP/工具执行、显式 agent run 与定时调度、隔离的
`agent-worker` 执行（托管模式，或通过可验证 mTLS 接入的自托管
worker）、面向 agent 消费的资产托管闭环（含静态站点）、可观测性、Admin
API、集群运维和自动 HTTPS。

该项目也是 [Token4AI Cloud](https://token4ai.cloud) 背后的开源网关基础。

更完整的能力清单和当前实现状态见
[`docs/product-overview.zh-CN.md`](docs/product-overview.zh-CN.md)。

## 核心能力

- **多协议推理网关：** `GET /v1/models`、`POST /v1/chat/completions`、
  `POST /v1/responses`、Anthropic 原生 `POST /v1/messages`、
  `POST /v1/embeddings` 和 `POST /v1/images/generations`，支持非流式和
  SSE 流式转发。
- **供应商编排：** OpenAI-compatible API、OpenAI、Azure OpenAI、OpenRouter、
  Anthropic、Gemini、Grok/xAI，支持逻辑模型、fallback 路由，以及面向模型
  灰度发布的 canary 和 shadow/mirror 流量切分。附带可直接运行的
  [token4ai.cloud](https://token4ai.cloud) 示例
  （`config/ferrogate.token4ai.example.toml`），通过同一个 OpenAI 兼容
  适配器提供 gpt-5.5。
- **治理能力：** 虚拟 API Key、scope、租户上下文、allow/deny 规则、请求
  频率限制、带本地 tokenizer 预估的 Token 预算、面向精确金额扣费的钱包
  reserve/hold，以及 exact-match 加可选 semantic（向量相似度）响应缓存。
- **资产托管闭环：** 通过 `/v1/assets/*` 完成发布、治理、agent 消费 —
  版本化资产带 channel/semver 和平台 variant、签名与恶意软件扫描的
  供应链门禁、MCP `resources/*` 入口加内置 `fetch_asset` 工具供 agent
  消费、静态站点服务模式 `GET /sites/{tenant}/{site}/{path}`（含
  ETag/Range/304 缓存）、私有 S3 兼容 bucket（Supabase Storage）上的
  presigned 大文件路径、egress 计量/审计、retention/GC 生命周期策略，
  以及 `ferrogate assets` push/pull CLI。
- **服务拆分：** `ferrogate auth serve` 和 `ferrogate billing serve` 用同
  一个二进制把租户/RBAC 和 Token 用量结算作为独立 REST 服务运行，均可
  选用 durable Supabase 后端 —— 一个带死信追踪的 durable outbox 把结算
  用量从网关送到计费服务，不阻塞请求热路径。
- **Agent 与工具流量：** MCP host/client、基于 MCP 2026-07-28 规范的原生
  `POST /v1/mcp` JSON-RPC 入口、显式 `POST /v1/agent-runs`、带 Admin
  CRUD API 的 cron/interval agent 定时调度、对消息体做
  policy/guardrail/billing 的受治理 A2A 入口、受治理的工具执行、插件
  注册、Firecracker 后端的隔离 `agent-worker` 进程 —— 自托管 worker
  通过可验证 mTLS（控制面证书签发 + CRL 吊销）接入 —— 以及审计事件。
- **运维可见性：** 请求日志、usage/metering 事件、供应商健康、缓存/工具指标、
  agent run timeline、结构化 agent-run OTLP span、Prometheus、OTLP 导出、Admin API
  和 Dashboard。
- **生产运维：** durable control-plane storage、对请求日志和审计事件按租户
  TTL/清除的 retention 引擎、analytics warehouse、reload/drain readiness、
  集群计数器、Docker、Kubernetes manifests、Helm chart 和 ACME HTTPS。

## 快速开始

前置条件：

- 与 workspace `rust-version` 兼容的 Rust toolchain。
- `cmake`、`g++`、`make` 和 `pkg-config`，用于 Pingora 原生依赖链。

`ferrogate` 是单个二进制，用子命令选择运行哪个服务进程。下面的 `run`
启动 AI 网关本身；独立的 `auth serve` 和 `billing serve` 服务见
[服务拆分](#服务拆分)。

运行默认开发网关：

```bash
cargo run -- run --config Ferrogate/Caddyfile
```

`Ferrogate/Caddyfile` 自带一个模型（`fast-chat` → OpenAI 的
`gpt-4o-mini`）和一个开发 API Key（`dev-secret`，是真实的请求鉴权 ——
错误的 key 会被拒绝）。想拿到真实补全需要先设置 `OPENAI_API_KEY`；
不设置时请求仍会正确路由，并从 OpenAI 得到一个干净的 401。

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

在网关旁边运行计费服务，观察结算用量落入 durable ledger —— 两者是各自
独立的进程，用各自的子命令启动（完整说明包括 fail-closed 定价规则，见
[服务拆分](#服务拆分)）：

```bash
FERROGATE_BILLING_LISTEN=127.0.0.1:8092 cargo run -- billing serve &
TOKEN4AI_API_KEY=sk-... cargo run -- gateway --config config/ferrogate.token4ai.example.toml

curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'authorization: Bearer client-secret' -H 'content-type: application/json' \
  -d '{"model":"gpt-5.5","messages":[{"role":"user","content":"hello"}]}'

curl -s http://127.0.0.1:8092/v1/billing/ledger
```

## Agentic Gateway

FerroGate 支持显式 agent 流量，但不会把所有 AI 请求都变成 agent loop。普通
Chat Completions 和 Responses 请求保持原有行为；agent 执行通过 agent runtime、
upstream、workflow、skill、prompt 和 plugin 控制面显式开启。

已实现的 agentic gateway 能力包括：

- 通过 `/.well-known/agent.json` 做 agent discovery，并通过 `GET /v1/skills`
  和 `GET /v1/skills/{id}` 暴露可见 skill package。
- 受治理的 A2A-style agent upstream：支持 tenant/API-key 可见性、
  `agents.read`/`agents.invoke` scope、请求转发，以及 `message:stream` 路径的
  流式转发。
- 显式 `POST /v1/agent-runs` 执行，并带 max-turn 和 timeout 限制。
- managed agent runtime 默认指向外部 `agent-worker` 进程，由它负责
  Firecracker microVM 生命周期；gateway 只负责 policy、quota、template 选择、
  capability envelope 和 evidence 记录，不在请求 handler 中直接运行 microVM。
- 外部进程 provider 仅用于本地测试和 harness adapter；生产 managed execution
  应通过 `agent-worker` 和 Firecracker microVM 隔离来完成。
- 独立的 `agent-worker` 进程边界：负责 Firecracker microVM 生命周期、
  framework-handler adapter（Codex、Claude Code、Hermes），以及经网关授权
  的 CLI、tool、MCP tool、skill、memory、secret、network-egress、browser、
  REST 和 filesystem 动作的受治理执行。`--worker-type cloud|self-hosted`
  在同一个二进制上选择信任/执行策略；自托管 worker 以 report-only 模式
  执行已覆盖的命令族，通过可验证 mTLS（单一显式 issuing CA、控制面证书
  签发、轮换和 CRL 吊销）连接网关生产入口，并通过
  `/v1/self-hosted-workers/*` 拉取派发的 run。详见
  [`docs/security/self-hosted-mtls-transport.md`](docs/security/self-hosted-mtls-transport.md)。
- 时间触发的 agent 定时调度：cron/interval 触发器把 `agent_run` 目标发进
  自托管 worker 拉取的同一个 dispatch lease queue，通过
  `/admin/v1/agent-schedules` 的 CRUD、`run-now` 和每个 schedule 的触发
  历史来管理。
- Workflow graph policy：支持 model/tool node、edge condition、model-call 与
  tool-call budget、token budget、iteration limit、counter 和 runtime timeline。
- Skill package 可以声明可见 capability，并 materialize 自有 plugin、tool、MCP
  server、prompt template 和 workflow。
- Versioned prompt template 支持经审计的 `POST /v1/prompts/{id}/render`，输出
  Chat Completions 或 Responses request body。
- Plugin registration 和 plugin-owned tool exposure 支持 permission、approval
  policy、secret redaction、lifecycle status 和 Admin API inspection。
- agent run 发起的工具调用仍走统一 gateway 治理链路：auth、scope、policy、
  approval、billing 和 audit evidence。
- durable `agent_run` / `agent_run_event` 记录，以及
  `GET /admin/v1/agent-runs` 和 `GET /admin/v1/agent-runs/{run_id}` timeline，
  用于查看 request、billing、audit、tool 和 run-event 证据。
- agent run timeline 会导出为结构化 OTLP trace，包含 `ferrogate.agent.run`、
  provider-step、billing-write、audit/tool 和 runtime lifecycle span，并保留 W3C
  trace context 以便外部链路关联。

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

## 服务拆分

`ferrogate` 是一个带子命令的单一二进制，用子命令选择运行哪个服务进程，
而不是每个服务一个二进制：

- `ferrogate run`（别名 `gateway`）—— Pingora AI 网关。
- `ferrogate auth serve` —— 租户/RBAC REST API，可选用 Supabase 持久化
  虚拟 API Key。见 [`docs/auth-service-contract.md`](docs/auth-service-contract.md)。
- `ferrogate billing serve` —— Token 用量定价与 ledger REST API，默认
  内存存储，可用 `--supabase-dsn` 持久化。
- `ferrogate storage migrate-to-supabase` —— 一次性把遗留 Postgres 控制面
  状态迁移到 Supabase。

用 `[billing_service]` 配置段（`enabled`、`endpoint`、`timeout_millis`、
可选 `token`/`token_env`）把网关指向运行中的计费服务。开启后，除非每个
模型（含 fallback 路由）都带 `input_price_per_1m`/`output_price_per_1m`，
配置校验会 fail-closed，确保月度预算控制不会和计费服务自己的 ledger
静默偏离。网关随后以 fire-and-forget 方式向计费服务上报每笔结算用量
—— 计费往返永不阻塞请求热路径 —— 失败时由带死信追踪的 durable outbox
重投。

用 token4ai.cloud（gpt-5.5）示例体验完整闭环：

```bash
FERROGATE_BILLING_LISTEN=127.0.0.1:8092 cargo run -- billing serve
TOKEN4AI_API_KEY=sk-... cargo run -- gateway --config config/ferrogate.token4ai.example.toml

curl -s http://127.0.0.1:8080/v1/chat/completions \
  -H 'authorization: Bearer client-secret' -H 'content-type: application/json' \
  -d '{"model":"gpt-5.5","messages":[{"role":"user","content":"hello"}]}'

curl -s http://127.0.0.1:8092/v1/billing/ledger
```

注意 `GET /v1/billing/ledger` 属于独立计费服务自己的端口（上例中的
`8092`），不属于网关的 `/admin` 或 `/v1` 面。

管理控制台（`admin-console/`）是第四个独立部署物：一个静态 React SPA，
不是 `ferrogate` 子命令。它调用 `ferrogate auth serve` 的 `/v1/admin/*`
做登录/注册，其余全部走网关的 `/admin/v1/*`，两者都是跨域调用，所以都
需要为控制台的来源配置 CORS（auth 服务的 `--cors-allowed-origin` /
`FERROGATE_AUTH_CORS_ALLOWED_ORIGIN`，以及网关的
`admin.cors_allowed_origin` 配置项）。本地运行方式见
[`admin-console/README.md`](admin-console/README.md)。

## 核心模块

```text
crates/
  agent-worker              隔离 agent 执行的独立进程：Firecracker microVM、
                             framework-handler adapter、受治理的
                             CLI/tool/MCP/browser/REST/filesystem 动作
  ferrogate-admin           未来独立 admin-API 服务的脚手架；尚未接入任何二进制
  ferrogate-auth            独立租户与 RBAC REST API 服务
  ferrogate-billing         独立计费服务：rate card、ledger 记账、durable
                             outbox 投递
  ferrogate-cli             CLI、Pingora runtime 接线、gateway/auth/billing/
                             storage 子命令、gateway handlers
  ferrogate-config          Caddyfile/TOML/YAML 配置模型与解析器
  ferrogate-core            跨 crate 共享的领域原语（租户/请求上下文、工具
                             定义、错误类型）
  ferrogate-mcp             MCP host/client 管理器与工具执行桥接
  ferrogate-observability   Metrics、spans、exporter contracts
  ferrogate-policy          策略决策模型与引擎
  ferrogate-providers       AI 供应商适配器与模型注册表
  ferrogate-routing         未来共享路由匹配边界的脚手架；runtime 尚未使用
  ferrogate-runtime         Reload、lifecycle、有界 harness、managed worker
                             isolation
  ferrogate-storage         Repository trait 与控制面存储边界（in-memory、
                             Postgres、Supabase）
tools/
  ferrogate-test            端到端测试 harness，本地或 Docker 驱动
                             admin/auth/gateway/billing/storage 场景

admin-console/               独立管理控制台前端（Vite + React + TypeScript +
                             Tailwind + shadcn/ui），覆盖完整 Admin API 面；
                             不是 `ferrogate` 子命令
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

这些 manifest 目前只部署网关进程（`ferrogate run`）单容器。独立的计费
和 auth 服务（`ferrogate billing serve` / `ferrogate auth serve`，见
[服务拆分](#服务拆分)）在同一镜像里，但还没有作为并列 deployment 模板化
—— 在此之前请把它们作为独立 workload 运行，网关用 `[billing_service]`
配置和 auth contract 指向它们。

### 管理控制台

管理控制台前端以独立镜像发布，由 `admin-console/Dockerfile` 构建
（nginx 提供的静态 SPA —— 不在主 `ferrogate` 镜像内）：

```bash
docker build -t ferrogate-admin-console admin-console/
docker run --rm -p 8081:8080 \
  -e AUTH_BASE_URL=https://auth.ferrogate.example.com \
  -e GATEWAY_ADMIN_BASE_URL=https://ferrogate.example.com \
  ferrogate-admin-console
```

`AUTH_BASE_URL`/`GATEWAY_ADMIN_BASE_URL` 由镜像的 nginx entrypoint 在容器
启动时渲染进 `env-config.js`（见
[`admin-console/README.md`](admin-console/README.md)），所以同一个镜像可以
跨环境使用而无需重建 —— 这一点不同于本地 `npm run dev` 使用的 Vite
构建期环境变量 `VITE_AUTH_BASE_URL`/`VITE_GATEWAY_ADMIN_BASE_URL`。

它有自己的 Kubernetes manifest
（[`deploy/kubernetes/admin-console.yaml`](deploy/kubernetes/admin-console.yaml)）
和可选、默认关闭的 Helm 组件（在
[`charts/ferrogate/values.yaml`](charts/ferrogate/values.yaml) 中设
`adminConsole.enabled: true`）—— 两者都被上面的
`scripts/check-kubernetes-examples.sh` / `helm template` 验证覆盖。

## Admin API

OpenAPI 3.1 文档位于
[`docs/openapi/admin-api.openapi.json`](docs/openapi/admin-api.openapi.json)。

以下是代表性子集 —— 完整 API 面以 OpenAPI 文档为准，还包括虚拟 API
Key、配额策略、自托管 worker 注册、MCP server/插件 CRUD、租户/项目/
workspace 管理等：

```text
GET  /healthz
GET  /readyz
GET  /v1/models
POST /v1/chat/completions
POST /v1/responses
POST /v1/messages
POST /v1/embeddings
POST /v1/images/generations
POST /v1/agent-runs
GET  /.well-known/agent.json
GET  /v1/skills
GET  /v1/skills/{id}
POST /v1/prompts/{id}/render
GET  /v1/tools
POST /v1/tools/execute
POST /v1/mcp
POST /v1/mcp/tool/execute
POST /v1/functions/execute
GET  /v1/assets
GET/PUT/DELETE /v1/assets/{asset_type}/{name}/{version}
POST /v1/assets/presign/upload/{asset_type}/{name}/{version}
POST /v1/assets/presign/commit/{asset_type}/{name}/{version}
GET  /v1/assets/presign/download/{asset_type}/{name}/{version}
GET  /sites/{tenant}/{site}/{path}
POST /v1/self-hosted-workers/heartbeat
POST /v1/self-hosted-workers/runs/poll
GET  /admin/v1/agent-runs
GET  /admin/v1/agent-runs/{run_id}
GET  /admin/v1/agent-upstreams
GET  /admin/v1/agent-upstreams/{id}
GET  /admin/v1/agent-workflows
GET  /admin/v1/agent-workflows/{id}
GET  /admin/v1/skill-packages
GET  /admin/v1/skill-packages/{id}
GET  /admin/v1/prompt-templates
GET  /admin/v1/prompt-templates/{id}
GET  /admin/v1/plugins
GET  /admin/v1/plugins/{plugin_id}
GET  /admin/v1/plugins/{plugin_id}/tools
GET  /admin/v1/virtual-keys
GET  /admin/v1/quota-policies
GET/POST /admin/v1/agent-schedules
POST /admin/v1/agent-schedules/{id}/run-now
GET  /admin/v1/agent-schedules/{id}/fires
GET  /admin/v1/self-hosted-workers
GET  /admin/v1/status
GET  /admin/v1/providers
GET  /admin/v1/provider-health
GET  /admin/v1/request-logs
GET  /admin/v1/audit-events
GET  /admin/v1/metering-events
GET  /admin/v1/billing-events
GET  /admin/v1/usage-aggregates
GET  /admin/v1/usage-reports
GET  /admin/v1/billing-outbox-dead-letters
GET/POST /admin/v1/drain
POST /admin/v1/config/validate
POST /admin/v1/config/reload
GET  /metrics
GET  /admin
```

独立计费服务（`ferrogate billing serve`）在自己的监听地址上暴露
`GET /v1/billing/ledger` 和 `POST /v1/billing/charge` —— 这些是计费服务
路由，不是网关路由。

## 质量与安全

提交前运行本地门禁：

```bash
./scripts/security-check.sh
```

严格模式需要 cargo-deny 和 cargo-audit，也是 CI 对每个变更强制执行的
门禁（见 [`.github/workflows/rust-quality.yml`](.github/workflows/rust-quality.yml)）：

```bash
FERROGATE_SECURITY_REQUIRE_TOOLS=1 ./scripts/security-check.sh
```

漏洞披露流程见 [`SECURITY.md`](SECURITY.md)；已实现安全能力的控制族映射见
[`docs/security-controls.md`](docs/security-controls.md)。

更轻量的本地检查：

```bash
cargo fmt --all -- --check
cargo metadata --locked --format-version=1
python3 scripts/check-openapi.py
git diff --check
```

## 文档

- 产品概览与状态：[`docs/product-overview.zh-CN.md`](docs/product-overview.zh-CN.md)
- Agentic gateway 架构：[`docs/agentic-gateway-architecture.md`](docs/agentic-gateway-architecture.md)
- Agent framework 兼容性：[`docs/agent-framework-compatibility.md`](docs/agent-framework-compatibility.md)
- Agent worker 协议：[`docs/agent-worker-protocol.md`](docs/agent-worker-protocol.md)
- Durable storage：[`docs/durable-storage.md`](docs/durable-storage.md)
- Analytics warehouse：[`docs/analytics-warehouse.md`](docs/analytics-warehouse.md)
- 集群部署：[`docs/cluster-deployment.md`](docs/cluster-deployment.md)
- Auth service contract：[`docs/auth-service-contract.md`](docs/auth-service-contract.md)
- 性能测试：[`docs/performance-testing.md`](docs/performance-testing.md)
- 安全控制：[`docs/security-controls.md`](docs/security-controls.md)
- Guardrail 调查视图（被拦截请求的 who/why/target/action/cost）：[`docs/guardrails/investigation-view.md`](docs/guardrails/investigation-view.md)
- 供应链验证（SBOM、cosign 签名、provenance）：[`docs/security/supply-chain.md`](docs/security/supply-chain.md)
- Agent 沙箱安全模型：[`docs/security/agent-sandbox-model.md`](docs/security/agent-sandbox-model.md)
- 自托管 worker mTLS 传输：[`docs/security/self-hosted-mtls-transport.md`](docs/security/self-hosted-mtls-transport.md)
- 私有资产 bucket 迁移 runbook：[`docs/assets/private-bucket-migration.md`](docs/assets/private-bucket-migration.md)
- SOC 2 审计范围：[`docs/soc2-audit-scoping.md`](docs/soc2-audit-scoping.md)
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
