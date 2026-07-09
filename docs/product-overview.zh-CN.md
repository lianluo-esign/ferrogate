# FerroGate 产品概览

这个页面承接 README 首页之外的较长产品说明。这里应该只描述已经实现或明确
追踪的能力；路线图内容放在 [`roadmap.md`](roadmap.md)。

## FerroGate 提供什么

- **Pingora 网关运行时**：HTTP 反向代理、路由匹配、上游池、路径/Header
  重写、请求 ID、Trace ID、流式响应、优雅关闭和监听器级 graceful upgrade。
- **OpenAI 兼容 AI API**：`GET /v1/models`、`POST /v1/chat/completions` 和
  `POST /v1/responses`，支持非流式和 SSE 流式转发。
- **供应商适配器**：OpenAI-compatible API、OpenAI、Azure OpenAI、OpenRouter、
  Anthropic、Gemini 和 Grok/xAI。
- **模型注册表与 fallback 路由**：逻辑模型名、供应商模型映射、priority
  fallback、weighted fallback、最低成本、最低延迟、balanced routing、租户可见性
  和供应商 allow/deny 控制。
- **Exact-match AI 响应缓存**：支持非流式请求，并提供全局、模型、API Key
  级别启用控制。
- **MCP gateway**：通过 `ferrogate-mcp` 支持 streamable HTTP、SSE、stdio
  session、`initialize`、`tools/list`、命名空间工具、默认拒绝的执行 allowlist、
  健康检查、重连和受治理的工具执行。
- **原生 MCP JSON-RPC 入口**：`POST /v1/mcp` 支持 `initialize`、`ping`、
  `tools/list` 和 `tools/call`。
- **Agentic Lite 插件面**：用于治理 capability bundle、tool provider、event
  sink、权限声明、tool session、Admin 视图和审计事件。
- **Agent runtime 与 skill package surface**：支持 agent discovery、受治理的
  agent upstream、bounded run、workflow counter/timeline，以及 skill-owned plugin、
  tool、MCP server、prompt template 和 workflow。
- **Caddy 风格配置兼容**：支持 `Ferrogate/Caddyfile`，同时支持结构化 TOML 和 YAML。
- **虚拟 API Key 与策略检查**：哈希 key、租户上下文、scope、禁用/过期 key、
  模型/供应商 allowlist 和 denylist、deny-rule evaluation、请求频率限制和 Token
  预算。
- **Token usage metering events**：优先使用供应商返回的 usage，缺失时由网关估算。
- **可观测性**：结构化请求日志、token metering event、可配置 retention、usage
  aggregate、供应商健康、缓存指标、MCP 工具指标、agent-run OTLP span、Prometheus、
  请求/Trace ID 传播和 OTLP/HTTP 导出。
- **Admin API 与 Dashboard**：状态、供应商、模型目录发现、已配置模型、API
  Key、租户、策略、请求日志、agent run timeline、metering event、aggregate、审计事件、
  gateway config profile、供应商健康、plugin/extension、tool、MCP server、配置验证、
  reload、readiness 和 drain。
- **Durable control-plane storage**：以 Supabase-compatible PostgreSQL 作为生产
  控制面目标，同时保留 memory、PostgreSQL、PostgreSQL TLS 兼容 provider。遗留
  Turso/libSQL 配置只作为迁移输入，不再作为新的生产 provider 选择；MySQL 已
  彻底退出，不再保留任何迁移工具。
- **Analytics delivery boundary**：支持 Vector-to-ClickHouse pipeline mode 或
  direct ClickHouse warehouse mode。
- **集群运维**：多节点部署的节点身份、共享文件控制面状态、Redis 请求和 Token
  计数器、状态、readiness 和 drain 语义。
- **自动 HTTPS**：手动 TLS、ACME HTTP-01、内置 Cloudflare provider 的 ACME DNS-01、
  续期调度，以及监听器级 TLS reload 需要时的 graceful-upgrade handoff。
- **供应链与安全门禁**：格式化、clippy、locked metadata、高置信度密钥扫描、
  cargo-deny、cargo-audit 和 GitHub Actions。

## 当前状态

开源网关实现已经覆盖自托管第一版生产切片需要的核心 API 网关、AI 网关、治理、
工具执行、可观测性、TLS、durable storage、analytics 和集群运维能力。

已完成端到端验证：

- 基于 Pingora 的 HTTP 反向代理运行时。
- OpenAI 兼容 Chat Completions 和 Responses API 路径。
- Responses 请求中 text、image、tool definitions、tool choice 和 tool-call input
  shape 在供应商路径中的规范映射。
- OpenAI-compatible 客户端通过 FerroGate `base_url`、虚拟 API key、逻辑模型、
  请求日志、metering event 和 Prometheus model/provider 指标接入。
- 供应商适配器，以及 priority、weighted、cost、latency、balanced 路由。
- 虚拟 API Key 鉴权、策略检查、频率限制和 Token 预算处理。
- 非流式 AI 请求的 exact-match 响应缓存。
- Agentic Lite tools 和 MCP gateway 执行，并经过鉴权、策略、计费、审计和指标链路。
- `POST /v1/mcp` 原生 MCP JSON-RPC 入口。
- Agent discovery、A2A-style agent upstream invocation/streaming、bounded agent
  run、workflow graph execution、workflow budget、tool-call limit、immutable
  approval/audit evidence 和 agent run timeline。
- agent run timeline 会导出为可重建的 OTLP trace tree，包含 agent root、
  provider-step、billing-write、audit/tool 和 runtime lifecycle span。
- Plugin registration、plugin-owned tool exposure、skill package compatibility
  metadata 和 skill-owned resource materialization。
- 请求日志、token metering event、usage aggregate、供应商健康、缓存指标、MCP 工具
  指标、Prometheus、支持 W3C 关联的 agent-run OTLP export 和 ClickHouse analytics。
- Admin API、API key 和 policy CRUD、静态 Dashboard、配置验证、reload、status、
  readiness 和 drain。
- 以 Supabase-compatible PostgreSQL TLS 为默认生产目标的控制面重启行为，同时保留
  PostgreSQL、PostgreSQL TLS 作为兼容和本地测试 provider。遗留 Turso/libSQL
  数据仍是迁移来源；MySQL 已彻底退出。
- 手动 TLS、ACME HTTP-01、ACME DNS-01、续期调度和监听器级 graceful upgrade handoff。
- 集群身份、共享文件状态、Redis 计数器、readiness 和 drain runbook。

仍有意留作下一阶段生产工作的范围：

- 已实现的 Supabase 控制面路径之上的生产硬化；generic PostgreSQL 在其运维边界
  单独硬化前保留为兼容 provider，Turso/libSQL 和 MySQL 已从生产 provider surface
  退出。
- 当前已实现资源之外的完整 hosted Admin API control plane。
- Semantic/vector cache matching。当前已实现的缓存是 exact-match。
- 内置 Cloudflare provider 和通用外部 hook 边界之外的更多 DNS provider。

## Provider 说明

OpenRouter 是一等 provider kind，复用 OpenAI 兼容的 Chat Completions 和
Responses API dispatch 路径。可选的 `openrouter_http_referer` 和
`openrouter_x_title` 会作为 `HTTP-Referer` 和 `X-Title` header 发送给上游。

暴露兼容 `/v1/chat/completions` 或 `/v1/responses` 的商业和开源上游使用共享
`openai-compatible` 路径。只有当上游需要独立鉴权或 endpoint shape 时，才应该新增
专用 provider kind。

## 运维说明

- 第三方 usage billing 可设置 `export_provider = "openmeter"`，并将
  `export_endpoint` 指向 OpenMeter-compatible CloudEvents ingestion endpoint。
- 可复用 gateway config profile 可通过 `x-ferrogate-config` 按请求选择；profile
  evidence 会记录到 request log。
- MCP tool execution、agent 操作和外部 API 调用默认拒绝，并且必须经过 gateway auth、
  policy、billing、audit 和 observability。直接绕过 gateway 的 agent/tool 路径不在
  支持的安全边界内。
- 多节点 rate limit 和 token-budget reservation/settlement 应使用
  `cluster.counter_backend = "redis"`。Redis 计数器是 fail-closed。
- 只有 listen socket 和 TLS listener 指纹不变时才使用 process-local reload。
  Listener/TLS 变更需要 graceful upgrade。

## 相关文档

- README 首页：[`../README.zh-CN.md`](../README.zh-CN.md)
- Agent framework 兼容性：[`agent-framework-compatibility.md`](agent-framework-compatibility.md)
- Durable storage：[`durable-storage.md`](durable-storage.md)
- Analytics warehouse：[`analytics-warehouse.md`](analytics-warehouse.md)
- 集群部署：[`cluster-deployment.md`](cluster-deployment.md)
- Auth service contract：[`auth-service-contract.md`](auth-service-contract.md)
- Admin API OpenAPI：[`openapi/admin-api.openapi.json`](openapi/admin-api.openapi.json)
