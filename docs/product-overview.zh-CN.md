# FerroGate 产品概览

这个页面承接 README 首页之外的较长产品说明。这里应该只描述已经实现或明确
追踪的能力；路线图内容放在 [`roadmap.md`](roadmap.md)。

## FerroGate 提供什么

- **Pingora 网关运行时**：HTTP 反向代理、路由匹配、上游池、路径/Header
  重写、请求 ID、Trace ID、流式响应、优雅关闭和监听器级 graceful upgrade。
- **多协议推理 API**：`GET /v1/models`、`POST /v1/chat/completions`、
  `POST /v1/responses`、Anthropic 原生 `POST /v1/messages`、
  `POST /v1/embeddings`（同时支持 OpenAI 兼容和非 OpenAI 适配器族）和
  `POST /v1/images/generations`，支持非流式和 SSE 流式转发。
- **供应商适配器**：OpenAI-compatible API、OpenAI、Azure OpenAI、OpenRouter、
  Anthropic、Gemini 和 Grok/xAI。
- **模型注册表与 fallback 路由**：逻辑模型名、供应商模型映射、priority
  fallback、weighted fallback、最低成本、最低延迟、balanced routing、canary
  灰度切分、shadow/mirror 流量复制、租户可见性和供应商 allow/deny 控制。
- **AI 响应缓存**：非流式请求的 exact-match 缓存，以及同一缓存 seam 之后
  可选启用的 semantic（向量相似度）缓存，提供全局、模型、API Key 级别
  启用控制。
- **MCP gateway**：通过 `ferrogate-mcp` 支持 streamable HTTP、SSE、stdio
  session、`initialize`、`tools/list`、命名空间工具、默认拒绝的执行 allowlist、
  健康检查、重连和受治理的工具执行。这些适配器仍基于 `initialize`；原生入口
  支持旧版 2025-11-25，并保留 2025-06-18。
- **原生 MCP JSON-RPC 入口**：`POST /v1/mcp` 支持 `initialize`、`ping`、
  `tools/list`、`tools/call`，以及基于托管资产注册表的
  `resources/list`/`resources/read`。入口还实现了基于官方 commit
  `71e306956a4959c9655e5036be215d41986596e6` 固定的 MCP 2026-07-28 候选规范：
  无状态 `server/discover` 和逐请求校验。这只是入口切片，不代表候选规范的
  出站客户端支持或最终规范一致性。
- **托管资产闭环**：`/v1/assets/*` 上的版本化 publish/pull/delete 带租户
  配额记账、artifact registry 语义（latest/stable/canary 等 channel、
  semver 解析、平台/架构 variant、yank）、供应链信任门禁（恶意软件扫描、
  签名验证、跨租户发布审批）、私有 Supabase Storage（S3 兼容）bucket 上
  的 presigned 大文件上传/下载、带下载侧审计和带宽配额的 egress
  计量/计费、pull 路径统一的 ETag/Range/304 HTTP 缓存、版本 retention
  策略与无引用 blob GC、静态站点服务模式
  `GET /sites/{tenant}/{site}/{path}`（index.html 解析、可选 SPA
  fallback、每站点匿名访问 opt-in），以及通过 MCP `resources/*` 和内置
  `fetch_asset` 工具的 agent 消费。
- **Agentic Lite 插件面**：用于治理 capability bundle、tool provider、event
  sink、权限声明、tool session、Admin 视图和审计事件。
- **Agent runtime 与 skill package surface**：支持 agent discovery、受治理的
  agent upstream、bounded run、workflow counter/timeline，以及 skill-owned plugin、
  tool、MCP server、prompt template 和 workflow。
- **A2A 入口深度治理**：对 agent-to-agent 消息体施加 policy、guardrail 和
  billing；以及**workflow graph 级执行预算**（model-call、tool-call、token
  预算和 iteration limit），治理多步 agent run。
- **Agent 定时调度**：cron/interval 触发器把 `agent_run` 目标发进 dispatch
  lease queue，并提供 `/admin/v1/agent-schedules` CRUD API、`run-now` 和
  每个 schedule 的触发历史。
- **自托管 worker 传输**：可验证的双向 TLS —— 单一显式配置的 issuing
  CA、控制面证书签发与轮换、CRL 吊销、fail-closed 的信任锚处理，以及
  共享 `agent-worker` 二进制（`--worker-type self-hosted`）上对已覆盖
  命令族的 report-only 受治理执行。
- **Caddy 风格配置兼容**：支持 `Ferrogate/Caddyfile`，同时支持结构化 TOML 和 YAML。
- **虚拟 API Key 与策略检查**：哈希 key、租户上下文、scope、禁用/过期 key、
  模型/供应商 allowlist 和 denylist、deny-rule evaluation、请求频率限制和 Token
  预算。
- **Token usage metering events**：优先使用供应商返回的 usage，缺失时由网关
  估算，并带本地 BPE tokenizer 做请求前预估和预算预检。
- **计费原语**：预付费钱包的 reserve/hold 机制，支撑并发下精确金额、
  不可逆的扣费决策。
- **按租户 SSO 持久化**：独立 auth 服务中 OIDC 之外新增 SAML。
- **可观测性**：结构化请求日志、token metering event、应用于请求日志和
  审计事件的 retention 引擎（按租户 TTL、经审计的清除，默认关闭且
  dry-run）、usage aggregate、供应商健康、缓存指标、MCP 工具指标、
  agent-run OTLP span、Prometheus、请求/Trace ID 传播和 OTLP/HTTP 导出。
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
工具执行、资产托管、agent 调度、可观测性、TLS、durable storage、analytics
和集群运维能力。

已完成端到端验证：

- 基于 Pingora 的 HTTP 反向代理运行时。
- OpenAI 兼容 Chat Completions 和 Responses API 路径、Anthropic 原生
  `/v1/messages` 入口、覆盖 OpenAI 兼容与非 OpenAI 适配器族的
  `/v1/embeddings`，以及带按图计量的受治理 `/v1/images/generations` 入口。
- Responses 请求中 text、image、tool definitions、tool choice 和 tool-call input
  shape 在供应商路径中的规范映射。
- OpenAI-compatible 客户端通过 FerroGate `base_url`、虚拟 API key、逻辑模型、
  请求日志、metering event 和 Prometheus model/provider 指标接入。
- 供应商适配器，以及 priority、weighted、cost、latency、balanced 路由，加上
  canary 灰度切分和 shadow/mirror 流量复制。
- 虚拟 API Key 鉴权、策略检查、频率限制，以及带本地 tokenizer 请求前预估
  的 Token 预算处理。
- 非流式 AI 请求的 exact-match 和 semantic（向量相似度）响应缓存。
- Agentic Lite tools 和 MCP gateway 执行，并经过鉴权、策略、计费、审计和指标链路。
- `POST /v1/mcp` 原生旧版 MCP JSON-RPC 入口，包括基于托管资产的
  `resources/list`/`resources/read`。固定版本的 MCP 2026-07-28 候选规范入口切片
  已有聚焦回归覆盖；外部 SDK 兼容性、候选规范出站客户端行为和最终规范一致性
  仍待完成。
- 托管资产闭环：`/v1/assets/*` 上带鉴权的 publish/pull/delete、
  channel/semver/variant 解析、签名与恶意软件扫描门禁、私有 bucket 上的
  presigned 大文件 upload/commit/download（基于 mock S3 兼容端点验证；
  真实 Supabase Storage bucket 验证仍待完成）、带下载配额和审计的 egress
  计量、pull 路径 304/Range 缓存、retention/GC 清扫、`/sites/*` 下的静态
  站点服务，以及通过 MCP resources 和 `fetch_asset` 的 agent 消费。
- Agent discovery、A2A-style agent upstream invocation/streaming、A2A 消息体
  深度治理（policy、guardrail、billing）、bounded agent run、workflow graph
  execution、workflow graph 级预算、tool-call limit、immutable
  approval/audit evidence 和 agent run timeline。
- cron/interval agent 定时调度发进 dispatch lease queue，带 admin CRUD、
  run-now 和触发历史端点。
- 自托管 worker 注册、带控制面证书签发和 CRL 吊销的可验证 mTLS 入口、
  run poll/ack，以及已覆盖命令族的 report-only 受治理执行。
- 钱包 reserve/hold 结算，以及 auth 服务中的按租户 SSO（OIDC 与 SAML）
  持久化。
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
- 音频端点（`/v1/audio/speech`、`/v1/audio/transcriptions`）—— 多模态
  surface 目前只实现了图像；音频需要 body 路径支持 multipart 请求和二进制
  响应。
- `agent-worker` 中真实的 Firecracker guest 执行（受阻于需要 KVM 的基础
  设施）；per-VM rootfs 隔离和 boot 验证 harness 已就绪。
- 资产对象存储路径的真实 Supabase Storage bucket 验证，目前基于 mock S3
  兼容端点验证。
- 静态站点自定义域名（通过 ACME 把托管站点绑定到主机名）。
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
