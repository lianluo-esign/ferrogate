---
title: FerroGate PRD 执行计划任务
aliases:
  - Implementation Plan
  - PRD 执行计划
  - FerroGate 执行计划任务
tags:
  - development
  - planning
  - rust
  - api-gateway
---

# FerroGate PRD 执行计划任务

本文档根据 [[产品需求文档]] 制定，用于把 PRD 转换为可执行、可验收、可持续更新进度的工程任务。

## 0. 执行原则

1. 必须按照标准化 Rust 大型工程代码库设计和实现。
2. 网关核心运行时必须基于 Cloudflare Pingora，不能用通用 Web 框架替代代理生命周期。
3. 每完成一个步骤，必须更新本文档的「进度」字段、验收结果和必要的设计/测试链接。
4. 每个阶段完成前必须运行对应校验，包括格式化、静态检查、单元测试、集成测试和文档同步检查。
5. 代码、PRD、架构文档和执行计划必须保持同步，任何范围变化都要先更新文档再实现。
6. 采用“工程骨架 + 可运行垂直切片 + 增量扩展”的节奏，避免只做横向大框架而长期不可运行。
7. Caddy 基础能力和 Caddyfile 兼容必须对照 Caddy 官方源码实现语义审查，但只能以 Rust/Pingora/FerroGate 模块重新实现，不能复制 Go 源码或 Caddy 内部架构。

## 1. 合理性审查结论

当前计划方向合理，符合 PRD 中“Rust 大型工程代码库”和“Pingora 作为核心代理运行时”的硬性约束，但需要避免以下风险：

1. **配置系统不能太晚**：Pingora runtime、路由、Provider、API Key 都依赖配置模型，因此配置模型和 `check` 命令必须在 P0/P1 就形成最小闭环，而不是等到独立后置阶段。
2. **Provider Adapter 不能晚于 AI Proxy**：`/v1/chat/completions` 要想可维护，必须先有 OpenAI-compatible Adapter 的最小接口，否则容易把 Provider 逻辑写死在 runtime 中。
3. **缺少 storage 边界**：虚拟 API Key、租户、请求日志、Token 计费、Admin API 都需要存储抽象。即使 MVP 先用 in-memory/file，也必须提前定义 repository/storage 接口。
4. **crate 边界需要补齐 routing/storage**：原计划有 core/runtime/providers/policy/auth/billing/admin，但路由和存储是独立变化轴，应单独建边界。
5. **不要一次性实现所有 crate 的完整功能**：P0 只要求 workspace、crate skeleton、公开接口和最小编译，不要求一次性写完所有业务模块。
6. **每个阶段必须产生可运行结果**：优先保证 P1 起就能运行最小网关，后续按垂直切片扩展 AI、鉴权、可观测性和控制面。
7. **Caddyfile 兼容必须前置**：PRD 要求标准启动配置支持 `Ferrogate/Caddyfile`，因此 P0 必须建立 Caddyfile 解析边界和内部 typed config model，而不是只做 TOML。

因此，本计划采用修订后的 P0-P8 顺序，并作为 PRD 第 8 节里程碑的执行级来源。若后续调整阶段边界，必须同步更新 PRD 里程碑和本文档进度总览。

## 2. 进度总览

| 阶段 | 名称 | 状态 | 进度 | 当前产出 |
| --- | --- | --- | --- | --- |
| P0 | 工程基线、crate 边界与 Caddyfile 配置契约 | 已完成 | 100% | 已创建 Rust workspace、P0 crate skeleton、Caddyfile parser/adapter 边界和最小 typed config model |
| P1 | Pingora 通用 API Gateway Runtime 垂直切片 | 已完成 | 100% | 已实现配置驱动 Pingora 反向代理、路由匹配、upstream pool、header/path rewrite、healthz、日志和测试 |
| P2 | 配置校验、生命周期和平滑重载 | 已完成 | 100% | 已完成字段级诊断、Secret env 引用、Caddyfile listener/route/upstream/TLS/log/AI provider/model/API key typed config、Caddy 源码语义对照、配置 snapshot 可观测性、reload 状态机契约、CLI lifecycle 接入、CLI-to-Admin API 运行中 reload、Pingora graceful upgrade listener 级 reload、process-local 管理端配置 swap 和 serde roundtrip |
| P3 | OpenAI-compatible AI Proxy MVP | 已完成 | 100% | 已实现 OpenAI-compatible Adapter MVP、adapter registry 解耦、`/v1/models`、HTTP/HTTPS chat completion dispatch、`stream=true` 增量式 SSE forwarding、Provider 错误归一化、usage 提取接口、鉴权/模型路由负例和 AI dispatch/registry 性能并发 smoke |
| P4 | 虚拟 API Key、租户上下文与 Policy MVP | 已完成 | 100% | 已实现 API Key hash 生成/校验、disabled/expired/rate limit/budget exhausted 拒绝、模型/Provider allowlist、租户字段进入 AuthContext 与 chat route log、RBAC 领域模型、最小 deny-rule Policy Engine、AI Proxy 接入，以及 Key/Tenant/Policy repository 边界 |
| P5 | 多 Provider Adapter 与 Model Registry | 已完成 | 100% | 已实现 OpenAI-compatible、Anthropic、Gemini、Grok、Azure OpenAI adapter 的 registry 分发、请求转换、错误归一化、usage 提取和可重试判断；已定义并接入 Model Registry 的逻辑模型解析、优先级 fallback、加权 fallback 轮转和租户级模型可见性 |
| P6 | 可观测性、请求日志、Storage 与计费事件 | 已完成 | 100% | 已定义 Token usage、模型价格、成本估算、Billing Event、请求日志、usage aggregate、in-memory repository/sink、观测 span 模板和可扩展 exporter/plugin 边界；非流式 AI Proxy 成功响应已写入 in-memory Billing Event、usage aggregate 与结构化 request log；已支持全局+API Key 双开关控制 prompt/response body 记录；所有本地/代理响应已带 request_id/trace_id；Prometheus `/metrics` 已输出 request/billing/token/cost/model-provider 指标并受 `admin.read` 鉴权保护；OTLP/HTTP 后台 sender 已可周期性导出 metrics、request logs 和 gateway request spans |
| P7 | Admin API 与 Dashboard MVP | 已完成 | 100% | 已完成版本化 Admin API 与静态 Dashboard MVP：只读资源通过 `admin.read` 访问，候选配置校验写操作通过 `admin.write` 访问并写审计日志；Dashboard 通过 Admin API 展示 Overview、API Key、Provider、Model、请求日志、Token 用量、审计和网关健康视图 |
| P8 | 生产级可靠性、安全和部署增强 | 已完成 | 100% | 已实现可配置 Provider 熔断器、真实 API Key 请求限流、Token 预算预留/结算、用量估算兜底、Provider dispatch 超时/重试、graceful shutdown 配置、Admin Provider 健康检查/看板、本地安全检查脚本、手动 TLS listener、ACME DNS-01 自动证书启动签发、AI streaming 并发性能 smoke 和自托管部署 runbook |

## 3. P0 工程基线、crate 边界与 Caddyfile 配置契约

**目标**：建立符合大型 Rust 工程实践的 workspace、crate 边界、质量门禁、Caddy 源码对照方法和最小 Caddyfile 配置契约。

### 任务

- [x] 创建 Cargo workspace。
- [x] 拆分核心 crate skeleton，P0 只要求最小可编译和职责边界清晰：
  - `ferrogate-cli`：Caddy 风格命令入口，包含 `run`、`validate`、`reload` 占位和 `check` 兼容别名。
  - `ferrogate-core`：领域模型、错误类型、请求上下文、公共 Result。
  - `ferrogate-config`：Caddyfile 风格配置解析、内部 typed config model、加载、校验、环境变量 Secret 引用。
  - `ferrogate-runtime`：Pingora 服务生命周期和代理运行时边界。
  - `ferrogate-routing`：Host/Path/Header 路由、模型路由、upstream 选择接口。
  - `ferrogate-providers`：AI Provider Adapter trait 和 OpenAI-compatible Adapter skeleton。
  - `ferrogate-auth`：虚拟 API Key、租户解析接口。
  - `ferrogate-policy`：Policy Engine trait 和决策模型。
  - `ferrogate-storage`：Repository/storage trait，MVP 可先提供 in-memory 实现。
  - `ferrogate-billing`：Token 统计、用量聚合、Billing Event 模型。
  - `ferrogate-observability`：日志、指标、Tracing 初始化。
  - `ferrogate-admin`：Admin API 边界。
- [x] 下载 Caddy 源码到 `.references/caddy`，记录参考 commit，并建立 Caddy 源码对照清单。
- [x] 定义最小 `Ferrogate/Caddyfile` 配置子集：site block、matcher、`reverse_proxy`、`route`、`handle`、`handle_path`、`header`、`rewrite`、`respond`、`redir`、`encode`、`tls`、`log`。
- [x] 定义 Caddyfile 风格配置到 FerroGate 内部 typed config model 的转换模型：listener、route、upstream、provider、model、log。
- [x] 实现 Caddy 风格子命令 `ferrogate run --config <path>`、`ferrogate validate --config <path>`，并保留 `check` 作为 `validate` 兼容别名。
- [x] 建立 `cargo fmt`、`cargo clippy --all-targets --all-features`、`cargo test --workspace` 质量门禁。
- [x] 建立统一错误处理、tracing 初始化、feature gate 和 crate 依赖规范。
- [x] 添加 workspace README、crate README 或模块级文档注释。

### 验收标准

- [x] `cargo fmt --check` 通过。
- [x] `cargo clippy --all-targets --all-features -- -D warnings` 通过。
- [x] `cargo test --workspace` 通过。
- [x] `Ferrogate/Caddyfile` 示例可被 `check` 命令校验通过。
- [x] 不支持的 Caddy directive 会返回带文件名、行列号、directive 名称和迁移建议的错误。
- [x] 每个 crate 有清晰职责说明和最小可编译代码。

**进度**：100%。

**验收结果**：

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
cargo run -- validate --config Ferrogate/Caddyfile
```

以上命令已通过。P0 测试覆盖 Caddyfile parser/adapter、unsupported directive 诊断、CLI `check` 集成、workspace skeleton 和轻量 parser 性能 smoke。

## 4. P1 Pingora 通用 API Gateway Runtime 垂直切片

**目标**：实现一个配置驱动、可运行、可测试的 Pingora 反向代理最小闭环。

### 任务

- [x] 基于 Pingora 实现监听器和代理服务。
- [x] 从 P0 配置模型加载 listener、route、upstream。
- [x] 定义请求上下文，包括 request_id、trace_id、route、upstream、tenant 占位字段。
- [x] 实现 Host/Path/Header 路由匹配。
- [x] 实现 upstream pool 和基础 round-robin 负载均衡。
- [x] 实现请求/响应 header 改写和 path rewrite。
- [x] 实现 `/healthz` 静态健康检查响应。
- [x] 输出结构化访问日志。
- [x] 添加端到端代理集成测试。

### 验收标准

- [x] 可以代理普通 HTTP 请求到配置的上游。
- [x] 路由匹配、header 改写、path rewrite 有单元测试和集成测试。
- [x] Streaming 响应不被完整缓冲。
- [x] 所有请求都有 request_id。
- [x] Pingora 是代理关键路径，未用 axum/reqwest/hyper 替代核心 runtime。

**进度**：100%。

**验收结果**：

```bash
cargo test -p ferrogate-cli --test proxy_runtime -- --nocapture
cargo test -p ferrogate-cli --test upstream_pool -- --nocapture
cargo test -p ferrogate-cli --test runtime_perf -- --nocapture
cargo test -p ferrogate-cli --test check_command -- --nocapture
```

以上命令已通过。P1 覆盖 Pingora 代理成功路径、streaming 首包不完整缓冲、upstream pool round-robin、请求/响应 header 改写、path rewrite、命令契约和 runtime debug 性能 smoke。

## 5. P2 配置校验、生命周期和平滑重载

**目标**：让网关具备可靠启动、可诊断配置错误和平滑生命周期管理。

### 任务

- [x] 完善 Caddyfile 风格监听器、路由、upstream、TLS、日志、Provider、模型、API Key 的配置模型。（已支持 site listener、`admin`、`log`、`respond`、`route`/`handle`/`handle_path`、`reverse_proxy` upstream pool/header、`tls cert key`，并新增 `ai_gateway` 子集：`provider`、`model`、`api_key` 会映射到现有 typed config 并复用字段级校验。）
- [x] 对照 Caddy 源码中的 `caddyconfig/caddyfile`、`caddyconfig/httpcaddyfile` 和关键 HTTP directive 行为，完善 FerroGate parser/adapter 设计。（已记录 parser/dispenser、directive order、`route`/`handle`/`handle_path`、`reverse_proxy` 子集差异和后续扩展边界。）
- [x] 支持环境变量引用 Secret，并保证错误日志不泄漏 Secret。
- [x] 实现启动前配置校验和字段级错误诊断。
- [x] 设计并实现 Pingora-backed 平滑重载接口。（已定义 validate-only/no-swap CLI reload 契约、runtime reload 状态机，并已接入 CLI lifecycle；`ferrogate reload --admin-url ... --admin-token ...` 已可调用运行中 Admin API 执行 candidate reload；运行中 `/admin/v1/config/reload` 已支持 process-local 请求处理状态 swap；`graceful_upgrade_pid_file`、`graceful_upgrade_sock` 和 `graceful_upgrade_sock_retries` 已透传到 Pingora `ServerConf`；`ferrogate reload --graceful-upgrade` 会启动新 `ferrogate run --upgrade` 进程并向旧进程发送 SIGQUIT，由 Pingora FD transfer 完成 listener 级接管。）
- [x] 设计配置快照、版本号和回滚语义。
- [x] 补充 `ferrogate run`、`ferrogate validate`、未来 `ferrogate reload` 命令约定。
- [x] 更新 [[03-development/development-workflow|Development workflow]]。

### 验收标准

- [x] 示例 `Ferrogate/Caddyfile` 可通过校验。
- [x] 无效配置可以返回字段级错误。
- [x] 配置模型有 serde roundtrip 测试。
- [x] 平滑重载设计文档同步更新。
- [x] reload 失败不会破坏当前运行配置。（runtime reload 状态机和 `/admin/v1/config/reload` 集成测试均覆盖 candidate reject 保留 active snapshot；listener/TLS 变更通过 `ferrogate reload --graceful-upgrade` 编排 Pingora graceful upgrade 完成 listener 级接管。）

**进度**：100%。

**验收结果**：

```bash
cargo test -p ferrogate-cli config::tests -- --nocapture
cargo test -p ferrogate-cli config::snapshot -- --nocapture
cargo test -p ferrogate-cli lifecycle -- --nocapture
cargo test -p ferrogate-runtime -- --nocapture
cargo test -p ferrogate-config --test caddyfile_parser -- --nocapture
cargo test -p ferrogate-config -- --nocapture
cargo test -p ferrogate-cli --test check_command -- --nocapture
cargo test -p ferrogate-cli --test proxy_runtime -- --nocapture
cargo test -p ferrogate-cli --test ai_proxy_runtime admin_process_local_reload_swaps_request_state_without_rebinding_listener -- --nocapture
cargo test -p ferrogate-cli config -- --nocapture
cargo run -- validate --config Ferrogate/Caddyfile
cargo run -- reload --config Ferrogate/Caddyfile
```

2026-05-04 本轮继续推进 P2 Caddyfile typed config：`ferrogate-config` 新增 `GatewayApiKey`，扩展 `GatewayProvider` 和 `GatewayModel`，并在 Caddyfile parser 中支持保守的 `ai_gateway` 子集。当前语法支持 `provider <name> { kind ... base_url ... api_key env.NAME/{env.NAME}/{$NAME} }`、`model <name> -> <provider>:<provider_model> { capabilities ... context_window ... input_price_per_1m ... output_price_per_1m ... }`、`api_key <id> { key env.NAME/{env.NAME}/{$NAME} scopes ... allowed_models ... denied_models ... allowed_providers ... denied_providers ... monthly_token_budget ... request_limit_per_minute ... }`。CLI Caddyfile loader 会把这些字段转换为现有运行时 `Provider`、`Model`、`ApiKey`，并继续走 `Config::validate()` 的字段级诊断。新增 parser 单元/集成测试和 CLI config 测试验证 Caddyfile AI Gateway 配置可进入有效运行时 config。后续兼容性增量修正 lexer：`{env.NAME}` 和 `{$NAME}` 现在作为无空白参数 token 处理，普通 `{ ... }` block 语义不变。

2026-05-04 本轮继续推进 P2 运行中 reload：`FerroGateway` 改为持有 `SharedAppState`，每个新请求会读取当前 `AppState` 快照；`/admin/v1/config/reload` 接收 TOML/Caddyfile candidate，或通过 `source=file` 重新读取当前 `ferrogate run --config` 的配置文件，复用字段级校验和 `ferrogate-runtime` prepare/commit/reject 语义。当前实现允许不改变 `listen` 与 TLS listener 设置的 process-local swap，能即时替换 routes、upstreams、providers、models、api_keys、policies、reliability 等请求处理状态，并保留 request log、audit、billing、usage aggregate 与 request id 运行中数据；监听地址/TLS 变更由 listener runtime fingerprint 统一判定，不走 process-local。`/admin/v1/config/validate` 会返回 `reload_mode`、`listener_reload_required` 和 `reload_reason`，让 Dashboard/运维调用在真正 reload 前区分 process-local 与 listener-level 路径。`ferrogate reload` 默认仍为 validate-only/no-swap；当提供 `--admin-url` 与 `--admin-token` 时，会读取候选 TOML/Caddyfile 并调用运行中 Admin API 完成 process-local reload 或返回 rejected outcome；当提供 `--graceful-upgrade` 时，会读取 `graceful_upgrade_pid_file` 中的旧进程 pid，启动新 `ferrogate run --upgrade` 进程并向旧进程发送 SIGQUIT，Pingora 通过 `graceful_upgrade_sock` 完成 listener FD transfer。新增集成测试验证 Caddyfile candidate 通过 `/v1/models` reload 后切到新模型、CLI-to-Admin API reload 后切到当前配置文件模型、listener 级 graceful upgrade 后同一监听地址返回新配置模型；单元测试覆盖请求状态变更可 process-local、listen/TLS 变更必须 listener-level reload。

2026-05-04 本轮补齐 P2 Caddy 源码语义对照：已核对 `.references/caddy` 中 `caddyconfig/caddyfile.Parse`、`Dispenser`、`httpcaddyfile.RegisterHandlerDirective`、`ParseSegmentAsSubroute`、directive order 排序、`route`/`handle`/`handle_path` 与 `reverse_proxy` Caddyfile adapter。当前设计结论写入 [[02-architecture/mature-api-gateway-design|Mature API gateway design]]：FerroGate 继续保持窄 typed adapter，普通 `{}` 维持 block 语义，仅对 Secret env 参数保留 `{env.NAME}` / `{$NAME}` token；不支持的 Caddy middleware graph 能力必须 fail fast 并给迁移提示，避免静默产生与 Caddy 不同的路由顺序。

以上命令已通过。当前 `reload` CLI 默认仍是 validate-only/no-swap 契约，会输出候选配置 snapshot id；invalid candidate 会在 swap 前失败。带 `--admin-url`/`--admin-token` 时，CLI 会把候选配置提交到运行中 Admin API 并报告 committed/rejected outcome。带 `--graceful-upgrade` 时，CLI 会编排 Pingora listener 级 graceful upgrade。CLI lifecycle 已通过 `ferrogate-runtime` 的 prepare/reject 路径生成报告，保证 rejected candidate 不覆盖 active snapshot。`Ferrogate/Caddyfile` 的 `admin localhost:2019` 已进入 typed config，`/admin/status` 会暴露 active snapshot；运行中的管理面可通过 `/admin/v1/config/validate` 和 `/admin/v1/config/reload` 校验或切换 TOML/Caddyfile candidate，也可通过 `source=file` 重新读取当前启动配置文件。

## 6. P3 OpenAI-compatible AI Proxy MVP

**目标**：让 OpenAI SDK 能通过 FerroGate 调用 AI 请求，并保持 Provider 逻辑隔离在 Adapter 中。

### 任务

- [x] 在 `ferrogate-providers` 中定义 Provider Adapter trait 的 MVP 版本。
- [x] 实现 OpenAI-compatible Adapter MVP，包括鉴权 header planning、endpoint 映射、logical model 到 provider model 改写、stream 标记保留、Provider 错误归一化、usage 提取接口、adapter registry 统一入口和 secret debug 脱敏。
- [x] 实现 `GET /v1/models`。
- [x] 实现 `POST /v1/chat/completions` 非流式路径，支持 HTTP 和 HTTPS OpenAI-compatible upstream dispatch。
- [x] 实现 `stream=true` 的增量式 SSE response forwarding，provider 首段 chunk 会在 provider 完成前转发给客户端。
- [x] 定义统一错误响应格式。
- [x] 记录 logical_model、provider、provider_model 的路由计划。
- [x] 提供 OpenAI-compatible mock upstream 集成测试。

### 验收标准

- [x] OpenAI-compatible 客户端可配置 base_url 调通 FerroGate 的非流式 mock upstream 路径。
- [x] 非流式和流式请求均有集成测试。
- [x] Provider 错误被归一化。
- [x] 响应不泄漏 API Key 和 Provider Secret。（日志脱敏仍需随 observability 切片继续验证。）
- [x] OpenAI-compatible 逻辑未写死在 runtime crate 中。（`gateway/chat.rs` 只调用 `AppState`/`ProviderAdapterRegistry` 统一入口；adapter 选择、请求准备、错误归一化和 usage 提取均收敛在 `ferrogate-providers`。）

**进度**：100%。

**验收结果**：

```bash
cargo test -p ferrogate-providers -- --nocapture
cargo test -p ferrogate-cli --test ai_proxy_auth -- --nocapture
cargo test -p ferrogate-cli --test ai_proxy_dispatch_errors -- --nocapture
cargo test -p ferrogate-cli --test ai_proxy_runtime -- --nocapture
cargo test -p ferrogate-cli --test ai_proxy_perf -- --nocapture
cargo clippy -p ferrogate-providers --all-targets --all-features -- -D warnings
```

以上命令此前已通过；2026-05-03 的 `stream=true` SSE response forwarding MVP 变更在本地通过 `cargo fmt --check`，并新增 `ai_proxy_runtime` streaming SSE 集成测试与 `ai_proxy_dispatch_errors` streaming provider 连接失败负例。2026-05-03 本轮新增 Provider 统一错误响应、OpenAI-compatible usage 提取接口、Provider 429 错误归一化集成测试、AI Proxy 并发性能 smoke，以及本地复用 skill `ferrogate-wiki/.jcode/skills/ferrogate-phase-validation/SKILL.md`。本轮已通过：

```bash
cargo fmt --check
cargo test -p ferrogate-providers -- --nocapture
cargo test -p ferrogate-config -- --nocapture
cargo test -p ferrogate-core -- --nocapture
cargo clippy -p ferrogate-providers --all-targets --all-features -- -D warnings
```

2026-05-03 本轮继续完成 adapter registry 解耦：`ProviderAdapterRegistry` 现在统一负责 adapter 选择、chat request planning、Provider 错误归一化和 usage 提取，`gateway/chat.rs` 不再直接依赖 `ProviderAdapter` trait 或 OpenAI-compatible adapter 具体类型；registry 还补充了大小写/空白归一化、并发调用和 1000 次 planning 延迟 smoke。新增/复跑通过：

```bash
cargo fmt --check
cargo test -p ferrogate-providers -- --nocapture
cargo test -p ferrogate-providers registry -- --nocapture
cargo test -p ferrogate-config -- --nocapture
cargo test -p ferrogate-core -- --nocapture
cargo clippy -p ferrogate-providers --all-targets --all-features -- -D warnings
```

2026-05-03 本轮完成 P3 收尾：provider dispatch 支持 `http://` 和 `https://` endpoint，HTTPS 使用 rustls 与系统根证书；`stream=true` 路径改为 provider response head 解析后边读边写，不再等待 provider 完整结束才写回客户端，并新增延迟 SSE 集成测试验证首段 chunk 会早于 provider `[DONE]` 到达客户端。本轮为本地验证创建 ignored 的 `.jcode/cmake-venv`，用于提供 `cmake` 给 Pingora `libz-ng-sys` 编译链；该目录不进入仓库。新增/复跑通过：

```bash
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo clippy -p ferrogate-cli --all-targets --all-features -- -D warnings
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli dispatch -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli --test ai_proxy_dispatch_errors -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli --test ai_proxy_runtime -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli --test ai_proxy_perf -- --nocapture
npm --prefix ferrogate-wiki run wiki:build
```

当前 P3 覆盖 OpenAI-compatible adapter 的模型改写、stream flag 保留、非对象 body 拒绝、unsupported provider kind 拒绝、Provider Secret debug 脱敏、Provider 错误归一化、usage 提取接口和 adapter registry 解耦，以及真实 `ferrogate run` 进程下的 `/v1/models`、`/v1/chat/completions` 非流式 HTTP mock provider dispatch、HTTPS provider endpoint 连接失败归一化、`stream=true` 增量式 SSE response forwarding、`Authorization` 与 `x-api-key`、missing/invalid/scope/model deny 负例、provider Authorization header、provider body 模型改写、逻辑模型名不透传、provider/client secret 响应脱敏。

## 7. P4 虚拟 API Key、租户上下文与 Policy MVP

**目标**：实现基础企业级访问控制和租户隔离，满足 PRD 中 P4 对虚拟 API Key、租户上下文和 Policy MVP 的要求。

### 任务

- [x] 实现虚拟 API Key 生成、Hash 存储和校验。（当前提供 `ferrogate hash-key --secret ...` 生成 `blake2b:` hash，配置支持 `key_hash` 校验；生产级 key ID/secret 生成流程待 Admin API 切片。）
- [x] 定义 Organization、Team、Project、User、Service Account、Role、Permission、Policy 模型。
- [x] API Key 解析到唯一租户上下文。（当前从配置中的 `organization_id`、`team_id`、`project_id`、`user_id`、`api_key_id` 进入 `AuthContext`，chat route log 会记录非敏感租户字段。）
- [x] 基于 `ferrogate-storage` 定义 Key、Tenant、Policy repository。（已定义 `ApiKeyRepository`、`TenantRepository`、`PolicyRepository` 和 in-memory 实现；运行路径仍使用配置内存态，生产级持久化实现待后续切片。）
- [x] 实现模型 allowlist/denylist。（当前支持 API Key 级 `allowed_models` 和 `denied_models`；denylist 优先级高于 allowlist。）
- [x] 实现 Provider allowlist/denylist。（当前支持 API Key 级 `allowed_providers` 和 `denied_providers`；denylist 优先级高于 allowlist，并在 provider dispatch 前拒绝。）
- [x] 实现基础请求频率限制和 Token 预算接口。（P4 曾先支持 `request_limit_per_minute = 0` 与 `monthly_token_budget = 0` 的 exhausted 占位拒绝；P8 已升级为 per-API-key 60 秒请求窗口和基于 billing usage aggregate 的 Token 预算拒绝。）
- [x] 将 Auth 和 Policy 接入 P3 AI Proxy 请求路径。（Auth 与最小 deny-rule `BasicPolicyEngine` 已在 provider dispatch 前执行。）

### 验收标准

- [x] 被禁用、过期、超限、无权限 Key 会被拒绝。（当前覆盖 disabled、expired、真实 `request_limit_per_minute`、真实 `monthly_token_budget`、scope/model/provider/policy deny。）
- [x] 请求上下文包含 organization_id、project_id、api_key_id 等租户字段。
- [x] 所有安全相关日志脱敏。（已复核 tracing 字段仅记录 request_id、tenant/api_key id、模型/Provider 名称、预算数值、usage 与错误类型，不记录 client/provider secret 或 Authorization；命令/响应测试覆盖 secret 不回显。）
- [x] Policy 决策有单元测试。
- [x] OpenAI SDK 请求在无 Key 或无权限时返回统一错误。

**进度**：100%。

**验收结果**：

```bash
cargo fmt --check
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli auth -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli --test ai_proxy_auth -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli --test check_command -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli config::validation_tests -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-policy -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-storage -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-auth -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo clippy -p ferrogate-auth --all-targets --all-features -- -D warnings
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo clippy -p ferrogate-storage --all-targets --all-features -- -D warnings
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo clippy -p ferrogate-cli --all-targets --all-features -- -D warnings
rg -n "(info!|warn!|error!|debug!|trace!)" crates/ferrogate-cli/src crates/ferrogate-providers/src crates/ferrogate-auth/src crates/ferrogate-policy/src crates/ferrogate-storage/src -S
```

2026-05-04 本轮补齐 P4 allowlist/denylist 收尾：`ApiKey` 配置新增 `denied_models` 和 `denied_providers`，`AuthContext::can_use_model()` / `can_use_provider()` 明确让 denylist 优先于 allowlist；配置校验会提前拒绝未知 denied model/provider 引用，Caddyfile `ai_gateway api_key` 子集也支持 `denied_models` / `denied_providers`。新增单元测试覆盖 denylist 覆盖 allowlist，集成测试覆盖 chat 请求因模型/provider denylist 返回统一 `model_not_allowed` / `provider_not_allowed`，且不回显 client secret。

2026-05-03 本轮启动 P4：`ApiKey` 配置新增 `allowed_providers` 与 `expires_at_unix`，`authenticate` 会对 disabled、expired、budget exhausted、scope deny 进行统一错误拒绝；`chat` 请求路径在 model/provider 解析后执行 Provider allowlist，并在 route planning log 中记录 `api_key_id`、`organization_id`、`project_id`、logical/provider model 和 stream 标记，避免记录 secret。

2026-05-03 本轮继续接入最小 Policy Engine：`ferrogate-policy` 新增 `BasicPolicyEngine`、`PolicySubject` 与 deny-rule `PolicyRule`，CLI 配置新增 `[[policies]]`，并在 AI Proxy provider dispatch 前执行策略决策；配置校验会提前拒绝 policy 或 API key allowlist 中不存在的 api key、model、provider 引用。

2026-05-03 本轮继续补齐虚拟 API Key hash 能力：`ApiKey` 配置新增 `key_hash`，`authenticate` 同时支持明文开发 key、环境变量 key 和 `blake2b:` hash 校验；新增 `ferrogate hash-key --secret ...` 用于生成配置 hash，并有命令测试确保输出不回显原始 secret。

2026-05-03 本轮继续补齐 storage 边界：`ferrogate-storage` 新增 `StoredApiKey`、`StoredTenant`、`StoredPolicyRule`，并定义 `ApiKeyRepository`、`TenantRepository`、`PolicyRepository` 与 in-memory repository 测试，为后续从配置内存态迁移到持久化控制面保留边界。

2026-05-03 本轮继续补齐限流占位：`ApiKey` 配置新增 `request_limit_per_minute`，当值为 `0` 时 AI Proxy 在 provider dispatch 前返回 `rate_limit_exceeded`；这与 `monthly_token_budget = 0` 一起作为 P4 的本地策略占位。2026-05-04 P8 已将该占位升级为真实 per-API-key 请求窗口和 Token usage 预算拒绝。

2026-05-03 本轮继续补齐 RBAC 领域模型：`ferrogate-auth` 新增 `Organization`、`Team`、`Project`、`User`、`ServiceAccount`、`Role`、`Permission`、`PolicyBinding` 与 `PolicySubject`，为后续 Admin API、Storage repository 和控制面权限配置复用。

2026-05-03 本轮完成安全日志脱敏复核：当前 tracing 调用不输出 secret、Authorization、`key`、`key_hash` 或 provider API key；`hash-key`、`validate`、`reload`、AI Proxy 鉴权与 provider dispatch 测试均覆盖响应/命令输出不回显 secret。

## 8. P5 多 Provider Adapter 与 Model Registry

**目标**：抽象不同 AI Provider 差异，支持逻辑模型路由、fallback 和权重路由。

### 任务

- [x] 完善 Provider Adapter trait，覆盖请求转换、响应转换、Streaming、错误归一化、usage 提取、可重试判断。
- [x] 实现 OpenAI Adapter。
- [x] 实现 Anthropic Adapter。
- [x] 实现 Gemini Adapter。
- [x] 实现 Grok Adapter。
- [x] 实现 Azure OpenAI Adapter。
- [x] 定义 Model Registry、模型别名、模型能力、价格和上下文长度。（当前已定义模型条目、primary route、fallback route 占位、capabilities、context window、pricing 元数据，并接入 chat route 解析；别名规则待后续扩展。）
- [x] 实现优先级 fallback 和权重路由。
- [x] 支持租户级模型可见性。

### 验收标准

- [x] 每个 Adapter 支持鉴权注入、请求转换、响应转换、错误归一化、usage 提取。
- [x] 逻辑模型可以路由到不同 Provider 模型。
- [x] fallback 过程有 trace span 和日志字段。
- [x] Provider Adapter 单元测试覆盖典型错误和 streaming 事件。

**进度**：100%。

**验收结果**：

```bash
cargo fmt --check
cargo test -p ferrogate-providers -- --nocapture
cargo clippy -p ferrogate-providers --all-targets --all-features -- -D warnings
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli --test ai_proxy_auth -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli --test ai_proxy_runtime gemini -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli --test ai_proxy_runtime azure -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli --test ai_proxy_runtime falls_back -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli state -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli config -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo clippy -p ferrogate-cli --all-targets --all-features -- -D warnings
```

2026-05-03 本轮启动 P5：`ferrogate-providers` 新增 `AnthropicAdapter`，可将 OpenAI-style chat plan 转换为 Anthropic `/messages` 请求，注入 `x-api-key` 与 `anthropic-version` header，归一化 Anthropic error response，并从 `input_tokens`/`output_tokens` 提取 usage；`ProviderAdapterRegistry` 已支持 `anthropic` kind。

2026-05-03 本轮继续推进 P5：`ferrogate-providers` 新增 `ModelRegistry`、`ModelRegistryEntry`、`ModelRoute` 和 `ResolvedModelRoute`，覆盖 enabled 过滤、重复模型诊断、稳定模型列表、primary provider route 与 fallback route 占位；`ferrogate-cli` 的 `/v1/chat/completions` 已改为通过 Model Registry 解析逻辑模型，再将 primary provider/provider_model 交给 Provider Adapter dispatch。

2026-05-03 本轮补齐 Gemini adapter：支持将 OpenAI-style `messages` 转换为 Gemini `contents` 与 `systemInstruction`，映射 `max_tokens`、`temperature`、`top_p`、`top_k`、`stop` 到 `generationConfig`，通过 `x-goog-api-key` header 注入 provider secret，非流式使用 `:generateContent`，流式使用 `:streamGenerateContent?alt=sse`；已新增 provider 单元测试和真实 CLI mock-provider 集成测试，验证请求路径、body shape、usageMetadata 提取和 secret 不回显。

2026-05-03 本轮补齐 Grok adapter：`grok`/`xai` 作为显式 provider kind 进入 registry，协议层复用 xAI 官方兼容的 OpenAI Chat Completions 请求、Bearer 鉴权、错误归一化和 usage 提取；原 unsupported provider 负例已改为 `unsupported-test`，避免与新增 adapter 冲突。

2026-05-03 本轮补齐 Azure OpenAI adapter：`azure-openai`/`azure` 作为显式 provider kind 进入 registry，provider model 被视为 Azure deployment name 并写入 `/openai/deployments/{deployment}/chat/completions?api-version=...` endpoint，provider secret 通过 `api-key` header 注入，请求 body 移除客户端逻辑模型名；已新增 provider 单元测试和 CLI mock-provider 集成测试验证 endpoint、header、usage、错误归一化和 secret 不回显。

2026-05-03 本轮补齐 fallback/权重路由：`[[models.fallbacks]]` 支持 fallback provider、provider model、priority、weight 和 enabled 字段；配置校验会拒绝未知 fallback provider、空 provider model 和 0 weight。Model Registry 会按 priority 生成候选路由，同一 priority 下按 weight 做轻量轮转；`/v1/chat/completions` 在 primary 出现 adapter 错误、dispatch 错误或 adapter 判定可重试的 5xx/429 时继续尝试 fallback，并记录 `candidate_index`、`fallback_count`、provider、provider_model、status/error 等日志字段。

2026-05-03 本轮完成 P5 收尾：模型配置新增 `visible_organization_ids` 与 `visible_project_ids`，运行时会在 provider dispatch 前基于 API Key 的 organization/project 上下文返回 `model_not_visible`，避免租户不可见模型被路由到上游；`ai_proxy_auth` 已覆盖租户不可见模型拒绝且不回显 client secret。

## 9. P6 可观测性、请求日志、Storage 与计费事件

**目标**：提供 AI Gateway 需要的追踪、指标、审计、请求日志和成本统计能力。

### 任务

- [x] 集成 OpenTelemetry traces、metrics、logs。（已定义 exporter/plugin 配置边界；Prometheus `/metrics` runtime 已接入；OTLP/HTTP 后台 sender 会按 `telemetry.otlp_endpoint` 周期性导出 metrics、request logs 和由 request log 派生的 gateway request spans。）
- [x] 定义 PRD 中要求的 span 层级。
- [x] 定义可扩展观测 exporter/plugin 边界，支持按 trace/metric/log 信号拆分 exporter；Prometheus 作为 metrics exporter 暴露 `/metrics`，不作为日志插件。
- [x] 接入 Prometheus 文本格式 `/metrics`，输出 request log、错误数、status、billing event、token、cost、model/provider 聚合指标，并在开启 API Key 时要求 `admin.read`。
- [x] 定义 OTLP/HTTP traces、metrics、logs 请求规划和 `telemetry.otlp_endpoint` 配置校验。
- [x] 实现结构化请求日志模型和 repository。
- [x] 实现 Token usage 提取和估算接口。
- [x] 实现模型价格表和成本计算。
- [x] 实现 Billing Event 模型和异步写入接口。（当前为非阻塞边界和 in-memory sink，并已接入非流式 AI Proxy usage 成功路径；真正异步队列待后续切片。）
- [x] 支持按租户策略控制 prompt/response body 记录。
- [x] 提供 in-memory/file storage，预留 SQLite/Postgres 实现边界。（当前已提供 in-memory repository/sink；file/SQLite/Postgres 待后续实现。）

### 验收标准

- [x] 每次请求都有 request_id 和 trace_id。
- [x] 日志包含 PRD 要求的核心字段。
- [x] Token 和成本可以按组织、项目、API Key、模型聚合。
- [x] 敏感字段默认脱敏。
- [x] Billing Event 写入失败不会明显阻塞响应路径。

**进度**：100%。

**验收结果**：

```bash
cargo fmt --check
cargo test -p ferrogate-billing -- --nocapture
cargo test -p ferrogate-storage -- --nocapture
cargo test -p ferrogate-observability -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli state -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli --test ai_proxy_runtime openai_models -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli telemetry -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo clippy -p ferrogate-cli --all-targets --all-features -- -D warnings
```

2026-05-03 本轮启动 P6：`ferrogate-billing` 定义 `TokenUsage`、`ModelPrice`、`CostEstimate`、`BillingEvent`、`BillingEventSink` 和 `InMemoryBillingEventSink`，支持按 input/output token 价格估算 USD 成本并记录 billing event；`ferrogate-storage` 新增 `StoredRequestLog`、`StoredUsageAggregate`、`RequestLogRepository`、`BillingEventRepository`、`UsageAggregateRepository` 和 `InMemoryAppendRepository`，覆盖请求日志顺序追加、租户/模型 usage aggregate 存储和 billing event repository 边界。

2026-05-03 本轮继续推进 P6：`ferrogate-cli` 新增 `ferrogate-billing` 依赖，`AppState` 维护模型价格表和 `InMemoryBillingEventSink`；非流式 `/v1/chat/completions` 在 provider usage 提取成功后生成 `BillingEvent`，写入失败只记录 `billing event write failed` warning，不影响响应路径。事件包含 request/trace、tenant、logical/provider model、provider、usage、status code 和按模型价格估算的 cost。

2026-05-03 本轮补齐观测 span 模板边界：`ferrogate-observability` 定义 `ObservabilityConfig`、`GatewaySpanKind`、`GatewaySpanTemplate` 和默认 span 层级，覆盖 `ferrogate.gateway.request`、`ferrogate.auth`、`ferrogate.policy.evaluate`、`ferrogate.model.route`、`ferrogate.provider.dispatch`、`ferrogate.billing.write`，并固化 request_id、trace_id、tenant、provider、model、retryable、usage/cost 等 PRD 核心字段。

2026-05-03 本轮接入 request log 成功路径：`ferrogate-cli` 依赖 `ferrogate-storage`，`AppState` 维护 in-memory request log repository；非流式 AI Proxy provider 成功响应会记录 request_id、trace_id、tenant、route、provider、logical model、provider model、status code，`prompt_recorded`/`response_recorded` 默认均为 `false`，避免默认落 body 或 secret。

2026-05-03 本轮补齐 body 记录策略：`telemetry.log_bodies` 作为全局总开关，`api_keys[].log_bodies` 作为 API Key/租户级授权开关；只有二者同时开启时，非流式成功路径 request log 才会保存 prompt/response body，并将 `prompt_recorded`、`response_recorded` 置为 `true`。默认配置继续不记录 body，测试覆盖默认脱敏、API Key 授权和全局开关组合。

2026-05-03 本轮补齐 chat 错误路径 request log：`/v1/chat/completions` 的鉴权失败、JSON/请求解析失败、模型不可用/不可见、Provider 不存在/不可用、Policy 拒绝、adapter error、provider dispatch error 等网关内部拒绝路径会记录结构化 request log，包含 request_id、trace_id、tenant、route、model/provider 上下文、status_code 和 error_code，body 字段保持不记录。

2026-05-03 本轮补齐可扩展 observability exporter/plugin 边界：`ferrogate-observability` 新增 `ObservabilitySignal`、`ObservabilityExporterKind`、`ObservabilityExporterConfig`、`ObservabilityPipelineConfig` 和 `ObservabilityPlugin` trait，可按 trace、metric、log 三类信号分别声明 stdout、OTLP、Prometheus、file 等 exporter。Prometheus 被明确约束为 metrics-only，并要求绝对 HTTP path（默认形态为 `/metrics`）；日志类插件继续走 log signal，避免将 Prometheus 误作为日志插件。当前完成的是配置/插件契约和校验，实际 exporter runtime wiring 待后续切片。

2026-05-03 本轮接入 Prometheus runtime 切片：`ferrogate-observability` 新增 `GatewayMetricsSnapshot` 和 Prometheus text renderer；`ferrogate-cli` 从 in-memory request log 与 billing event 聚合 request log 总数、错误数、HTTP status、billing event、prompt/completion/total token、cost currency、logical model/provider 请求和 token 指标，并通过 `/metrics` 输出 `text/plain; version=0.0.4`。当网关配置 API Key 时，`/metrics` 复用 `admin.read` 鉴权，避免指标中模型/provider 维度裸露。

2026-05-04 本轮补齐 request/trace 传播、OTLP 规划和 usage aggregate runtime：`handle_request_filter` 统一为本地、AI 和代理路径生成 `trace_id`，JSON/raw/streaming 响应与代理响应均带 `x-trace-id`，转发到上游时补 `x-ferrogate-trace-id`；`ferrogate-observability` 新增 OTLP/HTTP traces、metrics、logs JSON 请求规划，可生成 `/v1/traces`、`/v1/metrics`、`/v1/logs` 请求体；`TelemetryConfig` 新增 `otlp_endpoint` 并做 http/https endpoint 校验；`AppState` 在 billing event 成功写入后同步累加 organization/project/api key/logical model/provider 维度的 usage aggregate。

2026-05-04 本轮完成 P6 收尾：`ferrogate-cli` 新增 OTLP/HTTP 后台 sender，`ferrogate run` 在配置 `telemetry.otlp_endpoint` 后会启动独立线程，周期性导出现有 Prometheus metrics snapshot、新增结构化 request logs，以及由新增 request log 派生的 `ferrogate.gateway.request` spans。导出使用短超时 HTTP/HTTPS POST，不在 Pingora 请求关键路径中访问外部 collector；OTLP log/span attributes 只携带 request_id、trace_id、tenant id、route、model/provider、status/error 和 body-recorded 标记，不导出 prompt/response body。新增单元测试使用本地 mock collector 验证 `/v1/metrics`、`/v1/logs`、`/v1/traces` 三类 payload 均发送且不泄漏 body 内容。

## 10. P7 Admin API 与 Dashboard MVP

**目标**：提供基础控制平面和可用的后台管理入口。

### 任务

- [x] 实现 Admin API 版本化路由。（当前提供 `/admin/v1/status`、`/admin/v1/providers`、`/admin/v1/models`、`/admin/v1/api-keys`、`/admin/v1/policies`、`/admin/v1/tenants`、`/admin/v1/request-logs`、`/admin/v1/billing-events`、`/admin/v1/usage-aggregates`、`/admin/v1/audit-events`、`POST /admin/v1/config/validate`、`POST /admin/v1/config/reload`；`/admin/status` 保留为兼容入口。）
- [x] 明确 Admin API 使用的 Rust Web 框架仅限管理面，不能替代 Pingora 代理 runtime。（当前只读 Admin API 直接由 Pingora 本地 handler 暴露，未引入管理面 Web 框架。）
- [x] Admin API 接入 RBAC。（当前只读端点统一要求 `admin.read` scope，候选配置校验写操作要求 `admin.write` scope。）
- [x] 所有写操作写审计日志。（当前 MVP 唯一写操作是候选配置校验，不修改运行中配置，但会写入 audit event；后续新增 mutating CRUD 时必须复用该审计边界。）
- [x] 实现组织、团队、项目、用户、API Key、Provider、Model、Policy、Usage、Request Log 查询接口。（当前组织/团队/项目/用户先通过 API Key tenant ref 视图暴露；后续独立组织/用户实体待存储模型扩展。）
- [x] Dashboard 通过 Admin API 访问数据。（当前静态 Dashboard 浏览器端只请求 `/healthz` 与 `/admin/v1/*` JSON 接口，不注入 Rust 内部状态快照。）
- [x] 实现 Overview、API Key、Provider、Model、请求日志、Token 用量、审计、候选配置校验、网关健康页面。

### 验收标准

- [x] Dashboard 不直接访问内部状态。
- [x] Admin API 写操作可审计。
- [x] 常见管理任务可以通过 UI 完成。（当前 MVP 覆盖状态查看、资源查看、请求/用量/审计查看、候选配置校验；持久化 CRUD 与运行时配置切换留给后续生产增强切片。）
- [x] 权限不足会返回统一错误。
- [x] 管理面框架依赖不会进入代理关键路径。

**进度**：100%。

**验收结果**：

```bash
cargo test -p ferrogate-storage -- --nocapture
cargo test -p ferrogate-cli --test ai_proxy_runtime openai_models_and_chat_non_streaming_dispatch_work -- --nocapture
cargo test -p ferrogate-cli state -- --nocapture
cargo test -p ferrogate-cli --test runtime_perf admin_dashboard_static_debug_perf_smoke -- --nocapture
cargo test -p ferrogate-cli --test ai_proxy_perf openai_chat_concurrent_dispatch_debug_perf_smoke -- --nocapture
cargo clippy -p ferrogate-cli --all-targets --all-features -- -D warnings
cargo clippy -p ferrogate-storage --all-targets --all-features -- -D warnings
npm --prefix ferrogate-wiki run wiki:build
```

2026-05-04 本轮启动 P7：`ferrogate-storage` 的 request log 与 usage aggregate 等存储模型支持 serde 序列化；`ferrogate-cli` 暴露版本化 Admin API 只读入口 `/admin/v1/status`、`/admin/v1/request-logs`、`/admin/v1/billing-events`、`/admin/v1/usage-aggregates`，全部复用 `admin.read` 鉴权。AI Proxy 集成测试覆盖成功请求后通过 Admin API 查询 request log、billing event 和 usage aggregate，普通 client key 访问 Admin API 会被 `scope_denied` 拒绝。

2026-05-04 本轮继续补齐 Admin API 查询面：新增 `/admin/v1/providers`、`/admin/v1/models`、`/admin/v1/api-keys`、`/admin/v1/policies`、`/admin/v1/tenants`。Provider 响应只暴露 `has_api_key`，不返回 `api_key_env`；API Key 响应只返回 `key_source` 和权限/租户元数据，不返回明文 key、hash 或 env 名称。集成测试覆盖这些端点的 `admin.read` 访问、secret 不回显，以及普通 client key 被拒绝。

2026-05-04 本轮新增 Pingora 本地静态 Dashboard：`/admin`、`/admin/`、`/admin/dashboard` 返回内置 HTML/JS/CSS，页面通过浏览器端 bearer token 调用 `/admin/v1/status`、`/admin/v1/api-keys`、`/admin/v1/providers`、`/admin/v1/models`、`/admin/v1/request-logs`、`/admin/v1/usage-aggregates`、`/admin/v1/billing-events` 与 `/healthz`，覆盖 Overview、API Key、Provider、Model、请求日志、Token 用量和网关健康视图。集成测试验证 Dashboard 可访问、页面只包含 Admin API endpoint 引用、不回显 client/admin/provider secret；性能 smoke 覆盖 100 次 Dashboard 顺序请求 p95、16 并发请求和 RSS 增长边界。

2026-05-04 本轮完成 P7 写操作审计 MVP：`ferrogate-storage` 新增 `StoredAuditEvent` 与 `AuditLogRepository` 边界，`AppState` 持有 in-memory audit event sink；Admin API 新增 `GET /admin/v1/audit-events`、`POST /admin/v1/config/validate` 与 `POST /admin/v1/config/reload`。候选配置校验要求 `admin.write`，可解析/校验提交的 TOML/Caddyfile 或 `source=file` 当前启动配置并返回 snapshot 或字段级错误；process-local reload 仅在不改变 listener/TLS 时替换运行中请求状态。每次授权写操作都会记录 actor API key、request/trace、action、target、outcome 和 message。Dashboard 新增 Config 与 Audit 视图，并支持 TOML/Caddyfile candidate 和 file source reload 格式选择；集成测试覆盖 `admin.write` 成功/失败校验、审计事件 accepted/rejected/committed 记录、普通 client key 被 `scope_denied` 拒绝，以及 secret 不回显。

## 11. P8 生产级可靠性、安全和部署增强

**目标**：补齐生产运行需要的治理、可靠性、安全和部署能力。

### 任务

- [x] 实现熔断器。（当前提供全局 Provider circuit breaker：配置 `reliability.provider_circuit_breaker_failure_threshold` 与 `reliability.provider_circuit_breaker_cooldown_secs` 后，连续可重试失败会打开 provider 熔断，后续候选会在冷却期内跳过该 provider 并尝试 fallback。）
- [x] 实现请求限流和 Token 限流。（当前实现 per-API-key 60 秒请求窗口；Token 预算采用 new-api 启发的请求前预留、成功后按真实 provider usage 结算、失败路径自动释放；provider 未返回 usage 或 streaming 响应会记录 gateway estimate 并标记 `usage_source = gateway_estimate`。）
- [x] 实现超时、重试、fallback 策略。（当前支持 `reliability.provider_dispatch_timeout_secs` 控制 provider connect/read/write 超时，`reliability.provider_dispatch_max_retries` 控制 retryable 5xx/429 或 dispatch error 在当前 provider 上的重试次数；重试耗尽后继续走已有 fallback 和熔断路径。）
- [x] 实现 Provider 健康检查和健康看板。（当前提供 `/admin/v1/provider-health`，使用短超时 TCP 可达性探测 `providers[].base_url` 的 host/port，不调用模型接口、不携带 provider secret；Dashboard Health 页展示 provider status、reachable、circuit_open 和 consecutive_failures。）
- [x] 完善 TLS 配置和证书加载。（当前支持 TOML `[tls]` 手动证书、Caddyfile `tls cert.pem key.pem`、以及 `[tls.acme]` / Caddyfile `tls { issuer acme ... dns exec ... }` 的 ACME DNS-01 自动证书启动签发。配置加载会按配置文件目录解析相对路径，并在 validate 阶段提前拒绝缺失或冲突的 TLS/ACME 配置；运行时会按配置启动 TLS listener，可选 `tls.http2 = true` 开启 h2 ALPN。）
- [x] 增加供应链与安全检查，例如 `cargo deny`、secret 扫描、依赖审计。（当前 `scripts/security-check.sh` 固定运行 `cargo fmt --check`、workspace clippy、`cargo metadata --locked` 和高置信 secret scan；本地未安装 `cargo deny`/`cargo audit` 时默认明确跳过，CI 通过 `FERROGATE_SECURITY_REQUIRE_TOOLS=1` 强制要求工具存在；`deny.toml` 固化 license/bans/sources 策略，`.cargo/audit.toml` 固化 RustSec 审计策略和 Pingora metrics 依赖链的临时 advisory 例外。）
- [x] 增加性能基准和 streaming 压测。（当前已有 AI chat 非流式顺序/并发、鉴权错误路径、Dashboard/proxy runtime debug perf smoke；本轮新增 `stream=true` 32 并发 chat streaming smoke，覆盖 p95、RSS 增长、provider streaming body 透传和 secret 不泄漏。）
- [x] 编写部署文档、运维手册和容量评估指南。（当前新增 [[04-operations/self-hosting-runbook|Self-hosting runbook]]，覆盖 binary/Docker/systemd、自托管 TOML、TLS 证书、Provider secret、Admin health/metrics、graceful shutdown 停机窗口、容量估算、发布步骤和 incident runbook。）

### 验收标准

- [x] Provider 故障时可以自动 fallback。
- [x] 超限请求被稳定拒绝且有可观测记录。
- [x] 平滑关闭不会中断已接收的关键请求。（当前将 `reliability.graceful_shutdown_grace_period_secs` 与 `reliability.graceful_shutdown_timeout_secs` 透传到 Pingora；SIGTERM 触发 Pingora graceful terminate，部署文档要求 supervisor 停机窗口大于两者之和。）
- [x] 性能基准能体现代理路径开销和 streaming 内存表现。
- [x] 部署文档可以指导用户完成自托管安装。

**进度**：100%。

**验收结果**：

```bash
cargo fmt --check
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli config -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli state -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli --test ai_proxy_runtime provider_circuit_breaker -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli --test ai_proxy_auth limit -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli --test ai_proxy_auth budget -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli gateway::dispatch -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli gateway::chat -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli --test ai_proxy_runtime retry -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli --test ai_proxy_runtime provider_health -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-config -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli --test proxy_runtime tls_listener_serves_healthz_when_certificate_is_configured -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli --test ai_proxy_perf streaming -- --nocapture
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo test -p ferrogate-cli pingora_server_conf_uses_graceful_shutdown_settings -- --nocapture
FERROGATE_SECURITY_REQUIRE_TOOLS=1 ./scripts/security-check.sh
PATH="$PWD/.jcode/cmake-venv/bin:$PATH" cargo clippy -p ferrogate-cli --all-targets --all-features -- -D warnings
npm --prefix ferrogate-wiki run wiki:build
```

2026-05-04 本轮启动 P8：`Config` 新增 `[reliability]` 配置节，支持 `provider_circuit_breaker_failure_threshold` 和 `provider_circuit_breaker_cooldown_secs`，并做成对字段校验，避免半配置或 0 值造成不明确行为。`AppState` 新增 provider 熔断状态，AI Proxy 在 provider dispatch 前检查熔断；连续可重试 provider 5xx 或 dispatch error 达到阈值后打开熔断，冷却期内跳过该 provider 并继续尝试 fallback。新增状态层单元测试覆盖熔断打开、成功重置和默认关闭；新增真实网关集成测试验证 primary 连续 503 后第三次请求不再打 primary，而直接走 fallback，响应不泄漏 client secret。

2026-05-04 本轮继续推进 P8：`AppState` 新增 per-API-key 请求窗口和 API Key Token usage 查询，`authenticate` 在 scope 通过后执行真实 `request_limit_per_minute` 消耗，超过 60 秒窗口限制返回 `rate_limit_exceeded`；`monthly_token_budget` 会读取已记录 usage aggregate，达到预算后返回 `token_budget_exceeded`，并且拒绝路径不会触达 provider。新增状态层测试覆盖请求窗口限流；新增真实网关集成测试覆盖 `request_limit_per_minute = 1` 第二次请求 429 且 provider 只收到 1 次请求，以及 `monthly_token_budget = 8` 在首次成功记录 8 tokens 后第二次请求 429 且不泄漏 secret。

2026-05-04 本轮采用方案 B 推进 Token 统计计费：保留 FerroGate 的 `TokenUsage` + `CostEstimate` 模型，借鉴 new-api 的“预扣/结算”生命周期。`BillingEvent` 新增 `usage_source`，区分 provider 返回的真实 usage 与 gateway 估算；`AppState` 新增 API Key Token reservation，chat 请求在 provider dispatch 前按 prompt 估算和 `max_tokens`/`max_completion_tokens` 预留预算，预算不足直接返回 `token_budget_exceeded` 且不触达 provider；成功响应优先按 provider usage 写账，缺失 usage 或 streaming 响应按 gateway estimate 写账并释放预留，失败路径由 reservation drop 兜底释放。新增单元测试覆盖预留释放、估算 usage 事件和 chat 估算；新增真实网关集成测试覆盖预算不足时 provider 收到 0 次请求。

2026-05-04 本轮继续推进 P8：`ReliabilityConfig` 新增 `provider_dispatch_timeout_secs` 和 `provider_dispatch_max_retries`。Provider dispatch 改为使用配置化 connect/read/write timeout，默认保持 10 秒；非流式请求和 streaming 首包前请求在 retryable 5xx/429 或 dispatch error 时会先重试当前 provider，达到最大重试次数后再进入既有 fallback/熔断路径。新增 dispatch 单元测试覆盖读超时生效，新增真实网关集成测试覆盖 provider 首次 503、同 provider 重试后 200 成功且不触发 fallback。

2026-05-04 本轮补齐 Provider 健康检查和健康看板：`AppState` 新增 provider health snapshot，按需对 `providers[].base_url` 执行短超时 TCP 可达性探测，同时叠加 circuit breaker 的 open/failure 状态；Admin API 新增 `/admin/v1/provider-health`，复用 `admin.read` 鉴权，响应不包含 provider secret 或环境变量名。Dashboard Health 页改为展示 provider health rows，并汇总 healthy/unhealthy provider 数量。新增状态层单元测试覆盖 disabled provider 不探测，新增真实网关集成测试覆盖 provider 可达时返回 `status = healthy` 且不泄漏 secret。

2026-05-04 本轮补齐本地安全检查门禁：新增 `scripts/security-check.sh`，不引入新依赖，按顺序执行 `cargo fmt --check`、`cargo clippy --workspace --all-targets --all-features -- -D warnings`、`cargo metadata --locked --format-version=1` 和高置信 secret scan（private key、AWS/GitHub/OpenAI/Anthropic/Google API key 形态）。若本机安装 `cargo deny` 或 `cargo audit`，脚本会自动运行供应链/license/advisory 检查；未安装时明确输出 skipped。README 增加本地安全检查使用说明，本轮已运行脚本并通过。

2026-05-04 本轮继续完善供应链门禁：本地已安装 `cargo-deny 0.19.4` 和 `cargo-audit 0.22.1`；仓库新增 `deny.toml`，将 `cargo deny` 职责限定为 licenses/bans/sources，避免与 `cargo audit` 重复输出 advisory；新增 `.cargo/audit.toml`，记录 `RUSTSEC-2024-0437` 的临时例外，原因是当前 `pingora-core 0.8 -> prometheus 0.13 -> protobuf 2.x` 无法通过 `cargo update` 解除，且 FerroGate 请求路径不直接解析 protobuf。`scripts/security-check.sh` 新增 `FERROGATE_SECURITY_REQUIRE_TOOLS=1` 严格模式，并新增 `.github/workflows/security.yml` 在 PR、main push 和手动触发时安装 `cargo deny`/`cargo audit` 后运行同一门禁。当前 `cargo audit` 仍保留 `daemonize`、`derivative`、`rustls-pemfile` 的 unmaintained warning，后续需跟进 Pingora/rustls-native-certs 升级路径。

2026-05-04 本轮继续收敛供应链噪声：`ferrogate-cli` 的直接 `rustls-native-certs` 依赖升级到 `0.8.3`，并适配其 `CertificateResult` API，使 FerroGate 自己的 provider HTTPS dispatch 与 OTLP/HTTPS sender 不再直接依赖 `rustls-native-certs 0.7`；`rustls-pemfile` warning 现在只剩 `pingora-rustls 0.8` 内部路径。`deny.toml` 为当前 Pingora 0.8 固定的重复版本加入带原因的 skip 项，`cargo deny check licenses bans sources` 输出已收敛为 `bans ok, licenses ok, sources ok`，CI 日志不会再被已知 transitive duplicate 图刷屏。

2026-05-04 本轮补齐手动 TLS listener：typed config 新增 `[tls]`，支持 `enabled`、`cert_path`、`key_path` 和 `http2`；Caddyfile adapter 会把 `tls cert.pem key.pem` 映射到同一配置模型。配置加载会把 TLS 相对路径解析到配置文件目录，validate 阶段通过 Pingora/rustls 加载证书链和私钥，提前拒绝缺失、空值或无法解析的证书材料；`ferrogate run` 在 TLS 启用时使用 Pingora `TlsSettings` 启动 TLS listener，`http2 = true` 时开启 h2/h1 ALPN。新增 Caddyfile parser 测试、config 校验测试和真实进程 TLS healthz 测试，使用临时自签证书验证 `/healthz` 可通过 TLS 访问。

2026-05-04 本轮补齐 ACME DNS-01 自动 HTTPS MVP：`TlsConfig` 新增 `[tls.acme]`，支持 `domains`、`email`、`directory_url`、`storage_dir`、`dns_provider`、`dns_config`、`dns_hook_set`、`dns_hook_cleanup` 和 `dns_propagation_delay_secs`；手动 `cert_path/key_path` 与 ACME 自动证书互斥，避免 listener 启动材料不明确。运行时在 Pingora TLS listener 启动前复用已有 `fullchain.pem/privkey.pem`，缺失或无效时通过 `instant-acme` 创建/恢复 ACME 账号、创建订单、调用 DNS-01 set hook 写 TXT、等待传播、完成 challenge、下载证书并写入 storage。Caddyfile adapter 新增 `tls { issuer acme { email ... } storage ... dns exec <set> <cleanup> { provider ... <key> <value> } }` 子集，site host 会映射为 ACME domain；hook 不再通过环境变量接收 challenge/provider 数据，而是由 FerroGate 写入 0600 JSON payload 文件并以 `<hook> <action> <payload-json-path>` 调用，DNS 厂商配置统一来自配置文件。新增 ACME helper 单元测试、配置校验测试、TOML/Caddyfile 路径解析测试和 Caddyfile parser 测试；当前 renewal 为启动时复用/签发，运行中热续期和无重启证书 reload 进入后续 listener 管理任务。

2026-05-04 本轮继续补齐 ACME HTTP-01：`[tls.acme]` 支持 `challenge = "http-01"` 与 `http_challenge_listen`，validate 阶段拒绝 HTTP-01 wildcard domain，并允许 HTTP-01 不配置 DNS hooks。签发期间 FerroGate 会在主 HTTPS listener 启动前临时启动 HTTP-01 challenge server，服务 `/.well-known/acme-challenge/<token>`，order ready 后关闭临时 server 并继续下载证书、启动 Pingora TLS listener。新增 HTTP-01 challenge server 单元测试、HTTP-01 配置校验测试和 Caddyfile `challenge http-01` parser 测试。

2026-05-04 本轮补齐 ACME 实机验证链路：构建 `ferrogate-acme-test:20260504` Docker 镜像并推送到 `47.98.57.86`，使用 Let’s Encrypt staging 对 `token4aicloud.com` 执行 HTTP-01 实测。FerroGate 容器成功启动临时 challenge server 并发布 80/443，但 staging CA 返回 `urn:ietf:params:acme:error:connection`，错误详情为连接 `47.98.57.86:80` 超时；服务器本机 firewall/iptables/nftables 未发现 INPUT 拒绝规则，tcpdump 未看到本地强制解析 curl 请求进入公网网卡，当前阻塞点判定为云厂商安全组/公网入站路径/域名代理规则，而不是 FerroGate HTTP-01 实现。DNS-01 侧新增内置 Cloudflare provider，凭据仍来自 `dns_config`，不使用环境变量，也不引入 Python/script 运行时；测试镜像只包含 FerroGate 二进制和 CA 证书，后续填入 Cloudflare `api_token` + `zone_id`/`zone_name` 后可直接执行 DNS-01 staging 签发。

2026-05-04 本轮完成 ACME HTTP-01 与 DNS-01 实机闭环：用户放通 `47.98.57.86` 的 80/443 后，HTTP-01 staging 与 production 均成功签发 `token4aicloud.com` 证书，外部严格 HTTPS `/healthz` 校验通过。DNS-01 侧使用 Cloudflare API Token 完成 staging 与 production 签发，过程中发现并修复两个真实问题：Cloudflare API 返回 chunked response 时内置 HTTP parser 未解 chunk，导致 JSON parse 失败；DNS-01 原流程在 TXT 写入后立即 `set_ready`，传播等待发生在 ACME server 开始验证之后，导致 Let’s Encrypt 查询 NXDOMAIN。修复后流程为写入 TXT -> 等待 `dns_propagation_delay_secs` -> `set_ready` -> poll order，production DNS-01 签发成功，外部严格 HTTPS 校验显示 Issuer 为 Let’s Encrypt E8，SAN 匹配 `token4aicloud.com`，签发后的 `_acme-challenge.token4aicloud.com` TXT 已由 FerroGate 清理。

2026-05-04 本轮补齐 streaming 性能 smoke：`ai_proxy_perf` 新增 `openai_chat_streaming_concurrent_dispatch_debug_perf_smoke`，以 32 并发请求访问 `/v1/chat/completions` 的 `stream=true` 路径，断言响应包含 SSE chunk 和 `[DONE]`、provider 请求体保持 streaming 标记、client secret 不回显、p95 低于 500ms 且 RSS 增长不超过 32MB。本地已与既有非流式 perf smoke 一起运行通过。

2026-05-04 本轮完成 P8 收尾：`ReliabilityConfig` 新增 `graceful_shutdown_grace_period_secs` 和 `graceful_shutdown_timeout_secs`，启动 Pingora server 时透传到 `ServerConf`，让 SIGTERM graceful terminate 的等待窗口可由 FerroGate 配置控制；新增单元测试覆盖配置透传，并在 `config/ferrogate.example.toml` 给出默认生产建议。运维文档新增 [[04-operations/self-hosting-runbook|Self-hosting runbook]]，覆盖 binary/Docker/systemd、自托管 TOML、TLS 证书、Provider secret、Admin health/metrics、容量估算、发布步骤和 incident runbook；`user-guide`、wiki index、overview、roadmap 与 PRD 均已同步。

## 12. 每一步实现后的进度更新规范

每完成一个任务，必须更新：

1. 对应 checklist。
2. 阶段 `进度` 百分比。
3. `进度总览` 表格中的状态和当前产出。
4. 相关 PRD、架构或开发文档链接。
5. 验收命令和结果，例如：

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo test --workspace
```

状态枚举：`未开始`、`进行中`、`已阻塞`、`待验收`、`已完成`。

## 13. 阶段完成定义

一个阶段只有同时满足以下条件才可以标记为 `已完成`：

1. 阶段内所有 checklist 已完成或明确移入后续阶段。
2. 验收标准全部通过。
3. 相关测试已提交。
4. 文档已同步更新。
5. 当前阶段产出可以被下一阶段直接依赖。
6. 若发现 PRD 或架构假设不成立，必须先更新 PRD/ADR/架构文档再继续实现。
