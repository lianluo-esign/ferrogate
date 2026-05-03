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
| P2 | 配置校验、生命周期和平滑重载 | 进行中 | 80% | 已完成字段级诊断、Secret env 引用、admin typed config、配置 snapshot 可观测性、reload 状态机契约、CLI lifecycle 接入和 serde roundtrip |
| P3 | OpenAI-compatible AI Proxy MVP | 已完成 | 100% | 已实现 OpenAI-compatible Adapter MVP、adapter registry 解耦、`/v1/models`、HTTP/HTTPS chat completion dispatch、`stream=true` 增量式 SSE forwarding、Provider 错误归一化、usage 提取接口、鉴权/模型路由负例和 AI dispatch/registry 性能并发 smoke |
| P4 | 虚拟 API Key、租户上下文与 Policy MVP | 已完成 | 100% | 已实现 API Key hash 生成/校验、disabled/expired/rate limit/budget exhausted 拒绝、模型/Provider allowlist、租户字段进入 AuthContext 与 chat route log、RBAC 领域模型、最小 deny-rule Policy Engine、AI Proxy 接入，以及 Key/Tenant/Policy repository 边界 |
| P5 | 多 Provider Adapter 与 Model Registry | 未开始 | 0% | 待实现多 Provider 抽象和逻辑模型路由 |
| P6 | 可观测性、请求日志、Storage 与计费事件 | 未开始 | 0% | 待集成 OpenTelemetry 和 usage/billing 存储接口 |
| P7 | Admin API 与 Dashboard MVP | 未开始 | 0% | 待实现管理面和基础后台页面 |
| P8 | 生产级可靠性、安全和部署增强 | 未开始 | 0% | 待实现限流、熔断、fallback、部署文档 |

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

- [ ] 完善 Caddyfile 风格监听器、路由、upstream、TLS、日志、Provider、模型、API Key 的配置模型。（已补齐 Caddyfile `admin` 到 typed config 的映射；TLS/Provider/API Key 的 Caddyfile 高级模型仍待后续切片。）
- [ ] 对照 Caddy 源码中的 `caddyconfig/caddyfile`、`caddyconfig/httpcaddyfile` 和关键 HTTP directive 行为，完善 FerroGate parser/adapter 设计。
- [x] 支持环境变量引用 Secret，并保证错误日志不泄漏 Secret。
- [x] 实现启动前配置校验和字段级错误诊断。
- [ ] 设计并实现 Pingora-backed 平滑重载接口。（已定义 validate-only/no-swap 候选 reload 契约、runtime reload 状态机，并已接入 CLI lifecycle；Pingora 运行中 swap 待实现。）
- [x] 设计配置快照、版本号和回滚语义。
- [x] 补充 `ferrogate run`、`ferrogate validate`、未来 `ferrogate reload` 命令约定。
- [x] 更新 [[03-development/development-workflow|Development workflow]]。

### 验收标准

- [x] 示例 `Ferrogate/Caddyfile` 可通过校验。
- [x] 无效配置可以返回字段级错误。
- [x] 配置模型有 serde roundtrip 测试。
- [x] 平滑重载设计文档同步更新。
- [x] reload 失败不会破坏当前运行配置。（runtime reload 状态机已覆盖 candidate reject 保留 active snapshot；Pingora 连接级平滑 reload 待实现。）

**进度**：80%。

**验收结果**：

```bash
cargo test -p ferrogate-cli config::tests -- --nocapture
cargo test -p ferrogate-cli config::snapshot -- --nocapture
cargo test -p ferrogate-cli lifecycle -- --nocapture
cargo test -p ferrogate-runtime -- --nocapture
cargo test -p ferrogate-config --test caddyfile_parser -- --nocapture
cargo test -p ferrogate-cli --test check_command -- --nocapture
cargo test -p ferrogate-cli --test proxy_runtime -- --nocapture
cargo run -- validate --config Ferrogate/Caddyfile
cargo run -- reload --config Ferrogate/Caddyfile
```

以上命令已通过。当前 `reload` CLI 仍是 validate-only/no-swap 契约，会输出候选配置 snapshot id；invalid candidate 会在 swap 前失败。CLI lifecycle 已通过 `ferrogate-runtime` 的 prepare/reject 路径生成报告，保证 rejected candidate 不覆盖 active snapshot。`Ferrogate/Caddyfile` 的 `admin localhost:2019` 已进入 typed config，`/admin/status` 会暴露 active snapshot。真正接入 Pingora 运行中服务替换和连接级平滑 reload 仍留在 P2 后续切片。

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
npm run wiki:build
```

当前 P3 覆盖 OpenAI-compatible adapter 的模型改写、stream flag 保留、非对象 body 拒绝、unsupported provider kind 拒绝、Provider Secret debug 脱敏、Provider 错误归一化、usage 提取接口和 adapter registry 解耦，以及真实 `ferrogate run` 进程下的 `/v1/models`、`/v1/chat/completions` 非流式 HTTP mock provider dispatch、HTTPS provider endpoint 连接失败归一化、`stream=true` 增量式 SSE response forwarding、`Authorization` 与 `x-api-key`、missing/invalid/scope/model deny 负例、provider Authorization header、provider body 模型改写、逻辑模型名不透传、provider/client secret 响应脱敏。

## 7. P4 虚拟 API Key、租户上下文与 Policy MVP

**目标**：实现基础企业级访问控制和租户隔离，满足 PRD 中 P4 对虚拟 API Key、租户上下文和 Policy MVP 的要求。

### 任务

- [x] 实现虚拟 API Key 生成、Hash 存储和校验。（当前提供 `ferrogate hash-key --secret ...` 生成 `blake2b:` hash，配置支持 `key_hash` 校验；生产级 key ID/secret 生成流程待 Admin API 切片。）
- [x] 定义 Organization、Team、Project、User、Service Account、Role、Permission、Policy 模型。
- [x] API Key 解析到唯一租户上下文。（当前从配置中的 `organization_id`、`team_id`、`project_id`、`user_id`、`api_key_id` 进入 `AuthContext`，chat route log 会记录非敏感租户字段。）
- [x] 基于 `ferrogate-storage` 定义 Key、Tenant、Policy repository。（已定义 `ApiKeyRepository`、`TenantRepository`、`PolicyRepository` 和 in-memory 实现；运行路径仍使用配置内存态，生产级持久化实现待后续切片。）
- [ ] 实现模型 allowlist/denylist。
- [x] 实现 Provider allowlist/denylist。（当前支持 API Key 级 `allowed_providers`，在 provider dispatch 前拒绝。）
- [x] 实现基础请求频率限制和 Token 预算占位接口。（当前支持 `request_limit_per_minute = 0` 与 `monthly_token_budget = 0` 的 exhausted 占位拒绝；真实滑动窗口和用量累加待 P6 storage/billing 切片。）
- [x] 将 Auth 和 Policy 接入 P3 AI Proxy 请求路径。（Auth 与最小 deny-rule `BasicPolicyEngine` 已在 provider dispatch 前执行。）

### 验收标准

- [x] 被禁用、过期、超限、无权限 Key 会被拒绝。（当前覆盖 disabled、expired、`request_limit_per_minute = 0`、`monthly_token_budget = 0`、scope/model/provider/policy deny。）
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

2026-05-03 本轮启动 P4：`ApiKey` 配置新增 `allowed_providers` 与 `expires_at_unix`，`authenticate` 会对 disabled、expired、budget exhausted、scope deny 进行统一错误拒绝；`chat` 请求路径在 model/provider 解析后执行 Provider allowlist，并在 route planning log 中记录 `api_key_id`、`organization_id`、`project_id`、logical/provider model 和 stream 标记，避免记录 secret。

2026-05-03 本轮继续接入最小 Policy Engine：`ferrogate-policy` 新增 `BasicPolicyEngine`、`PolicySubject` 与 deny-rule `PolicyRule`，CLI 配置新增 `[[policies]]`，并在 AI Proxy provider dispatch 前执行策略决策；配置校验会提前拒绝 policy 或 API key allowlist 中不存在的 api key、model、provider 引用。

2026-05-03 本轮继续补齐虚拟 API Key hash 能力：`ApiKey` 配置新增 `key_hash`，`authenticate` 同时支持明文开发 key、环境变量 key 和 `blake2b:` hash 校验；新增 `ferrogate hash-key --secret ...` 用于生成配置 hash，并有命令测试确保输出不回显原始 secret。

2026-05-03 本轮继续补齐 storage 边界：`ferrogate-storage` 新增 `StoredApiKey`、`StoredTenant`、`StoredPolicyRule`，并定义 `ApiKeyRepository`、`TenantRepository`、`PolicyRepository` 与 in-memory repository 测试，为后续从配置内存态迁移到持久化控制面保留边界。

2026-05-03 本轮继续补齐限流占位：`ApiKey` 配置新增 `request_limit_per_minute`，当值为 `0` 时 AI Proxy 在 provider dispatch 前返回 `rate_limit_exceeded`；这与 `monthly_token_budget = 0` 一起作为 P4 的本地策略占位，真实计数窗口待 P6。

2026-05-03 本轮继续补齐 RBAC 领域模型：`ferrogate-auth` 新增 `Organization`、`Team`、`Project`、`User`、`ServiceAccount`、`Role`、`Permission`、`PolicyBinding` 与 `PolicySubject`，为后续 Admin API、Storage repository 和控制面权限配置复用。

2026-05-03 本轮完成安全日志脱敏复核：当前 tracing 调用不输出 secret、Authorization、`key`、`key_hash` 或 provider API key；`hash-key`、`validate`、`reload`、AI Proxy 鉴权与 provider dispatch 测试均覆盖响应/命令输出不回显 secret。

## 8. P5 多 Provider Adapter 与 Model Registry

**目标**：抽象不同 AI Provider 差异，支持逻辑模型路由、fallback 和权重路由。

### 任务

- [ ] 完善 Provider Adapter trait，覆盖请求转换、响应转换、Streaming、错误归一化、usage 提取、可重试判断。
- [ ] 实现 OpenAI Adapter。
- [ ] 实现 Anthropic Adapter。
- [ ] 实现 Gemini Adapter。
- [ ] 实现 Grok Adapter。
- [ ] 实现 Azure OpenAI Adapter。
- [ ] 定义 Model Registry、模型别名、模型能力、价格和上下文长度。
- [ ] 实现优先级 fallback 和权重路由。
- [ ] 支持租户级模型可见性。

### 验收标准

- [ ] 每个 Adapter 支持鉴权注入、请求转换、响应转换、错误归一化、usage 提取。
- [ ] 逻辑模型可以路由到不同 Provider 模型。
- [ ] fallback 过程有 trace span 和日志字段。
- [ ] Provider Adapter 单元测试覆盖典型错误和 streaming 事件。

**进度**：0%。

## 9. P6 可观测性、请求日志、Storage 与计费事件

**目标**：提供 AI Gateway 需要的追踪、指标、审计、请求日志和成本统计能力。

### 任务

- [ ] 集成 OpenTelemetry traces、metrics、logs。
- [ ] 定义 PRD 中要求的 span 层级。
- [ ] 实现结构化请求日志模型和 repository。
- [ ] 实现 Token usage 提取和估算接口。
- [ ] 实现模型价格表和成本计算。
- [ ] 实现 Billing Event 模型和异步写入接口。
- [ ] 支持按租户策略控制 prompt/response body 记录。
- [ ] 提供 in-memory/file storage，预留 SQLite/Postgres 实现边界。

### 验收标准

- [ ] 每次请求都有 request_id 和 trace_id。
- [ ] 日志包含 PRD 要求的核心字段。
- [ ] Token 和成本可以按组织、项目、API Key、模型聚合。
- [ ] 敏感字段默认脱敏。
- [ ] Billing Event 写入失败不会明显阻塞响应路径。

**进度**：0%。

## 10. P7 Admin API 与 Dashboard MVP

**目标**：提供基础控制平面和可用的后台管理入口。

### 任务

- [ ] 实现 Admin API 版本化路由。
- [ ] 明确 Admin API 使用的 Rust Web 框架仅限管理面，不能替代 Pingora 代理 runtime。
- [ ] Admin API 接入 RBAC。
- [ ] 所有写操作写审计日志。
- [ ] 实现组织、团队、项目、用户、API Key、Provider、Model、Policy、Usage、Request Log 查询接口。
- [ ] Dashboard 通过 Admin API 访问数据。
- [ ] 实现 Overview、API Key、Provider、Model、请求日志、Token 用量、网关健康页面。

### 验收标准

- [ ] Dashboard 不直接访问内部状态。
- [ ] Admin API 写操作可审计。
- [ ] 常见管理任务可以通过 UI 完成。
- [ ] 权限不足会返回统一错误。
- [ ] 管理面框架依赖不会进入代理关键路径。

**进度**：0%。

## 11. P8 生产级可靠性、安全和部署增强

**目标**：补齐生产运行需要的治理、可靠性、安全和部署能力。

### 任务

- [ ] 实现熔断器。
- [ ] 实现请求限流和 Token 限流。
- [ ] 实现超时、重试、fallback 策略。
- [ ] 实现 Provider 健康检查和健康看板。
- [ ] 完善 TLS 配置和证书加载。
- [ ] 增加供应链与安全检查，例如 `cargo deny`、secret 扫描、依赖审计。
- [ ] 增加性能基准和 streaming 压测。
- [ ] 编写部署文档、运维手册和容量评估指南。

### 验收标准

- [ ] Provider 故障时可以自动 fallback。
- [ ] 超限请求被稳定拒绝且有可观测记录。
- [ ] 平滑关闭不会中断已接收的关键请求。
- [ ] 性能基准能体现代理路径开销和 streaming 内存表现。
- [ ] 部署文档可以指导用户完成自托管安装。

**进度**：0%。

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
