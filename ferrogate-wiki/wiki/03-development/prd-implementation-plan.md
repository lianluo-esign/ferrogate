<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-06-11
  GEO/SEO: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
-->

# FerroGate PRD Implementation Plan

> 本文件恢复为持续开发任务源。当前仓库中的旧 Markdown 源已缺失，只保留了
> `ferrogate-wiki/wiki-site/public/03-development/prd-implementation-plan.html`
> 构建产物；本轮从 `docs/roadmap.md` 和当前代码状态恢复最新可维护计划。

## 1. 当前阶段总览

| 阶段 | 名称 | 状态 | 进度 | 当前产出 |
| --- | --- | --- | --- | --- |
| P0 | 工程基线、crate 边界与 Caddyfile 配置契约 | 已完成 | 100% | Rust workspace、核心 crate skeleton、Caddyfile typed config model 已落地 |
| P1 | Pingora 通用 API Gateway Runtime 垂直切片 | 已完成 | 100% | 配置驱动反向代理、路由匹配、upstream pool、header/path rewrite、healthz 与测试已落地 |
| P2 | 配置校验、生命周期和平滑重载 | 已完成 | 100% | 字段级诊断、secret env、配置 snapshot、reload 状态机和 CLI 生命周期已落地 |
| P3 | OpenAI-compatible AI Proxy MVP | 已完成 | 100% | provider adapter registry、chat completions、SSE forwarding、provider error/usage 处理已落地 |
| P4 | Auth、Tenant、Policy 与 API Key 治理 | 已完成 | 100% | API Key 鉴权、租户上下文、模型/Provider allowlist、policy engine、请求限制和 token budget 已落地 |
| P5 | 多 Provider Adapter 与 Model Registry | 已完成 | 100% | OpenAI-compatible、Anthropic、Gemini、Grok、Azure OpenAI adapter 与 fallback routing 已落地 |
| P6 | 可观测性、请求日志、Storage 与计费事件 | 已完成 | 100% | 请求日志、billing event、usage aggregate、Prometheus、OTLP non-blocking sender 已落地 |
| P7 | Admin API 与 Dashboard MVP | 已完成 | 100% | 只读 Admin API、写操作审计、dashboard health/request/billing/audit 视图已落地 |
| P8 | 生产级可靠性、安全和部署增强 | 已完成 | 100% | 限流、熔断、fallback、TLS/ACME、graceful shutdown、security gate、self-hosting runbook 已落地 |
| P9 | Runtime stability hardening 与工程可维护性 | 进行中 | 85% | 已有 P9 runtime hardening；本轮补回任务源、阶段验证 skill，并拆分超 2000 行的 state 测试模块 |

## 2. P9 当前任务

- [x] 恢复可持续更新的 `prd-implementation-plan.md` Markdown 源。
- [x] 补回 `.jcode/skills/ferrogate-phase-validation/SKILL.md`，固化 fmt、clippy、单元测试、集成测试、延迟/RSS/并发性能测试顺序。
- [x] 拆分 `crates/ferrogate-cli/src/state.rs` 测试子模块，使生产实现文件回到 2000 行以内。
- [ ] 继续拆分 `state.rs` 中的 runtime route、provider health/circuit、admin pagination 等高内聚子模块。
- [ ] 设计并实现 durable storage adapter，替换当前只适合单进程生命周期的 in-memory repository。
- [ ] 完成 P9 全量验收：单元测试 -> 集成测试 -> 性能测试，并记录延迟、RSS 内存增长和并发结果。

## 3. P9 验收标准

- 单个生产源文件保持在 2000 行以内；新增代码优先按业务边界拆分。
- state/runtime/admin/storage 之间职责清晰，避免继续把 runtime 状态、管理分页、provider health 和 storage 逻辑集中到一个文件。
- 本地 validation skill 可复用，并能清楚记录 sandbox 阻塞与真实代码失败。
- `docs/roadmap.md` 与本文档同步反映当前阶段状态。

## 4. 本轮验证记录

2026-05-21:

- 通过：`cargo fmt --check`、`git diff --check`。
- 通过：生产 Rust 源文件行数复查，当前最大文件为 `crates/ferrogate-cli/src/state.rs` 1676 行，未超过 2000 行约束。
- 阻塞：`cargo test -p ferrogate-cli state -- --nocapture`、`cargo test --offline -p ferrogate-cli state -- --nocapture`、`cargo test --manifest-path crates/ferrogate-storage/Cargo.toml -- --nocapture`、`cargo test --manifest-path crates/ferrogate-core/Cargo.toml -- --nocapture`、`cargo test --manifest-path crates/ferrogate-billing/Cargo.toml -- --nocapture` 均在解析依赖阶段失败。当前本机 registry/cache 缺少 `instant-acme`，并且网络无法解析 `index.crates.io`。
- 未完成：集成测试和性能测试尚未执行到项目代码；需要在可访问 crates.io 或已缓存 `instant-acme` 的环境中复验。
