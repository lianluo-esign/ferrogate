<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-06-11
  description: Token4AI Cloud, FerroGate AI Gateway, TypeScript on Cloudflare Workers, agent-native AI traffic infrastructure.
-->

<p align="center">
  <img src="docs/assets/ferrogate-logo.svg" alt="FerroGate" width="440" />
</p>

# FerroGate

**语言：** [English](README.md) | 简体中文

FerroGate 是一个完全运行在 Cloudflare Workers 上的开源 AI 网关。它是 AI
流量的控制点：OpenAI 兼容与 Anthropic 原生推理 API、OpenAI 兼容的 Files + Batch
接口、带 canary 和 shadow 灰度的多供应商路由、带 scope 与**每租户 Durable Object
隔离**（每租户一个 SQLite 对象，运行时寻址、无需按租户部署）的虚拟 API Key、策略与
guardrail 检查、频率限制、配额与预付钱包、durable 的 Token 计量与计费、资产闭环、
MCP server、agent run，以及约 240 个操作的 Admin API。

它端到端由 TypeScript 编写，作为一组 Worker 部署，底层依赖 D1、R2、KV、
Durable Objects、Queues 和 Analytics Engine。

该项目也是 [Token4AI Cloud](https://token4ai.cloud) 背后的开源网关基础。

## 架构概览

`apps/` 下有 6 个可部署单元。其中 5 个是 Worker，第 6 个是 CLI 二进制。

| 可部署单元 | Worker 名称 | 说明 |
|---|---|---|
| `apps/gateway` | `ferrogate-gateway` | **数据面**。基于 Hono 的流式代理，负责推理、OpenAI 兼容的 Files + Batch 接口和资产接口，并定义每租户的 `TenantDataObject`。拥有 49 个 contract 操作。 |
| `apps/control-plane` | `ferrogate-control-plane` | **Admin API** —— 约 240 个 contract 操作（235 个在 `/admin/v1/**` 下，另有 `/admin` 页面和 `/metrics`），以及 admin-console 会话接口、SAML、OIDC 和 SCIM。 |
| `apps/mcp` | `ferrogate-mcp` | Model Context Protocol server：JSON-RPC 入口、OAuth 流程、会话、受治理的工具执行。6 个 contract 操作。 |
| `apps/agent-runtime` | `ferrogate-agent-runtime` | Agent run 与 job、A2A agent upstream，以及自托管 worker plane。15 个 contract 操作。 |
| `apps/telemetry` | `ferrogate-telemetry` | OTLP 接收端，写入 Analytics Engine。不拥有任何 contract 路由；其他 Worker 通过 service binding 向它投递。 |
| `apps/cli` | —— | `ferrogate` 管理 CLI。由 Bun 编译的二进制，不是 Worker。 |

`/healthz` 和 `/readyz` 在每个 Worker 中都有实现。

### 网关请求路径

进入 `apps/gateway` 的请求会按以下顺序穿过同一条表驱动的链路：

1. **Request id** 和请求指标。
2. **网络门禁** —— 鉴权前的 IP allow/deny，使得洪泛流量永远不会付出凭证
   查询的代价。
3. **Contract 鉴权** —— 面向全部 312 个操作的单一守卫，由路由 contract 的
   `auth.kind` / `auth.scope` / `rbac_action` 驱动。
4. **准入** —— 频率限制（Durable Object 计数器）、配额、月度预算、预付钱包
   hold。
5. **Guardrails** —— 请求阶段的内容检查。
6. **Drain 门禁** —— 整个 fleet 处于 drain 状态时，产生消费的操作返回
   `503 node_draining`。
7. **响应缓存** —— exact-match，或可选的 semantic 模式（内置 feature-hashing
   embedder + 余弦相似度，不依赖任何向量数据库），基于 Cache API。
8. **Zod 校验**，随后是**模型注册表**（逻辑模型、fallback、canary 与 shadow
   分流）。
9. **上游派发** —— 供应商适配器，配合熔断器 Durable Object、重试与 failover；
   SSE 分帧逐字节保留，客户端断开会中止上游请求。
10. **Durable 计量** —— ledger 行与 billing outbox 行在同一次 D1 `batch()`
    中提交，然后投递到 Queue。

鉴权之后，租户自有状态被路由到以租户 id 寻址、每租户一个的 SQLite Durable Object；共享控制面仍在单一 CONTROL D1 库中。这样无需为每个租户单独部署数据库即可隔离租户事务。

### 共享 package

`packages/` 下有 15 个 package。每个都直接导出 `src/*.ts` —— 没有单独的
构建步骤。

| Package | 职责 |
|---|---|
| `core` | 请求身份、租户/workspace 归属、tool 原语、审批策略、脱敏守卫、边界错误。 |
| `schemas` | Zod 传输层信封与 OpenAPI contract 注册表。 |
| `config` | 面向运维的配置模型、加载器与校验。 |
| `policy` | 纯函数式 allow/deny 规则、配额合并、workflow 执行预算。 |
| `guardrails` | 检测器契约与运行时，带 deadline、bulkhead、熔断状态和防 SSRF 的端点校验。 |
| `secrets` | Secret 引用解析：`env://`、`vault://`、`cf://`（Cloudflare Secrets Store）。 |
| `providers` | 供应商适配器 —— 输入规范化 plan，输出上游 wire 请求，再把响应/用量归一化回来。 |
| `routing` | 路由匹配，以及确定性的 canary/shadow 灰度选择。 |
| `storage` | 基于 D1/KV/R2 的持久化边界。 |
| `billing` | 价目表、计价、幂等 ledger、outbox 投递。 |
| `payments` | x402 / Solana 客户端 wire 契约（已降优先级）。 |
| `observability` | 日志、指标与 OTLP 请求构造。 |
| `cloudflare` | Cloudflare 账号管理 REST 接口（R2 bucket、受限 token、D1 数据库生命周期）。 |
| `sso` | SAML 2.0 Service Provider。 |
| `identity` | OIDC relying party 与 SCIM 2.0 provisioning。 |

### 使用到的 Cloudflare 产品

- **D1** —— 一个控制面数据库，加上每租户一个的数据库。迁移脚本在
  `sql/d1-ts/{control,tenant}/`。
- **R2** —— 资产对象存储。
- **KV** —— MCP OAuth 状态。
- **Durable Objects** —— 共 7 个类：频率限制器、供应商熔断器、shadow 预算
  （gateway）；MCP OAuth flow claim 与 MCP session（mcp）；agent run 状态与
  worker plane（agent-runtime）。
- **Queues** —— billing report outbox 的生产者。
- **Cache API** —— 响应缓存。
- **Analytics Engine** —— 遥测数据落库。
- **Service binding** —— gateway → telemetry。
- **Secrets Store** —— `cf://` secret 引用，在部署时绑定。
- **Workers AI** —— Llama Guard guardrail 检测器适配器。`[ai]` binding 在部署
  时提供，未写入仓库中提交的配置。

## 路由 contract

`docs/openapi/runtime-api-contract.json` 是运行时接口的权威来源：**312 个
操作**，每个都带有 `path`、`method`、`operation_id`、`visibility`、
`auth.kind`、`auth.scope` 和 `rbac_action`。每个 Worker 都直接导入它，而不是
重复声明一份；任何一个 app 若没有注册它应当拥有的操作，其 contract 测试就会
失败。

其中 admin 236 个、public 69 个、internal 7 个；鉴权类型为 bearer 298 个、
internal 6 个（worker plane 回调）、anonymous 6 个、method-dependent 1 个。
`docs/rewrite/ROUTE-MAP.md` 把每个操作分配到具体 Worker。Admin 接口的字段级
请求/响应体在 `docs/openapi/admin-api.openapi.json`。

## 明确不提供的能力

有三个操作是**挂载了、走完守卫、然后拒绝**的，返回
`501 capability_not_offered`：

- `POST /v1/functions/execute`
- `GET /v1/tools` 和 `POST /v1/tools/execute`

这是一个产品决策，不是故障，不是未完成的工作，也不是平台限制 —— backlog 中
没有任何条目跟踪它，它不是 bug。该决策、其理由，以及重新实现者需要知道的内容
记录在
[`docs/rewrite/DROPPED-CAPABILITIES.md`](docs/rewrite/DROPPED-CAPABILITIES.md)；
有一个测试硬编码了这个被放弃的集合，因此若不同步记录新的决策，就无法把拒绝
悄悄改回承诺。

## 快速开始

前置条件：[Bun](https://bun.sh)（版本由 `package.json` 的 `packageManager`
锁定）。Wrangler 和其他所有工具都作为 dev 依赖引入 —— 下面的离线流程不需要
全局安装、不需要 Cloudflare 账号，也不需要联网。

```bash
bun install
```

### 运行测试

```bash
bun run test        # 所有 workspace
bun run typecheck   # 所有 workspace 的 tsc --noEmit
bun run lint        # biome
```

`bun run test` 会分发到每个 workspace 自己的 `test` 脚本，**这一点很重要**：
有四个 workspace 在默认套件之后再串接了一次（`apps/gateway` 是两次）使用
非默认配置的 Vitest 运行 —— `apps/gateway`（rate-limit 与 tenancy harness）、
`apps/agent-runtime`（durable harness）、`packages/storage`（D1）和
`packages/routing`（Durable Objects）。在仓库根目录或这些 workspace 里直接跑
`vitest run` 会静默漏报。

只跑一个 workspace：

```bash
bun run --filter '@ferrogate/app-gateway' test
```

### 本地运行 Worker

`wrangler dev --local` 会用本地 D1/KV/R2/DO 状态启动真实的 `workerd`。请先
执行迁移 —— `wrangler dev` 会为每个 database id 生成一个空的 SQLite 文件，
并不会运行 `migrations_dir`，而网关会正确地拒绝服务一个空 schema：

```bash
cd apps/gateway
bunx wrangler d1 execute DB --local -y --file=../../sql/d1-ts/tenant/0001_init_tenant.sql
bunx wrangler d1 execute BILLING_DB --local -y --file=../../sql/d1-ts/control/0001_init_control.sql
bunx wrangler dev --local --ip 127.0.0.1 --port 8787
```

每个 app 也提供 `bun run dev`（`wrangler dev`）和 `bun run deploy`
（`wrangler deploy`）。

仓库中提交的 `[vars]` 是**fail-closed 的空值**：没有配置凭证时，每个需要鉴权
的路由都会在 handler 运行之前返回 `401`；没有配置供应商和模型时注册表为空，
任何模型都返回 `400 model_not_found`。本地会话可以用 `--var` 覆盖（端到端
测试就是这么做的），或使用被 gitignore 的 `.dev.vars`。

### 端到端测试

```bash
bun run test:e2e
```

Playwright 会用每个 app 生产用的 `wrangler.toml` 各启动一个真实的
`wrangler dev`，应用本地 D1 迁移，并通过 HTTP 驱动这些 Worker。这里没有浏览器
—— 每个 spec 都使用 `request` fixture。冷启动一个 `wrangler dev` 需要 35–50
秒，所以可以让它保持运行，测试套件会直接复用。

## 部署

Wrangler 是唯一的打包器，也是唯一的部署工具。没有独立的构建步骤：
`wrangler deploy` 会为每个 app 打包 `src/worker.ts`。

**首次部署前请先阅读
[`docs/rewrite/CLOUD-VERIFICATION.md`](docs/rewrite/CLOUD-VERIFICATION.md)。**
它是有序的操作手册，而这个顺序不是随意的 —— service binding 在部署时按名称
解析，因此 `ferrogate-telemetry` 必须先于 `ferrogate-gateway` 存在，跨 Worker
的 rate-limit binding 则必须在它之后接上。该文档还列出了仓库刻意不提交的前置
条件：

- `apps/*/wrangler.toml` 中每个 `database_id`、bucket 名、queue 名和 KV
  namespace id 都是占位符。仓库不提交任何真实账号 id、数据库 uuid 或 secret。
- 在第一个需要鉴权的请求之前，必须先执行 D1 迁移
  （`wrangler d1 migrations apply`）。
- Secret 通过 `wrangler secret put` 写入 —— admin-console 的 JWT secret，以及
  每个租户 SSO 的 `env://` 引用各一份。
- 有几个提交在仓库里的 `[vars]` 是开发态默认值，必须在部署环境中覆盖，而不是
  在提交的文件里改掉 —— 因为离线测试套件正是按这些值来驱动这些 app 的。

Durable Objects、Queues 和 Analytics Engine 需要 Cloudflare 付费套餐。

## 仓库结构

```text
apps/          6 个可部署单元 —— 5 个 Worker + CLI 二进制
packages/      15 个共享 TypeScript 库（仅源码，无构建步骤）
e2e/           基于真实 `wrangler dev` 的 Playwright 黑盒套件
sql/d1-ts/     D1 迁移：control/ 和 tenant/
docs/openapi/  路由 contract 与 admin OpenAPI 文档
docs/rewrite/  架构、测试、部署与 parity 记录
```

约 9 万行 TypeScript 源码和 11.4 万行测试代码：21 个 workspace、385 个文件、
7,051 个测试，另有 22 个 Playwright 端到端测试。

## 测试策略

三层，全部**离线、无需 Docker** 即可运行。见
[`docs/rewrite/TESTING.md`](docs/rewrite/TESTING.md)。

1. **单元与集成测试** —— Vitest 配合 `@cloudflare/vitest-pool-workers`，启动
   真实的本地 `workerd`。D1、KV、R2 和 Durable Object binding 是真正生效的，
   不是 mock。集成测试通过 `cloudflare:test` 的 `SELF` 派发请求。
2. **上游 mock** —— MSW 拦截网关对供应商主机的出站 `fetch()` 并返回预置的
   SSE，从而以确定性方式验证 Token 计数、流式归一化和 MCP 转发。永远不会真的
   调用 LLM。
3. **端到端** —— Playwright 驱动 `wrangler dev`，这是唯一会真正走通 Wrangler
   自身打包和 `workerd` service 注册的一层 —— 一个 Worker 可能在
   `SELF.fetch` 下完全正确，却仍然无法作为 service 启动。

## 文档

当前架构的文档在 `docs/rewrite/` 下：

- 架构与 package 映射：[`PORT-PLAN.md`](docs/rewrite/PORT-PLAN.md)
- 每个 Worker 的路由归属：[`ROUTE-MAP.md`](docs/rewrite/ROUTE-MAP.md)
- 测试策略：[`TESTING.md`](docs/rewrite/TESTING.md)
- 部署手册与前置条件：[`CLOUD-VERIFICATION.md`](docs/rewrite/CLOUD-VERIFICATION.md)
- 明确不提供的能力：[`DROPPED-CAPABILITIES.md`](docs/rewrite/DROPPED-CAPABILITIES.md)
- 当前状态、未决问题与已知缺口：[`CUTOVER-READINESS.md`](docs/rewrite/CUTOVER-READINESS.md)
- 跨 Worker 一致性不变式：[`FLEET-CONSISTENCY.md`](docs/rewrite/FLEET-CONSISTENCY.md)
- 每个已挂载接口的验证位置：[`MOUNT-SEAMS.md`](docs/rewrite/MOUNT-SEAMS.md)

API contract 在 `docs/openapi/`。`docs/` 下的其他文档早于 TypeScript 实现，
描述的是更早的系统；与 `docs/rewrite/` 和 contract 冲突时，以后者为准。

## 参与贡献

FerroGate 面向人类维护者和 AI 编码 agent 协作而构建。最好的贡献是小而与
issue 关联的切片，能够被评审、被测试，并能从运维视角讲清楚。日常开发以 GitHub
milestone 组织，每个 milestone 汇集构成一个可发布增量的若干 issue。

其中两条约定即使对一次性的人工补丁也值得知道：

- **说清楚你没有验证什么。** 提交带 `Tested:` 和 `Not-tested:` trailer；一次
  看起来已验证、实际并未验证的交接，会白白消耗一整轮评审。
- **断言行为，而不是断言调用。** 一个只能证明守卫"被调用过"、而把守卫本身反
  过来写测试仍然全绿的用例，是本项目最常见、被拒绝最多的缺陷类型。如果你新增
  了一个守卫，请说明什么样的改动会让它失效。

实践规则：

1. 行为写在归属的 package 里；避免横切式重写。
2. 逻辑与测试在同一个改动里交付。
3. 新增运行时路由必须同时有 contract 条目 —— contract 是被导入的而不是被
   重述的，因此没有 contract 条目的 handler 不可达，而没有 handler 的 contract
   条目会让对应 app 的测试失败。
4. 在 PR 里写清确切的验证命令和已知缺口。

## 安全

漏洞披露流程见 [`SECURITY.md`](SECURITY.md)。请私下报告可疑漏洞，不要开公开
issue。

## 项目历史

FerroGate 早期基于 Cloudflare Pingora 用 Rust 实现。该实现已被当前实现取代，
其历史保存在 git tag `legacy-rs`。

## 许可证

采用 Apache License 2.0 许可。见 [LICENSE](LICENSE)。
