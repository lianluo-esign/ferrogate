<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-10
  description: Portkey Enterprise and FerroGate competitive analysis, commercial gaps, and recommended product direction.
-->

---
title: Portkey Enterprise 与 FerroGate 商业竞争分析 (2026-07)
description: 基于 Portkey 官方资料和 FerroGate 实际代码的企业 AI Gateway 能力对比、商业判断与 90 天建议。
status: research
last_reviewed: 2026-07-10
---

# Portkey Enterprise 与 FerroGate 商业竞争分析

## 0. 决策摘要

**结论先行：不要做一个功能更少的 Portkey。**

Portkey 已经把通用 AI Gateway 做成了一套完整的企业产品：广泛的推理协议和模型
接入、可编排路由、可观测、Prompt Studio、组织治理、混合部署、合规资质和企业
支持。FerroGate 在路由、策略、配额、审计、MCP、Prompt 版本和可观测基础设施上
已经有大量共性能力，但产品完成度、协议覆盖和采购可信度明显落后。正面复制
Portkey 的控制台和功能数量，投入大、差异小，而且 Portkey 正在把更多企业网关
核心合入开源 Gateway 2.0，这条路只会越来越商品化。

FerroGate 真正有机会形成差异化的是：

> **把“谁可以让 Agent 对什么目标执行什么动作，为什么允许，执行后发生了什么”
> 做成一个可部署在客户边界内、可验证、可审计的 Agent Action Security Gateway。**

这条路线不是放弃 AI Gateway 基础能力。相反，必须先补齐两项会破坏企业信任的
底座，再把已有沙箱和能力边界变成可卖产品：

1. **P0，修复 MCP 身份契约。** `McpAuthType` 已声明 `oauth`、
   `per_user_oauth`、`per_user_headers`，但运行时没有读取 `auth_type`，实际只发送
   静态 headers。这是“配置可写、运行时不生效”的直接实例，必须实现或拒绝。
2. **P0，补全公开 API 契约。** 配额、项目、Workspace、Plan、Wallet、Usage Report
   等运行时路由没有进入当前 OpenAPI 完整性门禁。企业集成不能依赖读 Rust 路由表。
3. **P1，把类级授权升级为目标级授权。** 当前沙箱能力边界能区分 Filesystem、
   NetworkEgress、McpTool 等类别，但不能限制具体路径、读写方式、主机、方法或工具
   参数。这个缺口不补，沙箱安全仍然不能成为完整商业承诺。
4. **P1，交付可验证的混合部署最小闭环。** 客户 VPC 数据面、出站式签名配置同步、
   本地日志和断连继续运行，是企业采购的真实门槛，不是架构装饰。
5. **P2，只补目标客户真正需要的协议。** 优先 Embeddings，再按设计伙伴需求决定
   Rerank/Batch；不要为了追 Portkey 的模型数量去铺开 Audio/Image/Fine-tuning。

商业定位应从“又一个更快的 AI Gateway”收窄为：

> **FerroGate Secure Agent Gateway：模型流量、MCP 工具、CLI/文件/网络动作和计费
> 决策共用一个身份、策略、审批、隔离和审计链。**

## 1. 调研边界与证据等级

本报告使用三类证据：

- **Portkey 一手材料**：官网定价、官方产品文档、官方 GitHub 仓库、官方客户案例。
- **FerroGate 代码事实**：配置类型、运行时调用链、OpenAPI、回归测试和仓库文档。
- **商业推断**：从产品包装和客户案例推导的买家需求，明确标为“推断”。

以下内容不能当成独立验证事实：

- Portkey 官网对接入规模同时出现 250+、1600+、3000+ 等不同口径，可能混用了
  provider、model 和 modality。本报告只判断其覆盖面显著更广，不采用一个精确数。
- Portkey 客户案例中的流量、节省金额、准确率和调试效率均是厂商发布的案例数据，
  没有第三方审计；这里只用于识别付费场景，不用于性能承诺。
- Portkey 公布了 SOC 2 Type II、ISO 27001、HIPAA、GDPR 等合规能力，但本次没有
  获得审计报告正文，不能独立确认认证范围和有效期。
- Portkey MCP 总览页把 guardrails、rate limits、circuit breakers 作为能力入口，
  但对应官方子页面在 2026-07-10 仍明确标注 **coming soon**。对比表不把这三项
  算作 Portkey 已交付 MCP 运行时能力。

## 2. Portkey 企业版到底在卖什么

### 2.1 商业包装

Portkey 当前公开三档：

| 方案 | 公开价格 | 公开边界 |
| --- | --- | --- |
| Developer | 免费 | 10K 月度记录日志；日志 3 天、指标 30 天；基础 Gateway、Prompt、确定性 Guardrail、简单缓存 |
| Production | $49/月 | 100K 月度记录日志，额外 100K 请求 $9；日志 30 天、指标 90 天；RBAC、Service Account Key、完整 Guardrails、语义缓存、生产支持 |
| Enterprise | 定制报价 | 10M+ 月度记录日志、定制留存、SSO、细粒度预算/限流、私有云/VPC、数据湖导出、数据隔离、合规/BAA、专属支持 |

企业版的计价数字没有公开。不能据此编造 FerroGate 年费。当前可确认的是 Portkey
用低价自助层完成开发者获客，把数据驻留、身份、治理、留存、支持和合规放进定制
企业合同。

Portkey 官方 GitHub README 还明确写着 Gateway 2.0 会把“core enterprise gateway”
合入开源版本。商业含义很直接：**网关执行内核本身越来越难收费，付费价值向控制
面、治理工作流、企业交付、合规和支持迁移。**

Portkey 官网同时声明 Palo Alto Networks 已完成对 Portkey 的收购，官方文档已经把
Prisma AIRS 接入请求/响应 Guardrail。交易条款不在本报告的可核实范围内，但竞争
含义明确：Portkey 现在不仅有产品完整度，还有大型安全厂商的渠道、合规采购关系和
安全产品组合。FerroGate 不能靠补齐一张通用 Gateway 功能表正面抵消这些资产；更
合理的突破口是厂商中立、客户边界内运行，以及 Portkey 尚未证明拥有的 Agent 工作
负载隔离和动作授权链。

### 2.2 企业部署模型

Portkey Enterprise 的核心架构是混合部署：

- Data Plane 运行在客户 VPC，处理 LLM 流量、访问控制、Guardrail、缓存和日志。
- Control Plane 由 Portkey 托管，提供 Dashboard、配置、集成和聚合分析。
- 数据面每分钟拉取配置增量，配置对象本地缓存，控制面短暂不可用时仍可运行。
- Prompt/Response 日志可留在客户 VPC，也可加密发送到 Portkey。
- 支持 Kubernetes/ECS、多种对象存储、MongoDB/DocumentDB、云 IAM、TLS 1.3 和
  AWS KMS BYOK envelope encryption。

这套设计解决的不是“能否 Self-host”，而是企业买家同时要的三件事：敏感流量留在
自己边界内、控制面由厂商持续更新、客户不用自己运营全部 SaaS 组件。

### 2.3 产品能力面

Portkey 企业产品不是单一 Gateway，而是六个互相咬合的面：

1. **推理网关**：Universal API、Fallback、Retry、Load Balance、Conditional
   Routing、Canary、Circuit Breaker、Timeout、Batch、Realtime、File、Fine-tuning
   以及文本/图像/音频等多模态协议。
2. **模型与密钥控制面**：Model Catalog、provider 集成、自定义模型/价格、Virtual
   Key、Workspace 访问、预算和速率限制。
3. **Guardrails**：请求和响应检查、同步/异步执行、deny/log/feedback/retry/fallback
   编排、PII、Prompt Injection、JSON Schema、自定义 Hook 和第三方安全平台。
4. **可观测与成本**：请求日志、Trace、21+ 指标、筛选、Metadata、Feedback、成本、
   OpenTelemetry、完整日志导出和外部平台集成。
5. **Prompt 协作**：Playground、并排对比、版本、发布、回滚、环境 Label、Partial、
   Library、权限和 Prompt 生产表现对比。
6. **企业治理**：Org/Workspace、RBAC、OIDC/SAML、SCIM、审计、留存、私有部署、
   合规和支持。

MCP Gateway 已交付的重点是集中注册、OAuth/API Key/Headers、IdP 接入、按用户和
Workspace 的访问控制、按 Tool 暴露、身份转发和调用日志。其文档支持三种身份转发：
claims header、原 Bearer Token 透传、Portkey 签名 JWT。Guardrail、MCP 速率限制和
MCP Circuit Breaker 仍是 coming soon，不能混入已交付清单。

## 3. 共性与差距矩阵

| 能力面 | Portkey Enterprise | FerroGate 当前实现 | 判断 |
| --- | --- | --- | --- |
| 基础推理 API | 覆盖 Chat、Responses、Messages、Embeddings、Image、Audio、Batch、Files、Fine-tuning、Realtime 等 | `GET /v1/models`、Chat Completions、Responses，含 SSE | **明显缺失**：协议面过窄 |
| Provider 接入 | 官方口径不一致，但覆盖面显著更广，并有 Model Catalog | 8 个显式 adapter family 加通用 OpenAI-compatible：OpenAI、Anthropic、Gemini、Grok、OpenRouter、Azure、Bedrock、Vertex | **缺失但不应全追**：按客户协议补齐 |
| 路由与可靠性 | Retry、Fallback、Load Balance、Conditional、Canary、可配置 Circuit Breaker/Timeout | Priority、weighted fallback、lowest-cost、lowest-latency、balanced、retry、fallback、provider circuit breaker、timeout、health | **核心共性强**；缺真正流量分配、条件路由和每 Config 编排 |
| Gateway Config | 路由、缓存、Guardrail、Retry、Fallback 等统一为版本化 Config | `GatewayConfigProfile` 目前只有启用状态、API Key 范围、`cache_enabled` | **明显缺失**：名字大于实际能力 |
| Cache | 简单和语义缓存，企业部署支持独立缓存组件 | 进程内非流式 exact-match，按全局/模型/API Key 开关 | **缺失**：共享缓存、语义缓存和集群一致性 |
| Virtual Key | Key Vault、Virtual Key、Provider/Model 控制、预算、速率限制 | 哈希 Virtual Key、Scope、Model/Provider allow/deny、区域限制、RPM/TPM/Token Budget | **核心共性强** |
| 多层配额与成本 | Workspace policy，可按条件和用户等维度 group；请求/token/cost，多周期 reset | Tenant → Project → Workspace → Key 的 RPM/TPM/月预算/模型交集，Usage Rollup、Budget Alert | **各有优势**：FerroGate 层级严谨；缺灵活条件、周期和完整公开契约 |
| Billing 产品 | 成本跟踪和预算为主 | 独立 Billing Service、幂等结算、持久 Outbox、Plan、Prepaid Wallet、Auto-recharge | **FerroGate 反向优势**：更适合卖模型/Agent 服务的平台 |
| Guardrails | 丰富内置/Partner 检查，输入/输出，异步/同步，多动作编排和结果 UI | Request/Response，keyword/regex/max bytes/custom HTTP，deny/redact，外部检测失败 fail-closed | **基础共性**；缺检测库、动作编排、结果详情和 Partner 生态 |
| 请求可观测 | Logs、Trace、21+ 指标、筛选、Feedback、Metadata、成本、OTel、完整日志导出 | Request log、Usage/Metering、Provider health、Prometheus、OTLP、ClickHouse、Metadata rollup、JSONL export | **后端共性强，产品层明显落后**：无 Feedback/Eval，查询和 UI 弱 |
| Agent Trace | Agent/Sub-agent/Tool 树、逐节点查看和 Trace 对比 | Agent run timeline 和可重建 OTLP trace tree，含 provider/billing/audit/runtime span | **核心共性强**；缺可用的树形调试和对比工作流 |
| Prompt 管理 | Playground、Library、Partial、权限、不可变版本、发布/回滚、Label、生产对比 | Template CRUD、变量、Revision、active/draft/archive、Chat/Responses render | **运行时种子已存在，协作产品明显缺失** |
| MCP 代理 | Registry、OAuth/API Key/Header、IdP、用户/Workspace/Tool provisioning、身份转发、日志 | HTTP/SSE/stdio、Registry CRUD、tool include/execute allowlist、审批、审计、计费、超时、并发、重连 | **各有优势但有 P0 缺口**：FerroGate 有执行审批；身份配置未闭环 |
| MCP Guardrail/限流/熔断 | 官方子页面均标为 coming soon | Tool 审批、通用策略/计费存在；没有独立 per-user/team/server MCP 限流和 MCP circuit breaker | **不能说 Portkey 已领先**；FerroGate 可先做成差异化闭环 |
| 企业身份 | OIDC + SAML、SCIM User/Group、Workspace 映射、RBAC | OIDC Authorization Code + PKCE、简化 SCIM、RBAC；SAML/MFA 未实现，SSO 配置仍是内存态 | **明显缺失**：身份生命周期和持久化不足 |
| 审计 | 全 Org/Workspace、用户/IP/国家/资源/动作/时间筛选、定制留存 | Admin audit、Tool approval、Agent timeline、Request/Billing evidence；列表主要是 offset/limit | **数据存在，调查工作流不足** |
| 混合部署 | 客户 VPC 数据面 + 托管控制面，增量同步，本地日志/KMS/BYOK | Self-host、Kubernetes、集群、Redis Counter、Supabase、ClickHouse、reload/drain；没有托管混合控制面 | **企业商业化关键缺口** |
| 合规采购 | SOC 2 Type II、ISO 27001、HIPAA/GDPR、BAA、Trust Portal、企业支持 | 控制文档和供应链 gate 已有；正式认证没有；签名镜像 E2E 尚未验证 | **硬门槛缺失**，不能靠代码替代认证 |
| Agent 执行安全 | 重点在网络网关、Guardrail、MCP 身份；未发现其拥有 Agent 工作负载隔离的同类实现 | Agent worker、隔离后端抽象、Capability Boundary、审批、fail-closed function egress、红队回归 | **FerroGate 差异化资产**，但真实后端和目标级授权证据仍不完整 |

## 4. 最严重的产品真实性问题

### 4.1 MCP `auth_type` 是声明，不是运行时能力

`crates/ferrogate-mcp/src/lib.rs` 的 `McpAuthType` 声明了：

- `None`
- `Headers`
- `Oauth`
- `PerUserOauth`
- `PerUserHeaders`

但 `HttpMcpClient::new` 只调用 `resolved_headers(config)`，该函数只读取静态
`headers`/环境变量。仓库中除定义和序列化外，没有运行时分支消费 `auth_type`。
因此 `oauth` 和 per-user 模式目前不会完成 Token 获取、刷新、用户绑定或身份转发。

这比“不支持 OAuth”更糟，因为用户可以配置一个看起来被支持的值。最小可信修复：

1. 在实现前，配置校验拒绝三个未实现模式，并在 OpenAPI 标明实际支持范围。
2. 首个实现闭环选择 per-user OAuth/OIDC，而不是只做一个共享 Client Credentials。
3. 从入站身份到 MCP 上游建立明确映射，支持 Bearer passthrough 和签名 JWT 两种
   模式，先不做可伪造的裸 claims header。
4. 上游前剥离用户自带身份 header，由网关生成；审计记录 subject、server、tool、
   credential source、decision 和 request/trace id。
5. 用真实 OIDC mock + MCP server 做 E2E，证明两个用户拿到不同权限且不能伪造。

### 4.2 OpenAPI 门禁没有覆盖真实控制面

运行时路由表已包含 `/admin/v1/projects`、`/admin/v1/workspaces`、
`/admin/v1/quota-policies`、`/admin/v1/plans`、`/admin/v1/wallets`、
`/admin/v1/usage-reports` 和 `/v1/assets` 等能力，但当前 OpenAPI 和
`scripts/check-openapi.py` 的 expected method 集合没有完整覆盖这些路由。

这意味着“OpenAPI 检查通过”不能证明控制面契约完整。企业客户会据此生成 SDK、
做权限审查和变更评估，这不是文档美观问题。应从运行时的单一结构化路由定义生成
或校验 OpenAPI 路径，禁止维护一个人工挑选的子集。

### 4.3 沙箱授权仍是类级，不是目标级

`docs/security/agent-sandbox-model.md` 已诚实记录：`Filesystem` 授权不区分路径和
读写，`NetworkEgress` 授权不限制目标 Host。商业上不能把它说成“细粒度 Agent
权限”而不加限定。

下一层策略至少要能表达：

- MCP：server、tool、参数 schema/敏感字段、read/write 风险级别。
- Filesystem：workspace-relative path glob、read/write/execute。
- Network：scheme、host、port、HTTP method、DNS/IP 重绑定防护。
- Secret：secret reference、允许注入到哪个 adapter/action，永不返回明文。
- CLI：可执行文件、参数规则、工作目录和资源上限。

每次决策必须生成规范化 evidence，审批绑定参数指纹，防止“批了 A，执行 B”。

## 5. Portkey 案例透露的真实付费点

以下是厂商案例，不是独立审计，但买家问题高度一致：

- 医疗保险案例强调：Azure 私有端点、每次请求留痕、团队级访问、预算、PII、
  Prompt Injection 和混合部署。**推断：监管行业买的是可控扩张，而不是路由本身。**
- 大型配送平台案例强调：大量工程师和 Workspace、多 Provider、失败救援、缓存、
  成本、VPC 数据面。**推断：平台团队愿意为统一运营面和降低接入成本付费。**
- Snorkel AI 案例强调：Agent/Sub-agent/Tool 树、逐节点检查、标签筛选、好坏 Trace
  对比。**推断：Agent 可观测的价值不是多存一条 Log，而是把一次失败快速解释清楚。**

对 FerroGate 的含义：现有 Request Log、Agent Timeline、Billing Event、Audit Event
分别存在还不够。企业产品需要把同一个动作的身份、策略、路由、成本、审批、执行
和结果串成一个调查界面。

## 6. 推荐产品方向

### 6.1 主方向：Secure Agent Gateway

目标客户：

- 正在内部推广 MCP/Agent，但安全团队不允许工具凭证散落到每个客户端的企业。
- 需要 Self-host/VPC/受监管环境，不能把 Prompt、工具参数和文件内容发给公共 SaaS。
- 既需要模型访问，又需要治理 CLI、Filesystem、Browser、REST、Secret 和 Network
  Egress 的 Agent 平台团队。
- 对每次 Agent 动作需要回答“谁发起、为何允许、访问了什么、花了多少”的团队。

不以“支持最多模型”为核心卖点，而以一条闭环为产品：

```
Identity -> Policy -> Approval -> Isolation -> Governed Egress -> Billing -> Evidence
```

Guardrail 不能继续停在 keyword/regex/custom HTTP 的功能清单。其版本化策略、检测器
契约、失败语义、流式安全、Evidence 和 Agent/MCP 动作扩展设计见
[`guardrail-security-architecture-2026-07.md`](guardrail-security-architecture-2026-07.md)。

FerroGate 已有这条链的大部分模块。工作重点是把模块间的弱连接补齐并提供调查视图，
而不是再造一个 Prompt Studio 首页。

### 6.2 商业包装建议

**Community / OSS**

- Gateway 核心、Chat/Responses、基础 provider adapters、基础路由和日志。
- 静态 MCP Headers、基础 Tool allowlist、单节点开发体验。
- 保持真正可用，不能做成故意残缺的试用壳。

**Enterprise Secure Agent Gateway，定制合同**

- OIDC/SAML/SCIM、per-user MCP identity、Workspace/Tool provisioning。
- 目标级 Capability Policy、审批、Agent sandbox、governed egress。
- 客户 VPC Data Plane、托管/自管 Control Plane、签名配置快照、本地日志。
- 长期审计、合规证据、SLA、升级和响应支持。
- Agent Trace 调查、策略决策解释、成本和 Wallet/Plan 能力。

当前不建议立即推出 $49 自助 Production 层。FerroGate 的控制台、协议覆盖和托管
交付还不足以靠低价自助转化。先通过付费设计伙伴验证安全治理价值，再决定是否做
开发者 SaaS。企业价格应通过真实采购访谈确定，本报告没有足够证据给出年费数字。

## 7. 90 天可证伪路线

### 0-30 天：先把承诺变真

工程动作：

- 未实现前拒绝 `oauth`/`per_user_oauth`/`per_user_headers`，删除假能力。
- 实现第一条 per-user MCP identity E2E：OIDC subject -> Workspace/Tool policy ->
  signed JWT 或 Bearer passthrough -> upstream MCP -> audit evidence。
- 把全部公开运行时路由纳入 OpenAPI 完整性检查。
- 把 SSO 配置从进程内 HashMap 迁入 durable repository；明确 SAML 仍未实现。
- 为 MCP 身份链增加伪造 header、跨租户、过期 token、撤权后的回归测试。

商业动作：

- 访谈至少 5 个拥有内部 Agent/MCP 计划的平台或安全团队。
- 不问“你想不想要安全网关”，而问最近一次工具凭证、数据出口、审批或审计阻塞。
- 争取 2 个愿意提供真实 IdP + MCP server 测试环境的设计伙伴。

退出条件：5 个目标团队中少于 3 个确认这是近 6 个月实际阻塞，且没有 1 个愿意
进入技术验证，则暂停该定位，不继续凭感觉扩建沙箱。

### 31-60 天：做出差异化证据

- 实现 MCP/Filesystem/Network/Secret 的目标级 policy matcher。
- 审批绑定 action canonical hash，执行前再次比对，任何漂移 fail closed。
- 用攻击形状测试覆盖路径逃逸、Host 绕过、伪造身份、凭证跨租户和审批后换参。
- 运行一个真实隔离后端 E2E；当前单元测试和抽象层不能替代真实 Firecracker/
  gVisor/Rootless Docker 运行证据。
- Admin 调查视图按 request/trace/run id 展示 Identity、Policy、Approval、Target、
  Provider、Usage、Cost 和 Outcome。

成功标准：给一个不了解实现的安全工程师一条失败请求，他能在 10 分钟内回答谁、
为何、访问什么、在哪里被拒绝，并能复现证据。

### 61-90 天：形成可卖部署闭环

- 做混合部署最小切片：客户 VPC 数据面只建立出站连接，拉取签名版本快照；控制面
  断开时使用最后一个有效快照；过期策略可配置 fail-closed。
- Prompt/Response/Tool 参数默认留在客户 VPC，只上报允许的聚合指标。
- 日志位置、留存和导出策略按 Tenant/Workspace 配置，不再只有全局记录条数。
- 增加 Embeddings E2E，包括 auth、model mapping、budget、guardrail、usage、log。
- 完成真实 CI 镜像的 cosign/attestation 验证，发布可复现验证命令和结果。

商业成功标准：至少 1 个设计伙伴在其 VPC 跑通真实 Agent/MCP 流量，并愿意围绕
身份治理、动作控制、审计和支持讨论付费合同，而不只是免费试用。

## 8. 明确不做

- **不追 Portkey 的模型数量。** 通用 OpenAI-compatible adapter 已能覆盖大量服务；
  只为真实协议差异新增 adapter。
- **不先做 Prompt Studio 克隆。** Prompt Template 运行时要保留，但 Playground、
  协作和 Label 不是当前差异化的第一步。
- **不先做语义缓存。** 它能省钱，但不是安全治理定位的购买触发点；除非设计伙伴
  用真实成本数据证明优先级。
- **不把 Portkey coming-soon 的 MCP Guardrail/限流/熔断当作已交付基准。** 可以
  抢先做，但必须以 FerroGate E2E 证据为准。
- **不喊性能倍数。** Rust/Pingora 是实现约束和效率基础，不是未经第三方验证的
  商业承诺。
- **不宣称合规。** 没有正式审计就只能说已有控制；SOC 2、HIPAA、ISO 27001 是
  法务和审计结果，不是 README 功能。

## 9. 四问法复核

1. **心即理**：企业采用 Agent 的根本矛盾是扩大能力与保持控制之间的冲突。模型
   路由本身已商品化，动作身份、授权、隔离和证据仍未被普遍闭合。
2. **知行合一**：第一个可推翻动作不是写品牌文案，而是让两个真实用户通过 OIDC
   调同一个 MCP server，得到不同 Tool 权限，并证明身份不可伪造、撤权立即生效。
3. **致良知**：FerroGate 已有可贵的沙箱和审计基础，也有 `auth_type` 不生效、
   目标级授权不足、真实隔离后端证据不足、无正式认证等硬缺口，必须同时讲。
4. **事上磨**：判断来自 Portkey 当前定价/文档/案例和 FerroGate 实际调用链；90 天
   计划要求真实 IdP、MCP server、隔离后端、客户 VPC 和付费讨论来继续验证。

## 10. 一手来源

Portkey：

- [Pricing](https://portkey.ai/pricing)
- [Official Gateway repository](https://github.com/Portkey-AI/gateway)
- [Enterprise offering](https://portkey.ai/for/enterprise)
- [Hybrid deployment architecture](https://docs.portkey.ai/docs/self-hosting/hybrid-deployments/architecture)
- [MCP Gateway](https://docs.portkey.ai/docs/product/mcp-gateway)
- [MCP identity forwarding](https://docs.portkey.ai/docs/product/mcp-gateway/authentication/identity-forwarding)
- [MCP tool provisioning](https://docs.portkey.ai/docs/product/mcp-gateway/tool-provisioning)
- [MCP guardrails: coming soon](https://docs.portkey.ai/docs/product/mcp-gateway/guardrails)
- [MCP circuit breakers: coming soon](https://docs.portkey.ai/docs/product/mcp-gateway/circuit-breakers)
- [MCP rate limits: coming soon](https://docs.portkey.ai/docs/product/mcp-gateway/rate-limits)
- [Enterprise SSO](https://docs.portkey.ai/docs/product/enterprise-offering/org-management/sso)
- [SCIM](https://docs.portkey.ai/docs/product/enterprise-offering/org-management/scim/scim)
- [Audit logs](https://docs.portkey.ai/docs/product/enterprise-offering/audit-logs)
- [Usage and rate limit policies](https://docs.portkey.ai/docs/product/enterprise-offering/budget-policies)
- [KMS integration](https://docs.portkey.ai/docs/product/enterprise-offering/kms)
- [Observability](https://docs.portkey.ai/docs/product/observability)
- [Complete OTEL log export](https://docs.portkey.ai/docs/product/enterprise-offering/otel/complete-logs)
- [Guardrails](https://docs.portkey.ai/docs/product/guardrails)
- [Prisma AIRS guardrail integration](https://docs.portkey.ai/docs/integrations/guardrails/palo-alto-panw-prisma)
- [Prompt Engineering Studio](https://docs.portkey.ai/docs/product/prompt-engineering-studio)
- [Circuit breaker](https://docs.portkey.ai/docs/product/ai-gateway/circuit-breaker)
- [Canary testing](https://docs.portkey.ai/docs/product/ai-gateway/canary-testing)
- [Health insurer case study](https://portkey.ai/case-studies/health-insurer-enterprise-ai-governance)
- [Delivery platform case study](https://portkey.ai/case-studies/leading-delivery-platform)
- [Snorkel AI case study](https://portkey.ai/case-studies/snorkel-ai-multi-agent-debugging)

FerroGate：

- [`crates/ferrogate-mcp/src/lib.rs`](../../crates/ferrogate-mcp/src/lib.rs)
- [`crates/ferrogate-gateway/src/state_routing.rs`](../../crates/ferrogate-gateway/src/state_routing.rs)
- [`crates/ferrogate-config/src/config/types.rs`](../../crates/ferrogate-config/src/config/types.rs)
- [`crates/ferrogate-policy/src/quota.rs`](../../crates/ferrogate-policy/src/quota.rs)
- [`crates/ferrogate-auth/src/lib.rs`](../../crates/ferrogate-auth/src/lib.rs)
- [`docs/openapi/admin-api.openapi.json`](../openapi/admin-api.openapi.json)
- [`scripts/check-openapi.py`](../../scripts/check-openapi.py)
- [`docs/product-overview.md`](../product-overview.md)
- [`docs/analytics-warehouse.md`](../analytics-warehouse.md)
- [`docs/security/agent-sandbox-model.md`](../security/agent-sandbox-model.md)
- [`docs/security-controls.md`](../security-controls.md)
