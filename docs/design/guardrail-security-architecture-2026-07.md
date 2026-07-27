<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-10
  description: FerroGate enterprise guardrail security architecture derived from Portkey research and FerroGate runtime constraints.
-->

---
title: FerroGate Guardrail 安全架构 (2026-07)
description: 面向模型、MCP 和 Agent 动作的版本化安全护栏、检测器、执行语义与证据架构。
status: proposed
last_reviewed: 2026-07-10
related:
  - portkey-enterprise-competitive-analysis-2026-07.md
---

# FerroGate Guardrail 安全架构

## 0. 决策摘要

**Guardrail 不是一组正则表达式，也不是一个第三方内容审核 API。它是运行在客户
安全边界内、对每次模型和 Agent 动作给出可执行决定与可调查证据的策略平面。**

FerroGate 应学习 Portkey 已经验证有效的产品结构：

1. 将 Guardrail 拆成多个独立 Check，而不是让每条规则只能表达一个匹配器。
2. 将检测结果和 Action 分开，使同一个 Check 可以先 shadow、再 redact、最后 block。
3. 通过版本化 Gateway/Policy Config 绑定输入和输出阶段，而不是在请求里任意拼规则。
4. 保存每个 Check 的 verdict、耗时、错误和 transformation，支持逐请求调查。
5. 保留确定性检查、原生检测和 Partner/自定义检测器三种扩展层。

但以下 Portkey 行为不能照抄：

- Portkey 的自定义 Webhook 文档写明超时默认 `verdict: true`。FerroGate 的强制安全
  策略不得静默 fail-open；失败策略必须逐 Policy 显式声明并留下证据。
- Portkey 输出流在完整响应结束后才运行 Guardrail，此时内容已发送给客户端，
  只能做信息性检查。FerroGate 必须区分 `buffer_and_enforce` 和
  `shadow_after_complete`，不能把后者称为阻断。
- Portkey 只检查请求最后一条 message。FerroGate 要用协议适配器提取 system、
  developer、user、tool 和附件文本，并记录具体命中位置。
- Portkey Webhook 可返回完整替换后的请求/响应对象。FerroGate 只接受受限、可验证的
  typed patch，禁止检测器借 transformation 修改模型、Provider、工具权限或身份字段。

最终产品闭环：

```text
Identity + Scope
       |
       v
Versioned Guardrail Policy
       |
       v
Normalize -> Select -> Check -> Decide -> Transform/Block/Approve -> Dispatch
                         |                         |
                         +------ Evidence --------+
```

## 1. 证据与现状

### 1.1 Portkey 已验证的产品结构

以下来自 2026-07-10 的 Portkey 官方文档和开源 Gateway：

- Guardrail 由多个 Check 和独立 Action 组成，可在输入或输出阶段执行。
- Check 支持串行或并行；Guardrail 支持同步执行和异步 log-only。
- 同步失败可阻断，也可继续处理并记录结果；结果包含逐 Check verdict、latency、
  error、transformed 和 feedback。
- 确定性检查包含 regex、长度、JSON Schema、JSON keys、请求参数、模型、Metadata
  等；语义检测覆盖 PII、内容审核、语言和 gibberish。
- Partner 层通过统一插件接口接入 Bedrock、Azure、Lakera、Pangea、Prisma AIRS 等。
- Guardrail 可以在组织级强制，也可以附着到 Workspace/Gateway Config。
- 流式输入可以在 dispatch 前阻断；流式输出在完整响应后检查，不能撤回已发送内容。

这些事实证明“Check -> Action -> Config -> Evidence”是成熟的产品结构，但不能证明
每个检测器的准确率，也不能替代 FerroGate 自己的故障和泄漏模型。

### 1.2 FerroGate 已有资产

当前实现已经闭合以下路径：

- request/response 两阶段 Guardrail。
- organization/project/API key/model/provider scope。
- keyword、预编译 regex、最大输入字节和 `custom_http`。
- `deny` 和 response `redact`。
- 对存在 response Guardrail 的 SSE 先缓冲完整响应，再检查和发送，避免跨 chunk
  匹配绕过。
- 外部检测器不可达或响应不合法时转换成 deny。
- Audit Event、Request Log 和 Prometheus match/deny/redact 计数。

### 1.3 当前硬缺口

1. `GuardrailRule` 同时承担 scope、detector 和 action，无法组合多个 Check，也没有
   Policy revision、activation、rollback 或继承语义。
2. `match_guardrail` 使用 `find_map`，第一条匹配即结束；无法表达 all/any、阈值、
   多检测器并行或确定性的 precedence。
3. `custom_http` 通过同步 `TcpStream` helper 执行，位于 Pingora 请求路径，可能阻塞
   runtime worker；也没有并发舱壁、熔断、重试预算或 detector health。
4. 外部检测契约只有 `match` 和 `matched_text`，没有 category、location、confidence、
   transformed patch、error kind 或 detector version。
5. 请求检查面对的是序列化 body 文本，不能可靠区分 system prompt、用户内容、Tool
   schema、Tool result 和 Metadata。
6. 只有聚合计数和通用 Audit Event，没有持久的逐 Check evaluation，也没有结果查询、
   dry-run、diff、activation 或调查界面。
7. Guardrail 没有进入 MCP、Tool、CLI、Filesystem、REST 和 Network Egress 的统一
   动作路径；这正是 FerroGate 可以超过通用 AI Gateway 的位置。

## 2. 不可妥协的安全不变量

1. **执行前决定必须先于副作用。** 标记为 enforcing 的输入或动作 Guardrail 未完成
   前，不得调用模型、Tool、MCP server 或外部网络。
2. **已发送内容无法撤回。** pass-through streaming 的输出检查只能是 shadow；要阻断
   或脱敏，必须 buffer 后再发送。
3. **强制策略不能被下级覆盖。** Organization/Tenant enforced Policy 只能由同级授权
   管理员修改；Project、Workspace、Key 和请求级配置只能增加约束。
4. **错误不是通过。** 每个 Policy 必须声明 `on_error`；enforcing 安全策略默认
   `block`，shadow 策略默认 `record`。禁止隐式默认放行。
5. **检测器不是授权器。** 第三方 Detector 只能返回 Finding/Verdict/受限 patch；最终
   Action 由 FerroGate Policy Engine 决定。
6. **Transformation 不扩大权限。** patch 只能修改允许的内容字段，不能修改身份、
   scope、model/provider route、tools allowlist、预算或审批绑定值。
7. **原文最小化。** 只向 Detector 发送完成判断所需的 segment；Evidence 默认保存
   category、位置、长度和 HMAC fingerprint，不保存命中的 PII/Secret 原文。
8. **决定可重放。** 每条 Evidence 绑定 policy revision、detector version/config digest、
   input fingerprint 和 request/trace/run id。
9. **延迟有总预算。** Detector timeout、并发、重试和整条 Guardrail deadline 必须有界；
   不能让安全控制把 Gateway 变成无界队列。
10. **同一语义覆盖流式和非流式。** 允许行为差异，但必须通过显式 mode 和 E2E 证据
    描述，不能由代码路径偶然决定。

## 3. 领域模型

### 3.1 GuardrailPolicy

```rust
struct GuardrailPolicy {
    id: PolicyId,
    revision: u64,
    state: Draft | Active | Archived,
    enforced: bool,
    scope: ScopeSelector,
    targets: Vec<GuardrailTarget>,
    checks: Vec<CheckBinding>,
    aggregation: All | Any | Threshold(u32),
    execution: Parallel | Sequential,
    mode: Enforce | Shadow,
    streaming: BufferAndEnforce | ShadowAfterComplete | RejectStreaming,
    on_pass: Vec<Action>,
    on_fail: Vec<Action>,
    on_error: Vec<Action>,
    deadline_ms: u64,
}
```

要求：

- revision 不可变；更新产生新 revision，activation 原子切换并记录操作者。
- `enforced=true` 的上级 Policy 在选择阶段做并集，不能被低层配置替换。
- Scope 至少覆盖 tenant/organization/project/workspace/API key/user/service account、
  model/provider/region、MCP server/tool 和 Agent workflow/node。
- 请求头只能选择管理员已授权的 Policy/Profile，不能提交任意 raw enforcing Policy。

### 3.2 GuardrailEnvelope

协议适配器把 Chat、Responses、MCP 和 Agent 动作归一成不可变 Envelope：

```rust
struct GuardrailEnvelope {
    request_id: String,
    trace_id: Option<String>,
    agent_run_id: Option<String>,
    subject: AuthenticatedSubject,
    tenant: TenantContext,
    target: GuardrailTarget,
    model: Option<String>,
    provider: Option<String>,
    metadata: Map<String, Value>,
    segments: Vec<ContentSegment>,
    input_fingerprint: String,
}
```

`ContentSegment` 必须保留来源：`system`、`developer`、`user`、`assistant`、
`tool_schema`、`tool_arguments`、`tool_result`、`attachment_text`、`metadata`、
`http_body`、`filesystem_path`、`network_target`。Detector 可声明接受哪些 segment，
避免把整份请求和凭证发给不需要它们的外部服务。

### 3.3 Detector 契约

```rust
#[async_trait]
trait GuardrailDetector: Send + Sync {
    fn descriptor(&self) -> DetectorDescriptor;
    async fn evaluate(
        &self,
        input: DetectorInput<'_>,
        deadline: Instant,
    ) -> Result<DetectorResult, DetectorError>;
}
```

DetectorResult 不是 boolean：

```rust
struct DetectorResult {
    verdict: Pass | Fail,
    findings: Vec<Finding>,
    patches: Vec<ContentPatch>,
    detector_version: String,
}

struct Finding {
    category: String,
    severity: Info | Low | Medium | High | Critical,
    confidence: Option<f32>,
    segment_id: String,
    byte_range: Option<Range<usize>>,
    fingerprint: Option<String>,
    attributes: Map<String, Value>,
}
```

`DetectorError` 区分 timeout、unavailable、invalid_response、overloaded、unauthorized、
payload_too_large 和 internal。Policy 根据错误类型执行 `on_error`，而不是把所有错误
压成一次普通命中。

### 3.4 Action

首批 Action：

- `allow`：继续处理，仅适用于 pass 或明确的 shadow。
- `block`：返回稳定 FerroGate error code 和 request id，不回显敏感 finding。
- `redact`：应用 typed patch；Evidence 保存 patch 数量和字段，不保存原值。
- `require_approval`：用于高风险 Tool/MCP/Agent 动作，审批绑定 action fingerprint。
- `quarantine`：不向客户端泄漏原文，把受限证据交给人工调查流程。
- `route` / `fallback`：只允许用于输出格式/质量问题，不得用来重放恶意输入。
- `retry`：必须有次数和成本上限，且禁止对 PII、Secret、Injection 类输入失败执行。
- `record`：写 Evaluation、metrics 和 OTLP，不影响请求。

不采用 Portkey 的 246/446 非标准 HTTP 状态作为内部编排协议。FerroGate 内部使用
typed outcome；外部保持标准 4xx/5xx，并用稳定 error code 表达
`guardrail_blocked`、`guardrail_unavailable`、`guardrail_streaming_unsupported` 等。

## 4. 执行架构

### 4.1 模块边界

- `ferrogate-guardrails`：只拥有领域类型、Policy composition、Detector trait、内置
  确定性 Detector、typed patch 校验和 Evaluation。它不是通用插件系统。
- `ferrogate-policy`：决定身份/scope 是否允许选择或管理某个 Guardrail Policy，并
  合并上级 enforced policies。
- `ferrogate-providers`：把各推理协议映射为/映射回 `ContentSegment`，不包含具体
  安全厂商逻辑。
- `ferrogate-cli`：在 Gateway 请求路径编排 normalize/evaluate/dispatch，持有 async
  detector clients 和 runtime health。
- `ferrogate-storage`：Guardrail Policy revision、activation 和 Evaluation repository
  contract；内存实现只用于开发测试。
- `ferrogate-observability`：低基数 metrics、OTLP span/event 和 detector health。

### 4.2 执行顺序

模型输入：

```text
auth -> tenant -> route candidates -> normalize input
     -> merge enforced + selected policies
     -> sync checks -> action
     -> dispatch only when allowed
     -> async shadow checks on bounded queue
```

模型输出：

```text
provider response -> normalize output
  non-stream: sync checks -> transform/block -> billing/log -> client
  stream enforce: buffer with byte/time cap -> sync checks -> client
  stream shadow: pass-through -> bounded capture/fingerprint -> async result
```

Agent/MCP 动作：

```text
authenticated subject -> target-level capability policy
 -> normalize server/tool/arguments/secret/network target
 -> guardrail checks -> optional exact-action approval
 -> isolated execution -> output guardrail -> billing/audit/evidence
```

Guardrail 不替代 capability policy。前者判断内容和风险，后者判断主体是否有权对目标
执行动作；两者都通过才可产生副作用。

### 4.3 外部 Detector runtime

- 使用 async HTTP client，不得调用 `TcpStream::connect_timeout` 等同步 helper。
- 每个 Detector 独立 semaphore、timeout、连接池、circuit breaker 和 health state，
  避免一个安全厂商拖垮全部请求。
- 默认不自动 retry；只有显式配置且剩余 deadline 足够时重试一次幂等检测。
- URL 必须经过 scheme/host/port allowlist 和 DNS/IP 校验，阻断 localhost、link-local、
  metadata endpoint 和 DNS rebinding，除非管理员显式配置私网目标。
- Credential 只接受 `secret_ref`，日志/Debug/OpenAPI 永不返回值；支持 mTLS 是企业
  部署后续切片，不把 bearer token 写入普通 config。
- 发送前按 DetectorDescriptor 做字段投影和大小限制。
- 供应商适配器只负责请求/响应翻译；Policy 语义不能泄漏某一家供应商的字段。

### 4.4 内置 Detector 首批范围

P0/P1 不追求“50+”数量，先覆盖可复现、高确定性的企业控制：

1. regex/contains/size，兼容现有配置。
2. JSON parse、JSON Schema、required/forbidden keys。
3. request parameter/tool allow-deny 和字段约束。
4. model/endpoint/metadata constraints；能由普通 Policy 表达的逻辑不重复实现。
5. Secret patterns：高置信度 token/private key/cloud credential 形态，默认 redact/block。
6. PII 只提供保守的高置信度 deterministic pack；复杂实体识别通过外部 Detector，
   不用一堆正则宣称“完整 DLP”。

Prompt injection、jailbreak、toxicity、grounding 和 hallucination 都需要模型或专业服务，
首期通过标准 Detector contract 接入，不在 Gateway 热路径手写一个无法验证的分类器。

## 5. Policy 继承与发布

Policy 选择按以下优先级合并：

```text
Organization/Tenant enforced
  + Project enforced
  + Workspace enforced
  + API key/service account assigned
  + approved Gateway Profile
  + request-selected non-enforcing profile
```

- `enforced` 层全部执行；不存在“后者覆盖前者”。
- 相同 Policy ID 只执行解析后的 active revision，Evidence 记录 revision。
- Draft 支持 `dry-run` 和固定 fixture test；激活前返回 diff、预估作用域和冲突。
- 支持 shadow rollout：按稳定 subject/request hash 采样，不用随机数导致调查不可重现。
- rollback 是切回上一不可变 revision，不原地修改历史对象。
- 配置 reload/混合部署同步使用签名 snapshot；数据面只接受单调 revision 和有效签名。

## 6. Evidence 与运营面

新增持久对象 `GuardrailEvaluation`：

```text
evaluation_id, request_id, trace_id, agent_run_id
subject_id/type, tenant/project/workspace
policy_id/revision, target, stage, mode
overall_outcome, selected_action, execution_ms
check_id, detector_id/version/config_digest
check_verdict, error_kind, finding categories/severity/count
transformed, input_fingerprint, created_at
```

安全要求：

- finding 原文默认不存；可选受限 forensic store 必须独立加密、短留存、RBAC 和审计。
- API 对普通调用方只返回稳定 error code，不返回 detector 内部提示或匹配原文。
- Admin API 支持按 request/trace/run、subject、scope、policy/revision、detector、category、
  verdict、action、error 和时间过滤。
- Request investigation 把 Identity、Route、Guardrail、Approval、Provider、Usage/Cost、
  Tool/Action outcome 串成同一时间线。
- Metrics 只使用低基数 label：stage、mode、outcome、action、detector class、error kind；
  policy id、user id 和原始 category 不直接成为 Prometheus label。
- OTLP span 记录 detector latency 和 policy revision，敏感 Finding 只以计数/分类输出。

必须能回答：

1. 哪个不可变 Policy revision 被选中，为什么？
2. 哪些 Check pass/fail/error，各自耗时多少？
3. 是内容失败还是 Detector 不可用？
4. 采取了 block、redact、approval、fallback 还是 shadow record？
5. 是否发生了模型/Tool 副作用，花费如何结算？

## 7. Control Plane 与 OpenAPI

最小 Admin API：

- `POST /admin/v1/guardrail-policies`
- `GET /admin/v1/guardrail-policies`
- `GET /admin/v1/guardrail-policies/{id}`
- `POST /admin/v1/guardrail-policies/{id}/revisions`
- `POST /admin/v1/guardrail-policies/{id}/activate`
- `POST /admin/v1/guardrail-policies/{id}/rollback`
- `POST /admin/v1/guardrail-policies/{id}/dry-run`
- `GET /admin/v1/guardrail-evaluations`
- `GET /admin/v1/guardrail-evaluations/{id}`
- `GET /admin/v1/guardrail-detectors/health`

所有写操作进入 Admin Audit；OpenAPI 是完整契约并由运行时路由门禁校验。Config 文件
继续支持静态部署，但要编译到同一个 versioned domain model，禁止形成第二套语义。

## 8. 验证策略

### 8.1 单元与属性测试

- Scope merge 不允许低层移除 enforced Policy。
- parallel/sequential 与 all/any/threshold 的真值表。
- pass/fail/error/skipped 不互相混淆。
- typed patch 只能触及 allowlist 路径，不能改变身份、路由、工具权限和预算。
- finding byte range 在 UTF-8、多 segment 和 transformation 后保持正确。
- Evidence sanitizer 不保存 PII、Secret、Authorization 和 Detector credential。

### 8.2 Contract 与故障测试

- External Detector pass/fail/transform、invalid JSON、timeout、TLS、401、429、5xx、
  payload too large 和 partial response。
- deadline、semaphore、circuit breaker 和 recovery；证明不会阻塞 Pingora worker。
- `on_error=block|record|fallback_detector` 每种路径都有可见 evidence。
- SSRF：localhost、link-local、cloud metadata、DNS rebinding 和重定向逃逸。

### 8.3 E2E

- 非流式 input block 证明 Provider 没有收到请求、没有错误计费。
- 非流式 output redact 证明 Billing 使用原始 Provider usage，客户端和普通日志看不到原文。
- SSE `buffer_and_enforce` 跨 chunk 命中并在首字节发送前阻断。
- SSE `shadow_after_complete` 明确标记 `not_enforced`，不能生成“blocked”证据。
- 两个 Workspace 同一模型命中不同 Policy，Org enforced Policy 对两者都生效。
- MCP/Tool 高风险参数先 Guardrail、再 exact-action approval、最后才执行。
- 本地 Docker + `ferrogate-test` 证明 Admin API、runtime、metrics、audit 和 evaluation
  repository 是同一条路径。

### 8.4 安全效果验证

每个语义 Detector 上线前需要固定、版本化测试集，至少报告 precision/recall 和已知
绕过，不使用“AI-powered”代替指标。设计伙伴流量先 shadow，人工抽样确认误报/漏报，
达到双方约定门槛后再按 scope 灰度 enforce。

## 9. 分期与商业闭环

### P0：可信底座

- 将 `custom_http` 从同步热路径迁移到 async Detector runtime。
- 建立 versioned Policy/Check/Action/Evaluation domain 和持久 repository。
- 显式 failure policy、deadline、streaming mode 和完整 OpenAPI。
- 兼容现有 Guardrail 配置，但编译为新模型；不做双引擎长期共存。

### P1：企业可用

- JSON Schema、request/tool parameters、Secret pattern 等 deterministic pack。
- Guardrail CRUD/dry-run/activate/rollback 和逐 Check 调查证据。
- Agent/MCP/Tool 动作 Guardrail 与 exact-action approval 串联。
- 标准 Partner adapter contract，并按设计伙伴选择两个真实集成，不先铺数量。

### P2：差异化与规模

- 混合部署下签名 Policy snapshot、VPC 内 Detector 和本地 Evidence。
- 受限 forensic store、评估数据集、shadow-to-enforce rollout 和误报分析。
- 语义 Detector marketplace/adapter SDK；只在 contract 和供应链审查成熟后开放。

商业验收不是“支持了多少检测器”，而是一个安全团队可以：定义上级不可绕过策略，
在 shadow 中看到影响，灰度启用，阻止真实泄漏/越权，并在 10 分钟内解释一次决定。

## 10. 明确不做

- 不把原始 Prompt/Response 默认发送给 FerroGate SaaS 或第三方 Detector。
- 不把异步检查、pass-through streaming 检查宣传成实时阻断。
- 不用第一条命中和隐式规则顺序承载复杂 Policy 语义。
- 不允许请求方提交 raw enforcing hooks 绕过管理员版本和审计。
- 不允许 Webhook 完整替换身份、路由或权限相关请求对象。
- 不在没有基准数据时宣称“检测 Prompt Injection/PII 的准确率领先”。
- 不把正式合规认证等同于存在 Guardrail 功能。
- 不为了 Partner 数量把供应商 SDK 和密钥逻辑硬编码进 Gateway core。

## 11. 四问法复核

1. **心即理**：企业买 Guardrail 的第一性需求不是检测器数量，而是敏感数据和高风险
   Agent 动作在产生副作用前能被一致控制，并能在事后解释。
2. **知行合一**：第一个可推翻切片是 async Detector + versioned Policy + Evaluation，
   用真实 timeout/5xx/SSE/PII 场景证明 block、redact、shadow 和 error 不混淆。
3. **致良知**：现有 fail-closed 和 SSE buffering 是真实优势；同步 HTTP、第一条命中、
   无逐项证据、无语义检测准确率则是硬缺口，必须同时公开。
4. **事上磨**：架构来自 Portkey 官方文档/代码和 FerroGate 当前调用链；最终仍需真实
   Detector、红队数据集、客户 VPC 和设计伙伴误报数据验证。

## 12. 一手来源

Portkey：

- [Guardrails overview and actions](https://docs.portkey.ai/docs/product/guardrails)
- [Supported endpoints, sync/async and streaming semantics](https://docs.portkey.ai/docs/product/guardrails/capabilities)
- [Guardrail check catalog](https://docs.portkey.ai/docs/product/guardrails/list-of-guardrail-checks)
- [Raw Guardrails](https://docs.portkey.ai/docs/product/guardrails/creating-raw-guardrails-in-json)
- [Bring Your Own Guardrails](https://docs.portkey.ai/docs/integrations/guardrails/bring-your-own-guardrails)
- [Organization-level enforcement](https://docs.portkey.ai/docs/product/administration/enforce-orgnization-level-guardrails)
- [Create Guardrail API](https://docs.portkey.ai/docs/api-reference/admin-api/control-plane/guardrails/create-guardrail)
- [Portkey Gateway source](https://github.com/Portkey-AI/gateway)
- [Hook engine source](https://github.com/Portkey-AI/gateway/blob/main/src/middlewares/hooks/index.ts)
- [Hook result types](https://github.com/Portkey-AI/gateway/blob/main/src/middlewares/hooks/types.ts)
- [Webhook detector](https://github.com/Portkey-AI/gateway/blob/main/plugins/default/webhook.ts)

FerroGate：

- [`crates/ferrogate-config/src/config/types.rs`](../../crates/ferrogate-config/src/config/types.rs)
- [`crates/ferrogate-gateway/src/state_quota_and_policy.rs`](../../crates/ferrogate-gateway/src/state_quota_and_policy.rs)
- [`crates/ferrogate-gateway/src/server/chat.rs`](../../crates/ferrogate-gateway/src/server/chat.rs)
- [`crates/ferrogate-gateway/src/state.rs`](../../crates/ferrogate-gateway/src/state.rs)
- [`crates/ferrogate-secrets/src/lib.rs`](../../crates/ferrogate-secrets/src/lib.rs)
- [`crates/ferrogate-observability/src/lib.rs`](../../crates/ferrogate-observability/src/lib.rs)
- [`docs/security/agent-sandbox-model.md`](../security/agent-sandbox-model.md)
- [`docs/openapi/admin-api.openapi.json`](../openapi/admin-api.openapi.json)

## 13. GitHub Tracking

Guardrail epic：[#193](https://github.com/lianluo-esign/ferrogate/issues/193)

| 优先级 | Issue | 可验收切片 |
| --- | --- | --- |
| P0 | [#195](https://github.com/lianluo-esign/ferrogate/issues/195) | async Detector runtime，消除热路径阻塞 |
| P0 | [#196](https://github.com/lianluo-esign/ferrogate/issues/196) | 不可变 Policy revision、继承、激活和回滚 |
| P0 | [#197](https://github.com/lianluo-esign/ferrogate/issues/197) | 协议归一化与明确的流式执行语义 |
| P1 | [#198](https://github.com/lianluo-esign/ferrogate/issues/198) | 确定性结构检查与受限 typed patch |
| P1 | [#199](https://github.com/lianluo-esign/ferrogate/issues/199) | 逐 Check Evidence 与统一调查视图 |
| P1 | [#200](https://github.com/lianluo-esign/ferrogate/issues/200) | MCP/Tool/Agent 动作 Guardrail |
| P1 | [#201](https://github.com/lianluo-esign/ferrogate/issues/201) | 两个经测量的语义安全适配器 |

Secure Agent Gateway 路线 epic：
[#194](https://github.com/lianluo-esign/ferrogate/issues/194)。其余优先项为 MCP 身份
[#202](https://github.com/lianluo-esign/ferrogate/issues/202)、OpenAPI 完整性
[#203](https://github.com/lianluo-esign/ferrogate/issues/203)、目标级能力
[#204](https://github.com/lianluo-esign/ferrogate/issues/204)、真实隔离
[#205](https://github.com/lianluo-esign/ferrogate/issues/205)、混合部署
[#206](https://github.com/lianluo-esign/ferrogate/issues/206)、Embeddings
[#207](https://github.com/lianluo-esign/ferrogate/issues/207)、供应链证据
[#208](https://github.com/lianluo-esign/ferrogate/issues/208) 和设计伙伴验证
[#209](https://github.com/lianluo-esign/ferrogate/issues/209)。
