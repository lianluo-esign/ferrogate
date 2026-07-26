# Cloudflare 可观测能力调研（2026-07-26）

调研问题：Cloudflare 是否支持可观测能力？FerroGate 的全链路可观测能否对接、走 Cloudflare 组件？

**结论：不能把 Cloudflare 当作 FerroGate 的可观测后端，但应该把 CF 侧 Worker 的可观测数据接进 FerroGate 的链路。**

Cloudflare 的可观测栈全部是 **Worker 内生 + 只出不进（outbound-only）**：整个平台没有任何 OTLP / 日志 ingest 入口，Analytics Engine 的写入只有 Worker binding，Workers Logs 没有写入 API。一个跑在容器里的 Rust 进程无法把自己的 trace/metric/log 写进去。反方向是通的且是官方一等公民：Workers 原生 OTLP **导出**（traces + logs）可以指向任意 collector —— 包括我们已有的 Vector。

---

## 1. 现状对齐：FerroGate 这边的可观测栈

| 项 | 现状 | 位置 |
|---|---|---|
| OTel SDK | **无**。OTLP/HTTP+JSON 请求体是 `serde_json` 手搓，HTTP 走裸 `TcpStream`+`rustls` | `crates/ferrogate-observability/src/otlp.rs`、`ferrogate-cli/src/telemetry.rs:1221` `dispatch_otlp_request` |
| 采集模型 | **不是 SDK 埋点**，是 5s 定时线程从 Postgres 增量拉行、在导出时合成 span | `telemetry.rs:32` `start_otlp_background_sender`（`OTLP_EXPORT_INTERVAL = 5s`） |
| trace id | `stable_trace_id` 对 request_id 做 fnv1a64 哈希合成；真实 32-hex W3C id 原样透传 | `telemetry.rs:1408` |
| 协议 | 仅 OTLP/HTTP + JSON（硬编码 `protocol: "otlp_http_json"`），无 gRPC、无 protobuf | `state_observability.rs:150` |
| metrics | Prometheus 文本 `/metrics`，**全是 counter/gauge，没有 histogram** → 没有延迟分位数 | `gateway/local.rs:4058` |
| 已对接后端 | Vector（默认，`deploy/vector/vector.yaml` 收 4317 gRPC / 4318 HTTP + 抓 `/metrics`）、ClickHouse（NDJSON 直写） | `sql/clickhouse/001_init_analytics.sql` |
| 入站 trace 传播 | 手写 W3C `traceparent`/`tracestate` 校验，`tracestate` 限 512B | `gateway/mod.rs:144` `ingress_trace_context` |
| 出站传播 | ✅ LLM provider 各端点、反向代理；❌ **MCP、sandbox、agent-worker 完全没有 traceparent** | `gateway/chat.rs:3570` 等 |
| 可插拔缝 | `ObservabilityPlugin`（`ferrogate-observability/src/config.rs:125`）**只做配置校验，没有 export 方法**；`ObservabilityExporterKind` 是封闭 enum | — |

关键点：**`dispatch_otlp_request` 是全部 HTTP 出口的唯一收口**，且 `OtlpHttpRequest` 已带 `headers: Vec<(String,String)>` 逃生口（#228 为 HMAC webhook 加的，`budget_alerts.rs:120` 已复用）——任何新后端的鉴权头从这里插。

CF 相关已有资产：`crates/ferrogate-cloudflare/`（D1/R2/Secrets Store，**无可观测**）、`workers/` 下 4 个 Worker（agent-gateway、gateway-front、mcp-server、d1-proxy）。其中 3 个只写了 `[observability] enabled = true`，`gateway-front` 连这行都没有。仓库里 `logpush` / `analytics engine` / `tail_consumers` **零命中**。

---

## 2. Cloudflare 侧能力盘点

### 2.1 能从外部（非 Worker）直接用的 —— 只有两个半

| 组件 | 外部可写？ | 说明 |
|---|---|---|
| **Workers Analytics Engine** | ⛔ 否 | 写入只有 `env.X.writeDataPoint()` binding。唯一的 HTTP API 是**只读** SQL API。可用一个 ~20 行 collector Worker 中转 |
| **Workers Logs** | ⛔ 否 | 没有日志 ingest API。代理 Worker 变通会让事件数翻倍，不划算 |
| **Workers Traces / OTLP** | ⛔ 否 | **CF 全平台没有 OTLP ingest**，只有 export |
| **Logpush** | ⛔ 否 | 只能推 CF 自己产生的 dataset，不能注入 |
| **AI Gateway** | 🟡 是（唯一真例外） | 外部服务直接 HTTPS 调用即可拿到 token/成本/缓存/延迟日志 + OTLP span 导出，**无需 Worker** |
| **GraphQL Analytics API** | ⛔ 只读 | 免费全plan，但只有 CF 边缘自己的数据；Free 保留 7 天、单次查询窗口 1 天 |

### 2.2 Workers Traces（2025-10 开放 Beta，2026 持续演进）

这是 2025–2026 变化最大的部分，也是对我们唯一真正有用的部分：

- `workerd` **自动埋点**，无需 SDK 改代码：handler 调用、出站 `fetch()`、binding 调用（KV/R2/D1/DO）都自动出 span，明确「遵循 OpenTelemetry 标准」。
- **原生 OTLP 导出**（traces + logs，共享 trace id），destination 在 dashboard 配 URL + 自定义鉴权头，wrangler 里按名引用。
- 2026-05-07：Worker→Worker（service binding）、Worker→Durable Object 的 trace **自动跨子请求串联**。
- 2026-06-16：支持 **custom span**（`tracing.enterSpan()`，`import { tracing } from "cloudflare:workers"`），与自动埋点正确嵌套并流入 OTLP 导出。

**三个必须记住的限制：**
1. ⚠️ **不支持 binary protobuf 的 OTLP ingest**，只有 JSON over HTTP。已有用户因此对接 Elastic APM 失败。
2. ⚠️ **metrics 明确不支持导出**（只有 traces + logs）。
3. ⚠️ 仍是 **beta**；`observability.enabled = true` 不会打开 tracing，要单独 `observability.traces.enabled = true`。**需要 Workers Paid**，Free plan 两个信号都没有。

### 2.3 跨边界 trace 传播 —— **今天还没有**

- Worker↔Worker↔DO 的内部传播已经可用（2026-05-07）。
- **对外（到非 CF 源站）的 W3C traceparent 注入/传播，CF changelog 明确说是「正在做」，未发布。**（网上有第三方文章声称已自动传播，与 CF 官方 changelog 矛盾，以 changelog 为准。）
- 今天可用的关联手柄只有 `cf-ray`（CF→源站请求头，格式 `<16-hex>-<IATA>`）。⚠️ **CF 官方声明 Ray ID 不保证唯一**，只能当 log-join key，不能当 trace id。它同时出现在 Workers Observability 查询 API 的 `$metadata.rayId` 里，所以两侧都有这个 join 字段。
- 实际做法：**在 Worker 里自己往出站 `fetch()` 上塞 `traceparent`**，源站按 `cf-ray` 记一个 span attribute 兜底。

### 2.4 AI Gateway 可观测（注意：本项目已 descope）

技术上它是唯一能被外部 Rust 服务当一等公民用的 CF 可观测组件：记录 prompt/response/provider/token/成本/时延/缓存状态；`cf-aig-metadata` 每请求最多 5 个自定义标签；**OTLP 导出遵循 Gen AI 语义约定**（`gen_ai.usage.input_tokens`、`gen_ai.usage.cost` 等）；并且支持 `cf-aig-otel-trace-id` / `cf-aig-otel-parent-span-id` —— **可以把 CF 侧 span 直接挂到我们 Rust 服务发起的 trace 下面**。

但 2026-07-24 founder 已判定 **CF AI Gateway 冗余并 descope（#406/#407 closed）**：FerroGate 自身就是 AI gateway，绕一跳只会带来双重日志/缓存/限流 + 成本 + 上游耦合。**本次调研不改变该结论** —— 这些字段（token/成本/缓存/时延）FerroGate 的 `request_logs` + `billing_metering_events` 已经全有，且是我们的计费权威源；用 CF 的版本反而引入两套不一致的口径。

其余限制备查：日志量 Free 全账号 10 万条 / Paid 每 gateway 1000 万条（**按条数而非时间保留**，满了停写除非开自动删除）；写入 500 logs/s/gateway；Logpush 导出**用你上传的公钥 RSA 加密**，下游必须先解密才能进 SIEM。

### 2.5 其它

- **Tail Workers**：Workers Paid 起，按 CPU 时间计费。CF 官方文档现在反而引导用户改用原生 OTLP 导出，把 Tail Workers 定位为「需要自定义处理时的进阶选项」。
- **Logpush**：⭐ **`workers_trace_events` 是唯一明确豁免 Enterprise 的 dataset —— $5 Workers Paid 即可用**（AI Gateway 日志同理）。zone 级的 `http_requests` 等全部 Enterprise 独占。目的地含 R2/S3/GCS/Azure/BigQuery/Datadog/Splunk/通用 HTTP。⚠️ **投递延迟下限约 1 分钟**（与批量参数无关，「大约每分钟处理一次」），**且不能回补**——任务中断期间的数据永久丢失。
- **Workers Analytics Engine**：GA（ClickHouse 底座）。每 data point 最多 20 blobs / 20 doubles / **仅 1 个 index**、blob 合计 16KB、index ≤96B、**每次 Worker 调用最多 250 个 data point**、**保留 3 个月**。⚠️ 写入和读取**都做采样**，必须用 `SUM(_sample_interval)` 加权，**高流量下拿不到精确计数，不能用于计费**。

---

## 3. 成本（$5/月 Workers Paid，**按账号计费，不是按 Worker**）

| 项 | Free | Paid（$5/mo 起） |
|---|---|---|
| Workers 请求 | 10 万/天，超了直接报错 | **1000 万/月含**，超出 $0.30/百万 |
| Workers CPU | 每次调用 10ms 上限 | **3000 万 CPU-ms/月含**，超出 $0.02/百万 CPU-ms |
| **Workers Logs** | 20 万事件/天，留 3 天 | **2000 万事件/月含**，超出 **$0.60/百万**，留 7 天 |
| **Traces（2026-03-01 起计费）** | 与 Logs 共享 20 万/天 | 与 Logs **共享同一配额池** |
| **OTLP 导出** | ⛔ 不可用 | ✅ |
| **Analytics Engine** | 10 万点/天 + 1 万查询/天 | **1000 万数据点/月含**（超出 $0.25/百万）+ **100 万读查询/月含**（超出 $1.00/百万），留 3 个月 |
| **Logpush `workers_trace_events`** | ⛔ | **1000 万/月含**，超出 **$0.05/百万**（按**过滤/采样后**真正落地的条数计费） |
| AI Gateway 日志 | 免费（10 万条/账号） | 免费（1000 万条/gateway）；Logpush 导出需 Paid |
| GraphQL Analytics API | 免费，留 7 天，查询窗口 1 天 | 免费，Business 31 天 / Ent 90 天 |

⚠️ **文档自相矛盾**：Traces 页写 Paid 含 **1000 万** 事件，Workers Logs 页和 Workers 定价页都写 **2000 万** —— 说的是同一个共享池。下面按 2000 万算，落地前需实测确认。
🟢 **AE 当前实际不计费**：定价页原文「Currently, you will not be billed for your use of Workers Analytics Engine」，上表价格仅供预测。

### 按请求量测算（假设每请求 1 条结构化事件、2ms CPU、R2 滚动留 30 天）

| 请求/月 | 基础计算 | (a) Workers Logs | (b) Analytics Engine | (c) Logpush→R2 |
|---|---|---|---|---|
| 100 万 | **$5.00** | $0 | $0 | $0 |
| 1000 万 | **$5.00** | $0（恰好卡满） | $0（恰好卡满） | $0 |
| 1 亿 | **$35.40** | **$108.00**（含 invocation log，2 事件/请求）<br>关掉 invocation log → $48.00 | **$22.50**（当前实际 $0） | **~$4.50** |

> 基础计算 1 亿 = $5 + 90×$0.30 + (200−30)×$0.02 = $35.40。用 CF 官方样例（1 亿请求 @7ms CPU = $45.40）验算公式一致。
> R2 侧：$0.015/GB-月、Class A $4.50/百万、**出口免费**，免费额度 10GB + 100 万 Class A；Logpush 每分钟出一个文件 → 约 4.3 万文件/月，稳在免费额度内。

**结论：Logpush→R2 在 1 亿量级比 Workers Logs 便宜约 20 倍（$4.50 vs $108）**；AE 更便宜但只给预聚合指标且带采样。1 亿量级把 `head_sampling_rate` 调到 0.1，Workers Logs 也能压回 $0。

### 会先于成本咬人的硬限制

1. AE **每次 Worker 调用 250 个 data point**、**每点仅 1 个 index**（index 的选择决定了采样轴 —— 应当选租户键）、blob 合计 16KB。
2. Workers Logs 单条 **256KB** 截断；但 **Workers Logpush 的 `logs`+`exceptions` 合计只有 16,384 字符**，远比前者紧。
3. **50 亿条/账号/天** → 当天剩余时间强制 1% 采样，静默的质量悬崖。
4. AE 与 GraphQL 都是自适应采样，**不能用于计费口径**。
5. Logpush 无法回补 + ~1 分钟延迟下限。
6. 采样全部是 head-based，**没有任何 tail-based 采样**。
7. ⚠️ Workers Observability 查询 API 和 AE SQL API 都**没有公开限流文档**，要按会被限流来设计。

---

## 4. 决策（founder, 2026-07-26）：完全切换到 Cloudflare 基建

**本节以下的「分层」建议已被 founder 决策取代 —— 可观测后端整体切到 CF，Vector 与 ClickHouse 下线，不保留任何第三方可观测后端。**
落地形态见 **#520**：因为 CF 全平台没有 ingest 端点，切换通过**我们自部署的 collector Worker**（`workers/telemetry-collector`）实现 —— 与 #413 的 fronting-Worker 模式一致；FerroGate 经现有 `dispatch_otlp_request` 推 OTLP/HTTP+JSON 给它，它再用 binding 扇出到 Analytics Engine / Workers Logs / Logpush→R2。

边界：Postgres 的 `request_logs` / `audit_events` / `billing_metering_events` **不在切换范围内** —— 它们是计费与审计权威源，不是遥测；AE 读写双向采样、只留 3 个月，且 CF 官方明说其数据集不可用于计费口径。控制面存储迁 CF 是另一条已立项的线（#419 → #420 / #410）。

### 已落地（第一刀）

| 组件 | 位置 |
|---|---|
| `TelemetryBackend` trait —— 后端扩展点 | `crates/ferrogate-observability/src/backend.rs` |
| `OtlpBackend`（原有行为，改为一等后端，导出循环里不再有特例） | 同上 |
| `CloudflareBackend`（bearer 鉴权 + 租户回退头 + 凭据脱敏 Debug） | `crates/ferrogate-observability/src/cloudflare.rs` |
| `ObservabilityProvider::Cloudflare` + `cloudflare_collector_token_ref` / `cloudflare_default_tenant` | `crates/ferrogate-cli/src/config/types.rs` |
| 后端构造（token 经 `SecretResolverRegistry`，解析失败**失败关闭**而非降级为无凭据发送） | `crates/ferrogate-cli/src/state_observability.rs` `telemetry_backend()` |
| 启动期配置校验（缺 token ref / 明文外发凭据 → 启动即报错） | `crates/ferrogate-cli/src/config/validate.rs` |
| collector Worker（OTLP 三路 ingest → AE + Workers Logs，含全部硬限制的强制执行） | `workers/telemetry-collector/` |

设计要点：`ferrogate-observability` 保持**零 I/O**（依赖只有 `serde_json` + `tracing`），所以 `TelemetryBackend` 的方法**构造** `OtlpHttpRequest` 而不发送它；传输仍然只在 `ferrogate-cli` 的 `dispatch_otlp_request` 一处。因此每个后端都能在没有网络、没有 runtime、没有 mock server 的情况下被单测覆盖。

安全边界（均有测试）：bearer 凭据**只允许**走 https，或 http 到 loopback（保住 `wrangler dev`）；`localhost.evil.com` / `127.0.0.1.evil.com` / `user@evil.com` 这类伪装 loopback 一律拒绝；凭据不进 Debug 输出、不进启动日志（日志打 backend 名而非 endpoint）；含 CR/LF 的凭据在启动期就被拒（否则是每 5 秒静默失败一次）。

### 补充决策（founder, 2026-07-26）：可观测闭合在网关层，不在 agent 内

本文档 §1 与 §4b 中把「MCP / sandbox / agent-worker 出站没有 traceparent」列为全链路缺口的说法**已被推翻**，详见 **#522**。

理由：agent 的全部流量（LLM 调用、tool 调用、MCP 调用）本来就都经过 FerroGate，网关一侧即可重建完整链路；而客户的 agent 怎么跑不在我们控制范围内，不可插桩。因此 agent 的唯一义务是**声明一个 action id**，关联靠「流量收口」而不是「上下文传播」。**向不可插桩的第三方 agent 传播 W3C trace context 是明确的非目标。**

连带影响：#520 的 scope 第 7 项作废，且本方案不再依赖 Cloudflare 那个尚未发布的对外 traceparent 传播能力。

以下原「分层」分析保留作为技术依据。

## 4b. 原建议（已被上述决策取代）：分层，而不是替换

**不要做的：** 把 FerroGate（容器内 Rust）的 trace/metric/log 写进 CF —— 技术上要么不可能（Logs/Traces/Logpush），要么需要自建代理 Worker 且倒贴成本（AE/Logs）。同时 CF 各组件保留期（Logs 7 天、AE 3 个月、AI GW 按条数）和采样特性都不满足审计/计费级证据链的要求，而 FerroGate 的 `request_logs`/`audit_events`/`billing_metering_events` 才是权威源。

**应该做的（价值真实存在，且正好补 #413/#428 这条链）：**

1. **CF Worker 段接入我们自己的链路。** 给 `workers/` 下 4 个 Worker 打开 `observability.traces.enabled = true`，OTLP destination 指向我们已有的 Vector（`deploy/vector/vector.yaml` 已在 4318 收 OTLP/HTTP）。
   - ⚠️ 待验证：CF 只发 **JSON 编码**的 OTLP，需确认 Vector 的 `opentelemetry` source 在 4318 上接受 JSON 而非仅 protobuf。
   - ⚠️ 待解决：CF 的 OTLP destination 需要**公网可达**的 endpoint；VPC 内的 Vector 需要经 CF Tunnel / Access 暴露并鉴权。
2. **补上跨边界 trace 传播。** CF 官方的对外 W3C 传播未发布，所以由我们自己做：`gateway-front` / `agent-gateway` 在回源 `fetch()` 上显式带 `traceparent`（我们的 `ingress_trace_context` 已能正确消费），源站侧把 `cf-ray` 记为 span attribute 作为 join 兜底。这与「tethered egress」原则一致 —— agent 全部流量回穿 FerroGate，链路本来就该在我们这一侧闭合。
3. **补齐自己栈的三个洞**（与 CF 无关但是全链路的真短板）：MCP / sandbox / agent-worker 出站无 `traceparent`；metrics 无 histogram（拿不到延迟分位数）；`ObservabilityPlugin` 有名无实（无 export 方法，`ObservabilityExporterKind` 封闭 enum）。
4. **可选、低优先：** 用免费的 GraphQL Analytics API 定期拉 CF 边缘 HTTP 聚合指标（Free 保留 7 天、查询窗口 1 天 → 必须每日轮询才能攒出历史），作为边缘侧补充视图。

对应的 issue 切片建议挂在 epic #404 下（#428「CF agent 可观测与成本治理」是天然归属），或独立挂 #294「Metrics, tracing, and analytics」。

---

## 引用

- Workers Logs / 限制 / 定价：`developers.cloudflare.com/workers/observability/logs/workers-logs/`、`/workers/platform/pricing/`
- Workers Traces（beta）与 OTLP 导出：`/workers/observability/traces/`、`/workers/observability/exporting-opentelemetry-data/`、blog.cloudflare.com/workers-tracing-now-in-open-beta/
- 跨 DO/子请求 trace：`/changelog/post/2026-05-07-automatic-tracing-across-do-and-worker-subrequests/`；custom spans：`/changelog/post/2026-06-16-custom-spans/`
- Tail Workers：`/workers/observability/logs/tail-workers/`
- Logpush：`/logs/logpush/`、`/logs/get-started/api-configuration/`、`/workers/observability/logs/logpush/`
- Analytics Engine：`/analytics/analytics-engine/limits/`、`/sql-api/`、`/pricing/`
- AI Gateway：`/ai-gateway/observability/logging/`、`/custom-metadata/`、`/otel-integration/`、`/reference/limits/`、`/reference/pricing/`
- GraphQL Analytics API：`/analytics/graphql-api/limits/`；Ray ID：`/fundamentals/reference/cloudflare-ray-id/`
- R2 定价：`/r2/pricing/`
