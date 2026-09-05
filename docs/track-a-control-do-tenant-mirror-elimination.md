# Track A:消除 CONTROL_DATA 单例 DO 里的租户/无归属数据镜像

> 上下文记忆固化(2026-09-05)。本文把分散在会话记忆里的 Track A 全过程、当前状态、验证结论、红线例外与未决边界项整理成一份可移交的仓内文档。

## 1. 硬红线与背景

**红线:** 租户 / 无归属数据只能落在 per-tenant `TenantDataObject` 或 `PlatformDataObject`,**禁止镜像进共享的 `CONTROL_DATA` 单例 DO**。

- 控制 D1(`ferrogate-control`)已于 2026-09-01 物理删除;权威 = `CONTROL_DATA` DO(workerd 内 SQLite),整库 lift-and-shift 进单例 DO。
- `ControlDataObject` 仅由 `apps/gateway/src/worker.ts` 导出;其余 worker 跨脚本绑定 `CONTROL_DATA`。
- 迁移在 `ControlDataObject` 冷启动经 `#migrate()`(`blockConcurrencyWhile`)惰性 apply;失败记 `#failure`,之后所有数据 RPC 拒绝。name-gated append 型账本 `control_schema_applied`。
- 权威 live 表清单 = parity-guarded 的 `CONTROL_BACKFILL_TABLES`(`packages/storage/src/control-backfill.ts`);被 DROP 的表必须同时从 manifest 删除,否则 `packages/storage/test/do/control-backfill.test.ts` parity guard 报警。

## 2. 已完成的消除分片(全部已部署上线)

| 迁移 | 家族 / 表 | 说明 |
|---|---|---|
| 0036 / 0040 | 死投影 6 表:`managed_worker_isolation_evidence`、`online_eval_regressions`、`usage_monthly_rollups`、`usage_aggregate_rollups`、`usage_metadata_rollups`、`observed_agent_presence` | 早期死投影链 + rollup;冷启随 gateway apply |
| 0038 | `spend_anomaly_episodes` | anomaly 家族 reader/writer-free 纯 DROP |
| 0039 | `online_eval_leg_quality` | 全重算 REPLACE 型单源切 |
| 0041 | managed_worker 6 表(sessions/lifecycle/isolation_policies/selections/templates/agent_worker_instances) | 纯 DROP,reader/writer-free |
| 0042 | self_hosted worker 证据 5 表(run_dispatches/artifacts/checkpoints/heartbeats/telemetry_events) | 纯 DROP |
| 0043 | `experiment_shadow_legs`、`online_eval_scores` | 读者已扇出租户 DO,死投影链清理 |
| **0045** | **8 表:`quota_policies`、`spend_throttles`、`guardrail_evaluations`、`guardrail_check_evaluations`、`request_logs`、`billing_report_outbox`、`billing_ledger`、`billing_events`** | 本轮一次性收官 DROP(见 §3) |

`v0.27.57` 承载 0038–0042;0045 于 2026-09-04 单独部署。

## 3. 0045 收官分片(本分支主体)

用户两条约束改变了算法:①「一次搞定,不需要的表直接删」= 不再做 OFF-by-default 过渡 flag,**直接删控制腿 + 删 gate helper + 删 env var**;②「线上无客户,不担心数据安全」= **零 backfill**,直接删控制写腿 / 源读者。硬红线:镜像写功能整段删,不留 gated 双写残留。

分层(单迁移 `sql/d1-ts/control/0045_drop_tenant_billing_requestlog_quota_guardrail.sql`,children-first):

- **Tier 1 `quota_policies` + `spend_throttles`:** 删 G2 gate(权威永远 tenant-object),3 个 admission clone(gateway/agent-runtime/mcp)+ 非 admission 读者硬切租户对象 / fail-open;删 quota-policy-backfill 路由;删 5×`*_QUOTA_POLICY_SOURCE` + 2×`*_SPEND_THROTTLE_SOURCE` env var 与 drift 计数。
- **Tier 2 guardrail:** 删两个 drain-on-read backfill 桥 + `admin_request_log` 触发点(fleet/investigation 读走 tenantRouter/platformDb,不动)。
- **Tier 3 `request_logs`:** 删 sink 的 control 投影臂(tenant 权威臂保留,platform best-effort 提升为权威);删 `platform_request_log_backfill` 源与触发点。生产零控制读者。
- **Tier 4 billing 三表:** `runtime.ts` undefined-tenant 分支 `controlDatabaseFrom → platformDatabaseFrom`(整族系此一行);删 sink 双写 shadow / sweepPlatform / platform-billing-flags;删 platform-billing-backfill;`billing.ts` 无归属读切 `platformData`,replay fallback 丢弃(决策 B,404)。
- **Tier 5 收口:** 0045 迁移 + `scripts/generate-control-schema-sql.mjs` 重生 `packages/storage/src/control-schema-sql.ts`(勿手改,字节比对)+ `CONTROL_BACKFILL_TABLES` 删 8 行;parity guard 同批断言 manifest == live `sqlite_master`。

### 部署(2026-09-04,已上线)
本地 `wrangler deploy`,序 **CP → agent-runtime → mcp → gateway**(gateway 最后 = 唯一导出 `ControlDataObject`,冷启 apply 0036→0045 物理 DROP 8 表,不可逆已执行)。

| worker | 版本 |
|---|---|
| control-plane | `68377b53` |
| agent-runtime | `3eee50c5` |
| mcp | `2338e904` |
| gateway | `d0e61bb2` |

部署后 4 worker × `healthz`/`readyz` 全 **200**(`readyz` 触 `ControlDataObject` 冷启读 = DROP 已干净 apply;中途失败会 503)。

- 命令:每 worker `bunx wrangler deploy --config wrangler.deploy.toml --keep-vars`;creds `set -a; source ~/.token4ai-enterprise-live.env; set +a`。
- ⚠️坑:`.deploy.toml` 是模板,`PLATFORM_CONFIG_KV_ID_SET_BY_WORKFLOW` 需临时 sed 成真值 `528fbc4fd13b48f5a7e4cc0086ae13d5`(KV `ferrogate-platform-config`),部署后 sed 还原占位符,树内不留真 id。
- 冷备:`/home/dev/ferrogate-control-backup-20260901-094023.sql`(0045 前 schema)。

## 4. 红线例外(合法 control 权威,**不 DROP**)

- `audit_events` —— 控制面 admin 变更哈希链,**必须单条共享链**,仍活写 control(`apps/control-plane/src/store/d1.ts` hash-chain);SIEM / R2 anchor 读。
- `spend_anomaly_runs` —— single-flight 协调台账,**无 tenant 列**,合法 control 状态(`finops/pass.ts`)。
- 7 张 `*_legacy`(`budget_alert_notifications_legacy`、`control_plane_replay_floors_legacy`、`delegation_revocations_legacy`、`semantic_cache_policies_legacy`、`sso_provider_configs_legacy`、`tenant_provider_credentials_legacy`、`tenant_role_bindings_legacy`)—— **drain-on-read backfill 源**(0016 RENAME 而来),唯一读者 `packages/storage/src/tenant-config-backfill.ts`,经 `tenant_provisioning_marks`/`TENANT_CONFIGURATION_BACKFILL_MARK` 每租户一次性门守护,排空进租户对象后只读对象;无 authority 读者、无 writer。判定 = **非镜像 / 不动**。
- 全部平台 / 账户 / RBAC / 注册表(plans、tenants、platform_*、api_key_directory、static_api_keys、site_domains、sso_*、self_hosted_worker_registrations 等)= 合法控制面权威。

## 5. 验证结论(2026-09-05,回应「是否真的镜像消除了」)

**代码审计 = PASS(红线主张成立,无法证伪)。** 生产**零**活代码把租户/无归属数据写入 control、**零**活代码把这些表作为权威从 control 读。所有活路径解析到 per-tenant 对象(`tenantDatabaseFor` / `resolverForEnv().forTenant` / `tenantEvidenceDatabaseFor` / `fanOutProvisionedTenants`)或 platform 对象(`platformDatabaseFrom` / `deps.platformData`)。例外 `audit_events` / `spend_anomaly_runs` 已核合法。

**线上核查 = 强间接 PASS。** 4/4 worker `healthz`+`readyz` 200;部署版本与 0045 批次逐一吻合;`readyz` 200 证明 control DO 干净 apply 到 0045(中途 DROP 失败会以 503 暴露)。gateway `readyz` = `{"status":"ready", "active_revision":"2b9223c1c1e406bb", "readiness_reason":"state_loaded"}`。

**诚实局限:** 无现成 HTTP 端点枚举生产 control DO 的 live 表清单(`ControlDataObject.schemaStatus` RPC 存在但未挂 HTTP 路由;operator 侧 parity 端点需已删除的 `CONTROL_D1`)。若需字节级「表已消失」证明,可 (A) 加一个 GATED 平台运营专用诊断端点调 `schemaStatus` + 一次性 `sqlite_master` 列表(代码就绪停在部署前),或 (B) 用平台运营 key 做功能性读者切探针。

### 审计发现的死代码/防御性残留(非违规,可选清理)
1. `packages/storage/src/tenant-data-object.ts` `#flushAggregates` 里对 `tenant_*_rollups` 的休眠控制写腿,受 `const PROJECT_TENANT_AGGREGATES_TO_CONTROL = false` 门控(提前 return,不写)。
2. `packages/storage/src/d1/billing-d1.ts` `D1BillingEventLedger` 孤儿类,零调用者。
3. `apps/control-plane/src/routes/admin_request_log.ts` `guardrailChecksFor` 的 `source === "control"` 死分支。
4. `apps/control-plane/src/routes/tenant-teardown.ts` 控制 DELETE 清单仍列 `request_logs`(:122)、`guardrail_evaluations`(:131)、`guardrail_check_evaluations` —— 均受 `existingTables` sqlite_master 探针门控,表已 DROP 故 inert。
5. 少量陈旧注释。

以上均非活体违规,列为可选后续清理片,未启动(须显式确认)。

## 6. 收官决策与未决边界项

**2026-09-04 用户拍板「收官,声明 Track A DROP 完成」。** 未阻塞纯代码 DROP 队列已抽干:0036–0045 后所有主要租户/无归属镜像表均 control-reader/writer-free 且物理 DROP 上线。

仍开放(均 BLOCKED/GATED/设计题,非「零镜像已完全成立」的反例):
- legacy 家族红线收尾(§4,GATED:须先确认全租户含 keep 租户 drain 完 → 退四 worker ~15 处 drain-on-read 桥 → DROP;触及活 BYOK/RBAC/entitlement 热路径)。
- SIEM `request_logs` 读切 #825(as-of 契约 = 设计题;但 `request_logs` 表本身已 0045 DROP)。
- §5 的 5 项死代码清理(非违规)。

## 7. 恒定约束

- keep 租户 `tenant-9a03494f-728d-4871-bc9f-63baa0f48b24` 不动。
- #976 Bedrock/Vertex 不动。
- 部署走本地 `wrangler`(不走 gh workflow;CF token 常过期);creds `~/.token4ai-enterprise-live.env`;`--keep-vars`。
- 分支 `feat/remove-control-d1-tenant-isolation`。
