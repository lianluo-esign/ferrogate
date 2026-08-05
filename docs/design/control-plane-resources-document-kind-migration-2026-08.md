# `control_plane_resources` Kind Migration Matrix

Issue [#861](https://github.com/lianluo-esign/ferrogate/issues/861) is the
generic-document slice of parent [#831](https://github.com/lianluo-esign/ferrogate/issues/831).
The discriminator is `resource_kind`; `tenantScopeSql` is only valid for the
control-D1 compatibility path. The object-local destination is the
tenant's `TenantDataObject`, using a same-shape `tenant_resources` table.

## Matrix legend

- `object`: authoritative document in the tenant's object; the JSON
  `tenant_id` remains a misrouting tripwire, not an object-local filter.
- `control`: authoritative platform-global document in control D1; tenant
  reads may see it and tenant writes remain protected by `tenantWriteScopeSql`.
- `projection`: the generic document is not authoritative; follow the typed or
  evidence table named in the reader column.
- `compat`: the existing control-D1 row is retained until the named reader has
  moved. It is never a fallback when an object read fails.

## Tenant-discriminated kinds

| Kind | Authority | Writer | Reader | Migration / compatibility |
|---|---|---|---|---|
| `tenant-accounts` | object | `control-plane/routes/tenant_hierarchy.ts`, `session/routes.ts` | control-plane lifecycle and hierarchy; tenant typed `tenants` row | Copy by tenant id; keep typed control projection. |
| `projects` | object | `control-plane/routes/tenant_hierarchy.ts` | tenant `projects`; lifecycle gate | Copy; object-first document, typed object projection. |
| `workspaces` | object | `control-plane/routes/tenant_hierarchy.ts` | tenant `workspaces`; lifecycle gate | Copy; object-first document, typed object projection. |
| `virtual-keys` | object | `control-plane/routes/admin_virtual_key.ts`, `session/gateway_key.ts` | control `api_key_directory` plus tenant `api_keys` | Copy; retain both typed indexes. |
| `api-keys` | object | control-plane admin API-key routes | tenant `api_keys` | Copy; control directory remains the pre-tenant auth index. |
| `quota-policies` | object | `control-plane/routes/quota_policy.ts` | gateway typed `quota_policies` admission source | Move document and projection together; operator-only write fence stays. |
| `agent-upstreams` | object | `control-plane/routes/admin_agent_upstream.ts` | gateway discovery/dispatch and agent-runtime registry | Copy, then switch reach-set readers; control row is compat only. |
| `agent-workflows` | object | `control-plane/routes/admin_agent_workflow.ts` | gateway workflow gate and agent runtime | Copy, then switch gate readers; control row is compat only. |
| `agent-schedules` | object | `control-plane/routes/admin_agent_schedule.ts` | tenant schedule engine | Copy; object is the schedule source. |
| `agent-schedule-fires` | object | control-plane schedule engine | tenant fire ledger | Copy with schedules; preserve at-most-once keys. |
| `agent-runs` | object | gateway/agent-runtime evidence writers | request investigation and runtime history | Copy; control evidence row is compat/projection. |
| `agent-run-events` | object | gateway/agent-runtime evidence writers | tenant run timeline | Copy; control evidence row is compat/projection. |
| `mcp-servers` | object | `control-plane/routes/admin_mcp_server.ts` | `apps/mcp/src/catalog.ts` | Copy; switch catalog reader in the MCP follow-up slice; control row is compat. |
| `tool-approvals` | object | control-plane tool routes | MCP/tool approval path | Copy; retain control compat until MCP reader cutover. |
| `tool-sessions` | object | MCP/tool session writer | tool-session lookup | Copy; retain control compat until reader cutover. |
| `tool-session-events` | object | MCP/tool session writer | tool-session event listing | Copy; retain control compat until reader cutover. |
| `plugins` | object | `control-plane/routes/admin_plugin.ts` | plugin registry consumer, if enabled | Copy; no hidden control authority. |
| `plugin-tools` | object | plugin registry writer | plugin tool listing | Copy; no hidden control authority. |
| `skill-packages` | object | `control-plane/routes/skill.ts` | gateway skill/package consumer | Copy; control row is compat until consumer cutover. |
| `prompt-templates` | object | `control-plane/routes/prompt.ts` | gateway prompt resolver | Copy; KV label pointer remains a projection. |
| `prompt-template-labels` | object | `control-plane/routes/prompt.ts` | prompt label reader plus KV pointer | Copy; keep KV pointer projection. |
| `policies` | object | `control-plane/routes/admin_policy.ts` | policy consumers | Copy; control row is compat until consumer cutover. |
| `x402-spend-policies` | object | `control-plane/routes/x402_spend_policy.ts` | x402 policy consumer | Copy; control row is compat until consumer cutover. |
| `wallets` | object | `control-plane/routes/wallets.ts` | tenant wallet tables and gateway wallet guard | Copy; typed money tables remain transactional authority. |
| `wallet-ledger` | object | `control-plane/routes/wallets.ts` | tenant wallet ledger | Copy; preserve idempotency and ordering. |
| `payment-methods` | object | `control-plane/routes/wallets.ts` | tenant payment-method reader | Copy; typed secret-bearing fields stay tenant-local. |
| `payment-attempts` | object | payment attempt store | x402 payment attempt reader | Copy when the typed table exists; no control fallback. |
| `site-domains` | object | `control-plane/routes/site_domain.ts` | router/domain path plus typed site-domain index | Copy; keep typed control projection. |
| `site-domain-verifications` | object | `control-plane/routes/site_domain.ts` | domain verification path | Copy; verification CAS runs against object document. |
| `semantic-cache-policies` | object | `control-plane/routes/admin_semantic_cache.ts` | gateway cache governance | Copy; typed control policy is a projection. |
| `asset-reviews` | object | `control-plane/routes/admin_asset.ts` | asset review/takedown path | Copy; preserve review-before-reclaim ordering. |
| `asset-deletions` | object | `control-plane/routes/admin_asset.ts` | asset deletion/reclamation path | Copy; preserve deletion evidence and retry state. |
| `tenant-roles` | object | `control-plane/routes/rbac.ts` | tenant RBAC path | Copy; control role/permission tables remain shared inputs. |
| `self-hosted-workers` | object | `control-plane/routes/self_hosted_worker.ts` | worker registration and fleet view | Copy; operator fleet view uses bounded fan-out. |
| `self-hosted-runs` | object | self-hosted runtime | worker run reader | Copy; control row is compat/projection. |
| `self-hosted-run-events` | object | self-hosted runtime | worker timeline reader | Copy; control row is compat/projection. |
| `self-hosted-run-dispatches` | object | `control-plane/routes/self_hosted_worker.ts` | dispatch callback path | Copy; preserve operator-only callback fence. |
| `self-hosted-worker-artifacts` | object | self-hosted runtime | tenant artifact metadata | Copy; bytes remain in R2. |
| `self-hosted-worker-checkpoints` | object | self-hosted runtime | tenant checkpoint recovery | Copy; object is the recovery authority. |
| `self-hosted-worker-events` | object | self-hosted runtime | tenant worker event timeline | Copy; control row is compat/projection. |
| `experiments` | object | `control-plane/routes/admin_experiment.ts` | tenant experiment/evaluation path | Copy; control row is compat for operator inspection. |
| `investigations` | object | control-plane investigation path | tenant investigation view | Copy; cross-tenant view uses bounded fan-out/projection. |
| `workflow-run-steps` | object | gateway workflow history | gateway workflow history reader | Copy; switch direct control-D1 reader to object. |
| `metering-events` | object/projection | gateway metering writer | typed billing/metering reader | Copy only where document is authoritative; typed billing remains source. |
| `billing-outbox-dead-letters` | object/projection | gateway billing outbox | billing replay path | Copy only where tenant-owned; control fleet replay is a projection reader. |
| `usage-reports` | object/projection | usage/finops writer | tenant usage/report reader | Copy only where tenant-owned; aggregate source remains typed. |
| `cost-record-exports` | object/projection | cost export writer | tenant export reader | Copy only where tenant-owned; fleet export uses named projection. |
| `request-log-exports` | object/projection | request-log export writer | SIEM/export reader | Resolve the sink tenant before reading; no tenant-anonymous object lookup. |

Rows with an `object/projection` label are derived document faces. The typed
source and any cross-tenant reader must be named before the document is removed
from control D1.

## Platform-global kinds

| Kind | Authority | Writer | Reader | Migration |
|---|---|---|---|---|
| `plans` | control | control-plane plan routes | gateway quota admission | Stay on control D1. |
| `permissions` | control | control-plane RBAC seed/admin | RBAC authorizer | Stay on control D1. |
| `roles` | control | control-plane RBAC routes | RBAC authorizer | Stay on control D1. |
| `providers` | control | provider registry | gateway provider resolver | Stay on control D1. |
| `provider-models` | control | provider registry | gateway model resolver | Stay on control D1. |
| `provider-health` | control | health/update path | gateway provider selection | Stay on control D1. |
| `models` | control | model registry | gateway model resolver | Stay on control D1. |
| `gateway-configs` | control | gateway config admin path | gateway runtime config | Stay on control D1. |
| `framework-adapters` | control | adapter registry | gateway runtime | Stay on control D1. |
| `extensions` | control | plugin/extension registry | platform extension status | Stay on control D1. |
| `runtime-state` | control | config ops (`drain`, `active-config`) | gateway and agent-runtime readiness/drain | Stay on control D1; read occurs before tenant routing. |
| `d1_tenant_database` | control | storage registry migration | tenant database registry | Stay on control D1; typed `tenant_databases` is newer state. |
| `guardrail-policies` | control | guardrail policy routes | gateway guardrail resolver | Stay on control D1; nested selectors are not `$.tenant_id`. |
| `guardrail-policy-revisions` | control | guardrail policy routes | gateway guardrail resolver | Stay on control D1; nested selectors are not `$.tenant_id`. |

## Read-only/projection collections

These names are exposed by the admin API but have no generic document writer.
They follow the typed/evidence source and are not independently migrated:

| Kind | Source / authority | Reader disposition |
|---|---|---|
| `tenants` | control typed `tenants` | platform/shared; control D1 |
| `request-logs` | tenant request-log evidence plus control projection | tenant object for tenant view; bounded fleet projection |
| `audit-events` | control audit chain | control D1 until audit migration |
| `guardrail-evaluations` | tenant guardrail evidence plus control projection | tenant object for tenant view; bounded fleet projection |
| `cost-records` | typed cost records | derived; follow cost source |
| `usage-aggregates` | typed usage rollups | derived; tenant object plus aggregate projection |
| `agent-cost-burn` | typed tenant cost burn | derived; capped tenant fan-out |
| `managed-workers` | typed managed worker tables | tenant object plus bounded fleet view |
| `managed-worker-sessions` | typed managed worker sessions | tenant object plus bounded fleet view |
| `self-hosted-worker-records` | typed control worker registry | platform/shared; control D1 |
| `spend-anomalies` | typed anomaly episodes | derived; control/finops source |
| `metering-export-status` | export cursor/status tables | tenant-scoped projection; cursor owner names tenant |
| `observed-agent-activity` | typed activity rollup | derived; follow rollup source |
| `tools` | MCP/plugin registry | tenant object after MCP cutover; control row is compat |

## Safety contract

1. A new kind must be added to the registry and this matrix before the durable
   split store can persist it.
2. Object-local SQL has no `tenantScopeSql`; the object identity is the fence,
   while the document's `tenant_id` is checked as a misrouting tripwire.
3. Legacy tenant rows are copied idempotently and resumably. Control rows are
   not deleted while a named reader still depends on them.
4. Platform-operator tenant reads use a bounded tenant fan-out or a named
   control projection. They never address an arbitrary object from unvalidated
   JSON.
5. Unknown kinds fail closed rather than silently defaulting to control D1.
