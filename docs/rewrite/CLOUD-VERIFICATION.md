# Cloud verification — the ONE authorised live deploy

**Status: PLAN ONLY. Nothing in this document has been executed.** *(Wave 22: still true. This wave ran the full regression sweep, the seam pass, five `wrangler dev --local` boots and the E2E suite — all offline. No `wrangler deploy`, no live Cloudflare resource, no upstream LLM call. Wave 19 added **B10**; wave 22 added **B11** and the `runtime-state/drain` row in §2(d).)* No
`wrangler deploy` has been run, no Cloudflare resource has been created or
mutated, and no upstream LLM has been called. Everything proven so far is
`--local` (workerd) or vitest.

The user has authorised **exactly one** deploy + real-request verification and
does not want repeated cloud testing. So the goal of this file is that the run
succeeds on the FIRST attempt: every value a human must supply is named, every
ordering constraint is spelled out, and every binding that is declared but not
yet resolvable is called out **before** the deploy rather than discovered by a
500 afterwards.

Read §0 first — several of the committed defaults must be changed or the
deployed Workers will run in a dev posture: `FG_DEV_IN_MEMORY_PORTS` (B1),
`FG_REQUIRE_PRODUCTION_MTLS` (B6), and the two commented-out cross-script
`RATE_LIMIT` stanzas (B10). None of the three can be gated by a local test.

---

## 0. Blockers that must be resolved BEFORE the deploy

| # | Blocker | Where | What a human must do |
|---|---------|-------|----------------------|
| B1 | `FG_DEV_IN_MEMORY_PORTS = "1"` is committed in **apps/mcp** and **apps/agent-runtime** `[vars]` | `apps/{mcp,agent-runtime}/wrangler.toml` | Override to `"0"` in the deploy environment (`[env.production.vars]` or `--var`). It must NOT be flipped in the committed file: the offline suites and the E2E harness drive the deployed app through that posture, and flipping it in place turns them red on a correct tree. |
| B2 | **R2 is enabled on the account but NO BUCKET EXISTS**, while `apps/gateway` declares `[[r2_buckets]] ASSETS` with a placeholder name | `apps/gateway/wrangler.toml` | Either `wrangler r2 bucket create <name>` and put the real name in the stanza, or delete the `[[r2_buckets]]` stanza for this one verification. A **declared** bucket that does not exist fails the deploy outright. If the stanza is deleted, the gateway boots and the asset family answers `503 asset_bucket_unavailable` — the whole family, not just the presign half. That last part became true only in the wave that added `AssetLimits.objectStoreEnabled`; before it the four presign ops answered 503 while the inline push answered **200** into an isolate-local `Map` whose bytes died with the isolate, leaving a durable D1 metadata row pointing at nothing. `test/assets/r2.test.ts` ("no ASSETS binding ⇒ 503, never a 200 whose bytes evaporate") now holds the posture this row promises, and it is mutation-proven. The developer escape hatch is `FG_DEV_IN_MEMORY_PORTS = "1"`, which must stay unset (or `"0"`) for this run — same var as **B1**. |
| B3 | **The account token lacks KV** (prior finding) but `apps/mcp` declares `[[kv_namespaces]] MCP_OAUTH_KV` | `apps/mcp/wrangler.toml` | Grant the token KV rights and create the namespace, or drop the stanza for this run. Without KV, `resolvePorts` does not enter the `durableIdentityBound` branch and stored-credential encryption is not exercised — say so in the result rather than assuming it passed. |
| B4 | `apps/agent-runtime` declares **no D1 bindings** (both stanzas are committed commented-out, deliberately) | `apps/agent-runtime/wrangler.toml` | `resolveDeps` **fails closed** with no `DB`/`CONTROL_DB`: every authenticated surface refuses. If agent-runtime is in scope for the verification, add the two `[[d1_databases]]` stanzas at deploy time AND apply the migrations; otherwise verify only `/healthz` on it and record that the authenticated surface was not covered. **Wave 21 raised the cost of leaving this unbound:** `CONTROL_DB` is now also the durable A2A upstream registry (`src/agents/registry.ts`), so with no control database `DELETE /admin/v1/agent-upstreams/{id}` still does not reach the DISPATCH path and a compromised upstream withdrawal covers the gateway's discovery door only — the fleet-consistency defect class. See the `AGENT_UPSTREAMS` row in §2 and **V-A3**. |
| B5 | Analytics Engine must be enabled on the account for `apps/telemetry` | `apps/telemetry/wrangler.toml` | AE is a paid-plan feature. With the binding absent the Worker still boots and the OTLP routes answer without writing; with the binding **declared but unavailable**, the deploy fails. |
| B6 | `FG_REQUIRE_PRODUCTION_MTLS = "0"` is committed in **apps/agent-runtime** `[vars]` | `apps/agent-runtime/wrangler.toml` | **Added wave 14.** Same shape as **B1** and previously missing from this table: the flag is committed OFF so `wrangler dev --local` and the offline suite can drive the self-hosted-worker callbacks without client certificates, and a deploy that inherits it runs the production plane with mTLS enforcement DISABLED. Override to `"1"` in the deploy environment; do not flip it in the committed file. `apps/agent-runtime/test/wrangler-bindings.test.ts` now pins the spelling so the var cannot drift out of this row while `src/mtls.ts` still reads it — but no test can stop a deploy inheriting the value, so this stays a human step. |
| B7 | **The admin console + every SSO login is DOWN without `ADMIN_CONSOLE_JWT_SECRET`** on **apps/control-plane** | `apps/control-plane/wrangler.toml` (documented, never declared in `[vars]`) | **Added wave 18**, with the surface itself. `wrangler secret put ADMIN_CONSOLE_JWT_SECRET --name ferrogate-control-plane` BEFORE the first console request. Unset is fail-closed and loud — `POST /v1/admin/login`, `/register`, `/refresh`, `GET /me`, `/team*`, and both SSO callbacks answer `503 admin_console_unconfigured` — so nothing is silently forgeable; but the console is simply unusable until it is set. It must NOT be added to `[vars]`: that file is committed. |
| B8 | **SSO per-tenant IdP secrets are `env://` references, and the referenced secrets must exist** | `sso_provider_configs.oidc_client_secret_ref` (a D1 row, not config) | **Added wave 18.** A tenant's OIDC config stores `env://<NAME>`, never the secret, so the control-plane row can never leak a live IdP credential. Each `<NAME>` must be provisioned with `wrangler secret put <NAME> --name ferrogate-control-plane`. An unresolvable reference fails the login CLOSED (`500`, no session), which is correct but indistinguishable from an IdP outage in the logs — check this explicitly during the run. SAML needs no secret at all: its trust anchor is the certificate the tenant owner pasted into `POST /v1/admin/team/sso-config`. |
| B9 | **The control migrations are now TWO files** | `sql/d1-ts/control/` | **Added wave 18.** `0002_sso_flow_nonce.sql` adds the OIDC `nonce` column to `sso_pending_flows`. `wrangler d1 migrations apply` runs both in order; a database migrated by an earlier wave needs the second file applied or every OIDC callback refuses (the nonce rung cannot be checked). §3's command is unchanged — only the file count is. |
| B10 | **The shared RPM counter is ONE counter on `apps/gateway` only. `apps/mcp` and `apps/agent-runtime` carry the cross-script `RATE_LIMIT` stanza COMMENTED OUT** | `apps/mcp/wrangler.toml:225-231`, `apps/agent-runtime/wrangler.toml:170-176` | **Added wave 19.** Uncomment both stanzas at deploy time, AFTER `ferrogate-gateway` is deployed (a `script_name` binding is resolved by name at deploy time — see §1's deploy order; the gateway is step 3, so both of these move after it). They are committed commented out because workerd cannot resolve a `script_name` binding offline: uncommenting takes each app's suite to **0 collected tests** (`binding "RATE_LIMIT" refers to a service "core:user:ferrogate-gateway", but no such service is defined`), so this can never be gated by a local test and is a **human step with no mechanical backstop**. Left commented, a credential capped at 60 rpm is charged **60 on the gateway PLUS 60×N across N MCP isolates PLUS 60×M across M agent-runtime isolates** — i.e. the RPM ceiling is not enforced fleet-wide. The other four admission legs (quota scope, monthly USD budget, prepaid-wallet hold, counter-key derivation) ARE shared and durable across all three and are proven by `apps/gateway/test/admission-consistency.test.ts`. **Do NOT instead define a local `RateLimiterDurableObject` in either Worker**: that compiles, deploys and passes every test while handing each Worker its own private counter and a second full RPM allowance — a quieter version of the admission bypass wave 16 closed. `apps/{mcp,agent-runtime}/test/env-var-drift.test.ts` pins the three ways the commented stanza can rot (uncommented locally, `script_name` dropped, or a `new_sqlite_classes` added for a class the script does not export). |

| B11 | **`POST /admin/v1/drain` is now a REAL fleet control, and it needs `CONTROL_DB` bound on all three spend Workers to be one** | `apps/{gateway,mcp,agent-runtime}` | **Added wave 22 (FLEET-CONSISTENCY FC-1, all three legs closed).** The operator drain used to be a no-op: the control plane wrote the durable `runtime-state/drain` document and nothing read it, while `apps/gateway` refused off the unrelated deploy-time `GATEWAY_DRAIN` var. All three spend Workers now read that document per request and refuse the spend-producing operations with the same `503 node_draining`. **No new binding was introduced** — each Worker reads it through the control-database handle it already declares (`CONTROL_DB` on gateway and agent-runtime, `DB` on mcp), so there is no new stanza, no new placeholder id, no `[[migrations]]` tag and no `src/worker.ts` re-export. `apps/gateway/test/env-var-drift.test.ts` ("FC-1's durable drain needed NO new binding — wave 22 is wrangler-INERT") asserts that rather than asserting it in prose. The DEPLOY consequence is the one to check during the run: **agent-runtime's two `[[d1_databases]]` stanzas are still committed commented out (B4)**, so on a deployment that leaves them commented `POST /admin/v1/drain` shuts the gateway and mcp and NOT agent-runtime — the same partial-control shape FC-1 was, reintroduced by configuration rather than by code. Uncomment them (B4) or record explicitly that agent-runtime was not covered. `GATEWAY_DRAIN` survives as a gateway-only DEPLOY-TIME override, OR-ed with the document, never "latest wins": either source drains and neither cancels the other, so a stale var cannot silently un-drain a deployment an operator just drained by API. |

---

## 1. Deploy order (it is not arbitrary)

1. **`ferrogate-telemetry`** — first, because `ferrogate-gateway` declares
   `[[services]] binding = "TELEMETRY_COLLECTOR", service = "ferrogate-telemetry"`.
   A service binding is resolved **by name at deploy time**: deploying the
   gateway while no Worker of that name exists fails the gateway deploy.
2. **`ferrogate-control-plane`** — it owns the control database's schema in
   practice (it is the app whose `migrations_dir` and admin routes write the
   control tables).
3. **`ferrogate-gateway`** — needs the control DB (2 of its 3 D1 bindings point
   at it) and the telemetry service.
4. **`ferrogate-mcp`**, 5. **`ferrogate-agent-runtime`** — independent of each
   other; both read the control DB.

---

## 2. (a) Placeholder bindings, per Worker, and the exact value a human supplies

Every value below is a **placeholder in the repo by policy** — no real account
id, database uuid, bucket name or secret is committed.

### `ferrogate-gateway`

| Binding | Stanza | Committed placeholder | Value to supply |
|---|---|---|---|
| `ASSETS` | `[[r2_buckets]]` | `replace-at-deploy-ferrogate-assets` (+ `…-preview`) | Real R2 bucket names — see **B2** |
| `DB` | `[[d1_databases]]` | `database_id = "replace-at-deploy"` | uuid of the **tenant** D1 database |
| `BILLING_DB` | `[[d1_databases]]` | `database_id = "replace-at-deploy"` | uuid of the **control** D1 database |
| `CONTROL_DB` | `[[d1_databases]]` | `database_id = "replace-at-deploy"` | uuid of the **same control** database as `BILLING_DB` |
| `BILLING` | `[[queues.producers]]` | `replace-at-deploy-ferrogate-billing-reports` | Real Queue name. Queues is a paid feature; the queue must exist. **Producer only — nothing consumes it** (documented in the toml), so messages accumulate until a consumer exists. That is expected, not a defect. |
| `GATEWAY_TENANT_DB_ACCOUNT_ID` | `[vars]` | `replace-at-deploy` | Cloudflare account id — **only needed if** `GATEWAY_TENANT_DB_ROUTING` is set to `rest`; it is `off` by default and `off` needs nothing. |
| `RATE_LIMIT` / `PROVIDER_CIRCUIT` / `SHADOW_BUDGET` | `[[durable_objects.bindings]]` | — | Nothing to supply. All three classes are exported by `src/worker.ts` and introduced by `new_sqlite_classes` migrations `v1`/`v2`/`v3`; `test/wrangler-bindings.test.ts` now fails if a binding, an export or a migration goes missing. DOs require a paid plan. |
| `TELEMETRY_COLLECTOR` | `[[services]]` | — | Nothing to supply, but see the deploy ORDER above and §2(d). |
| `BILLING_ALERTS_WEBHOOK_URL`, `BILLING_ALERTS_WEBHOOK_TIMEOUT_SECS` | `[vars]` | `""` and `"5"` | **Wave 20 (cutover HOLD item A1).** Empty is the complete OFF posture, not an unfilled hole: `budgetAlertConfigFromEnv` requires a non-empty `http://`/`https://` URL, so with `""` no threshold crossing is detected, no arbiter row is written and no request pays the two extra D1 round trips. Supply the receiver's URL to turn budget-threshold alerting on; `5` seconds is the Rust default deadline for the POST. Alerting is orthogonal to the `429 monthly_budget_exceeded` hard stop at 100%, which is enforced on the request path either way. The alert is delivered from the metering path AFTER the response is served, so a bad URL costs an alert, never a metering write. **Needs `CONTROL_DB`** — the once-per-period arbiter is the `budget_alert_notifications` table there. |
| `FERROGATE_ASSET_REQUIRE_SIGNATURE`, `FERROGATE_ASSET_PUBLISHER_ED25519_KEYS`, `FERROGATE_ASSET_PUBLISHER_MINISIGN_KEYS` | `[vars]` | `""` (all three) | **Wave 13, and NOT a placeholder that has to be filled.** Blank is a complete, supported posture: `withSignatureVerification` returns the inner screener by identity, so asset publishing behaves exactly as it did before the stage existed. Supply values only to turn publisher-signature verification on: the two key tables hold **public** verification keys (`key-id=<base64>` comma list; minisign public keys, newline list) and belong in a var, not `wrangler secret put` — this Worker verifies and never signs. Setting `FERROGATE_ASSET_REQUIRE_SIGNATURE=1` **with no keys** is fail-closed by design: every push is refused `asset_signature_required` (422). |

### `ferrogate-control-plane`

| Binding | Committed placeholder | Value to supply |
|---|---|---|
| `DB` | `database_id = "PLACEHOLDER_SET_AT_DEPLOY_TIME"` | uuid of the **control** database |

Note `CONTROL_PLANE_STORE` is unset, which means **D1**; `resolveStore` throws a
loud, explicit error if `DB` is missing rather than silently falling back to the
in-memory store.

### `ferrogate-mcp`

| Binding | Committed placeholder | Value to supply |
|---|---|---|
| `MCP_OAUTH_KV` | `id = "PLACEHOLDER_SET_AT_DEPLOY_TIME"` | KV namespace id — see **B3** |
| `DB` | `database_id = "PLACEHOLDER_SET_AT_DEPLOY_TIME"` | uuid of the **control** database |
| `MCP_OAUTH_FLOWS`, `MCP_SESSION` | — | Nothing; classes are exported and migrated (`v1`, `v2`). |

**`apps/mcp`'s `DB` stanza has no `migrations_dir`.** Apply the control schema
from the control-plane app's directory instead (§2(b)) — do not add a second
`migrations_dir` pointing at the same database from two apps.

### `ferrogate-agent-runtime`

No BINDING placeholders — and that is the problem, not the reassurance: it
declares no D1 at all. See **B4**.

| Var | Committed placeholder | Value to supply |
|---|---|---|
| `AGENT_UPSTREAMS` | `"[]"` | **Wave 21 (cutover CLASS A item A3, leg 2).** The operator catalog of A2A upstreams (Rust `[[agent_upstreams]]`) behind the DISPATCH path `POST /v1/agents/{name}` and the `message:*` verbs. **This var is the whole registry ONLY while `CONTROL_DB` is unbound (B4).** Bind the control database and the `control_plane_resources` documents of kind `agent-upstreams` — the same rows `apps/gateway` publishes `GET /.well-known/agent.json` from and the same rows `DELETE /admin/v1/agent-upstreams/{id}` removes — become the whole registry, read once per dispatch with no cache, and **the var is NOT merged over them** (`src/agents/registry.ts`): a union would keep dispatching to an id declared in both after its document is deleted, which is the withdrawal defect this closed. A read error is `503 agent_upstream_unavailable`, never a fall back to this var and never a `404` — an outage must not be reportable as a successful withdrawal. **So leaving `CONTROL_DB` unbound (B4) means `DELETE /admin/v1/agent-upstreams/{id}` still does not reach this Worker,** and the fleet-wide withdrawal is only half-live. Verify with **V-A3** below. |
| `AGENT_WORKFLOWS` | `"[]"` | **Wave 20 (cutover HOLD item A2).** The operator workflow table (Rust `[[agent_workflows]]`) read by the tool-side graph gate in `src/runs/workflow.ts`. Supply a JSON array of workflow documents to pin tools to nodes and constrain edge transitions; leave `"[]"` if workflows are managed exclusively through the admin API, which writes `control_plane_resources` documents of kind `agent-workflows` that this var is materialised OVER. **`"[]"` is not "allow everything":** the gate is opt-in by the `x-ferrogate-workflow-id` header, so a caller that declares a workflow against an empty table is refused `400 workflow_not_found`, and a caller that declares none is unaffected. Reading the durable half additionally needs `CONTROL_DB`, which this Worker does not yet declare (**B4**) — until it does, this var IS the whole table. |

### `ferrogate-telemetry`

| Binding | Committed placeholder | Value to supply |
|---|---|---|
| `TELEMETRY` | `dataset = "PLACEHOLDER_ferrogate_telemetry"` | Real dataset name. The dataset does **not** need to be pre-created — it is created on first write — but AE must be enabled (**B5**). |

---

## 3. (b) Can the D1 migrations be applied from the repo as-is?

**Yes, for the control and tenant databases, via the two apps that declare
`migrations_dir`.** The files are:

- `sql/d1-ts/control/0001_init_control.sql` — 893 lines, 44 `CREATE TABLE`
- `sql/d1-ts/control/0002_sso_flow_nonce.sql` — **wave 18**, one `ALTER TABLE`
  adding the OIDC `nonce` column to `sso_pending_flows`. Wrangler applies both,
  in filename order. See **B9**.
- `sql/d1-ts/tenant/0001_init_tenant.sql` — 627 lines, 20 `CREATE TABLE`

Both follow wrangler's required `NNNN_name.sql` convention, contain no
`PRAGMA`, no explicit `BEGIN TRANSACTION`, and no `ATTACH` — i.e. nothing D1
rejects. The same tenant migration is already executed on every gateway test run
(`vitest.config.ts` feeds it through `readD1Migrations`), so it is known to
apply cleanly to a real SQLite/D1 engine rather than only to a fixture.

Commands (run from the app whose `migrations_dir` points at the database):

```bash
# control schema — from apps/control-plane (migrations_dir = ../../sql/d1-ts/control)
bunx wrangler d1 migrations apply DB --remote

# tenant schema — from apps/gateway (binding DB, migrations_dir = ../../sql/d1-ts/tenant)
bunx wrangler d1 migrations apply DB --remote
```

Caveats a human must know before running them:

1. **`--remote` is the live database.** Without it wrangler applies to the local
   miniflare copy and the deploy will meet an empty schema.
2. **The gateway declares three D1 bindings across two databases.** Applying
   from the gateway applies the TENANT schema to `DB` only; `BILLING_DB` and
   `CONTROL_DB` point at the control database and are covered by step 1.
   Applying the tenant migration to the control database (or vice versa) is the
   easiest way to break this run.
3. **Ordering matters at request time, not at migration time**: a bound `DB`
   whose `api_keys` table is missing makes every bearer request answer 503
   (`ApiKeyStoreUnavailable`) rather than falling through to the config keys.
   Migrate before the first request, not after.

---

## 4. (c) Secrets that must be set with `wrangler secret put`

None of these is committed, and each is read as `env.<NAME>`. All are **absent =
inert**, never absent = insecure.

| Worker | Secret | Consequence if unset |
|---|---|---|
| gateway | `TELEMETRY_TOKEN` | `telemetryFromEnv` returns `NO_TELEMETRY`; every emit is a no-op. **Required if the verification is meant to prove telemetry reaches `apps/telemetry`.** |
| gateway | provider credentials named by `GATEWAY_PROVIDERS[].api_key_var` (e.g. `OPENAI_API_KEY`) | The catalog fails **closed**: the provider refuses rather than dispatching with an empty credential. Required for any real inference request. |
| gateway | `ASSET_S3_ACCESS_KEY_ID`, `ASSET_S3_SECRET_ACCESS_KEY`, (`ASSET_S3_SESSION_TOKEN`) | SigV4 presign stays disabled; the presign family answers 503. Only needed if the S3-compatible asset path is in scope. |
| gateway | `FERROGATE_ASSET_PUBLISHER_MINISIGN_KEYS` / `FERROGATE_ASSET_PUBLISHER_ED25519_KEYS`, `FERROGATE_ASSET_REQUIRE_SIGNATURE` | Detached publisher-signature verification is inert: every push is labeled `signature=unsigned` and admitted, which is the Rust unconfigured posture. Setting `FERROGATE_ASSET_REQUIRE_SIGNATURE=1` WITHOUT keys fails closed (every push `422 asset_signature_required`) — that is deliberate, not a misconfiguration to work around. Not needed for the verification. |
| gateway | `GATEWAY_TENANT_DB_API_TOKEN` | Only for `GATEWAY_TENANT_DB_ROUTING = "rest"`; the resolver refuses to route without it. Not needed at the default `off`. |
| gateway | `BILLING_ALERTS_WEBHOOK_SIGNING_SECRET` | **Wave 20.** HMAC-SHA256 key for `X-FerroGate-Signature` over `"<timestamp>.<body>"`, i.e. the key the alert RECEIVER authenticates the notification with. Unset with a URL set ⇒ the alert is still delivered, **unsigned** — the documented Rust posture for an operator who configured no key, and the reason this is "absent = inert" rather than "absent = insecure". Committing it would be worse than useless: anyone who can read the repo could forge a budget alert. Read as `bindings.BILLING_ALERTS_WEBHOOK_SIGNING_SECRET` (a renamed parameter), which is why `apps/gateway/test/env-var-drift.test.ts` carries it in `SECRETS_READ_INDIRECTLY` rather than `SECRETS`. Only needed if the budget-alert webhook is in scope for the run. |
| mcp | `FERROGATE_MCP_IDENTITY_KEY` | Envelope encryption for stored credentials is unavailable; the cipher port is unbound. Needed for the stored-credential path. |
| control-plane | `ADMIN_CONSOLE_JWT_SECRET` | **Wave 18. The one secret on this Worker that is REQUIRED, not optional.** HS256 signing key for the admin-console session JWT, which every SSO login also ends in. Unset ⇒ the whole `/v1/admin/*` surface and both SSO callbacks answer `503 admin_console_unconfigured`. There is deliberately no default: a constant is forgeable by anyone who reads the source, and a per-isolate random value silently invalidates every session on isolate eviction. See **B7**. |
| control-plane | one per tenant IdP, named by `sso_provider_configs.oidc_client_secret_ref` | **Wave 18.** The OIDC client secret. Stored as an `env://NAME` REFERENCE in D1, resolved just-in-time at the callback through `@ferrogate/secrets`. Unset ⇒ that tenant's OIDC login fails closed (no session). SAML tenants need none. See **B8**. |
| all | — | There is **no** `[[secrets_store]]` binding declared in any app. `cf://<store>/<name>` references therefore do not resolve; only `env://NAME` does. This is a known open constraint (Secrets Store bindings are deploy-time), not a regression. |

```bash
# from the app directory, e.g. apps/gateway
bunx wrangler secret put TELEMETRY_TOKEN
```

---

## 5. (d) Declared but not necessarily readable

| Binding | Declared in | Reality |
|---|---|---|
| `TELEMETRY_COLLECTOR` (`[[services]]` → `ferrogate-telemetry`) | gateway | **Resolvable only if `ferrogate-telemetry` is deployed first.** Under `wrangler dev --local` it boots and reports the binding as `[not connected]` — the gateway boot PASS in this repo therefore does *not* prove the collector is reachable. Under vitest it resolves to a stub Worker registered by `vitest.config.ts`. The new `test/wrangler-bindings.test.ts` pins that the stanza exists, names `ferrogate-telemetry`, and that whatever it resolves to has a `fetch` — it cannot prove the live cross-Worker hop. **Verify this one explicitly in the live run.** |
| `BILLING` (`[[queues.producers]]`) | gateway | Write-only by design; no consumer Worker exists in this repo. A successful publish proves the producer half only. |
| `TELEMETRY` (`[[analytics_engine_datasets]]`) | telemetry | `writeDataPoint()` is the only write path and it is fire-and-forget: a failed write does not surface in the response. Reading back requires the AE SQL API, which is a separate (read-only) HTTP call. |
| `MCP_OAUTH_KV` | mcp | Gated on **B3**; if the token lacks KV the deploy fails rather than degrading. |
| `DB` / `CONTROL_DB` on agent-runtime | agent-runtime | **Not declared at all** (B4) — the authenticated surface fails closed. **Wave 22 raised the cost again**: that handle is now also how this Worker reads the operator drain and the tenant lifecycle authority, so with it unbound `POST /admin/v1/drain` and a tenant SUSPENSION both stop two of three spend Workers and leave this one out of the answer. See **B11**. |
| `runtime-state/drain` (a ROW, not a binding) | control-plane writes, gateway + mcp + agent-runtime read | **Added wave 22.** There is nothing to declare and nothing to supply — the drain is a `control_plane_resources` row addressed by `(resource_kind='runtime-state', resource_id='drain')` through each Worker's existing control-database handle. It is listed here because it is the one control whose *deploy-time* correctness is a function of §2's D1 uuids rather than of a stanza: point two Workers at DIFFERENT control databases and each drains independently while every suite stays green. **All three spend Workers must resolve the SAME control database uuid.** `apps/gateway` uses the same uuid for `BILLING_DB` and `CONTROL_DB` (§2a) and `apps/mcp` binds it as `DB`; check the three values match before the deploy, and confirm with **V-FC1** below. |
| `/v1/admin/*`, `/scim/v2/*` (wave 18) | control-plane | **Mounted and locally proven** (`apps/control-plane/test/identity-mount.test.ts`, 23 SELF-driven cases including the adversarial refusals), but three legs cross the network and NO local runner can prove them: the OIDC discovery fetch, the token-endpoint exchange and the JWKS fetch all go to a real IdP. The offline suite stands a stand-in IdP over `globalThis.fetch`. **A live run must complete one real OIDC login and one real SAML login end to end**, or those three legs stay unproven against a real provider's document shapes. |
| Durable Objects (all 7) | gateway/mcp/agent-runtime | Require a paid plan. Each `class_name` is gated against both the entry-module export and a `new_sqlite_classes` migration — by `apps/gateway/test/wrangler-bindings.test.ts` for the three gateway classes, and, **as of wave 14, by the newly ported `apps/mcp/test/wrangler-bindings.test.ts` and `apps/agent-runtime/test/wrangler-bindings.test.ts` for the other four.** The earlier claim here that mcp/agent-runtime were "held by their own mutation proofs" was **wrong**, and the wave-14 sweep proved it: deleting either `new_sqlite_classes` line in `apps/mcp/wrangler.toml`, or the single one in `apps/agent-runtime/wrangler.toml`, left every test in those apps GREEN. Neither app read its committed toml at all (both `vitest.config.ts` files override `main` and bound no `TEST_WRANGLER_TOML`). All four seams are now RED under mutation, including the substitution of `new_classes` for `new_sqlite_classes` — the variant that DEPLOYS SUCCESSFULLY and silently gives the class the key-value backend instead of SQLite. |

---

## 6. Ordered checklist for the single run

Preconditions (once, by hand):

1. Confirm the account plan covers **Durable Objects, Queues, and Analytics
   Engine**; resolve **B2** (R2) and **B3** (KV) by either enabling the product
   or removing that one stanza for this run.
2. `wrangler d1 create ferrogate-control` and `wrangler d1 create
   ferrogate-tenant`; record both uuids.
3. `wrangler queues create <billing-reports-queue>`; record the name.
4. (If B2 resolved by enabling R2) `wrangler r2 bucket create <assets-bucket>`.
5. (If B3 resolved by enabling KV) `wrangler kv namespace create MCP_OAUTH_KV`;
   record the id.

Fill in the placeholders — **do not commit these edits**:

6. gateway: `database_id` ×3, `bucket_name` ×2, queue name.
7. control-plane: `database_id`.
8. mcp: `database_id`, KV `id`, and `FG_DEV_IN_MEMORY_PORTS = "0"` (B1).
9. agent-runtime: `FG_DEV_IN_MEMORY_PORTS = "0"` (B1),
   `FG_REQUIRE_PRODUCTION_MTLS = "1"` (**B6**) and, if in scope, the two
   D1 stanzas (B4). Leave `CONTAINER_GOVERNED_EGRESS_HOSTS = ""` as committed
   unless the run needs container egress: empty means SEALED (#471), and
   `test/governance-mount.test.ts` (wave 14) proves `resolveDeps` really reads
   the var rather than defaulting permissively.
10. telemetry: real `dataset` name.

Schema:

11. `cd apps/control-plane && bunx wrangler d1 migrations apply DB --remote`
12. `cd apps/gateway && bunx wrangler d1 migrations apply DB --remote`
    (tenant schema → tenant database only).

Secrets (§4), at minimum `TELEMETRY_TOKEN` and one provider key.

Deploy, in this order: `telemetry` → `control-plane` → `gateway` → `mcp` →
`agent-runtime`.

Verify with real requests — the smallest set that actually proves the wiring:

| # | Request | Expected | What it proves |
|---|---------|----------|----------------|
| V1 | `GET /healthz` on all five | 200 + `{"status":"ok","service":…,"version":…,"runtime":"workers"}` — **all five, identical shape** (measured wave 21 under `wrangler dev --local`; the older note that agent-runtime answers `{"ok":true}` is stale, wave 20 closed it) | The Worker boots in production, which `--local` only approximates |
| V2 | `GET /readyz` on the gateway | 200 | Config revision loaded and not draining |
| V3 | `GET /v1/models` with **no** credential | `401 missing_api_key` | The contract guard is live ahead of every route |
| V4 | `GET /v1/models` with a provisioned key | 200 + the configured registry | D1 key authentication against the REAL control database |
| V5 | `POST /v1/chat/completions` with a real provider key | 200 | The one request that costs money — the whole dispatch path, and the only step that calls an upstream LLM |
| V6 | Re-read the tenant `billing_ledger` / `billing_events` rows after V5 | one idempotent row each | Durable metering committed, not just computed |
| V7 | Query the AE dataset (SQL API) after V5 | ≥1 data point | **The `[[services]]` hop in §5** — the only thing that proves `TELEMETRY_COLLECTOR` actually resolved |
| V8 | `GET /admin/v1/tenants` on the control plane with an operator key | 200 | The control-plane D1 store on a real database |
| V9 | `POST /v1/mcp` with `{"jsonrpc":"2.0",…}` and no credential | `401` in a well-formed 2.0 envelope | MCP transport guard with durable auth bound |
| V10 | Wait one minute, then check the Cron invocation log on gateway + control-plane | one invocation each | `[triggers] crons` → the `scheduled` handler on the default export. **Nothing local can prove this**: workerd never dispatches a scheduled event under vitest or `wrangler dev`. |
| **V-A3** | `POST /admin/v1/agent-upstreams` a throwaway upstream, then (a) `GET /.well-known/agent.json` on the **gateway** and (b) `POST /v1/agents/{id}` on **agent-runtime** — both must see it. Then `DELETE /admin/v1/agent-upstreams/{id}` and repeat (a) and (b) with **no redeploy and no restart** | before: published + dispatched. after: absent from the discovery document AND `404 agent_not_found` on dispatch | **Wave 21 (cutover CLASS A item A3).** The FLEET EFFECT of one withdrawal across two Workers, which is the property both halves exist for and which no per-Worker suite can see. It requires `CONTROL_DB` bound on agent-runtime (**B4**); with it unbound, (b) will keep answering off the deploy-time `AGENT_UPSTREAMS` var and the withdrawal is half-live. Proven offline against a migrated D1 by `apps/agent-runtime/test/durable/agent-upstream-withdrawal.spec.ts` + `apps/gateway/test/routes/agent-upstream-withdrawal.test.ts`; this row is the account-side confirmation. |

| **V-FC1** | `POST /admin/v1/drain {"draining": true}` on the control plane ONCE, then, with **no redeploy, no restart and no var flip**: (a) `POST /v1/chat/completions` on the **gateway**, (b) `tools/call` on **mcp**, (c) `POST /v1/agent-jobs` on **agent-runtime**. Then `POST /admin/v1/drain {"draining": false}` and repeat all three | before: the three normal answers. after: **`503 node_draining` on all three, same status, same code, same message**. lifted: all three serving again | **Wave 22 (FLEET-CONSISTENCY FC-1, third leg).** The whole point of the finding: one operator action, every enforcer. Also check `GET /readyz` flips to `503` with `readiness_reason: "operator_drain"` while `GET /healthz` stays **200** — liveness must not flip or an orchestrator restarts the node and destroys the in-flight work the drain exists to let finish. If (c) keeps serving, agent-runtime's D1 stanzas are still commented (**B4**/**B11**). If any of the three answers `503 drain_state_unavailable` instead, that Worker's control database is bound and unreachable — a different fact, deliberately given a different code. Proven offline by `apps/gateway/test/fleet-control-matrix.test.ts` §5 and `apps/mcp/test/drain-fleet.test.ts`; this row is the account-side confirmation. |
| **V-FC2** | Suspend a tenant ONCE through the control plane (`tenants.status`), then call all three spend Workers with that tenant's still-valid credential | `403 tenancy_suspended` on all three, same status and code; a suspended KEY (as opposed to tenancy) stays `401 invalid_api_key` on all three | **Wave 22 (FC-2).** The wave-16 admission bypass wearing a second control: the credential still RESOLVES, so the exploit was "call the other endpoint". Requires `CONTROL_DB` on agent-runtime (**B4**). Proven offline by `apps/mcp/test/fleet-tenancy-suspension.test.ts`. |
| **V-FC3** | Activate ONE guardrail policy revision (`POST /admin/v1/guardrail-policies/{id}/activate`), then send a payload the gateway blocks (a) through `/v1/chat/completions`, (b) inside an MCP `tools/call` argument, (c) inside an A2A `message:send` body | blocked on all three with the OPERATOR's own policy code | **Wave 22 (FC-3).** Before this wave (b) and (c) screened from `FG_DEV_*` deploy-time vars that no deployment sets, so an activated revision covered one door of three. Note the deliberate scope split: a model-content policy does NOT police an MCP tool call and vice versa — that is Rust parity, not a gap. Proven offline by `apps/mcp/test/fleet-guardrail-activation.test.ts` and `apps/agent-runtime/test/durable/guardrail-policy-activation.spec.ts`. |

Roll back / stop: if any step fails, capture the error and stop — do not iterate
against the account. Every failure mode above is reproducible locally except
V5, V7 and V10.
