# Cloud verification — the ONE authorised live deploy

**Status: PLAN ONLY. Nothing in this document has been executed.** No
`wrangler deploy` has been run, no Cloudflare resource has been created or
mutated, and no upstream LLM has been called. Everything proven so far is
`--local` (workerd) or vitest.

The user has authorised **exactly one** deploy + real-request verification and
does not want repeated cloud testing. So the goal of this file is that the run
succeeds on the FIRST attempt: every value a human must supply is named, every
ordering constraint is spelled out, and every binding that is declared but not
yet resolvable is called out **before** the deploy rather than discovered by a
500 afterwards.

Read §0 first — three of the committed defaults must be changed or the deployed
Workers will run in a dev posture.

---

## 0. Blockers that must be resolved BEFORE the deploy

| # | Blocker | Where | What a human must do |
|---|---------|-------|----------------------|
| B1 | `FG_DEV_IN_MEMORY_PORTS = "1"` is committed in **apps/mcp** and **apps/agent-runtime** `[vars]` | `apps/{mcp,agent-runtime}/wrangler.toml` | Override to `"0"` in the deploy environment (`[env.production.vars]` or `--var`). It must NOT be flipped in the committed file: the offline suites and the E2E harness drive the deployed app through that posture, and flipping it in place turns them red on a correct tree. |
| B2 | **R2 is enabled on the account but NO BUCKET EXISTS**, while `apps/gateway` declares `[[r2_buckets]] ASSETS` with a placeholder name | `apps/gateway/wrangler.toml` | Either `wrangler r2 bucket create <name>` and put the real name in the stanza, or delete the `[[r2_buckets]]` stanza for this one verification. A **declared** bucket that does not exist fails the deploy outright. If the stanza is deleted, the gateway boots and the asset family answers `503 asset_bucket_unavailable` — the whole family, not just the presign half. That last part became true only in the wave that added `AssetLimits.objectStoreEnabled`; before it the four presign ops answered 503 while the inline push answered **200** into an isolate-local `Map` whose bytes died with the isolate, leaving a durable D1 metadata row pointing at nothing. `test/assets/r2.test.ts` ("no ASSETS binding ⇒ 503, never a 200 whose bytes evaporate") now holds the posture this row promises, and it is mutation-proven. The developer escape hatch is `FG_DEV_IN_MEMORY_PORTS = "1"`, which must stay unset (or `"0"`) for this run — same var as **B1**. |
| B3 | **The account token lacks KV** (prior finding) but `apps/mcp` declares `[[kv_namespaces]] MCP_OAUTH_KV` | `apps/mcp/wrangler.toml` | Grant the token KV rights and create the namespace, or drop the stanza for this run. Without KV, `resolvePorts` does not enter the `durableIdentityBound` branch and stored-credential encryption is not exercised — say so in the result rather than assuming it passed. |
| B4 | `apps/agent-runtime` declares **no D1 bindings** (both stanzas are committed commented-out, deliberately) | `apps/agent-runtime/wrangler.toml` | `resolveDeps` **fails closed** with no `DB`/`CONTROL_DB`: every authenticated surface refuses. If agent-runtime is in scope for the verification, add the two `[[d1_databases]]` stanzas at deploy time AND apply the migrations; otherwise verify only `/healthz` on it and record that the authenticated surface was not covered. |
| B5 | Analytics Engine must be enabled on the account for `apps/telemetry` | `apps/telemetry/wrangler.toml` | AE is a paid-plan feature. With the binding absent the Worker still boots and the OTLP routes answer without writing; with the binding **declared but unavailable**, the deploy fails. |

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

No placeholders — and that is the problem, not the reassurance: it declares no
D1 at all. See **B4**.

### `ferrogate-telemetry`

| Binding | Committed placeholder | Value to supply |
|---|---|---|
| `TELEMETRY` | `dataset = "PLACEHOLDER_ferrogate_telemetry"` | Real dataset name. The dataset does **not** need to be pre-created — it is created on first write — but AE must be enabled (**B5**). |

---

## 3. (b) Can the D1 migrations be applied from the repo as-is?

**Yes, for the control and tenant databases, via the two apps that declare
`migrations_dir`.** The files are:

- `sql/d1-ts/control/0001_init_control.sql` — 893 lines, 44 `CREATE TABLE`
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
| mcp | `FERROGATE_MCP_IDENTITY_KEY` | Envelope encryption for stored credentials is unavailable; the cipher port is unbound. Needed for the stored-credential path. |
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
| `DB` / `CONTROL_DB` on agent-runtime | agent-runtime | **Not declared at all** (B4) — the authenticated surface fails closed. |
| Durable Objects (all 7) | gateway/mcp/agent-runtime | Require a paid plan. Each `class_name` is now gated against both the entry-module export and a `new_sqlite_classes` migration by `apps/gateway/test/wrangler-bindings.test.ts`; the equivalent for mcp/agent-runtime is held by their own mutation proofs. |

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
9. agent-runtime: `FG_DEV_IN_MEMORY_PORTS = "0"` (B1) and, if in scope, the two
   D1 stanzas (B4).
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
| V1 | `GET /healthz` on all five | 200 + `{"status":"ok","service":…}` (agent-runtime answers `{"ok":true}`) | The Worker boots in production, which `--local` only approximates |
| V2 | `GET /readyz` on the gateway | 200 | Config revision loaded and not draining |
| V3 | `GET /v1/models` with **no** credential | `401 missing_api_key` | The contract guard is live ahead of every route |
| V4 | `GET /v1/models` with a provisioned key | 200 + the configured registry | D1 key authentication against the REAL control database |
| V5 | `POST /v1/chat/completions` with a real provider key | 200 | The one request that costs money — the whole dispatch path, and the only step that calls an upstream LLM |
| V6 | Re-read the tenant `billing_ledger` / `billing_events` rows after V5 | one idempotent row each | Durable metering committed, not just computed |
| V7 | Query the AE dataset (SQL API) after V5 | ≥1 data point | **The `[[services]]` hop in §5** — the only thing that proves `TELEMETRY_COLLECTOR` actually resolved |
| V8 | `GET /admin/v1/tenants` on the control plane with an operator key | 200 | The control-plane D1 store on a real database |
| V9 | `POST /v1/mcp` with `{"jsonrpc":"2.0",…}` and no credential | `401` in a well-formed 2.0 envelope | MCP transport guard with durable auth bound |
| V10 | Wait one minute, then check the Cron invocation log on gateway + control-plane | one invocation each | `[triggers] crons` → the `scheduled` handler on the default export. **Nothing local can prove this**: workerd never dispatches a scheduled event under vitest or `wrangler dev`. |

Roll back / stop: if any step fails, capture the error and stop — do not iterate
against the account. Every failure mode above is reproducible locally except
V5, V7 and V10.
