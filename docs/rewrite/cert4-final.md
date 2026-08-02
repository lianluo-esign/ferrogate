# CERT-4 — THE FINAL CERTIFICATION

**Wave 25 · 2026-08-02 · branch `main-ts` · worktree `/home/dev/ferrogate-ts`**

This document answers one narrow question:

> With **S1 and S2 dropped by owner decision**, S3/S4 transcribed, S5 built and
> both insurance artefacts captured — **does anything still make deleting
> `crates/**` a LOSS?**

It inherits no verdict. Wave 23's CLASS A list was re-checked row by row against
this tree; the two insurance artefacts were re-derived from scratch rather than
read; three mutations were applied and reverted by this agent; and the Rust
behind the two decisive S1 claims was opened directly, while it still exists.

---

## 0. THE VERDICT

| Decision | Verdict |
|---|---|
| **Merge `main-ts` → `main`** | **GO — unconditionally.** |
| **Delete `crates/**` + `workers/**` + `Cargo.*`** | **GO.** |
| **The compound decision as asked (delete AND merge)** | **GO.** |

**No CLASS A regression survives that requires `crates/**` to exist.** The
blocker wave 23 named was never the *size* of CLASS A — it was the **overlap
between CLASS A and the Rust's role as a specification**. That overlap is now
**empty**, and §2 is the audit that establishes it rather than asserts it.

### 0.1 The reasoning in four lines

1. CLASS A is not empty: **80 findings survive** (§1). None is new-and-severe.
2. **Zero of the 80** have their only complete definition in `crates/**` (§2).
   Every one is defined by a doc, an OpenAPI schema, a D1 table, or TypeScript
   that is already written.
3. The two artefacts that could only ever be captured *before* the delete are
   captured, and I re-derived both independently (§3).
4. What remains uncertain is uncertain because of **the local-only discipline**,
   not because of the Rust. Keeping `crates/**` closes none of it (§4).

### 0.2 What this GO is not

* It is **not** a claim that the TypeScript is complete. 80 CLASS A findings and
  a four-item silent-failure list (§4) are open, and §5 ranks them.
* It is **not** a claim that the drop was costless. S1 and S2 were real,
  finished Rust behaviour. The owner traded them away deliberately; that is a
  product position, and §2.4 records what it cost so nobody later mistakes it
  for an accident.
* It is **not** a licence to skip `CLOUD-VERIFICATION.md`. The single authorised
  live run is now the only remaining instrument for eleven blockers.

---

## 1. (1) THE CLASS A RE-COUNT — what actually survived waves 23–25

Wave 23 measured **83 CLASS A findings = 77 contract operations + 6
cross-cutting**. Reconstructed from §2.1/§2.2 and `cert3-controlplane-libs.md`
§4, the 77 decompose as **55 control-plane operations (A6) + 3 tooling
operations (A1/A2) + 19 tail items**.

### 1.1 The arithmetic

| Movement | Δ | Why |
|---|---:|---|
| Wave-23 baseline | **83** | 77 ops + 6 cross-cutting |
| **S1 + S2 owner-dropped** | **−3** | `executeFunction`, `listTools`, `executeTool`. A deliberate product position is CLASS C by the owner's own rule, not CLASS A. |
| **A3 / R1 built (S5)** | **−1** | `apps/mcp/src/entitlements.ts`, mounted at `MCP-P15`. **Re-verified by mutation by me** (§1.3). |
| **`client_action_time` added** | **+1** | A genuine CLASS A item that is in `MISSING-TRIAGE.md`'s A-list and was **absent from `CUTOVER-READINESS.md` §2** (§1.4). |
| **CERT-4 total** | **80** | **74 contract operations + 6 cross-cutting** |

### 1.2 The material items, each re-checked against THIS tree

| # | Finding | Status now | Evidence measured this wave |
|---|---|---|---|
| **A1/A2** | `executeFunction`, `listTools`, `executeTool` | **CLOSED as CLASS A — owner-dropped** | The three are the only contract operations not served. They are now mounted as `registerDropped` → `501 capability_not_offered` behind the full `contractAuth` ladder, with the decision, its date and its reasoning in `DROPPED-CAPABILITIES.md` (§2.4). |
| **A3 (R1)** | plan/RBAC tool-entitlement gate | **CLOSED** | `durableEntitlements(env)` is bound in `resolvePorts`; replacing it with `inMemoryPorts().entitlements` takes `apps/mcp/test/entitlements.test.ts` to **5 failed / 3 passed (8)**. Mutation applied and reverted by me; `sha256` back to `308b02ca…`, 8/8 green. |
| **A4 (R2)** | `monthly_token_budget = 0` kill switch on 1 of 3 spend Workers | **SURVIVES** | Files able to emit `token_budget_exceeded`, per Worker: **gateway 11 · control-plane 2 · mcp 0 · agent-runtime 0.** |
| **A5 (L1)** | Cloudflare AI Gateway routing unreachable + its config REFUSED | **SURVIVES** | `packages/providers/src/registry.ts` still records in its own docblock that `apps/gateway` dispatches through `defaultAdapterRegistry` and never through this class. `cloudflare_ai_gateway` appears in `packages/config` (`entities.ts:61`, `sections.ts:798`) and **nowhere in `apps/gateway`**. |
| **A6** | 55 control-plane operations whose write takes no effect | **SURVIVES (29 of 55 now fully specified in `docs/`)** | `gateway_providers` / `gateway_models` exist in `sql/d1-ts/control/0001_init_control.sql` with no writer; `guardrail_evaluations` exists in **none** of the 64 tables in `sql/d1-ts/**`. |
| **A7 (R5)** | guardrail evidence durable nowhere | **SURVIVES** | `new InMemoryGuardrailEvidenceSink()` at `apps/gateway/src/guardrails/config.ts:184`, unconditional. No evidence table in the schema. |
| **A8** | no CORS on the `/v1/**` data plane | **SURVIVES** | The only `cors` hits under `apps/gateway/src` are three prose pointers in `inference/errors.ts` at `apps/control-plane/src/middleware/cors.ts`. |
| **A9 (D1)** | half-bound deployment fails OPEN on 2 Workers, CLOSED on 1 | **SURVIVES** | `FG_DEV_IN_MEMORY_PORTS = "1"` is still committed in `apps/mcp/wrangler.toml:37` and `apps/agent-runtime/wrangler.toml:64`. |
| **A10** | `GET /metrics` served by two Workers with two bodies | **SURVIVES** | unchanged. |
| **A11 (R4)** | `apps/mcp` keeps no durable audit trail | **SURVIVES** | `InMemoryAuditSink` at `ports.ts:944`, constructed at `ports.ts:1503`. |
| **tail (19)** | error codes, `/readyz` `version`, `chars/4`, … | **SURVIVE** | Spot-checked the one the boot proof reaches: `apps/gateway/src/routes/readiness.ts` still builds `{status, service, runtime, cluster}` with **no `version`**, and its own docblock says so. |

**Severity did not increase anywhere.** Nothing found this wave is new, and no
survivor moved up a band.

### 1.3 The one closure I did not take on trust

A3/R1 is the largest single claim waves 23–24 make, so I re-proved it as an
EFFECT rather than reading the delivering agent's note:

```
mutate   apps/mcp/src/ports.ts  «const entitlements = durableEntitlements(env);»
      →  «const entitlements = inMemoryPorts().entitlements;»
off-disk grep: original text present 0 · mutation present 1 · sha256 changed
run      apps/mcp/test/entitlements.test.ts →  5 failed | 3 passed (8)
restore  sha256 308b02ca7e11…  IDENTICAL   →  8 passed (8)
```

The five that fail are the five that carry the money and the capability: plan
denial on both transports, plan admission, the role override, the undeclared
permission granting nothing, and a `plan_id` naming no plan row.

### 1.4 What wave 23 missed — `client_action_time`, and why it is still not a blocker

Cross-checking `CUTOVER-READINESS.md` §2 against `MISSING-TRIAGE.md`'s
independent A/B/C triage of the 28 unported Rust modules surfaces **one CLASS A
item present in the second and absent from the first**.

`MISSING-TRIAGE.md`'s A-list is 8 modules / 3,391 lines:

| Triage item | Modules | Disposition on this tree |
|---|---|---|
| **A1** `gateway/budget_alerts.rs` | 1 | **CLOSED** — ported at `apps/gateway/src/metering/budget-alerts.ts` (`budgetAlertConfigFromEnv`, wave 20). |
| **A2** brokered function egress | 5 | = **S1**, owner-dropped. |
| **A3** `gateway/extensions.rs` | 1 | = **S2**, owner-dropped. |
| **A4** `gateway/client_action_time.rs` | 1 | **OPEN — and it was not on the wave-23 list.** |

**The finding, stated precisely.** Rust ran a Pingora `HttpModule` on every
request: a request carrying `x-ferrogate-action-id` MUST also carry a valid
`x-ferrogate-time-token` (HMAC-SHA256, 30 s TTL, ≤60 s cap, rotation via a
trusted-key list); malformed id → 400, id without token → 400; a request
carrying neither header passes through untouched, so the feature is opt-in per
client. In TypeScript the **signing/echoing half shipped and the verifying half
did not**: `apps/cli/src/action-identity.ts:19-22` defines both headers and
`apps/cli/src/ports.ts:354` harvests the token off responses, while
`grep` over `apps/gateway/src` returns **zero** hits for either header. That is
a live Rust behaviour the port dropped — the definition of CLASS A.

**It does not block, for two independent reasons.**

1. **No exploitable gap exists today.** No TypeScript surface consumes
   `x-ferrogate-action-id`, so nothing downstream can be spoofed by an
   unverified one; the CLI degrades cleanly when no token comes back. What is
   lost is a *false assurance*, not a control.
2. **It is not spec-bound** (§2.3, row 12).

---

## 2. (2) THE SPECIFICATION-OVERLAP QUESTION — the one that decides it

For each of the 80 survivors: **after `crates/**` is gone, is its definition
still recoverable from `docs/` and from the TypeScript that exists?**

### 2.1 The four instruments that survive the delete

| Artefact | Size | What it fixes |
|---|---:|---|
| `docs/openapi/runtime-api-contract.json` | **251 operations** (parsed this wave) | path · method · `operation_id` · visibility · `auth.kind` · `auth.scope` · `rbac_action` for every operation. It is imported directly by all four Workers' `contract.ts`, so it cannot rot silently. |
| `docs/openapi/admin-api.openapi.json` | OpenAPI **3.1.0**, **170 paths**, **371 component schemas** | **Field-level** request/response bodies, parameters, headers and error responses for the whole admin + data-plane surface. This is the artefact that answers "what does this operation actually carry", and it lives in `docs/`. |
| `docs/rewrite/SPEC-TRANSCRIPTS.md` | 1,334 lines | S3 (PART A) and S4 (PART B) as **algorithms**, plus a PART C ledger of where the Rust is unfinished and must *not* be transcribed as specification. |
| `docs/rewrite/DROPPED-CAPABILITIES.md` | 18 KB, landed this wave | S1 and S2 — *what the Rust did*, why it was dropped, and what a future implementer would need. |

Coverage check I ran rather than assumed: the 26 A6 operations **not** covered by
S3/S4 all have paths in `admin-api.openapi.json` — billing 3, site-domains 3,
agent-runs 3, tools 11, request-logs 2, overview 1, tenant/wallet 11,
managed-workers 2.

### 2.2 The corollary nobody had stated

The 251-operation contract and the 3.1.0 OpenAPI document were **already the
authority** for the contract surface — the Rust was a second implementation of
them, not their source. `MODULE-OWNERSHIP.md` §"the mechanical reason" makes the
converse point about the auth-service surface, and it is the same fact read from
the other side: *where a contract row exists, the Rust is not the spec.*

That is why 74 of the 80 survivors are contract operations and **none of them is
spec-bound**. The 6 cross-cutting items needed to be checked one at a time.

### 2.3 The per-item audit

| # | Item | Where its definition lives after the delete | Spec-bound? |
|---|---|---|---|
| 1 | A6 · the 25 config-backed ops | `SPEC-TRANSCRIPTS.md` PART A §§A1-A6 — transaction shape, the three rollback holes, `validate()` ordering, the four validators, the write/delete/405 ladders | **NO** |
| 2 | A6 · `admin_provider` (3) + `admin_model` (1) | `SPEC-TRANSCRIPTS.md` PART B §§B1-B5, including the #535 `None`-not-`Some([])` wildcard invariant | **NO** |
| 3 | A6 · the other 26 ops | `admin-api.openapi.json` (wire) + `sql/d1-ts/**` (the tables, all present) + the algorithms already ported in `packages/billing/*` and `packages/storage/site-domain.ts` | **NO** |
| 4 | the 19 tail items | Each is a **literal string** named in `CUTOVER-READINESS.md` §2.2 (`invalid_upload_intent`, `409 agent_job_not_cancellable`, `422 image_generation_unsupported`, …). An error code is fully specified by writing it down. | **NO** |
| 5 | A4 / R2 | The Rust rule is **three lines**, quoted verbatim in §2.4 of the cutover doc and re-stated as `V-R2` in `CLOUD-VERIFICATION.md` §7 | **NO** |
| 6 | A5 / L1 | `packages/providers/src/cloudflare.ts` is the complete, tested port; `packages/config` already accepts the config. The gap is three edits at a composition root. | **NO** |
| 7 | A7 / R5 | The record shape **is** the TypeScript `GuardrailEvidenceSink` interface (`apps/gateway/src/guardrails/ports.ts:269`). The gap is a D1 table. | **NO** |
| 8 | A8 / CORS | `apps/control-plane/src/middleware/cors.ts` (86 lines) is a working port of the same Rust function, already serving `/admin/v1/**` | **NO** |
| 9 | A9 / D1 | A TypeScript configuration asymmetry. **No Rust is involved at all.** | **NO** |
| 10 | A10 · `/metrics` | The 47 series names are in the TypeScript that emits them | **NO** |
| 11 | A11 / R4 | `AuditSinkPort` in TypeScript; `audit_events` already in the D1 schema and already written by the gateway | **NO** |
| 12 | `client_action_time` | `admin-api.openapi.json` `ClientTimeTokenHeader` carries the **wire format** — "a v1 semicolon-delimited list of `issued_at` (unix seconds), `ttl` (seconds), `action_id` and `sig`", with HMAC verification, action binding and TTL against the server's own receive clock — and `MISSING-TRIAGE.md` §A4 carries the refusal ladder. **And there is no interop constraint of the SigV4 kind: the token is server-minted and server-verified, and the CLI echoes it byte-for-byte without parsing it.** A fresh implementation is free to choose its own bytes. | **NO** |

**Result: 80 of 80 recoverable. Zero remain in the "only definition is Rust
source" category. §3 of `CUTOVER-READINESS.md` is satisfied and its NO-GO is
discharged.**

### 2.4 The drop, verified against the Rust while it still exists

Wave 23's exact words were that for S1 *"nothing in `docs/` reproduces the
allowlist semantics or the token claim set."* That was true when written. It is
not true now, and I checked the new transcription against the Rust myself rather
than accepting it:

| Claim in `DROPPED-CAPABILITIES.md` §2.1 | Rust, read directly | Verdict |
|---|---|---|
| Deny-by-default per-tenant allowlist of `{base_url, function_slugs}` | `function_egress.rs:8-11` module docs — *"Deny-by-default: an empty allowlist, an unknown tenant, or a non-listed target all reject"*; `FunctionEgressRule` fields at `:20-28` | **CONFIRMED** |
| `authorize_validated` trims the slug and matches per tenant | `function_egress.rs:125-150` — exactly that loop, with `normalize_base_url` on both sides | **CONFIRMED** |
| HS256 claim set `iss`/`aud`(= the function slug)/`tenant`/`capability`/`iat`/`exp` | `function_token.rs:28-44 FunctionTokenClaims`, doc comment for doc comment | **CONFIRMED** |
| TTL default 60 s, max 300 s, constant-time compare | `function_token.rs:24,26` (`MAX_…=300`, `DEFAULT_…=60`), `:19 use subtle::ConstantTimeEq`, `:135 ttl_secs.min(MAX_…)` | **CONFIRMED** |
| Error set `{EmptySigningSecret, EmptyField, ZeroTtl, Encoding, MalformedToken, BadSignature, Expired}` | `function_token.rs:46-56`, exactly those seven | **CONFIRMED** |

**One gap, named because it is the last moment it can be:**
`DROPPED-CAPABILITIES.md` §2.1 does not carry
**`ANY_FUNCTION_SLUG = "*"`** (`function_egress.rs:22`) — the wildcard slug that
permits *any* function under an allowed base URL for a tenant, matched at
`:144`. An implementer re-deriving from the doc alone would build an allowlist
without it. **That errs fail-CLOSED**, so it cannot become a security
regression, and it does not change the verdict — but it is a one-line addition
while `function_egress.rs` still exists, and it should be made.

### 2.5 The drop is recorded as a decision, not as a stub

Worth stating because it is what makes the drop safe to delete against. The
three operations answered `501` yesterday and answer `501` today; what changed is
that yesterday they were `PORT-TODO` stubs and today they are
`501 capability_not_offered` with a body naming the decision and its date,
mounted through `registerDropped` behind the same `contractAuth` ladder (so an
anonymous caller still gets `401` and an under-scoped one `403`), gated by
`apps/gateway/test/routes/dropped-capabilities.test.ts`, which hard-codes the
dropped set rather than importing it. **A 501 nobody decided and a 501 somebody
chose are indistinguishable in a route table**, and that difference is now on
the wire.

---

## 3. (3) THE TWO INSURANCE ARTEFACTS — re-derived, not read

Both were *irreversible-if-missed*. I treated wave 24's account as a claim and
re-established it from first principles.

### 3.1 The FNV-1a-64 rollout table — 165 of 165 reproduced

`packages/routing/test/fnv-golden.test.ts` holds **165 rows** of
`{salt, key, raw: 0x…n, bucket}` as **literals**. I parsed all 165 out of the
file and regenerated them with a from-scratch Python FNV-1a-64 that touches
neither the TypeScript nor the Rust, **anchored first against the canonical
reference vectors** (`""`, `"a"`, `"foobar"` → the published digests) so it
could not silently repeat the port's own mistake:

```
parsed rows 165 · canonical FNV-1a-64 reference vectors OK
checked 165 · mismatches 0     (both the full 64-bit `raw` and `bucket = raw % 100`)
```

Independence from `crates/**`: the only occurrence of `crates` in the file is a
**comment** recording provenance. Nothing at runtime reads the Rust.

**It still bites.** Mutation, applied and reverted by me:

```
packages/routing/src/fnv.ts  FNV_PRIME 0x…01b3n → 0x…01b5n
off-disk grep: original 0 · mutation 1 · sha256 48c33c1a… → ee3a9a3f…
run  test/fnv-golden.test.ts → 3 failed | 2 passed (5)
restore → sha256 48c33c1a… IDENTICAL → 5 passed (5)
```

### 3.2 The SigV4 golden vectors — both signatures reproduced from AWS's algorithm

`packages/providers/test/sigv4-golden.test.ts` (27 assertions, 13 hex literals).
I rebuilt the canonical requests and re-derived the signing chain in Python
(`hashlib`/`hmac`) from AWS's published algorithm, never calling the TypeScript:

| value | re-derived | pinned |
|---|---|---|
| canonical-request SHA-256, vector 1 | `c653759c…2cfddc` | matches |
| **signature, vector 1** | `ee11e038…3e6803` | matches |
| canonical-request SHA-256, vector 2 | `2a698d80…59d67f` | matches |
| **signature, vector 2** | `398afec7…013c13` | matches |

**It still bites**, and on precisely the failure that shape assertions cannot
see. Mutation, applied and reverted by me:

```
packages/providers/src/sigv4.ts:188   delete the mandatory blank line between the
                                      canonical headers and the signed-header list
off-disk: line 188 mutated, line 264 untouched · sha256 8c1baee7… → 05bd930e…
run  sigv4-golden.test.ts   →  6 failed | 21 passed (27)
run  crypto-sigv4.test.ts   →  2 failed | 21 passed (23)
restore → sha256 8c1baee7… IDENTICAL → 50 passed (50) across both files
```

Six of the eight failures come from the golden file. Before it existed, that
same mutation left `packages/providers` **75/75 green** while breaking every
Bedrock and every S3-compatible request the product makes.

**Both artefacts are independent of `crates/**` and would still catch a
divergence after the delete. Confirmed.**

---

## 4. (4) WHAT REMAINS UNVERIFIABLE LOCALLY — the honest cost, restated

None of this is closed by keeping `crates/**`. All of it is closed only by the
one authorised live run. It is restated here because it belongs *in* the final
decision, not beside it.

### 4.1 The four that can fail silently in production against a green tree

1. **The shared RPM counter (B10). Money. No mechanical backstop of any kind.**
   `apps/mcp` and `apps/agent-runtime` carry the cross-script `RATE_LIMIT`
   stanza **commented out**, because workerd cannot resolve a `script_name`
   binding offline — uncommenting takes both suites to **0 collected tests**.
   Left commented at deploy, a credential capped at 60 rpm is charged 60 on the
   gateway **plus 60×N mcp isolates plus 60×M agent-runtime isolates**. Nothing
   errors. This has now survived six waves in that state.
2. **The half-bound `agent-runtime` (B1 + B4 → A9). Security AND money.**
   Fully unbound is loud. Bind `DB`, forget `CONTROL_DB`, leave the committed
   `FG_DEV_IN_MEMORY_PORTS = "1"`, and `resolveDeps` **succeeds** — serving
   traffic with tenant suspension, the operator drain, guardrail screening and
   agent-upstream withdrawal **all four silently inoperative**.
   **Deploy rule: bind `CONTROL_DB` and `DB` together or bind neither.**
3. **Three control-database uuids that must be equal (B11).** The drain's
   fleet-wideness is a function of three `database_id` values matching. Point
   two Workers at different control databases and each drains independently,
   with `GET /admin/v1/drain` reporting `draining: true` and every local test
   green. No stanza, no placeholder, nothing to typecheck.
4. **The mTLS posture (B6).** At `FG_REQUIRE_PRODUCTION_MTLS = "0"` every
   transport channel is admitted — transport-downgrade acceptance, **not** an
   authentication bypass. The remediation is not a var flip: `"1"` admits
   `verified_mutual_tls` only, which `request.cf.tlsClientAuth` supplies
   **exclusively on a zone with Cloudflare mTLS configured**. Flip it on a zone
   without mTLS and every self-hosted-worker callback is refused. **Confirm the
   zone first.**

### 4.2 The rest of the blocker table, for completeness

**B2** (R2 bucket declared but non-existent) and **B5** (Analytics Engine) fail
the **deploy**; **B9** (two control migrations) fails the **callback**; **B3**
(no KV rights) leaves stored-credential encryption unexercised and must be
*reported* rather than assumed; **B7** (`ADMIN_CONSOLE_JWT_SECRET`) fails
**closed and loud** — `503 admin_console_unconfigured`; **B8** (per-tenant
`env://` IdP secrets) fails login closed but indistinguishably from an IdP
outage, so check it explicitly during the run.

**Three verification rows are expected to record a gap rather than a pass:**
`V-R2` (partial — gateway only) and `V-B10` (fails unless both stanzas were
uncommented) are still expected-FAIL; `V-R1` flipped to **expected-PASS** in
wave 24 and I re-proved its mount here (§1.3).

### 4.3 Axis-level gaps that change no verdict

SSE framing byte-for-byte against the Rust streamers; **AEAD interoperability
against a real Rust self-hosted-worker binary** (no `cargo`, by hard rule — and
this window genuinely does close on deletion); `sigv4`/Vertex signing against
live AWS/GCP; per-operation FIELD parity for ~60 control-plane collections; Cron
dispatch (workerd never fires a scheduled event under vitest or `wrangler dev`).

### 4.4 One invariant that is correct and held by nothing

**C1 — the operator's suspension WRITE leg.** Neutralising
`projectTenantAccount`'s `status` so every tenant is written `'active'` leaves
**693/693 control-plane tests green AND the FC-2 fleet gate 12/12 green**,
because the control plane's lifecycle gate reads the *document* and the fleet
gate writes the *column* with its own hand-written `UPDATE`. Nothing joins the
two. Carried forward from wave 23 unchanged; ~25 lines to close.

---

## 5. Ranked actions, now that the gate is open

1. **Merge, then delete.** `crates/**`, `workers/**` and `Cargo.*`. Tag first.
2. **Add `ANY_FUNCTION_SLUG` to `DROPPED-CAPABILITIES.md` §2.1** (§2.4) — the
   only thing in this document that is cheaper before the delete than after.
3. **Close C1** (§4.4) — security-adjacent, and FC-2 arriving through a door
   nobody is watching.
4. **Close A4/R2** — two SQL columns and one branch on each of two Workers.
5. **Close A5/L1** — three edits, the third being the one that matters: assert
   the PREPARED ENDPOINT is the AI Gateway host.
6. **Add the column property** to `fleet-control-matrix.test.ts`: *every column
   of a shared control table that any Worker PARSES must have at least one
   Worker that CONSUMES it in a decision.* R1 and R2 were both found by hand;
   this is the gate that finds the third.
7. **Close `client_action_time`** (§1.4) or delete the CLI's signing half. What
   is wrong today is the *asymmetry*, and either direction fixes it.
8. **Run `CLOUD-VERIFICATION.md` once, carefully**, treating §4.1 as the thing
   the run is FOR.
9. The 19 tail items, the 55 A6 write halves, R5, R4, CORS.

---

## 6. Evidence produced this wave, first-hand

Everything below was run by me in this worktree on 2026-08-02.

| Gate | Result |
|---|---|
| `bun run test`, all workspaces in parallel | **exit 0** |
| `bun run test`, **per workspace, serially** (21 workspaces) | **7,022 passed · 0 failed · 9 todo · 384 files · exit 0 in all 21** (= **7,031 including todos**) |
| `bun run typecheck` | **exit 0, zero diagnostics** — run twice, before and after the concurrent change in §7 |
| Seam pass — parse | CLAIMED **201** · PARSED **201** · gated **199** · no-gate-by-design **2** · **no-gate-no-reason 0** — run twice |
| `playwright test --config e2e/playwright.config.ts` | **22 passed**, 4.8 s |
| FNV golden table, re-derived in Python | **165 / 165**, 0 mismatches, anchored on the canonical FNV vectors first |
| SigV4 goldens, re-derived in Python from AWS's algorithm | **2 canonical digests + 2 signatures + 1 payload hash**, all exact |
| Mutation M1 — `FNV_PRIME` | **RED 3/5**, restored `sha256`-identical |
| Mutation M2 — SigV4 canonical blank line | **RED 6/27 + 2/23**, restored `sha256`-identical, 50/50 green after |
| Mutation M3 — unmount `D1ToolEntitlements` | **RED 5/8**, restored `sha256`-identical, 8/8 green after |
| Rust read directly (last chance) | `function_token.rs`, `function_egress.rs` — five transcription claims confirmed, one omission found (§2.4) |
| Boot proof — five Workers under `wrangler dev --local` | **NOT re-run this wave.** Inherited from wave 24 (5/5 "Ready on", `/healthz` 200×5 one shape, `/readyz` 200×5). Stated as inherited, not measured. |

---

## 7. A note on the tree moving under this certification

A sibling agent landed the S1/S2 drop-recording change (`registerDropped`,
`DROPPED_CAPABILITIES`, `DROPPED-CAPABILITIES.md`,
`test/routes/dropped-capabilities.test.ts`) **while this certification was
running**, between 02:40 and 02:49 UTC. Recorded rather than smoothed over:

* The full serial sweep in §6 was measured at **02:29–02:41**, before the change
  had fully landed.
* At **02:48** `apps/gateway` was momentarily **1 failed / 2,049 passed**. The
  failure was `fleet-control-matrix.test.ts > "comment stripping preserves every
  line of top-level code"` — a **vacuity guard**, not a product test, and it was
  right: a `//` line comment containing the literal `crates` followed by a glob
  puts a **`/*` token** in the source, and the matrix scanner's block-comment
  regex is non-greedy, so it swallowed everything up to the next `*/` and ate
  `export interface CreateGatewayAppOptions` out of the gateway's scanned code
  (1419 → 1418 top-level exports).
* The sibling agent found and fixed the same cause at **02:48:58**. Re-run at
  **02:49**: `apps/gateway` **2,050 + 24 + 42 = 2,116 passed, 0 failed**, and
  `bun run typecheck` **exit 0**. The whole-tree total is therefore **7,051
  passed + 9 todo** on the current tree, up 29 from the sweep.

**This is the third instance of the same defect class in this project** — text
that is inert to the compiler and corrupting to the evidence instrument: raw NUL
bytes (wave ~12), newlines in FILE NAMES (wave 23), and now `/*` inside a line
comment (wave 25). Each was caught by a guard someone had built *after* the
previous one. The pattern is worth naming as a class rather than fixing three
times.

None of it changes the verdict: the guard fired, the cause was one character
wide, and it was closed inside nine minutes.

---

## 8. Scope statement

Run in `/home/dev/ferrogate-ts` on `main-ts`. **No `cargo`. No Rust compiled,
imported, linked, wasm'd or subprocessed** — `crates/**` was **READ ONLY**, for
the provenance check in §2.4, which is the last moment that check can be made.
**No `wrangler deploy`, no live Cloudflare resource, no real upstream LLM call.**
**No `git`.** **No `bun install`.** **Nothing deleted, and no merge to `main`.**

**The only file this agent wrote is this one.** No source file, no test file and
no other document was created or modified. No `PORT-TODO` marker was added: §2
found no CLASS A gap lacking one.

No test was weakened, skipped or deleted. All three mutations in §3 and §1.3
were read back **OFF DISK with the ORIGINAL TEXT REQUIRED ABSENT**, then
reverted and verified **byte-identical by `sha256`**; the three files
(`packages/routing/src/fnv.ts` `48c33c1a…`, `packages/providers/src/sigv4.ts`
`8c1baee7…`, `apps/mcp/src/ports.ts` `308b02ca…`) are at their original hashes
and their suites are green.

Both independent re-derivations were written in Python from published
algorithm text — AWS's SigV4 specification and the canonical FNV-1a-64 reference
vectors — and never from the code under test.

---

## 9. The verdict, restated in one paragraph

`crates/**` was never the specification for the contract surface — the
251-operation contract and the 3.1.0 OpenAPI document were, and they live in
`docs/`. What the Rust uniquely held was five clusters. Three were closed by
wave 24 (two transcribed, one built), and the owner has dropped the other two —
one of the three exits the certification itself offered, taken deliberately and
recorded on the wire, in code and in a document that cannot drift from either.
The two artefacts that expire on deletion are captured and I re-derived both
from scratch. Eighty CLASS A findings survive and **not one of them needs the
Rust to exist in order to be specified, argued about, or fixed.** What is left
uncertain is uncertain because we have only ever run this system offline — and
keeping a Rust tree that cannot be deployed to Cloudflare at all closes none of
it. **Merge, and delete. GO.**
