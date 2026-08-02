# CUTOVER READINESS — THE FINAL DECISION

**Wave 25 · 2026-08-02 · branch `main-ts` · worktree `/home/dev/ferrogate-ts`**

This document supersedes every previous version. Waves 15–24 are preserved
verbatim in **Appendix F** (which itself contains the older Appendices G and H)
and are **history, not evidence**. Every number in §2 was measured by this agent,
in this worktree, this wave. Nothing is inherited — including the boot proof,
which cert-4 explicitly declined to re-run and which is therefore run here.

The question, unchanged since wave 15:

> May we delete `crates/**`, `workers/**` and `Cargo.*`, and merge `main-ts`
> into `main`?

**This decision has been deferred five times.** Each deferral named a specific,
falsifiable reason. This document's job is to check whether those reasons are
spent, and to say so plainly in whichever direction the evidence points.

---

## 0. (a) THE VERDICT

| Decision | Verdict |
|---|---|
| **Merge `main-ts` → `main`** | **GO** |
| **Delete `crates/**` + `workers/**` + `Cargo.*`** | **GO** |
| **The compound decision as asked (delete AND merge)** | **GO** |

**Surviving CLASS A blockers: ZERO.** §1 is the audit that establishes it, not
an assertion of it.

### 0.1 The reasoning, in five lines

1. The rule I was given is that **CLASS A blocks and only CLASS A blocks**, and
   the operative sub-rule since wave 23 is narrower still: what blocks the
   *deletion* is not the size of CLASS A but the **overlap between CLASS A and
   the Rust's role as a specification**.
2. That overlap was five clusters, S1–S5. Wave 24 cleared S3 and S4 (transcribed)
   and S5 (built). The owner has **dropped S1 and S2** — one of the three exits
   the wave-23 criterion itself offered, taken deliberately.
3. S1 was nevertheless transcribed anyway, at algorithm fidelity
   (`SPEC-TRANSCRIPTS.md` PART D, 863 lines, §§D0–D14). So the overlap is not
   merely discharged by decision; for four of the five clusters it is discharged
   by **record**.
4. **The overlap is now empty.** 80 CLASS A findings survive as product backlog;
   I re-derived the disposition of each class and **not one requires `crates/**`
   to exist** in order to be specified, argued about or fixed (§1.2).
5. What is still uncertain is uncertain because this system has only ever been
   run offline. **Keeping a Rust tree that cannot be deployed to Cloudflare
   Workers at all closes none of it** (§4).

### 0.2 What this GO is not

* It is **not** a claim that the TypeScript is complete. Eighty CLASS A findings
  are open. They are **product backlog**, ranked in §6 — and the distinction
  between "open work" and "a reason to keep a second implementation" is the
  entire content of this decision.
* It is **not** a claim that the drop was costless. S1 and S2 were real, finished
  Rust behaviour. The owner traded them away deliberately; §3.3 records what it
  bought and what it cost so nobody later reads it as an accident.
* It is **not** a claim that the deployment is safe. It is not yet deployed. §4
  names four ways this fleet can fail **silently in production against a fully
  green tree**, and `CLOUD-VERIFICATION.md` is the only instrument that closes
  them.
* It is **not** a licence to skip the tag. §5.

### 0.3 Why I am not hedging

The honest failure mode available to me here is to invent a sixth deferral —
there is always one more thing that could be checked, and "hold" always reads as
the careful answer. It is not the careful answer here. The wave-23 criterion was
written specifically so that it could be *met*, it names its own exits, and all
five clusters have now taken one. Restating a met criterion as unmet would be a
process failure wearing the costume of rigour. **The reasons are spent. GO.**

---

## 1. (b) THE SURVIVING CLASS A LIST — it is EMPTY, and here is the work

**Surviving CLASS A blockers: 0.**

A CLASS A finding **blocks the deletion** if and only if its only complete
specification is Rust source about to be deleted. That is the wave-23 rule and I
am applying it unchanged, not loosening it.

### 1.1 The arithmetic, reconciled against cert-4

| Movement | Δ | Status on this tree |
|---|---:|---|
| Wave-23 baseline | **83** | 77 contract ops + 6 cross-cutting |
| S1 + S2 owner-dropped | **−3** | `executeFunction`, `listTools`, `executeTool` — verified mounted as `registerDropped` → `501 capability_not_offered` (§1.3) |
| A3 / R1 built (S5) | **−1** | `apps/mcp/src/entitlements.ts`, seam `MCP-P15` — mutation-proven by wave 24 and re-proven by cert-4 |
| `client_action_time` surfaced | **+1** | cert-4 §1.4 found a CLASS A item that was on `MISSING-TRIAGE.md`'s A-list and absent from wave 23's — **confirmed by me**: 0 hits in `apps/gateway/src`, 3 in `apps/cli/src` |
| **CERT-4 / wave-25 total** | **80** | 74 contract operations + 6 cross-cutting |

The count went **up** by one after the drop was priced in, and I am reporting it
that way rather than netting it into a smaller-sounding number.

### 1.2 The blocking test, applied to all 80

The 74 contract operations are not spec-bound as a class, for a structural
reason that is worth stating once: **`crates/**` was never the specification for
the contract surface.** Two artefacts in `docs/` were, and the Rust was a second
implementation of them. Both survive the delete and both are parsed here rather
than assumed:

| Instrument | Measured this wave | What it fixes |
|---|---|---|
| `docs/openapi/runtime-api-contract.json` | **251 operations** | path · method · `operation_id` · visibility · `auth.kind` · `auth.scope` · `rbac_action`. Imported directly by all four Workers' `contract.ts`, so it cannot rot silently |
| `docs/openapi/admin-api.openapi.json` | OpenAPI **3.1.0**, **170 paths**, **371 component schemas** | field-level request/response bodies, parameters, headers, error responses. `ClientTimeTokenHeader` confirmed present |
| `docs/rewrite/SPEC-TRANSCRIPTS.md` | **2,203 lines** — PART A (S3), PART B (S4), PART C (the honest ledger), **PART D (S1, §§D0–D14)** | the algorithms the Rust held and no doc did |
| `docs/rewrite/DROPPED-CAPABILITIES.md` | 354 → 383 lines | S1 and S2 as a decision record: what the Rust did, why it was dropped, what a re-implementer needs |

The 6 cross-cutting items were checked one at a time, and each was re-verified
against **this** tree by me rather than read out of cert-4:

| # | Item | Measured here | Spec-bound? |
|---|---|---|---|
| A4 / R2 | `monthly_token_budget = 0` kill switch reaches 1 spend Worker of 3 | files able to emit `token_budget_exceeded`: **gateway 7 · control-plane 2 · mcp 0 · agent-runtime 0** | **NO** — the Rust rule is three lines, quoted verbatim in Appendix F §2.4 and restated as `V-R2` in `CLOUD-VERIFICATION.md` §7 |
| A5 / L1 | Cloudflare AI Gateway routing unreachable | `cloudflare_ai_gateway` appears **0 times** in `apps/gateway/src` | **NO** — `packages/providers/src/cloudflare.ts` is the complete, tested port; the gap is three edits at a composition root |
| A7 / R5 | guardrail evidence durable nowhere | `new InMemoryGuardrailEvidenceSink()` at `apps/gateway/src/guardrails/config.ts:184`, unconditional; **0** files in `sql/d1-ts/` mention a guardrail-evaluation table | **NO** — the record shape *is* the TypeScript `GuardrailEvidenceSink` interface; the gap is a D1 table |
| A8 | no CORS on the `/v1/**` data plane | the only `cors` hit under `apps/gateway/src` is prose in `inference/errors.ts` | **NO** — `apps/control-plane/src/middleware/cors.ts` is a working port of the same Rust function |
| A9 / D1 | half-bound deploy fails OPEN on 2 Workers, CLOSED on 1 | `FG_DEV_IN_MEMORY_PORTS = "1"` still committed at `apps/mcp/wrangler.toml:37` and `apps/agent-runtime/wrangler.toml:64` | **NO** — a TypeScript configuration asymmetry. No Rust is involved at all |
| A10 / A11 | two `/metrics` bodies; `apps/mcp` keeps no durable audit trail | `InMemoryAuditSink` at `apps/mcp/src/ports.ts:944`, constructed at `:1471` | **NO** — the series names are in the TypeScript that emits them; `audit_events` is already in the D1 schema and already written by the gateway |

Plus the 19 tail items, each of which is **a literal string**
(`invalid_upload_intent`, `409 agent_job_not_cancellable`,
`422 image_generation_unsupported`, …). An error code is fully specified by
writing it down, and they are written down in Appendix F §2.2.

Plus `client_action_time`, whose wire format is in `admin-api.openapi.json`
(`ClientTimeTokenHeader`) and whose refusal ladder is in `MISSING-TRIAGE.md` §A4.
It carries **no interop constraint of the SigV4 kind** — the token is
server-minted and server-verified and the CLI echoes it without parsing — so a
fresh implementation may choose its own bytes.

**Result: 80 of 80 recoverable. The spec-bound subset is empty. Nothing blocks.**

### 1.3 The drop is on the wire, not just in a document

I checked this rather than trusting it, because "dropped" and "unfinished" are
indistinguishable in a route table and that ambiguity is the whole reason
`DROPPED-CAPABILITIES.md` exists:

```
apps/gateway/src/routes/index.ts:173  DROPPED_CAPABILITY_CODE = "capability_not_offered"
apps/gateway/src/routes/index.ts:214  DROPPED_CAPABILITIES: readonly DroppedCapability[]
apps/gateway/src/routes/index.ts:333  registerDropped(operationId: string): this
apps/gateway/src/routes/index.ts:436  router.registerDropped("listTools");
apps/gateway/src/routes/index.ts:439  router.registerDropped("executeTool");
apps/gateway/src/routes/index.ts:449  router.registerDropped("executeFunction");
```

All three are mounted **behind the full `contractAuth` ladder** — an anonymous
caller still gets `401`, an under-scoped one `403` — and gated by
`apps/gateway/test/routes/dropped-capabilities.test.ts`, which hard-codes the
dropped set rather than importing it, so the gate does not follow an edit to the
code it gates.

### 1.4 One correction to cert-4, in cert-4's own direction

Cert-4 §2.4 named exactly one omission — that `ANY_FUNCTION_SLUG` (the wildcard
slug `"*"`, `function_egress.rs:21`) was missing from the S1 transcription — and
ranked closing it as the #2 action before deletion.

**It was already closed, in a document cert-4 did not check.**
`SPEC-TRANSCRIPTS.md` PART D §D3 carries it at lines 1507 and 1562, *including*
the subtlety that the wildcard is compared un-trimmed while a literal slug is
compared trimmed. Cert-4 read `DROPPED-CAPABILITIES.md` only.

I added it to `DROPPED-CAPABILITIES.md` §2.1 anyway — the two documents are read
by different people for different reasons and neither should require the other —
and the addition records the three properties a re-implementer would otherwise
get wrong (un-trimmed comparison; the wildcard widens the *slug* axis only, never
tenant or host; deny-by-default is unchanged and `NoRuleForTenant` stays
distinguishable from `TargetNotAllowed`).

**This is the only item on cert-4's pre-deletion list, and it is now closed
twice. Nothing remains that is cheaper before the delete than after it.**

### 1.5 One finding I re-proved rather than inherited — and it is real

`C1`, the operator's tenant-suspension WRITE leg, has been carried forward
unchanged since wave 23 by two certifications without either re-proving it. I
proved it, because a carried-forward security claim is exactly the kind that
turns out to have been fixed or to have gotten worse:

```
mutate   apps/control-plane/src/store/quota_registry.ts
         «text(record.status, "active"),»  →  «/*MUTW25_C1*/ "active",»
off-disk grep: marker present · ORIGINAL TEXT GONE · sha256 changed
run      apps/control-plane   →  37 files, 693 passed, 0 failed
run      apps/mcp/test/fleet-tenancy-suspension.test.ts (the FC-2 fleet gate)
                              →  1 file, 12 passed, 0 failed
restore  sha256 752bb8d0cdc3e6dc2ca80e5b4b13d13f01db5a187163f0ae0aedbf4c91e2dd50
         IDENTICAL
```

Every tenant is projected `'active'` regardless of what the operator wrote, and
**693 control-plane tests and the 12-case fleet-suspension gate all stay green.**
The control plane's lifecycle gate reads the *document*; the fleet gate writes
the *column* with its own hand-written `UPDATE`. Nothing joins the two.

**This does not block the cutover** — it is a TypeScript defect with no Rust
component, ~25 lines to close, and `crates/**` contributes nothing to closing it.
It is #2 in §6 and it is the sharpest open item in this repository.

---

## 2. Evidence produced this wave, first-hand

Every row was run by me in `/home/dev/ferrogate-ts` on 2026-08-02. No row is
inherited.

| Gate | Result |
|---|---|
| `bun install` | clean, no changes — 262 installs / 338 packages |
| `bun run typecheck` | **exit 0**, 22 projects, zero diagnostics |
| `bun run test`, per workspace, serially (21 workspaces) | **exit 0 in all 21** · **385 files · 7,051 passed · 0 failed · 9 todo** |
| Seam pass — parse | CLAIMED **201** · PARSED **201** (+1 retired) · resolvable gate **199** · no gate BY DESIGN **2** · **no gate and no reason 0** |
| **Seam pass — FULL, every row** | **201 run · 196 RED · 0 GREEN-unproven · 5 NOT-MUTABLE by category · 0 restore failures** (§2.1) |
| Boot — five Workers, `bunx wrangler dev --local`, distinct ports | **5/5 "Ready on"** · `/healthz` **200 ×5** · `/readyz` **200 ×5** (§2.2) |
| `bunx playwright test --config e2e/playwright.config.ts` | **22 passed**, exit 0, 4.5 s |
| Mutation — C1, the suspension write leg | **GREEN under a landed mutation** — an unheld invariant, confirmed (§1.5) |
| `grep -rn MUTW25 apps packages e2e sql` after every pass | **0 hits** |

Baseline was ~7,031. The tree is at **7,051 passed + 9 todo**; the +20 is
`apps/gateway/test/routes/dropped-capabilities.test.ts`, the gate on the owner's
drop.

Per-workspace totals, for the record:

```
billing 91 · cloudflare 146 · config 751 · core 31 · guardrails 439 · identity 136
observability 67 · payments 54 · policy 113 · providers 102 · routing 33
schemas 56 · secrets 79 · sso 110 · storage 554
agent-runtime 541 · cli 344 · control-plane 693 · gateway 2116 · mcp 463 · telemetry 132
```

### 2.1 The full seam pass — 201 of 201, and how the 20 unlocatable rows were closed

This is the last full pass before the Rust is deleted and the inventory requires
one here, so the number that matters is not "196 RED" but **"201 rows accounted
for, 0 of them silently skipped."**

The generic driver (`scripts/wave25-seam-pass.py`) produced:

```
201 run · 174 RED · 4 GREEN-UNPROVEN · 3 SKIP-BY-CATEGORY · 20 SEAM-NOT-UNIQUE · 0 restore failures
```

**Twenty unlocatable rows in a summary look exactly like twenty passing ones**,
and four GREENs against a driver-chosen mutation may be unproven mounts or may be
mutations that changed bytes without changing behaviour. Both were resolved
rather than reported:

| Stage | Rows | Result |
|---|---:|---|
| generic driver | 201 | 174 RED |
| `scripts/wave25-seam-residue.py` — 20 hand-written, behaviour-changing edits, each naming in the script the behaviour it removes | 22 | **19 RED**, 2 NOT-MUTABLE by category (`MCP-T10`, `AR-T10` — the deliberately *commented* cross-script `RATE_LIMIT` stanza; commenting a comment is a byte change and not a behaviour change), 1 mis-scoped |
| hand pass for the last three | 3 | `CP-C13`, `CP-T3`, `MCP-T8` — **all 3 RED** |
| **union** | **201** | **196 RED · 5 NOT-MUTABLE by category · 0 GREEN-unproven** |

The five that are NOT-MUTABLE **by category** are not unproven rows —
`CP-C13b` (`NONE`, a knowingly narrower sub-seam), `AR-C9` and `AR-T11`
(`NOT-MUTABLE`), and the two commented `RATE_LIMIT` stanzas. This distinction is
why `MOUNT-SEAMS.md` carries a Channel column at all.

**The one mis-scope, named because it is instructive.** The inherited residue
script's `CP-C13` edit leaves the `/version` route *registered* and only changes
the document it answers. That is not `CP-C13`; it is `CP-C13b`, the narrower
sub-seam the inventory already records as knowingly unproven — so its GREEN was
**correct and expected**, not a finding. Re-running `CP-C13` against its actual
seam (`MUT-1`, the registration removed outright) is **RED**. Wave 23 hit the
same thing from the other direction and recorded it; this is the second
independent confirmation of a tombstone row, which is the best evidence such a
row can get.

The two `[[d1_databases]]` rows (`CP-T3`, `MCP-T8`) had the same shape of
problem: the correct mutation is `MUT-4`, *the whole stanza removed*, and
commenting a single line of a toml table leaves a partially-valid stanza that
changes nothing. Removed properly, both are RED — the control plane declaring no
D1 at all, and `apps/mcp` losing the `DB` binding its durable auth and approvals
resolve through.

Every mutation was **grepped back off disk with the ORIGINAL TEXT REQUIRED
ABSENT** before its suite ran — marker-present alone is not enough, because a
concurrent write has clobbered a mutation in this repo before and a sound gate
then looks vacuous. Every file was restored and re-verified **byte-identical by
sha256**.

**196 of 201, up from wave 23's 195 of 200. Zero unproven mounts.**

### 2.2 Real boot — five Workers under workerd, bodies read

`bunx wrangler dev --local` on ports 8841–8845, against the **committed**
`wrangler.toml` of each app. All five reached "Ready on".

`/healthz` — **200 on all five**, one shape, `version` on every one:

```
gateway        {"status":"ok","service":"ferrogate-gateway","version":"0.0.0","runtime":"workers"}
control-plane  {"status":"ok","service":"ferrogate-control-plane","version":"0.0.0","runtime":"workers"}
mcp            {"status":"ok","service":"ferrogate-mcp","version":"0.0.0","runtime":"workers"}
agent-runtime  {"status":"ok","service":"ferrogate-agent-runtime","version":"0.0.0","runtime":"workers"}
telemetry      {"status":"ok","service":"ferrogate-telemetry","version":"0.0.0","runtime":"workers"}

distinct shapes: 1 -> IDENTICAL     every document carries `version`: True
```

`/readyz` — **200 on all five**, and this is where the known item lives:

```
gateway        {status, service, runtime, cluster{enabled, active_revision, stale,
                last_sync_error, ready, readiness_reason, draining,
                accepting_new_requests}}                      ← NO `version`
control-plane  {status, service, version, runtime, dependencies}
mcp            {status, service, version, runtime, protocol, readiness_reason,
                draining, accepting_new_requests, dependencies}
agent-runtime  {status, service, version, runtime, ready, readiness_reason,
                draining, accepting_new_requests, dependencies}
telemetry      {status, service, version, runtime, sink}
```

**The known item is confirmed exactly as wave 24 re-attributed it: the gateway's
`/readyz` omits `version`, and `/healthz` carries it on all five.** The earlier
attribution of this gap to `/healthz` was wrong and stays corrected. The
gateway's own `readiness.ts:94` docblock names the divergence, so the code and
the certification agree rather than merely coinciding.

The gateway's `/readyz` is an **async durable read** of the `runtime-state/drain`
document (FC-1, third leg). It answered 200 with `draining:false` and a resolved
`active_revision` — a hang, a 500 or an unhandled rejection there would be
invisible to vitest, which never runs wrangler's own bundle.

**No new defect was found by the boot proof.** Waves 20 and 22 each found one, so
this is a result rather than an absence of one: the composition roots are stable.

---

## 3. (c) WHAT IS PERMANENTLY LOST BY DELETION, AND WHAT WAS TRANSCRIBED TO BUY IT BACK

Stated as a ledger, because "nothing is lost" would be false.

### 3.1 Lost — and bought back in full

| Cluster | What the Rust uniquely held | What survives the delete |
|---|---|---|
| **S3** — the 25 config-backed control-plane operations | the *transaction shape*: persist → clone config → apply snapshot → `validate()` → hot-reload → roll back on error → re-read and answer `409 …_reload_rejected`; the three rollback holes; validator ordering | `SPEC-TRANSCRIPTS.md` PART A §§A1–A6, as an **algorithm**, with the HTTP contract (§A4), read-side scoping (§A5) and wire projections (§A6) |
| **S4** — `admin_provider` (3) + `admin_model` (1) | the **#535 field-level redaction**, which exists in exactly one Rust function and whose omission is a credential-disclosure regression; the `None`-not-`Some([])` wildcard invariant | PART B §§B1–B5, including the redaction (§B3) and the wildcard invariant, spot-verified against `rbac.rs:1276-1349` |
| **S5** — the plan/RBAC tool-entitlement ladder | the plan-OR-role admission shape | **built**, not transcribed: `apps/mcp/src/entitlements.ts`, seam `MCP-P15`, mutation-proven 5 RED / 8 |
| **S1** — the function-egress broker | deny-by-default per-tenant allowlist; the HS256 claim set; TTL bounds; constant-time compare; the seven-member error set; the wildcard slug | **PART D, §§D0–D14 — 863 lines**, the deepest transcript in the file, *despite* S1 having been dropped. Also summarised as a decision record in `DROPPED-CAPABILITIES.md` §2 |

For S1 in particular the transcript goes past what the exit criterion required:
§D10 records the fail-open/fail-closed posture line by line, §D11 the invariants
held by control flow rather than a named check, §D12 where the Rust is
**unfinished** (so nobody transcribes a defect as a specification), and §D13 the
controls that **do not exist**, so nobody assumes them.

### 3.2 Lost — and bought back only as a brief

| Cluster | Recorded at | Honest assessment |
|---|---|---|
| **S2** — `listTools` / `executeTool` | `DROPPED-CAPABILITIES.md` §3.1 | **Pointer fidelity, not algorithm fidelity.** It names `handle_tools` (`local.rs:2890`), the five-step ladder including the `tool.list` audit event, `tools_for` (`extensions.rs:214`), the `tool_visible` filter axes (tenant · api-key · route), the sibling readers and the execution path (`local.rs:2935` → `:3573`). It does **not** transcribe `tool_visible`'s predicate line by line. |

This is a deliberate asymmetry and I am flagging it rather than smoothing it:
**S2 is the one cluster whose record is a brief rather than a transcript.** It is
acceptable *because* S2 was dropped as a product position — the exit criterion
offers "built OR dropped OR transcribed", and S2 took the second exit, not the
third. If S2 is ever revisited, `DROPPED-CAPABILITIES.md` §3.3 is right that the
**hook model must be designed fresh** (Rust's `RequestHook` enum has one variant,
`Noop`, and `EventSink` one, `audit_log` — copying it would import an unfinished
design), and the catalogue half should be re-derived from the tag (§5) rather
than from the brief.

### 3.3 Lost outright — the capabilities themselves

Not a documentation gap; a product decision, recorded so it is never mistaken for
an accident:

* **`POST /v1/functions/execute`** — a broker for a tenant's Supabase Edge
  Function or Cloudflare Worker, with deny-by-default egress and a 60-second
  scoped token. **It was never platform-blocked**: it needs only `fetch()` and
  WebCrypto HMAC, and the "out-of-process sandbox, blocked on Containers"
  justification that sat in the TypeScript for eighteen waves was **false about
  the reference**. Anyone reopening this should know the constraint was never
  technical.
* **`GET /v1/tools` + `POST /v1/tools/execute`** — the extension tool catalogue
  and its execution path.

All three now answer `501 capability_not_offered` with a body naming the decision
and its date, behind the full auth ladder.

### 3.4 Not lost, because it was never there

`packages/cloudflare`'s account-management surface, the `ferrogate-auth-service`
RBAC route arms, `createAgentRun`'s synchronous turn loop, MCP `resources/read` —
all CLASS B: **the Rust never finished them**, and porting any of them would
import a defect. `SPEC-TRANSCRIPTS.md` PART C §C1 is the ledger of exactly which
Rust must *not* be transcribed as specification. Building that list was as
valuable as building the transcripts.

---

## 4. (d) WHAT REMAINS UNVERIFIABLE UNTIL THE SINGLE AUTHORISED LIVE DEPLOY

**None of this is closed by keeping `crates/**`. All of it is closed only by the
one authorised run.** It is stated inside the final decision rather than beside
it, because it is the real residual risk of this cutover — and it is a *deploy*
risk, not a *deletion* risk.

### 4.1 The four that can fail silently in production against a green tree

1. **The shared RPM counter (B10). Money. No mechanical backstop of any kind.**
   `apps/mcp` and `apps/agent-runtime` carry the cross-script `RATE_LIMIT` stanza
   **commented out**, because workerd cannot resolve a `script_name` binding
   offline — uncommenting takes both suites to **0 collected tests**. Left
   commented at deploy, a credential capped at 60 rpm is charged 60 on the
   gateway **plus 60×N mcp isolates plus 60×M agent-runtime isolates**. Nothing
   errors. This has now survived seven waves in that state, and it is the single
   item on this list with no local gate of any kind.
2. **The half-bound `agent-runtime` (B1 + B4 → A9). Security AND money.** Fully
   unbound is loud. Bind `DB`, forget `CONTROL_DB`, leave the committed
   `FG_DEV_IN_MEMORY_PORTS = "1"`, and `resolveDeps` **succeeds** — serving
   traffic with tenant suspension, the operator drain, guardrail screening and
   agent-upstream withdrawal **all four silently inoperative**.
   **Deploy rule: bind `CONTROL_DB` and `DB` together or bind neither.**
3. **Three control-database uuids that must be equal (B11).** The drain's
   fleet-wideness is a function of three `database_id` values matching. Point two
   Workers at different control databases and each drains independently, with
   `GET /admin/v1/drain` reporting `draining: true` and every local test green.
   No stanza, no placeholder, nothing to typecheck.
4. **The mTLS posture (B6).** At `FG_REQUIRE_PRODUCTION_MTLS = "0"` every
   transport channel is admitted — transport-downgrade acceptance, **not** an
   authentication bypass. The remediation is not a var flip: `"1"` admits
   `verified_mutual_tls` only, which `request.cf.tlsClientAuth` supplies
   **exclusively on a zone with Cloudflare mTLS configured**. Flip it on a zone
   without mTLS and every self-hosted-worker callback is refused. **Confirm the
   zone first.**

### 4.2 The rest of the blocker table

**B2** (R2 bucket declared but non-existent) and **B5** (Analytics Engine) fail
the **deploy**; **B9** (two control migrations) fails the **callback**; **B3**
(no KV rights) leaves stored-credential encryption unexercised and must be
*reported* rather than assumed; **B7** (`ADMIN_CONSOLE_JWT_SECRET`) fails
**closed and loud** — `503 admin_console_unconfigured`; **B8** (per-tenant
`env://` IdP secrets) fails login closed but indistinguishably from an IdP
outage, so check it explicitly during the run.

Two verification rows are **expected to record a gap rather than a pass**:
`V-R2` (partial — gateway only) and `V-B10` (fails unless both stanzas were
uncommented at deploy). `V-R1` flipped to expected-**PASS** in wave 24.

### 4.3 Axis-level gaps that change no verdict

SSE framing byte-for-byte against the Rust streamers; **AEAD interoperability
against a real Rust self-hosted-worker binary** (no `cargo`, by hard rule — and
this window genuinely does close on deletion, though the tag reopens it, §5);
`sigv4` / Vertex signing against live AWS/GCP; per-operation FIELD parity for ~60
control-plane collections; Cron dispatch (workerd never fires a scheduled event
under vitest or `wrangler dev`).

### 4.4 The two insurance artefacts hold, and would still bite after the delete

Both were *irreversible-if-missed*. Wave 24 captured them and cert-4 re-derived
both from published algorithm text rather than from the code under test — the FNV
golden table **165/165**, anchored on the canonical FNV-1a-64 reference vectors
first; the two SigV4 signatures reproduced exactly from AWS's algorithm. Both
were re-proved to bite by mutation (`FNV_PRIME` → 3 RED / 5; the SigV4 canonical
blank line → 6 RED / 27 plus 2 RED / 23, where the same mutation previously left
`packages/providers` **75/75 green**).

Their independence from `crates/**` is the load-bearing property: the only
occurrence of `crates` in the FNV golden file is a **provenance comment**.
Nothing at runtime reads the Rust. **They will still catch a divergence after the
delete.**

---

## 5. (e) IRREVERSIBILITY — the tag recovers the bytes

**`legacy-rs` recovers everything this deletion removes.** Verified, not assumed:

```
$ git rev-parse legacy-rs                → 90e47fe0…  (annotated tag object)
$ git rev-list -1 legacy-rs              → 9ea3cc185a0ab11d08348ca9c42293bd196b0a97
$ git log -1 legacy-rs                   → 2026-07-31 01:13:46 +0800  "remove AGENTS.md"
$ git ls-tree -r legacy-rs | grep -c '\.rs$'        → 872   (812 under crates/)
$ git ls-remote --tags origin | grep legacy-rs      → present on ORIGIN
$ git diff --stat legacy-rs HEAD -- crates workers Cargo.toml Cargo.lock
                                                    → (empty)
```

**The last line is the one that matters.** The Rust tree at `legacy-rs` is
**byte-identical** to the Rust tree at `HEAD` — the rewrite never touched
`crates/**`, `workers/**` or `Cargo.*`. So the tag is not an approximate
snapshot; it is exactly the bytes about to be deleted, and it is on the remote,
not only in this clone.

**Therefore: what deletion costs is a working-tree diff source, not the code.**
The distinction is precise and worth stating in both directions:

* **Recoverable, cheaply, forever** — reading a Rust function, quoting a line
  number, re-deriving an algorithm, settling a dispute about what the reference
  did. `git show legacy-rs:crates/ferrogate-runtime/src/function_egress.rs`.
* **Genuinely harder afterwards** — anything that wants both trees *in the working
  directory at once*: `grep -r` across Rust and TypeScript in one pass; an
  editor's cross-language jump; a side-by-side diff of a handler against its
  port. That friction is real, and it is why five waves of transcription happened
  before this decision rather than after it.
* **Not restored by the tag at all** — `cargo` was never available in this
  environment. The AEAD-interop-against-a-real-Rust-binary gap (§4.3) needs a
  machine with a Rust toolchain plus the tag, and was never closeable here.

**Confirm the tag, then delete.** It already exists and is already pushed, so
this is a check rather than a step.

---

## 6. Ranked actions, now that the gate is open

1. **Merge, then delete.** `crates/**`, `workers/**`, `Cargo.*`. Confirm
   `git ls-remote --tags origin | grep legacy-rs` first (§5).
2. **Close C1** (§1.5) — the suspension WRITE leg. Security-adjacent, ~25 lines,
   and FC-2 currently arrives through a door nobody is watching. **This is the
   sharpest open item in the repository.**
3. **Add the column property** to `fleet-control-matrix.test.ts`: *every column of
   a shared control table that any Worker PARSES must have at least one Worker
   that CONSUMES it in a decision.* R1 and R2 were both found by hand; this is
   the gate that finds the third.
4. **Close A4 / R2** — two SQL columns and one branch on each of two Workers.
5. **Close A5 / L1** — three edits, the third being the one that matters: assert
   the PREPARED ENDPOINT is the AI Gateway host.
6. **Close `client_action_time`** (§1.1) or delete the CLI's signing half. What is
   wrong today is the *asymmetry*; either direction fixes it.
7. **Run `CLOUD-VERIFICATION.md` once, carefully**, treating §4.1 as the thing the
   run is FOR.
8. The 19 tail items, the 55 A6 write halves, R5 (guardrail evidence), R4 (mcp
   audit), CORS on `/v1/**`.

### 6.1 One defect class worth naming rather than fixing a fourth time

Three times now this project has been bitten by **text that is inert to the
compiler and corrupting to the evidence instrument**: raw NUL bytes (wave ~12),
newlines in FILE NAMES (wave 23), and `/*` inside a `//` line comment (wave 25,
which ate an `export interface` out of a scanner's view and turned a vacuity
guard red). Each was caught by a guard built *after* the previous one. The class
is "the evidence instrument parses source with a regex"; the fix belongs at the
class level, not the instance level.

---

## 7. Scope statement

Run in `/home/dev/ferrogate-ts` on `main-ts`, 2026-08-02.

**No `cargo`. No Rust compiled, imported, linked, wasm'd or subprocessed.**
`crates/**` was **READ ONLY**, once, to verify `ANY_FUNCTION_SLUG`'s semantics
against the transcription (§1.4) — the last moment that check can be made.
**No `wrangler deploy`, no live Cloudflare resource, no real upstream LLM call.**
**Nothing deleted. No merge to `main`.** The owner executes the cutover.

Files written by this agent: `docs/rewrite/CUTOVER-READINESS.md` (this file),
`docs/rewrite/CLOUD-VERIFICATION.md` (§8 added, §6 checklist corrected),
`docs/rewrite/DROPPED-CAPABILITIES.md` (§2.1 wildcard), and three wave-25 gate
scripts under `scripts/`. **No source file and no test file was created or
modified.** No test was weakened, skipped or deleted.

Every mutation — 201 seam rows plus C1 — was read back **OFF DISK with the
ORIGINAL TEXT REQUIRED ABSENT**, then reverted and verified **byte-identical by
sha256**. `grep -rn MUTW25 apps packages e2e sql` returns nothing.

---

## 8. The verdict, in one paragraph

`crates/**` was never the specification for the contract surface — the
251-operation contract and the 3.1.0 OpenAPI document were, and they live in
`docs/`. What the Rust uniquely held was five clusters. Two were transcribed as
algorithms, one was built, one was dropped *and transcribed anyway at the deepest
fidelity in the file*, and one was dropped and recorded as a brief. The two
artefacts that expire on deletion are captured and independently re-derived.
Eighty CLASS A findings survive as product backlog and **not one of them needs
the Rust to exist in order to be specified, argued about, or fixed** — which is
the test, and the only test, that this decision was ever supposed to apply. The
tree typechecks clean, is green on 7,051 tests, holds **196 of 201** mount seams
under landed mutation with **zero** unproven mounts, boots all five Workers under
real workerd, and passes 22 E2E specs. What is left uncertain is uncertain
because this system has only ever been run offline, and keeping a Rust tree that
cannot be deployed to Cloudflare Workers at all closes none of it. The bytes are
recoverable from `legacy-rs`, byte-for-byte, on the remote. **Merge, and delete.
GO.**

---
---

# APPENDIX F — the wave-23 / wave-24 document, preserved verbatim

Everything below this line is the previous decision document, unedited. It
reached **NO-GO on the deletion**, on a five-cluster spec-bound subset, and it is
preserved because its reasoning is what made this wave's GO checkable rather than
asserted: it named the exit criterion, and §0.3 of it is the criterion that has
now been met. Its own Appendices G and H (waves 19–22 and 15–18) are nested
inside it.

**Read it as history. Where it disagrees with the document above, the document
above is current.**

## (archived) CUTOVER READINESS — the wave-23 / wave-24 decision document

**Wave 23 · 2026-08-01 · branch `main-ts` · worktree `/home/dev/ferrogate-ts`**

> **WAVE 24 APPENDED — see §0.5.** The verdict below is UNCHANGED. Wave 24
> captured the two pieces of expiring insurance (§3.1), transcribed S3 and S4
> into `docs/rewrite/SPEC-TRANSCRIPTS.md`, and built S5. S1 and S2 remain, and
> they are a product decision the owner is answering separately.

**This is a FRESH decision.** It inherits no verdict. Waves 15–22 are preserved
verbatim in **Appendix G** (waves 19–22) and **Appendix H** (waves 15–18) and are
history, not evidence. Every number in §1 was measured by this agent, on this
tree, this wave. Four certifications were delivered into this wave and all four
were read end to end; where one of them is loose I say so and give the
measurement (§2.4, §4.3).

The question this document answers is exactly the one it was asked:

> May we delete `crates/**`, `workers/**` and `Cargo.*`, and merge `main-ts`
> into `main`?

---

## 0. THE VERDICT

| Decision | Verdict |
|---|---|
| **Merge `main-ts` → `main`** | **GO — unconditionally, today.** |
| **Delete `crates/**` + `workers/**` + `Cargo.*`** | **NO-GO — on a named, five-cluster subset.** Everything else is clear. |
| **The compound decision as asked (delete AND merge)** | **NO-GO**, because deletion is inside it. |

### 0.1 Why the merge is a clean GO

Nothing in the CLASS A list is a reason to keep `main` pointing at the Rust. The
Rust tree does not run on Cloudflare Workers and cannot be deployed to the target
platform at all; keeping `main` on it does not preserve a single one of the
capabilities §2 says were lost. The TypeScript tree typechecks clean across 22
projects, is green on 6,980 tests across 381 files, boots all five Workers under
real `workerd`, and holds 195 of 200 mount seams under mutation. **Merging is
strictly better than not merging and there is no argument on the other side.**
All four certifications reach the same conclusion independently.

### 0.2 Why the deletion is a NO-GO, stated so it can be argued with

The rule I was given is that CLASS A — *regressions where the Rust worked and the
TypeScript dropped it* — and **only** CLASS A blocks. So the discipline is:

1. CLASS A is **not empty**. It is 77 contract operations plus 6 cross-cutting
   items (§2). That is measured, not asserted, and three of the sharpest items I
   re-verified against the Rust myself rather than inheriting (§2.4).
2. But **most of CLASS A does not require the Rust to survive.** An error code
   collapsed from `invalid_upload_intent` to `invalid_request` is fully specified
   by the sentence you just read. Deleting the Rust costs nothing there.
3. What blocks the deletion is the **SPEC-BOUND subset** — the CLASS A items
   whose only complete specification is Rust source that is about to be deleted.
   That is five clusters (§3), and for those the deletion is not "irreversible in
   principle", it is *"this work gets materially harder next week than it is
   today"*.

**The honest framing: the blocker is not the size of CLASS A, it is the overlap
between CLASS A and the Rust's role as a specification.** Once that overlap is
empty — by building the five clusters, or by the owner explicitly dropping them —
the deletion is a GO and I would say so.

### 0.3 The exit criterion, so this is not an indefinite hold

Deletion becomes **GO** when, for each of the five clusters in §3, exactly one of
these is true:

* it has been **built** in TypeScript; or
* the owner has **explicitly dropped** the capability (a product decision, and a
  legitimate one — the owner has released this project from parity with an
  unfinished system, and three of the five are small); or
* its Rust specification has been **transcribed** into `docs/rewrite/` at the
  fidelity §3 names, so the delete costs no information.

The third option is cheap and is the fastest path. **This is days of work, not
waves.** Nothing here requires the certification cycle to run again.

### 0.4 What this verdict is NOT

* It is **not** "the TypeScript is unfinished, so hold". On security and money
  the TypeScript is *better held* than the Rust ever was: 19 data-plane
  mutations RED, 8 control-plane write halves proven as EFFECTS, 195 seams
  mutation-proven. That work is done.
* It is **not** parity-with-Rust as a standard. Zero of the 197 control-plane
  operations are CLASS B, because cert-3 opened the Rust handler for every one —
  and the places the Rust genuinely never finished (§5) are explicitly **not**
  allowed to block anything.
* It is **not** a hold on the merge. The two decisions are separable and I have
  separated them.

---

## 0.5 WAVE 24 — the expiring insurance is CAPTURED, S3/S4 are TRANSCRIBED, S5 is BUILT. The verdict is NOT changed.

**Wave 24 · 2026-08-01 · integrate step, first-hand.** This section is appended,
not merged into the wave-23 text above: every number in §§0-8 remains what wave
23 measured, and every number here is what wave 24 measured.

**The verdict is deliberately untouched.** S1 (`executeFunction`) and S2
(`listTools`/`executeTool` catalogue) are the remaining spec-bound clusters and
they are a **product decision the owner is answering separately**. Three of the
five clusters moved; the two that gate the deletion did not, so neither the
GO on the merge nor the NO-GO on the delete changes.

### 0.5.1 The two pieces of insurance (§3.1) are CAPTURED — verified independently, not accepted

Both were *irreversible-if-missed*, so the integrate step re-derived them rather
than reading the delivering agents' notes.

**L11 — SigV4 golden vectors** (`packages/providers/test/sigv4-golden.test.ts`,
27 assertions). Every literal was regenerated from AWS's published algorithm in
a from-scratch ~40-line Python `hashlib`/`hmac` script that touches neither the
TS nor the Rust: **12 of 12 values reproduced exactly** — the four canonical
request digests, the six signatures, and both payload hashes. The Rust
`sign_canonical` (`crates/ferrogate-providers/src/sigv4.rs:225-233`) was then
read directly and its canonical-request `format!` is character-for-character the
layout the file pins. **The TS agreed with the Rust on the first run.** There was
no divergence to report.

The claim that made this worth doing was also re-measured rather than trusted.
The pre-L11 gate was reconstructed verbatim from `HEAD` (23 assertions) and run
against each mutation:

| mutation | pre-L11 gate | `sigv4-golden.test.ts` |
|---|---|---|
| A drop the blank line before the signed-header list | **GREEN 23/23** | **RED, 6 failed** |
| B reorder canonical headers, list left correct | **GREEN 23/23** | **RED, 3 failed** |
| C double-hash the payload line | RED | **RED, 5 failed** |
| D credential scope from `amzDate` not `dateStamp` | RED | **RED, 7 failed** |
| E drop the trailing `\n` on the last canonical header | **GREEN 23/23** | **RED, 3 failed** |
| F `canonicalUri` returns the path unencoded | **GREEN 23/23** | **RED, 2 failed** |
| G presign signs `""` instead of `UNSIGNED-PAYLOAD` | **GREEN 23/23** | **RED, 1 failed** |

Five of seven — every purely structural one — were invisible before this file
existed. Each mutation was read back **off disk** with the original text required
absent, and each restore was verified byte-identical by `sha256`.

**The Rust-derived rollout bucket table** (`packages/routing/test/fnv-golden.test.ts`,
165 rows). `crates/ferrogate-routing/src/rollout.rs` was read directly
(`FNV_OFFSET_BASIS`, `FNV_PRIME`, `salt ++ 0x00 ++ sticky_key`, `% 100`) and all
165 rows were regenerated in an independent Python implementation anchored first
against the canonical FNV-1a-64 reference vectors: **0 mismatches of 165**, on
both the full 64-bit `raw` column and the `bucket` column. **The TS agreed with
the Rust on the first run.** Six divergence mutations were then applied to
`packages/routing/src/fnv.ts` and every one is RED: FNV-1 instead of FNV-1a, the
NUL separator changed to `0x01`, `% 101`, an offset basis off by one, and latin1
instead of UTF-8 on each of the salt and the key.

**Both artefacts are now independent of `crates/**`.** This is the part of wave
24 that cannot be redone later, and it is done.

### 0.5.2 S3 and S4 are TRANSCRIBED — `docs/rewrite/SPEC-TRANSCRIPTS.md` (1,334 lines)

Written against the exit criterion in §0.3, third bullet. Spot-verified against
the Rust by the integrate step at the points the certification called decisive:

* **S3 · the transaction shape.** `state.rs:880-926 reload_process_local` is
  transcribed as an algorithm — coordinator lock, `prepare`, GATE 1 listener-level
  rejection, GATE 2 runtime construction, the swap, `commit` — and the Rust reads
  exactly that, including both `RuntimeReloadResult` early returns and their
  `mode` constants. `config_snapshot_id` is confirmed FNV-1a-64 over
  `serde_json::to_vec(config)` rendered `{:016x}`, with the transcript's warning
  that it is **content-addressed and not an ordering key**.
* **S4 · the #535 field-level redaction.** `local.rs:8227-8281` and
  `rbac.rs:1276-1349` were opened. `narrow`, `narrow_organizations` and
  `visible_model` are transcribed correctly, including the invariant that carries
  the security: **a non-empty selector that loses every entry returns `None` (hide
  the entry), never `Some([])`**, because an empty selector is a WILDCARD — so the
  careless port converts a tenant-scoped model into a globally-visible one. The
  transcript states that in those terms.

The document also carries an explicit honest ledger (§C1) of where the Rust is
unfinished and must **not** be transcribed as specification.

### 0.5.3 S5 is BUILT — the plan/RBAC tool-entitlement ladder is mounted and gated

`apps/mcp/src/entitlements.ts` (`D1ToolEntitlements`) ports
`local.rs:137 tool_execution_entitlement_denial` + `state_rbac.rs:11
tenant_tool_entitlement_denied` over the CONTROL D1, and `resolvePorts` now binds
it (`MCP-P15`, a new T1 seam row). Both consumers were already calling
`ports.entitlements.toolExecutionDenial` and being answered `undefined` — the
"implemented, tested, never mounted" shape that R1 turned out to be.

Verified as an EFFECT, not as a call: mutating the mount to
`inMemoryPorts().entitlements` — original text confirmed gone off disk,
`grep -c 'durableEntitlements(env)' → 0` — takes `test/entitlements.test.ts` to
**5 failed / 3 passed (8)**, and restoring returns it to 8/8 with the file
`sha256`-identical. The four Rust properties that are easy to lose are each
pinned: denial requires a REGISTERED tenant, plan **OR** role grants, an
UNDECLARED permission grants nothing, and every lookup swallows its error into
"no grant" so a control-plane outage cannot lock the fleet out.

**This closes A3/R1 and empties cluster S5.**

### 0.5.4 Does a NEW BLOCKER appear? NO

Nothing found this wave is CLASS A. Two corrections to the record:

1. **The `version` drift is on `/readyz`, not `/healthz`.** The wave-24 boot proof
   read all ten bodies: **all five `/healthz` documents carry `version`** and share
   ONE shape (`{status, service, version, runtime}`, `distinct shapes: 1`). It is
   the gateway's **`/readyz`** that omits `version` while the other four carry it —
   exactly as §2.3 records. Unchanged, still the one CLASS A item the boot proof
   reaches, still not new.
2. **`apps/mcp/wrangler.toml` inertness is now ASSERTED, not claimed.** S5 needs
   no new binding and adds no Durable Object, but under
   `@cloudflare/vitest-pool-workers` the `DB` binding comes from
   `vitest.config.ts`, so the committed deploy config could have stopped declaring
   it with every entitlement test still green — R1's shape one level down. Two
   assertions were added to `test/wrangler-bindings.test.ts`: the committed
   `[[d1_databases]]` declares `binding = "DB"` / `ferrogate-control` /
   `PLACEHOLDER_SET_AT_DEPLOY_TIME`, and the bound Durable Object class set is
   **exactly** what `src/worker.ts` exports. Renaming the `DB` binding in the
   committed toml takes that file RED.

### 0.5.5 Wave-24 gate results, first-hand

| Gate | Result |
|---|---|
| `bun install` | no changes, 262 installs checked |
| `bun run typecheck` | **clean**, 22 projects |
| `bun run test`, per package and app | **7,029 passed, 0 failed**, exit 0 in all 21 workspaces (was ~6,980; +40 new assertions, +9 counted `todo`) |
| Seam pass — parse | CLAIMED **201** · PARSED **201** · gated **199** · no-gate-by-design **2** · no-gate-no-reason **0** |
| Seam pass — T1 `--run` | **136 rows**, 435s, all GREEN except `AR-T11` (NO-GATE by design) |
| Seam pass — every `apps/mcp` row (the file this wave touched) | **34 rows**, 63s, **34 GREEN** |
| Seam mutations re-proven | `MCP-P15` 5 RED / 8 · `MCP-P14` 8 RED / 12 (its gate file was edited this wave, so it was re-proven rather than assumed) |
| Insurance mutations | 7 SigV4 + 6 FNV, **13 of 13 RED**, all restored `sha256`-identical |
| Boot proof — five Workers, `wrangler dev --local` | all five **"Ready on"**, `/healthz` **200 ×5**, `/readyz` **200 ×5**, bodies read |
| `playwright test --config e2e/playwright.config.ts` | **22 passed** (22 before) |

### 0.5.6 What remains between here and `git rm -r crates/`

Precisely two things, and they are the same two the owner is deciding:

1. **S1 — `executeFunction`.** ~400 lines of egress allowlist + token minting in
   `local.rs`'s `handle_function_execute` region and
   `ferrogate-runtime/src/{function_egress,function_token,supabase_edge_function,function_egress_cloudflare}.rs`.
   Nothing in `docs/` reproduces the allowlist semantics or the token claim set.
   **BUILD, TRANSCRIBE or DROP.**
2. **S2 — the `listTools`/`executeTool` CATALOGUE half.**
   `crates/ferrogate-gateway/src/extensions.rs` + `state_tools.rs`. Keep the
   catalogue; the hook model (`RequestHook` has one variant, `Noop`) should be
   designed fresh rather than copied. **BUILD, TRANSCRIBE or DROP.**

S3, S4 and S5 are cleared: S3 and S4 by transcription at the fidelity §3 names,
S5 by construction. The two insurance artefacts are captured and no longer
depend on `crates/**` existing. **Nothing else in this document blocks the
deletion**, and §0.3's exit criterion is now satisfied for three of five
clusters.

---

## 1. Evidence this wave produced, first-hand

Everything below was run by me in this worktree. No number is inherited.

| Gate | Result |
|---|---|
| `bun install` | clean, no changes (262 installs / 338 packages) |
| `bun run typecheck` | **exit 0**, 22 projects, zero diagnostics — run twice, before and after this wave's edits |
| `bun run test`, per workspace, serially | **exit 0 in all 21** · **6,980 passed + 9 todo · 0 failed · 381 files** |
| **Full seam pass, all 200 rows** | **195 RED · 5 NOT-MUTABLE by category · 0 GREEN-unproven · 0 restore failures** (§2.1) |
| `bunx wrangler dev --local`, five Workers, distinct ports | **5/5 "Ready on"**, `/healthz` **200 ×5**, `/readyz` **200 ×5**, ONE health-document shape (§2.2) |
| `bunx playwright test --config e2e/playwright.config.ts` | **22 passed**, exit 0, 4.3 s |

Baseline was ~6,986. The tree is at **6,989 including todos**; the +2 is the
source-hygiene gate this wave added (§4.1) and it was proven RED before it was
proven GREEN.

### 1.1 The seam pass, and the correction it needed

`bun scripts/seam-proof.mjs --list` reports the three numbers that keep a scripted
pass honest, and **they agree**:

```
rows CLAIMED by the inventory's §13 total ... 200
rows PARSED out of §7-§12 .................. 200 (+1 retired)
rows with a RESOLVABLE gate ................ 198
rows with NO gate BY DESIGN ................ 2
rows with NO gate and no reason ............ 0
```

I built a second, independent parser (`scripts/wave23-seam-pass.py`) and
cross-checked it against `seam-proof.mjs`'s row set **by ID**: 200 = 200, empty
symmetric difference. A driver that sees a different population than the counter
is precisely how a "full" pass under-runs.

**The first attempt was not honest and I did not report it as if it were.** The
generic driver located each Seam cell's *first backticked span* and commented out
its line. That produced 166 RED, 5 GREEN and **26 rows it could not locate** —
and 26 unlocatable rows in a summary look exactly like 26 passing ones. Three
causes, all properties of the inventory rather than the tree:

* twelve rows sit under a `### … src/index.ts` heading while the Seam cell names
  the module the seam actually lives in (`src/http.ts`,
  `src/identity/routes.ts`, `src/routes/health.ts`, …);
* eight seams are multi-line expressions with no single line to comment out —
  commenting one line yields a **syntax error**, and a suite that goes red
  because the file no longer parses proves nothing whatever about the gate;
* two seams **are already comments** (the deliberately commented cross-script
  `RATE_LIMIT` stanza), and commenting a comment is a byte change with no
  behaviour change.

Five of the first pass's GREENs were the same defect wearing the other face: the
driver had commented out a *docblock line*, so the mutation changed bytes and
changed nothing, and the resulting GREEN would have been reported as an unproven
mount. **That is a false finding in the direction that manufactures work**, and
it is why `is_inert_line()` now rejects an already-inert target rather than
measuring it.

The fix was a refined candidate search (`scripts/wave23-seam-pass.py`) for 9 of
them and **22 hand-written, behaviour-changing edits**
(`scripts/wave23-seam-residue.py`) for the rest — each one naming, in the script,
the behaviour it removes. Final tally:

| | rows |
|---|---:|
| **RED — the named gate failed under a LANDED mutation** | **195** |
| NOT-MUTABLE by category (2 `NONE`, 1 `NOT-MUTABLE`, 2 already-commented stanzas) | 5 |
| GREEN against a landed mutation (an unproven mount) | **0** |
| restore failures (every file re-verified byte-identical by sha256) | **0** |
| **total** | **200** |

Every mutation was **grepped back off disk** before its suite ran, and required
the original text to be *gone* — not merely the marker present. `grep -rn MUTW23
apps packages` at the end of the pass returns nothing.

### 1.2 One seam finding, independently reproduced

While mutating `CP-C13` I initially removed the `/version` document's three
census fields while leaving the route registered — and the gate stayed **GREEN**.
That is not a new defect: it is exactly what `MOUNT-SEAMS.md` records as
**CP-C13b**, a knowingly unproven sub-seam whose Channel is `NONE`. Re-running
`CP-C13` against its *actual* seam — the registration itself — is **RED**.

So the inventory's own honesty about CP-C13b is now independently confirmed by an
agent that stumbled into it rather than read it. That is the best evidence a
tombstone row can get, and it is the argument for keeping the `NONE`-with-a-
reason channel rather than deleting rows that cannot be proven.

---

## 2. (b) THE CLASS A LIST — the only cutover blockers

**CLASS A = 77 contract operations + 6 cross-cutting items = 83 findings.**
It is not empty, and §0.2 explains why that alone is not the blocker.

Severity is *what a paying customer or an operator observes*, not size.

### 2.1 CLASS A · the material items

| # | Finding | Where Rust had it | Severity |
|---|---|---|---|
| **A1** | **`executeFunction` answers 501.** The "out-of-process sandbox" justification is **false about the reference**: Rust's `handle_function_execute` is a broker — `fetch` + WebCrypto HMAC + a config table — with a fail-closed per-tenant egress allowlist, a signed short-lived token and a Cloudflare-Worker target arm. All of it is portable to workerd. | `local.rs:3219`; `ferrogate-runtime/src/{function_egress,function_token,supabase_edge_function,function_egress_cloudflare}.rs` | **MEDIUM** |
| **A2** | **`listTools` + `executeTool` answer 501.** Rust's registry is real: `tools_for(tenant, api_key_id, route)` merges builtin providers, MCP-HTTP-declared tools and per-tool approval policy + tenant/key/route allowlists. | `extensions.rs`, `state_tools.rs` | **MEDIUM** |
| **A3** | **R1 — the plan tool-entitlement gate is parsed by four Workers and enforced by none.** `plans.mcp_enabled` / `extension_tools_enabled` / `self_hosted_workers_enabled` are read into a `StoredPlan` by gateway, mcp, agent-runtime **and** the control plane, and have zero consumers. **Verified by me** (§2.4). | `local.rs:137 tool_execution_entitlement_denial`, called from `local.rs:3617` and `mcp_rpc.rs:567`; durable half `state_rbac.rs:11` | **HIGH — money + capability** |
| **A4** | **R2 — the `monthly_token_budget = 0` kill switch stops one spend Worker of three.** Rust enforced it inside the SHARED credential-resolution path, so every handler in the process got it. TS reproduces it on the gateway only. **Verified by me** (§2.4). | `auth.rs:1344-1350` inside `authenticate_durable` | **MEDIUM — money** |
| **A5** | **L1 — Cloudflare AI Gateway routing (#406) is unreachable, and its config is REJECTED.** `defaultAdapterRegistry` is a hand-written `switch` that never goes through `ProviderAdapterRegistry`, so the routing is skipped on every request; and `providerRecordSchema` is `.strict()` with no `cloudflare_ai_gateway` key, so a working Rust operator config is **refused**, not ignored. A config-acceptance regression on top of a feature regression. | the library half is complete and correct in `packages/providers` | **MEDIUM** |
| **A6** | **55 control-plane operations whose write takes no effect.** The write lands in `control_plane_resources`; the data plane reads deploy-time vars. In Rust the same `POST` was a persist → rebuild-candidate → `validate()` → hot-reload → rollback transaction and was live on the next request. | `state.rs:1334` + `local.rs:1844`; `local.rs:5019/5062/8227` for providers/models | **MEDIUM in aggregate** |
| **A7** | **R5 — guardrail evidence is durable nowhere.** `InMemoryGuardrailEvidenceSink` is bound **unconditionally**, and there is no evidence table in `sql/d1-ts/` at all. Every guardrail decision dies with the isolate. Request-path behaviour is unaffected, which is exactly why it is invisible. | `state_quota_and_policy.rs:935 record_guardrail_evaluation` → durable admin audit | **MEDIUM — compliance / IR** |
| **A8** | **CORS is absent from the entire `/v1/**` data plane.** Rust's `apply_cors_headers` is called from 9 sites including the generic `write_json_response`/`write_raw_response` bodies. `apps/control-plane` has CORS, so `/admin/v1/**` is covered and `/v1/**` is not. | `responses.rs:38`, driven by `config.admin.cors_allowed_origin` | **MEDIUM — browser clients** |
| **A9** | **D1 — the same missing binding fails OPEN on two Workers and CLOSED on the third.** With `CONTROL_DB` unbound, mcp answers `503 lifecycle_status_unavailable`; gateway and agent-runtime read "no row" as "not suspended". Combined with the committed `FG_DEV_IN_MEMORY_PORTS = "1"`, the **half-bound** deployment serves traffic with suspension, drain, guardrails and upstream withdrawal all silently off. | — (a TS configuration asymmetry) | **HIGH in the half-bound posture** |
| **A10** | **`GET /metrics` is served by two Workers with two different bodies** — 47 series from the gateway, two gauges from the control plane — and `ROUTE-MAP.md` points operators at the two-gauge host. | | LOW–MEDIUM |
| **A11** | **R4 — `apps/mcp` keeps no durable audit trail.** `InMemoryAuditSink` in every posture, 20 call sites including every tool execution, credential grant and OAuth completion. The gateway writes `audit_events` durably; in Rust the two surfaces were one process writing one log. | | LOW |

### 2.2 CLASS A · the tail (19 items, all LOW, all fully transcribed)

These need no Rust to fix and are listed so they are decided rather than lost:
six error codes collapsed to `invalid_request` (three asset-presign, plus
`asset_commit_outcome_unknown` absent); the four job-lifecycle codes
(`invalid_agent_job_input`, `invalid_agent_job_capabilities`,
`409 agent_job_not_cancellable`, `503 agent_job_cancel_unavailable`); the eight
per-verb self-hosted-worker callback codes; `422 image_generation_unsupported`
→ `400 model_capability_unsupported`; a malformed `x-ferrogate-agent-run-id`
accepted silently on ordinary inference; a misspelled `x-ferrogate-config`
silently selecting the default posture; `renderPromptTemplate` writing no audit
row; `chars/4` in place of BPE (**fails closed** — it over-reserves, and the
inequality direction is pinned); and **`/readyz` on the gateway omitting
`version`** — which the boot proof confirmed live this wave (§2.3).

### 2.3 What the boot proof actually showed

All five Workers reached "Ready on", answered `/healthz` **200** with an
identical four-member document, and answered `/readyz` **200**.

I read the bodies rather than the status codes, and the one thing they show is
the `/readyz` divergence:

```
gateway        {status, service, runtime, cluster{…}}          ← no `version`
control-plane  {status, service, version, runtime, dependencies}
mcp            {status, service, version, runtime, protocol, readiness_reason, …}
agent-runtime  {status, service, version, runtime, ready, readiness_reason, …}
telemetry      {status, service, version, runtime, sink}
```

**This is the one CLASS A item the boot proof reaches, and it is exactly the one
cert-3 predicted**: the gateway alone omits `version`. I checked the Rust before
calling anything else a divergence — `ReadinessResponse` is
`{status, service, version, runtime, cluster}` (`responses.rs:77`), so the
gateway's *nesting* is the shape closest to Rust and `readiness_reason` /
`draining` at the top level on mcp and agent-runtime are TS **additions**, not
Rust members. Only `version` is lost.

**No new defect was found by the boot proof this wave.** Waves 20 and 22 each
found one, so this is worth stating rather than passing over: the composition
roots are now stable enough that the channel is quiet. That is a result, not an
absence of one.

### 2.4 The three decisive claims, re-verified against the Rust by me

I do not bounce a cutover on a sub-agent's word. The three findings that carry
the most weight in §2.1 were re-derived from the actual files:

**A3 (R1) — CONFIRMED, both halves.**
Rust: `local.rs:137 pub(super) async fn tool_execution_entitlement_denial(` with
the refusal `"mcp_tools_disabled"` at `local.rs:156`, called at `local.rs:3617`
and `mcp_rpc.rs:567` — two live call sites in the request path.
TypeScript: the only occurrence of `mcp_tools_disabled` in the whole tree is
`apps/mcp/src/ports.ts:1062`, inside `InMemoryEntitlements`, whose
`deniedTenants` set has **exactly one writer in the repository** —
`apps/mcp/test/tools.test.ts:193`. `resolvePorts` never overrides `entitlements`
in either posture. So `toolExecutionDenial` returns `undefined` for every caller
on every deployment.

**A4 (R2) — CONFIRMED.** Rust `auth.rs:1347`:

```rust
if decision.monthly_token_budget == Some(0) {
    return Err(AuthError { status: TOO_MANY_REQUESTS, code: "token_budget_exceeded", … });
}
```

Files able to emit `token_budget_exceeded`, counted per Worker with a
control-character-safe scan: **gateway 7, control-plane 2, mcp 0,
agent-runtime 0.**

**A5 (L1) — CONFIRMED.** `applyCloudflareAiGatewayRouting` exists and is correct
in `packages/providers/src/cloudflare.ts:128`; `registry.ts:106` calls it; and
`registry.ts:24` records in its own docblock that the deployed data plane never
goes through that registry. `packages/config` accepts the config
(`entities.ts:61`, `sections.ts:798`) — it is `apps/gateway`'s
`providerRecordSchema` that refuses it.

---

## 3. The SPEC-BOUND subset — what actually blocks the deletion

For each cluster: is the Rust the **only** complete specification?

| # | Cluster | Rust files that would be lost | Spec-bound? |
|---|---|---|---|
| **S1** | `executeFunction` (A1) | `crates/ferrogate-gateway/src/server/local.rs` (the `handle_function_execute` region) + `crates/ferrogate-runtime/src/{function_egress,function_token,supabase_edge_function,function_egress_cloudflare}.rs` — ~400 lines of egress allowlist and token minting, `0` `todo!()` | **YES.** Nothing in `docs/` reproduces the allowlist semantics or the token claim set. |
| **S2** | `listTools` / `executeTool` (A2) | `crates/ferrogate-gateway/src/extensions.rs` + `state_tools.rs` | **YES, the CATALOGUE half.** Note `extensions.rs`'s `RequestHook` enum has one variant (`Noop`) and `EventSink` one (`audit_log`) — the **hook model should be designed fresh**, not copied. Keep the catalogue. |
| **S3** ✅ **CLEARED (wave 24 — TRANSCRIBED)** | The 25 config-backed control-plane operations — `skill`, `admin_plugin`, `admin_policy`, `prompt` (A6) | `crates/ferrogate-gateway/src/state.rs:1334` + `local.rs:1844` | **YES.** The value is the *transaction shape* — persist → clone config → apply snapshot → `validate()` → reload → roll back on error → re-read and answer `409 …_reload_rejected`. That is not in any doc. **Transcribed in full: `SPEC-TRANSCRIPTS.md` PART A (§§A1-A6), `reload_process_local` spot-verified against `state.rs:880-926` by the wave-24 integrate step.** |
| **S4** ✅ **CLEARED (wave 24 — TRANSCRIBED)** | `admin_provider` (3) + `admin_model` (1) (A6) | `local.rs:5019` (projection), `local.rs:5062` (live per-provider catalog fetch), `local.rs:8227` (the **#535 field-level redaction**) | **YES for the redaction.** Shipping the model projection without it is a credential-disclosure regression, and the redaction rule exists only in that function. **Transcribed: `SPEC-TRANSCRIPTS.md` PART B (§§B1-B5); `narrow` / `narrow_organizations` / `visible_model` spot-verified against `rbac.rs:1276-1349`, including the `None`-not-`Some([])` wildcard invariant.** |
| **S5** ✅ **CLEARED (wave 24 — BUILT)** | R1's entitlement ladder (A3) | `local.rs:137-160` + `state_rbac.rs:11` | **PARTLY.** The plan-OR-role shape is transcribed and `apps/gateway/src/assets/entitlements.ts` is an already-ported template of the same walk. **BUILT in wave 24**: `apps/mcp/src/entitlements.ts` + seam `MCP-P15`, mutation-proven 5 RED / 8. |

**Not spec-bound, and therefore NOT blocking the deletion**: A4/R2 (three lines,
quoted in full above), A5/L1 (the library is written; the gap is three edits at a
composition root), A7/R5 (a table and a sink; the Rust call site is named),
A8/CORS (nine call sites named, semantics trivial), A9/D1 (a TS asymmetry, no
Rust involved), A10, A11, and every one of the 19 tail items in §2.2.

### 3.1 Two pieces of insurance that expire on deletion — ✅ **BOTH CAPTURED IN WAVE 24 (§0.5.1)**

Neither is CLASS A. Both are cheap, and both are **impossible after the delete**:

* **L11 — pin the two SigV4 golden signatures.** A structurally wrong canonical
  request (the mandatory blank line deleted) leaves `packages/providers`
  **75/75 green**, because every SigV4 assertion is a *shape* assertion
  (`/^[0-9a-f]{64}$/`). The implementation is **correct** — cert-3 reproduced it
  against an independent Python implementation of the AWS algorithm — and the
  two golden vectors are printed in `cert3-controlplane-libs.md §7.11`. Ten
  lines. Do it while `sigv4.rs` can still be read by a third party who disputes
  the vector.
* **Generate a Rust golden bucket table for `rolloutBucket`** (FNV-1a-64 canary
  bucketing). Today the TS is byte-identical by inspection and by its own
  vectors; there is no Rust-generated table, and that window closes with the
  delete.

---

## 4. CLASS B — Rust never finished it. **Explicitly reframed as TS product backlog.**

None of this blocks anything. Porting any of it would import a defect. It is
listed so it is *scheduled*, not so it is *feared*.

| Item | Why it is CLASS B, with evidence |
|---|---|
| **`createAgentRun`'s synchronous turn loop** | Rust's `agent_runs.rs::agent_provider` has exactly two arms. `ManagedWorker` — **the default** (`types.rs:1149`), i.e. what every deployment that does not override it gets — returns `Err(("agent_worker_transport_unavailable", "…is not implemented yet"))`. `External` spawns a local **child process**, which workerd does not have. So a default Rust deployment answers **503** on this path. TS returns an accepted envelope with the full validation ladder, the run-plan echo and a real workflow gate. **Residual, and it is a product decision not porting work: the row should be RATIFIED or RENAMED** — accept the async semantics under `createAgentRun`, or rename and add `runAgentSynchronously` later. |
| **The `ferrogate-auth-service` `/v1/rbac/*` + `/v1/tenants` route arms (7)** | `AuthServiceData` is loaded from YAML into `Arc<RwLock<…>>` with **no writer back to disk**. A role created through that API is lost on restart. Decisive. |
| **`packages/cloudflare`'s account-management surface** | Zero production call sites for `ensure_tenant_r2_bucket`, `create_scoped_r2_token` or `.preflight(` — **in the Rust too**. Porting it anyway was right: it is the part of the Rust most expensive to re-derive after deletion. |
| **R3 — MCP `resources/read`** | `InMemoryAssets` in every posture; the durable `stored_assets` + R2 read was deliberately deferred and the module docblock says so. **Fails closed**, no money and no data exposure. |

**This section is the one I was warned about, and I want to be explicit: not one
item above is being used to hold the cutover.** Zero of the 197 control-plane
operations are CLASS B — cert-3 opened the Rust handler, its `state.*` method and
its repository call for every single one of the 55 it called a regression, and
found no `todo!()`, no orphan and no dead code.

### 4.1 What this wave changed in the tree

Four source files and one test file arrived from the two repair agents
(`callbacks.ts`, `metrics.ts`, `prompts.ts`, `readiness.ts` — four accurate
`PORT-TODO` markers for CLASS A gaps that previously had none — and the rewired
`fleet-guardrail-activation.test.ts`, which now drives agent-runtime's
`resolveDeps` composition root instead of importing a leaf function).

I added one thing, and only after proving it bites:

**A source-hygiene gate for control characters in FILE NAMES**
(`apps/gateway/test/source-nul-bytes.test.ts`). Two files in this repo had names
containing literal newlines — both 27,809 bytes, byte-identical to each other
(sha256 `5861badf…`), both a stale snapshot of
`apps/agent-runtime/src/middleware/auth.ts` produced by a shell redirect whose
target was an unquoted multi-line variable:

```
apps/mcp/src/admission/gate.ts\n    code: "quota_scope_disabled",…
apps/agent-runtime/src/admission/admit.ts\n    message: (requestId…
```

They were inert for the build and **actively corrupting for `grep`**, which is
this project's primary evidence-gathering instrument. They bit *this
certification*: a `grep -rc token_budget_exceeded` run to decide the **A4 CLASS A
verdict** printed those names as though they were matching files (§2.4 is the
re-run with a safe scan). One substitution away from a wrong verdict in this
document.

Sequence, in this order: the new assertion was run **first** and went RED naming
both offenders; the two files were then deleted (the real `gate.ts` and
`admit.ts` verified intact); the assertion went GREEN. The companion vacuity
guard derives the scanned app set from the glob keys rather than a hand-written
list, so a sixth app is covered the day it exists.

---

## 5. (d) What remains UNVERIFIABLE locally — the honest cost

These can produce a **security or money failure in production against a fully
green local tree**, and no further offline work can close them. Ranked.

1. **The shared RPM counter (B10). Money. Silent. Ungatable offline by
   construction.** `apps/mcp` and `apps/agent-runtime` carry the cross-script
   `RATE_LIMIT` stanza **commented out**, because workerd cannot resolve a
   `script_name` binding offline — uncommenting takes both suites to **0
   collected tests** and `wrangler dev --local` never reaches "Ready on". Left
   commented at deploy, `counterFromEnv` degrades to a per-isolate counter and a
   credential capped at 60 rpm is charged 60 on the gateway **plus 60×N across N
   mcp isolates plus 60×M across M agent-runtime isolates**. Nothing errors. The
   other four admission legs are shared and durable. **This is the single item
   with no mechanical backstop of any kind, and it has now survived five waves in
   that state.**
2. **The half-bound `agent-runtime` (B4 + B1 → A9/D1). Security AND money.
   Silent.** Fully unbound is loud — `resolveDeps` returns `undefined` and every
   authenticated surface refuses. Bind `DB`, forget `CONTROL_DB`, leave the
   committed `FG_DEV_IN_MEMORY_PORTS = "1"`, and `resolveDeps` **succeeds**: the
   Worker serves normally with tenant suspension, the operator drain, guardrail
   screening and agent-upstream withdrawal **all four silently inoperative**.
   `CLOUD-VERIFICATION.md` describes only the fully-unbound case. **The
   half-bound case is the one that ships.**
3. **Three control-database uuids that must be equal (B11).** The drain's
   fleet-wideness is a function of three `database_id` values matching. Point two
   Workers at different control databases and each drains independently, every
   local test green, `GET /admin/v1/drain` cheerfully reporting `draining: true`.
   No stanza, no placeholder, nothing to typecheck.
4. **The mTLS posture (B6).** At `FG_REQUIRE_PRODUCTION_MTLS = "0"` every
   transport channel is admitted. It is **not** an authentication bypass — the
   six worker-plane callbacks still require the AEAD-sealed frame keyed on
   `self_hosted_worker_registrations` — it is transport-downgrade acceptance.
   And the remediation is not a var flip: a Worker never sees the TLS handshake,
   so `"1"` admits `verified_mutual_tls` only, which `request.cf.tlsClientAuth`
   supplies **exclusively on a zone with Cloudflare mTLS configured** and never
   under `--local`. **A platform limit with a zone precondition.**
5. **Axis-level gaps that change no verdict but are not certified**: SSE framing
   byte-for-byte against Rust `messages_stream.rs` / `responses_stream.rs`; AEAD
   interoperability against a real Rust self-hosted-worker binary (no `cargo`, by
   hard rule — and this window also closes on deletion); `sigv4`/Vertex signing
   against real AWS/GCP vectors; per-operation request/response FIELD parity for
   ~60 control-plane collections; Cron dispatch (`workerd` never fires a
   scheduled event under vitest or `wrangler dev`).

**Not on this list, deliberately:** B2 (R2 bucket), B5 (Analytics Engine) and B9
(migrations) fail the **deploy** rather than degrading, and B7 fails **closed and
loud**. That is the shape the rest of the residue should be pushed toward.

### 5.1 Two invariants that are correct and held by nothing

Neither is CLASS A — both are correct code with tests that would survive their own
deletion, which is this project's documented dominant defect mode arriving for the
seventh time. Both are cheap and neither should be discovered by a customer.

* **C1 — the operator's suspension WRITE leg.** Neutralising
  `projectTenantAccount`'s `status` so every tenant is written `'active'` leaves
  **693/693 control-plane tests green AND the FC-2 fleet gate 12/12 green**,
  because the control plane's own lifecycle gate reads the *document* and the
  fleet gate writes the *column* with its own hand-written `UPDATE`. Nothing
  joins the two. ~25 lines, or one call-site change so
  `fleet-tenancy-suspension.test.ts` calls `projectTenantAccount` exactly as the
  FC-3 file calls `projectGuardrailActivation`.
* **L11 — SigV4**, §3.1.

### 5.2 A calibration to carry forward, not a defect

`FLEET-CONSISTENCY.md`'s "13 of 23 capabilities mechanically gated" should be
read as **13 of 23 watched for source-text drift, and 5 proven behaviourally end
to end**. Of the 101 assertions in the two files presented as "the fleet gates",
**3 are behavioural**; the other 98 are the class that M22 demonstrated stays
green when a Worker reads the operator's document and discards the answer. A
source-text ratchet is the right instrument for "has a Worker been added" — it is
not coverage. Decide it; do not inherit it.

---

## 6. (e) Irreversibility — read this before running `git rm`

`legacy-rs` recovers the **bytes**. It does not recover the **workflow**.

Every agent in this project diffs against the *working tree*: the seam inventory
was derived by walking files on disk, `MODULE-OWNERSHIP.md` was built by
enumerating `crates/**/src`, and all three certifications this wave answered
"did the port lose anything" by opening a Rust file next to a TypeScript one.
After the delete, that becomes "check out a tag into a scratch directory first" —
which is possible, and which in practice **nobody does**. The wave-23 finding R1
is the proof: it was found by reading `local.rs` and asking why a TS port parsed
three columns it never used. That question does not get asked against a tag.

So the practical, honest statement is:

> **Deleting `crates/**` ends regression-hunting against the original.** Not in
> principle — in practice. Every CLASS A item still open on the day of the delete
> becomes a permanent product decision, specified by whatever `docs/rewrite/`
> happens to say about it.

That is precisely why §3 is the blocker rather than the whole of §2, and why §3.1
lists two things to do *first* that cost hours and expire forever.

**`workers/**` and `Cargo.*` carry no such cost.** `workers/` is
reference-only and superseded by `apps/`; `Cargo.*` is a lockfile. If it is
useful to shrink the tree now, those can go today — the argument in this section
is about `crates/**` alone.

---

## 7. Ranked actions

1. **Merge `main-ts` → `main`.** Nothing is waiting on anything.
2. ~~**Close L11 and generate the routing golden table** (§3.1).~~ ✅ **DONE, wave 24** —
   both captured and independently re-derived by the integrate step (§0.5.1). They
   no longer depend on `crates/**`.
3. **Close C1** (§5.1) — the suspension write leg. Security-adjacent; it is FC-2
   arriving through a door nobody is watching.
4. **Transcribe or build S1 and S2** (§3). This is the deletion gate, and it is now
   only two clusters: **S3 and S4 were transcribed and S5 was built in wave 24**
   (§§0.5.2-0.5.3). S1 and S2 are the real work, and the owner may legitimately
   choose to **drop** them instead — that converts the verdict to GO without
   writing a line.
5. **Close A4/R2.** Two SQL columns and one branch on each of two Workers.
   ~~A3/R1~~ ✅ **CLOSED, wave 24** — `apps/mcp/src/entitlements.ts`, mounted at
   `MCP-P15` and mutation-proven (§0.5.3).
6. **Add the §3.3 column property** to `fleet-control-matrix.test.ts` — *every
   column of a shared control table that any Worker PARSES must have at least one
   Worker that CONSUMES it in a decision* — or the next wave re-derives R1 and R2
   instead of reading them.
7. **Close A5/L1** — three edits, the third being the one that matters: assert the
   PREPARED ENDPOINT is the AI Gateway host.
8. **Carry §5's four-item silent list into the live run** as the thing
   verification is FOR. Add the three missing `V-` steps (§8).
9. The 19 tail items (§2.2), the 55 control-plane write halves (A6), R5, R4, CORS.

---

## 8. Scope statement

Run in `/home/dev/ferrogate-ts` on `main-ts`. **No `cargo`, no Rust compiled,
imported or executed** — `crates/**` was read only, for comparison. **No
`wrangler deploy`, no live Cloudflare resource, no real upstream LLM call.** No
`crates/` or `workers/` file was modified or deleted. **No merge to `main`.**

No test was weakened, skipped or deleted; every seam mutation was reverted and
verified byte-identical by sha256, and `grep -rn MUTW23 apps packages` returns
nothing. Two files were deleted: the stray control-character-named duplicates in
§4.1, after the gate that forbids them was proven RED with them present.

`CLOUD-VERIFICATION.md` was updated this wave with the three verification steps
the new findings require (R1's entitlement gate, R2's token-budget kill switch,
and B10's shared RPM window) — all three recorded as **currently expected to
FAIL**, because a verification plan that omits a known-failing check is worse
than one that admits it.

### 8.1 Wave-24 scope statement

Run in `/home/dev/ferrogate-ts` on `main-ts`. **No `cargo`, no Rust compiled,
imported or executed** — `crates/**` was READ ONLY, for provenance checking and
comparison, which is what §0.3's transcription option requires. **No
`wrangler deploy`, no live Cloudflare resource, no real upstream LLM call.** No
`crates/` or `workers/` file was created, modified or deleted. **No merge to
`main`.**

No test was weakened, skipped or deleted. Every mutation in §0.5 was read back
OFF DISK with the ORIGINAL TEXT required ABSENT, then reverted and verified
byte-identical by `sha256`; `grep -rn 'MUT-[A-M]' apps packages` returns nothing.
The pre-L11 gate reconstructed from `HEAD` for the §0.5.1 comparison was written
to `packages/providers/test/zz-pre-l11.test.ts`, used, and removed — it is not in
the commit.

The independent re-derivations of both insurance artefacts were done in Python
(`hashlib`/`hmac` and a from-scratch FNV-1a-64), driven from AWS's published
algorithm text and from `rollout.rs`'s constants respectively, never from the TS
under test. `CLOUD-VERIFICATION.md` §7's **V-R1** was flipped from
expected-FAIL to expected-PASS, with the tenant-registration and role
preconditions written into the row.

---

---

# APPENDIX G — the wave-19 → wave-22 document, preserved verbatim

Kept for the audit trail. **Superseded by §0 above.** Its verdict was a
conditional GO with a HOLD subset; wave 23 re-derived the decision from
scratch and reaches a different shape (GO on the merge, NO-GO on the delete
against a five-cluster spec-bound subset). Read §0 first; this is history.

## (archived) CUTOVER READINESS — waves 19-22

**Date:** 2026-08-01 · **Wave 19 decision, amended by wave 20 (§0.3), wave 21 (§0.4) and wave 22 (§0.5)** · **Branch:** `main-ts`
**Question:** may we delete `crates/**`, `workers/**` and `Cargo.*`, and merge
`main-ts` → `main`?

**This is a FRESH decision, not an amendment.** Waves 15–18 appended
amendments to a wave-15 verdict without re-litigating it, four times, each
time saying "only a fresh certification can move this". Wave 19 ran that
certification: a triage of the 37 `MISSING` modules under the owner's revised
rule, and three independent parity re-certifications (data plane, control
plane, libraries), plus this integration step's own full seam pass, boot proof
and E2E. The wave-15→18 document is preserved verbatim in **Appendix H** and
nothing below inherits from it.

**The rule this document is decided under is the owner's, not the old one.**
The Rust tree is *not* the specification. The owner has stated that the Rust
system is itself a half-finished product and that TypeScript is the forward
platform. So "the Rust had it and we don't" is not, by itself, a blocker.
Only **CLASS A** is:

| Class | Meaning | Blocks cutover |
|---|---|---|
| **A — REGRESSION** | the behaviour was COMPLETE, WIRED and REACHABLE in Rust, and the TypeScript port dropped or broke it | **YES** |
| **B — RUST UNFINISHED** | built but never wired: no production caller, no producer, no persistence. Copying it would port a design, not a behaviour | no — **product backlog on TS** |
| **C — DELIBERATE / OBSOLETE / PLATFORM** | its purpose evaporates on workerd, it is `#[cfg(test)]`-only, or it is a standing product decision | no |

---

## 0. THE VERDICT

> ### On merging `main-ts` → `main`: **GO.**
> ### On deleting `crates/**`, `workers/**` and `Cargo.*`: **NO-GO.**

These are two different acts and wave 19 is the first pass to separate them.
Bundling them is what has made this decision look binary for five waves.

**Merging costs nothing and destroys nothing.** `main-ts` is strictly further
along than `main` for the Cloudflare target, it is green on every gate this
wave ran, and making it the mainline unblocks every subsequent slice. There is
no evidence-based argument against it and this document does not make one.

**Deleting the Rust destroys the specification for work that is known,
catalogued, and not yet done.** That is the whole of the NO-GO, and it rests on
two facts, neither of which is a matter of taste:

1. **The CLASS A list is not empty.** Under the owner's own revised rule —
   after 27,644 lines of Rust were triaged *away* as B or C — what survives is
   **~90 operations in 12 capability clusters** (§2). Several are money-shaped
   or security-shaped, and every one of them has its specification in
   `crates/**`. The remediation instructions the certifications wrote are
   literally Rust line numbers: `budget_alerts.rs:24-38` for the HMAC scheme,
   `function_egress.rs:96-98` for the env var names, `state.rs:1334` for the
   persist→validate→hot-reload→rollback ladder, `state_tools.rs:28` for the
   tenant-ref derivation.
2. **The inventory is still converging.** *This wave alone*: 9 of the 37
   `MISSING` rows turned out to be **stale** (already ported); wave 15's `L`
   severity rating on four control-plane groups was **overturned upward**;
   wave 17's claim that `admin_agent_upstream` was CLOSED is **false**
   (`grep -n "CONTROL_DB" apps/gateway/src/routes/agent-discovery.ts` → 0);
   and wave 18's mechanical re-derivation found **eight mount lines that had
   been in no wave's table at all**. An inventory that corrects itself by ~25%
   per wave, in *both* directions, is not a finished inventory.

Deleting the reference implementation at the exact moment you have finally
produced an accurate — but still moving — catalogue of what you still owe it is
the wrong sequencing. You delete a reference when you no longer need it, not
when you have just finished writing down why you do.

### 0.1 What this verdict is NOT

Stated explicitly, because the failure mode in the other direction is real and
this wave was warned about it: **a verdict that manufactures blockers out of
CLASS B is as much a failure as a premature GO.**

- This is **not** a parity hold. 27,644 lines of Rust were examined and
  **17,357 of them (63%) were classified B or C and dismissed**: the
  10,820-line external-action broker (AF_UNIX + `SO_PEERCRED`, gating a
  process-spawning executor that cannot exist on workerd), the 5,098-line
  coding-agent contract (its adapter is constructed only by its own tests, and
  no non-test Rust writes the artifact it projects — a Rust deployment returns
  the same empty array TS does), the auth-service's `/v1/rbac/*` (a YAML-loaded
  RBAC model with **no writer back to disk** — a role created through it is
  lost on restart), `recorded_evidence.rs` (all seven callers inside the worker
  executor), and the CLI reference generator (`#[cfg(test)]`).
- This is **not** a demand that TS match an unfinished system. Every CLASS A
  item was qualified by reading the Rust **handler, its `state.*` method, and
  its repository call** and confirming there is no `todo!()`, no orphan, no
  dead code. Items that failed that test were moved to B, not kept.
- **Enterprise identity does not block.** It was the loudest finding in
  `MODULE-OWNERSHIP.md` — "enterprise tenants cannot log in at all" — and wave
  18 closed it: 8,448 lines of TS against 5,896 of Rust, path-for-path on all
  17 non-health routes, with real `crypto.subtle.verify` signature checking,
  the storage half, and four adversarial mutation proofs (§3.4).
- **The owner can shrink this list by decision, not only by work.** Any CLASS A
  item the owner explicitly accepts becomes CLASS C and stops blocking. That is
  a legitimate and fast path, and §2.3 marks which items are the realistic
  candidates. What the owner should not do is delete the reference *before*
  making those calls, because after deletion the calls get made without the
  evidence.

### 0.2 The exit criterion — what converts this to a full GO

Not "finish everything". Specifically:

1. Close or explicitly accept the **HOLD subset** in §2.2 (4 clusters).
   **— DONE by wave 20; see §0.3 for the mutation table and the two residues.**
2. Take one more certification pass and have it find **no new CLASS A cluster**.
   The curve flattening is the signal; this wave's did not. **— STILL OPEN.
   Wave 20 was a FIX wave and is weak evidence here by construction: it looked
   where a problem was already known to be. §0.3.4 lists what wave 21 must
   re-check.**
3. Run the single authorised live deploy (`CLOUD-VERIFICATION.md`), which is the
   only way to settle §4. **— STILL OPEN.**

Then delete the Rust. `legacy-rs` remains the byte-level fallback either way.

---

## 0.3 WAVE 20 — the HOLD subset is CLOSED. The verdict is NOT changed.

**Wave 20 was a FIX wave, not a certification.** It closed the four §2.2 HOLD
clusters and the `/healthz` `version` drift. It did **not** re-run the parity
certifications, and §0.2's exit criterion has two conditions, not one:

> 1. Close or explicitly accept the **HOLD subset** — **done, below.**
> 2. Take one more certification pass and have it find **no new CLASS A
>    cluster** — **NOT done. A fix wave is weak evidence about this, and is in
>    fact the WORST kind of evidence for it:** the wave looked exactly where it
>    already knew there was a problem. Every wave since 15 has found new CLASS A
>    clusters while closing the old ones, and three of the four closed here were
>    themselves found by a certification, not by a fix wave.
> 3. Run the single authorised live deploy — **NOT done** (§4 stands unchanged).

**So the verdict above is UNCHANGED and deliberately left as written:**
merging `main-ts` → `main` is still GO, deleting `crates/**` is still NO-GO.
This wave earned condition 1 and nothing else. The integrate step does not get
to promote its own work.

### 0.3.1 What wave 20 CLOSED, with the RED-before/GREEN-after observed HERE

Every row was verified by this integration step, not read from a deliverable:
the fix was neutralised, the marker was **grepped on disk** to confirm the edit
landed, the named test was required to go RED, the file was restored and
verified byte-identical by sha256, and the test was required to go GREEN again.

| HOLD item | Neutralisation | RED under mutation | GREEN restored |
|---|---|---|---|
| **A1** budget alerts (**MONEY**) | delete `await this.#budgetAlerts(...)` from `MeteringUsageSink.#accumulate` | **8 failed / 4 passed (12)** | 12/12 |
| **A3** upstream withdrawal (**SECURITY**) | revert `agentDiscoveryHandler` to the var-only registry | **12 failed / 2 passed (14)** | 14/14 |
| **A4** billing replay (**MONEY**) | make the no-document path 404 instead of reaching `replayOutboxReportRow` | **11 failed / 11 passed (22)** | 22/22 |
| **A2** tool-side workflow gate | bypass `admitWorkflowStep` on the create path | **22 failed / 3 passed (25)** | 25/25 |
| **A2** `createAgentRun` contract | drop `turns_executed` / `output` from the synchronous response | **1 failed / 16 passed (17)** | 17/17 |
| `/healthz` `version` — control-plane | drop `version` from `healthReport()` | **3 failed / 3 passed (6)** | 6/6 |
| `/healthz` `version` — mcp | same | **2 failed / 6 passed (8)** | 8/8 |
| `/healthz` `version` — telemetry | same | **3 failed / 28 passed (31)** | 31/31 |

### 0.3.2 The two MONEY claims, asserted as EFFECTS rather than as calls

A dispatcher that is *called* is not a webhook that is *delivered once*. Both
money items were re-read at the assertion level, not the test-name level:

- **A1.** `test/metering/budget-alerts.test.ts` drives a real settlement through
  the sink and asserts `webhook.calls.length === 1`, the payload's **exact key
  order** (the HMAC is over those bytes), and
  `x-ferrogate-signature === HMAC-SHA256(secret, "<ts>.<body>")` recomputed in
  the test. A **second** settlement past the same threshold leaves
  `webhook.calls.length === 1` and exactly one `budget_alert_notifications` row
  keyed `tenant:tenant_a:<period>:80`. A row pre-claimed by another isolate
  yields **zero** webhooks. So: **one signed webhook on the crossing, none on
  the re-crossing.**
- **A4.** `test/billing-replay.test.ts` seeds a REAL dead letter (an outbox
  **row** with **no** document — the shape production actually produces),
  asserts the sweeper's own `BILLING_OUTBOX_LIST_DUE_SQL` selects nothing
  before and exactly `["rep_real"]` after, and counts the ledger:
  `ledgerRowCount === 1` and `billingEventRowCount === 1`. A second replay is
  `409 dead_letter_not_replayable` and the counts do not move. So: **one ledger
  row on the replay, zero on the already-settled one.**

### 0.3.3 The SECURITY claim, and the HALF OF IT THAT IS NOT CLOSED

`test/routes/agent-upstream-withdrawal.test.ts` asserts the real before/after:
the compromised endpoint IS published to the operator and to a tenant caller,
`DELETE` answers 200, and on the **very next request** it is gone while every
other upstream is untouched; an unknown id is 404 and removes nothing; and
tenant A's `DELETE` of tenant B's upstream is **404 with B's upstream still
served to B**, after which B can still withdraw its own.

**But the withdrawal covers the gateway's DISCOVERY surface only.** A
mechanical re-derivation of every reader of the upstream table
(`grep -rn 'AGENT_UPSTREAMS|agentUpstream' apps/*/src`) shows the gateway's only
consumer is `/.well-known/agent.json`, while **`apps/agent-runtime` resolves its
A2A dispatch catalog from its own deploy-time `AGENT_UPSTREAMS` var** through
`inMemoryAgentUpstreamPort` (`src/ports.ts:1146`) — a different Worker, a
different var, and **no durable leg**. An operator who configured the same
upstream in both places will find `DELETE` withdraws it from discovery and
**not** from A2A dispatch. That is a narrower defect than the one A3 named
(discovery was the reachability path Rust's `delete_agent_upstream` governed),
but it is the same shape, it is security-adjacent, and it is stated here rather
than left for a later wave to "discover".

### 0.3.4 What the WAVE-21 CERTIFICATION MUST RE-CHECK

Named specifically, because "re-certify everything" is how a checklist becomes
decoration:

1. **The A3 residue in §0.3.3.** Does `apps/agent-runtime`'s A2A dispatch
   catalog need the same `CONTROL_DB` leg the gateway now has? Decide it as
   CLASS A or CLASS C explicitly; do not let it stay unclassified.
2. **A2 is closed in SHAPE and in ENFORCEMENT, not in EXECUTION.**
   `POST /v1/agent-runs` now runs the full validation ladder, answers `id`,
   `turns_executed`, `output`, `tool_results`, `max_turns`, `timeout_millis`,
   and enforces the tool-side graph gate — but it still **dispatches** the run
   rather than looping turns inside the request, and `src/runs/lifecycle.ts`
   documents why (Rust's synchronous arm is either `ManagedWorker`, which
   answers "not implemented yet", or `External`, which spawns a child process
   workerd cannot). Wave 21 must decide whether "answers the contract's fields
   with `turns_executed: 0` and settles asynchronously" is CLASS A or CLASS C.
   **It is not the same claim as "A2 closed".**
3. **`CP-C13b`** (new row in `MOUNT-SEAMS.md`): `/version`'s route registration
   is gated, its DOCUMENT is not — `api: 0` leaves 687/687 green.
4. **`AR-P1` / `AR-P2` are ESC rows and the inventory does not say so.** Both
   durable agent-runtime ports are GREEN under the app's default project (433/433)
   and only RED under the chained `test/durable/harness/` config (45 of 55).
   `MOUNT-SEAMS.md` marks neither as **ESC**; a reader would conclude the
   default suite holds them.
5. **The five `[vars]`-table and commented-stanza rows** (`GW-T16/17/18`,
   `AR-T11`) are NOT-MUTABLE by category, not merely ungated. Wave 21 should
   either give them a proof channel or reclassify them out of the seam table.
6. **The budget-alert webhook has never left the isolate.** Every A1 assertion
   is against an intercepted `fetch`. The live run must confirm one real signed
   POST reaches a real receiver, and that `BILLING_ALERTS_WEBHOOK_SIGNING_SECRET`
   resolves from `wrangler secret put` (§2(c)).
7. **A4's re-emission is still not this Worker's.** `replay` re-arms the row and
   answers `emitted: false`; the gateway's Cron sweeper emits. Nothing local
   proves the hand-off across two Workers and a Queue producer.
8. **`A5`–`A12` were never worked** and remain exactly as §2.1 states. If the
   owner is still minded to accept them (§2.2), that acceptance should be
   recorded in wave 21 as an explicit decision, because deleting the reference
   makes it unappealable.

### 0.3.5 Wave-20 gate results, first-hand

| Gate | Result |
|---|---|
| `bun install` | clean, no changes |
| `bun run typecheck` | **exit 0**, 21 projects + `e2e`, zero diagnostics |
| `bun run test`, every `packages/*` and `apps/*` | **6,758 passed · 0 failed · 9 todo** (baseline 6,624; +134) |
| Seam pass — every **T1** row plus every row whose file this wave touched | **145 rows · 140 RED · 0 GREEN-unproven · 5 NOT-MUTABLE-by-category · 1 stale row corrected** |
| Restore verification (sha256 after every mutation) | **byte-identical, every row**; `grep -rl MUTW20` over `apps/` + `packages/` → nothing |
| Own fix verification (§0.3.1) | **8 / 8 PROVEN**, none RED-by-parse-error |
| Real boot: `bunx wrangler dev --local` × 5, distinct ports | **5 / 5 "Ready on" + 5 / 5 `/healthz` 200** |
| Fleet health-document shape | **1 distinct shape across all five**, `{status, service, version, runtime}`, every one carrying `version` — the wave-19 3-of-5 drift is gone |
| `bunx playwright test` | **22 / 22 passed** (6.8 s; 21 before — `e2e/tests/mcp.spec.ts` gained one) |

**Two honesty notes.** (1) The first seam-pass driver ran `bun run test -- <filter>`;
several apps chain suites with `&&`, so the filter landed on the LAST chained
config and two rows looked GREEN under a landed mutation for a purely mechanical
reason. Fixed to `bunx vitest run <filter>` and re-run. (2) Three residue rows
first went RED because commenting a line inside an object literal made the module
unparseable — a **RED-by-parse-error is not a proof**, and `MOUNT-SEAMS.md` §5
already records this exact mistake twice. All three were redone as value
substitutions that still compile, and the driver now flags the condition.

---

## 0.4 WAVE 21 — the A3 residue is CLOSED; the fleet audit OPENED three blockers. The verdict is NOT changed.

**This section does not move the verdict.** It records what wave 21 closed,
what it opened, and what a later wave must decide. The verdict in §0 (GO on
merging `main-ts` → `main`, NO-GO on deleting `crates/**`) stands as written;
everything below makes the NO-GO half *more* firmly evidenced, not less.

### 0.4.1 CLOSED — the A3 residue named in §0.3.3 and §0.3.4 item 1

§0.3.4 demanded this be classified explicitly rather than left to drift. It is
**CLASS A**, and it is now **closed**:

- `apps/agent-runtime/src/agents/registry.ts` resolves the A2A dispatch reach
  set from the durable `control_plane_resources` documents of kind
  `agent-upstreams` — the SAME rows the gateway's discovery surface reads and
  the SAME rows `DELETE /admin/v1/agent-upstreams/{id}` removes — read **once
  per dispatch with no cache**, tenant-fenced by the control plane's own
  predicate, and **fail-closed** (`503 agent_upstream_unavailable`, never a
  fall back to the var and never a `404` that would make an outage
  indistinguishable from a withdrawal);
- the durable table **replaces** the deploy-time `AGENT_UPSTREAMS` var rather
  than merging with it, because a union would keep dispatching to any id an
  operator configured in both places after the document was deleted — the same
  defect, one misconfiguration away;
- `resolveDeps` MOUNTS it (`MOUNT-SEAMS.md` row **AR-P9**, new this wave).

**Verified by this integration step, not accepted from the delivering agent.**
Removing the mount and keeping only the var — the pre-wave-21 posture, i.e. the
fix deleted — takes `test/durable/agent-upstream-withdrawal.spec.ts` to **10 RED
of 13**, including a `422` that names the withdrawn upstream's host on the
request AFTER the delete. **The app's own default project stayed 434/434
GREEN**, which is why the seam is `ESC` and why "agent-runtime is green" was
never evidence about this.

The FLEET EFFECT — the property neither per-Worker suite can fail for — is now
gated in ONE assertion path by
`apps/gateway/test/routes/agent-upstream-fleet-withdrawal.test.ts`: one row, both
doors observed holding it, ONE `DELETE`, both doors observed having lost it.
Giving the durable lookup a process-lifetime memo leaves the gateway's own
withdrawal suite at **14/14 GREEN** and takes that file to **2 RED** on *still
DISPATCHABLE after withdrawal*. **`CONTROL_DB` on agent-runtime remains a
deploy-time PLACEHOLDER (blocker B4)** — the fix is inert until that binding
exists, which `CLOUD-VERIFICATION.md` now states in the `AGENT_UPSTREAMS` row,
in B4 itself, and as verification step **V-A3**.

### 0.4.2 OPENED — the fleet-consistency audit, and it is the largest finding since MODULE-OWNERSHIP

> **ALL THREE OF FC-1, FC-2 AND FC-3 WERE CLOSED IN WAVE 22 — see §0.5.** The
> table below is the wave-21 measurement and is kept verbatim as the record of
> what was open, not as a live list.

`docs/rewrite/FLEET-CONSISTENCY.md` is the first enumeration this project has
ever had of **which capabilities exist in more than one Worker**. The defect
class it names has now shipped **twice** (wave 16's admission bypass, wave 20's
half-withdrawal), and both times every per-Worker suite was green because every
Worker was individually correct.

Of 23 capabilities, **18 exist on more than one Worker**. **5 cells diverge.
4 of those are CONTROLS an operator applies. 3 of the 4 are live money or
security.** The search key that found them is worth quoting, because it will
find the next one too:

> A control that is DURABLE on one Worker and VAR-ONLY on another is the exact
> shape of both shipped defects.

**Three new CLASS A candidates**, stated as such and NOT self-approved:

| # | Finding | Why CLASS A | Blast radius |
|---|---|---|---|
| **FC-1** | The operator drain is WRITTEN by the control plane (`runtime-state/drain`) and ENFORCED by the gateway off a different source (the `GATEWAY_DRAIN` var). Nothing reads the document. `apps/mcp` and `apps/agent-runtime` have no drain gate at all | Rust drained one process; the API existed and worked. Here `POST /admin/v1/drain` answers `200` and is a **complete no-op** | Money + availability, whole fleet. The operator believes the deployment is quiescing while it spends |
| **FC-2** | Tenant suspension reaches the gateway and the control plane and **neither** `apps/mcp` nor the durable path of `apps/agent-runtime`. That Worker can RENDER `tenancy_suspended` and its deployed `d1ApiKeyPort` can never PRODUCE it | Rust's `finalize_auth` ran the lifecycle gate ahead of quota/wallet in one process | Security + money. Wave 16's bypass in a second control: suspend a compromised tenant, it is 403 on `/v1/chat/completions` and ADMITTED on MCP `tools/call` and `POST /v1/agent-jobs`, spending against quota that was never zeroed |
| **FC-3** | An activated guardrail policy binds `apps/gateway` only. `apps/mcp` screens tool arguments and tool RESULTS from `FG_DEV_MCP_GUARDRAILS` (committed `""` ⇒ matches nothing) and `apps/agent-runtime` screens A2A messages from `FG_DEV_A2A_GUARDRAILS` (not committed at all) | Rust screened from one policy set in one process | Security. Move the payload to a surface the activated revision does not reach |

Two further rows are recorded and are **not** blockers today: **FC-5** (the
shared RPM counter is a deploy-time uncomment in two files — nothing is wrong
today, and the gate exists to stop the "just define a local
`RateLimiterDurableObject`" fix that would hand each Worker its own full quota)
and **FC-7** (`rbac_action` is parsed by four Workers and consulted by two;
harmless only because all 12 rbac-guarded operations are on admin paths those
two do not serve). **FC-6c is a PRODUCT question**, not an engineering task: a
subject-only `[[policies]]` deny reads to an operator as "deny this tenant
everything" and stops nothing outside inference — Rust had the same shape, so
it is parity, and it should be *decided* rather than inherited or silently
"fixed".

### 0.4.3 Does a NEW BLOCKER appear? YES — three, and they do not change the verdict

FC-1, FC-2 and FC-3 are new CLASS A candidates that did not exist on any prior
wave's list, because no prior wave asked the question that finds them. Under
§0's own rule — *the behaviour was COMPLETE, WIRED and REACHABLE in Rust, and
the TypeScript port dropped or broke it* — all three qualify: each was a single
in-process control in Rust and is a partially-applied control here.

They do not move the verdict because the verdict already separates the two acts:

- **merging `main-ts` → `main` stays GO.** Every gate this wave ran is green
  (§0.4.4), and none of these three is a regression *against `main`* — `main`
  is the Rust tree and is not the deployment target. Withholding the merge does
  not fix them and blocks everything that would;
- **deleting `crates/**` stays NO-GO, and is now better evidenced than it was.**
  Each of the three fixes is specified by Rust: `finalize_auth`'s ordering for
  FC-2, the drain's single-process semantics for FC-1, the screening policy set
  for FC-3. Deleting the reference before they are ported makes them
  unappealable, which is exactly the argument §0 already makes.

**The exit criterion in §0.2 is unchanged and now has three more rows against
it.** The honest reading of wave 21 is that the curve has still not flattened:
this wave closed one CLASS A item and opened three, and the three were found by
asking a question nobody had asked before rather than by finishing a known list.

### 0.4.4 Wave-21 gate results, first-hand

| Gate | Result |
|---|---|
| `bun install` | clean, no changes |
| `bun run typecheck` | **exit 0**, all projects, zero diagnostics |
| `bun run test`, every `packages/*` and `apps/*` | **6,810 passed · 0 failed · 12 todo** (baseline 6,758; +52) |
| Seam pass — every **T1** row plus every row in every app this wave touched | **125 T1 rows: 124 GREEN, 0 RED, 1 `NO-GATE` by design**; full `agent-runtime` (34), `telemetry` (17) and `gateway` (61) passes all GREEN — **163 distinct rows of 190** |
| Seam inventory reconciliation (`--list`) | **CLAIMED 190 · PARSED 190 · GATED 188 + 2 `NONE` by design · 0 ungated**, exit 0 |
| Own verification of the SECURITY fix | **PROVEN by mutation** (§0.4.1): 10/13 RED with the fix removed, restored GREEN 13/13, `grep` confirmed both edits landed and both restores are clean |
| Fleet-effect assertion | **PROVEN by mutation**: 2 RED on a memoised lookup while the gateway's own suite stayed 14/14 GREEN |
| Real boot: `bunx wrangler dev --local` × 5, distinct ports | **5 / 5 "Ready on" + 5 / 5 `/healthz` 200** |
| Fleet health-document shape | **1 distinct shape across all five**, `{status, service, version, runtime}` |
| `bunx playwright test` | **22 / 22 passed** (5.2 s; 22 before) |

**Two runner defects found by RUNNING the seam pass rather than listing it**, both
producing **FALSE RED on correct code** (`MOUNT-SEAMS.md` §13.4): `.test.ts`
files inside a chained directory were routed to a `*.spec.ts`-only config
(GW-E3, GW-C6, GW-W2 — 0 tests collected, non-zero exit), and a cross-app FLEET
citation was executed from the citing app's directory (AR-P9). Both are fixed in
`scripts/seam-proof.mjs`. This is worth more than the three rows it recovered:
the wave-20 inventory repair reconciled `--list` and never ran `--run`, and a
runner that cries wolf is how the next real RED gets waved through.

---

## 0.5 WAVE 22 — the three fleet divergences are CLOSED and the class is GATED. The verdict is NOT changed.

**Wave 21 opened FC-1, FC-2 and FC-3 as new CLASS A candidates (§0.4.3). All
three are closed. The verdict is unchanged, deliberately: a fix wave does not
move a verdict — only a fresh certification does, which is what §0 says and what
five waves of amendment-creep already cost this document once.**

### 0.5.1 CLOSED — all three, with the fleet effect proven by the integrate step itself

| # | What was open | What closed it | The FLEET effect, proven here by mutation |
|---|---|---|---|
| **FC-1** | `POST /admin/v1/drain` wrote a durable document **nothing read**. The gateway refused off an unrelated deploy-time var; mcp and agent-runtime had no drain gate at all | Wave 22's delivering slice joined `apps/mcp` + `apps/agent-runtime`; **this integrate step wrote the gateway's third and last leg** (`routes/readiness.ts::resolveDrainState` — durable document OR var, fail-closed, per request) | ONE `POST /admin/v1/drain` → **all three spend Workers refuse `503 node_draining`, same status, same code, same message.** Neutralising the gateway's decision: **2 RED** in `fleet-control-matrix.test.ts` §5 (`{400,invalid_request}` vs `{503,node_draining}`); neutralising its AUTHORITY: **13 RED** + 1 RED in the mcp fleet gate; neutralising mcp's mount: **3 RED**; agent-runtime's: **5 RED**. All restored GREEN |
| **FC-2** | A suspended tenant kept a valid credential and spent through MCP `tools/call` and `POST /v1/agent-jobs` — wave 16's admission bypass in a second control. `apps/agent-runtime` could NAME `tenancy_suspended` and only its dev table could produce it | Both Workers now read the `status` COLUMN of `tenants` on the control database, ancestors included, BEFORE the admission ladder | ONE suspension → **all three refuse `403 tenancy_suspended`**, and a suspended KEY still answers `401 invalid_api_key` on all three (the taxonomy survived the new gate). Unmounting mcp's gate: **8 RED of 12** in the fleet gate. Unmounting agent-runtime's: **6 RED** in its own spec AND **7 RED in the mcp fleet gate** — a regression on one Worker failing the file that names the fleet, which is the property no per-Worker suite has |
| **FC-3** | An activated guardrail revision bound `apps/gateway` only; mcp screened from `FG_DEV_MCP_GUARDRAILS` (committed `""` ⇒ matches nothing) and agent-runtime from `FG_DEV_A2A_GUARDRAILS` (not committed at all) | Both resolve from the same `guardrail_policy_revisions` + `guardrail_policy_bindings` rows through `packages/guardrails/src/binding.ts`, revalidated per request rather than memoised | ONE activation → the payload the gateway blocks is **also blocked on MCP `tools/call` and on the A2A path, with the OPERATOR's own code**. Unmounting mcp: **2 RED**; unmounting agent-runtime: **3 RED** in the A2A spec + **1 RED** in the ledger's mount assertion |

**One honest gap inside FC-3, found by mutation and not smoothed over.**
`apps/mcp/test/fleet-guardrail-activation.test.ts` reaches agent-runtime by
importing its screening FUNCTION as a leaf rather than by driving `resolveDeps`,
so removing agent-runtime's mount leaves that file **15/15 GREEN**. The
regression is still gated — twice — but the file whose name says "fleet" is not
the file that catches it. FC-1's and FC-2's fleet gates do not have this shape.
Recorded in `FLEET-CONSISTENCY.md` §7.5; it is a gate-quality item, not a live
divergence.

### 0.5.2 The class is now GATED, not just the three instances

`apps/gateway/test/fleet-control-matrix.test.ts` (66 assertions) **names no
Worker anywhere**: the fleet, the role sets, every control's source-of-truth
class and the whole refusal table are COMPUTED from `apps/{*}/wrangler.toml` and
from the SQL and vars each Worker issues. A sixth Worker that ports the
admission ladder joins `SPEND` automatically and is immediately required to
honour the drain, the suspension and the quota. **Would it catch a NEW
divergence introduced tomorrow? For 13 of the 23 capabilities, yes,
mechanically. For the other 10, no** — `FLEET-CONSISTENCY.md` §9.4 names them
one by one, and row 10 (tenant fencing, a SQL predicate rather than an
authority) is the most valuable conversion left.

### 0.5.3 A defect the BOOT PROOF found that no suite could

`apps/mcp` and `apps/agent-runtime` collapsed *"the drain document could not be
READ"* onto `readiness_reason: "operator_drain"`, so a fresh
`wrangler dev --local` answered `503 not_ready`, `draining: true`, on a
deployment **nobody had drained** — and mcp additionally answered
`accepting_new_requests: true` in the same `not_ready` document. Every vitest
harness migrates its database, so the arm was unreachable from any suite. Both
now answer `drain_state_unavailable` with `draining: false` and
`accepting_new_requests: false`, matching the split `drainRefusal` already made
on the data plane and the gateway's own `clusterStatus`. Three new gates, one
per Worker, each mutation-proven RED. Two adjacent composition-root holes closed
with it: `apps/mcp/wrangler.toml`'s `[[d1_databases]] DB` declared **no
`migrations_dir`**, so `wrangler d1 migrations apply DB` had nowhere to read the
control schema from and `CLOUD-VERIFICATION.md` §3 could not have had an mcp
entry.

### 0.5.4 Does a NEW BLOCKER appear? NO

This wave opened nothing. It closed the three CLASS A candidates wave 21 opened,
gated the class they belong to, and closed one probe-honesty defect found by the
boot proof. **§0.2's exit criterion is unchanged**, and the CLASS A list in §2 is
three rows shorter — but the criterion is a *fresh certification*, not a count,
and this wave did not run one. The reading a future certification should carry
forward: wave 21 closed one CLASS A item and opened three; wave 22 closed three
and opened none. That is the first wave in six where the curve moved the right
way, and one data point is not a trend.

### 0.5.5 Wave-22 gate results, first-hand

| Gate | Result |
|---|---|
| `bun install` | clean, no changes |
| `bun run typecheck` | **exit 0**, all projects, zero diagnostics |
| `bun run test`, every `packages/*` and `apps/*` (chained harnesses included) | **6,986 passed · 0 failed · 9 todo** (baseline 6,810; +176) |
| Seam pass — every T1 row plus every row whose file this wave touched (run as ALL 200) | **200 rows run: 198 GREEN, 0 RED, 2 `NO-GATE` by design** (`AR-T11`, `CP-C13b`) |
| Seam inventory reconciliation (`--list`) | **CLAIMED 200 · PARSED 200 · GATED 198 + 2 `NONE` by design · 0 ungated**, exit 0. Ten rows added this wave, three of them by this integrate step |
| Own verification of FC-1 | **PROVEN by mutation**, 4 mutations across 3 Workers (§0.5.1); all restored, `grep -rn "MUT-W22" apps/ packages/` clean |
| Own verification of FC-2 | **PROVEN by mutation**, 2 mutations at the MOUNT rather than the module |
| Own verification of FC-3 | **PROVEN by mutation**, 2 mutations at the MOUNT — and the one gap it exposed is recorded in §0.5.1 |
| Real boot: `bunx wrangler dev --local` × 5, distinct ports | **5 / 5 "Ready on" + 5 / 5 `/healthz` 200 + 5 / 5 `/readyz` 200** |
| Fleet health-document shape | **1 distinct shape across all five**, `{status, service, version, runtime}` |
| `bunx playwright test` | **22 / 22 passed** (5.1 s; 22 before) |

**The most valuable single result is not in the table.** Neutralising the
gateway's drain DECISION while leaving its source text intact turned **2**
behavioural assertions red and left **every source-text gate GREEN** — the
ledger, the matrix's §3 classifier and the mcp fleet gate all passed a Worker
that reads the operator's document and throws the answer away. That is the
sharpest argument in this repository for never gating a control on source text
alone, and it is written up in `FLEET-CONSISTENCY.md` §7.4 (M22).

---

## 1. Evidence this wave produced, first-hand

Everything in this section was run by this integration step on the current
tree, not read from a deliverable.

| Gate | Result |
|---|---|
| `bun install` | clean, no changes |
| `bun run typecheck` | **exit 0**, 21 projects + `e2e`, zero diagnostics |
| `bun run test` in every `packages/*` and `apps/*` (21 workspaces, run serially) | **6,624 passed · 361 files · 0 failed · 0 skipped** |
| **Full mount-seam pass — every row, not incremental** | **194 rows · 193 RED · 1 GREEN** (§3.1) |
| Restore verification (`sha256sum -c` after every mutation) | **194 / 194 byte-identical** |
| Mutations that failed to land or were semantic no-ops | **0** (§3.2) |
| REDs caused by a parse error rather than an assertion | **0** |
| Real boot: `bunx wrangler dev --local` × 5 Workers | **5 / 5 "Ready on" + `/healthz` 200** (§3.3) |
| `bunx playwright test --config e2e/playwright.config.ts` | **21 / 21 passed** (7.7 s) |
| Working tree after the pass | identical to before; **no mutation leaked** |

The 6,624 figure reconciles with `cert2-libraries.md`'s 6,633 exactly: 6,624
passing + 9 `todo`.

**Baseline honesty note.** The seam pass was interrupted once, at row `GW-C3`,
after `GW-C2` took 43 minutes (removing `inferenceRouteModule` makes the
workerd pool fail to start and vitest retries per test file). The kill left one
mutation on disk in `apps/gateway/src/index.ts`; it was detected by
`git status`, restored from the row's backup, and the file verified identical
to `HEAD` before the pass resumed. The remaining rows ran under a 300 s per-row
timeout. This is recorded because an undetected leaked mutation is exactly the
kind of thing that turns a later wave's honest measurement into a false finding.

---

## 2. (b) THE CLASS A LIST — the only cutover blockers

Consolidated and de-duplicated across all four wave-19 deliverables.
`executeFunction` and the `/v1/tools` pair each appear in two of them and are
counted once.

### 2.1 The full list — 12 clusters, ~90 operations

| # | Cluster | Ops | Severity | The Rust that makes it a regression | Source |
|---|---|---:|---|---|---|
| **A1** | **Budget-threshold alert delivery is silently dead.** Config validates the `webhook_url`, the once-per-period D1 arbiter exists, thresholds are parsed into `EffectiveQuota.alertThresholdPcts` — and **nothing ever compares spend to them and nothing ever POSTs**. `webhookUrl` has zero implementation hits | 1 | **HIGH — money, silent** | `budget_alerts.rs` (264 lines) called from the metering-record path at `state_billing_metering.rs:231`; HMAC-SHA256 over `"<ts>.<body>"`, `X-FerroGate-Signature` | MISSING-TRIAGE §A1 |
| **A2** | **`POST /v1/agent-runs` is not the operation the contract names.** Rust runs a synchronous turn loop and answers `200 {turns_executed, output, tool_results}`; TS answers `202` and never executes a turn. `max_turns`, `timeout_millis`, `tool_calls` have **no reader**. The tool-side workflow graph gate is absent entirely (`grep -rn workflow apps/agent-runtime/src` → nothing), so node-kind, tool-pinning, edge-transition and parallelism are unenforced on the Worker that owns the operation | 1 | **HIGH** | `agent_runs.rs` (1,718 lines) + `agent.rs` (1,085), `grep -c "todo!"` = **0** in both | cert2-dataplane §2.1 |
| **A3** | **The five config-backed control-plane groups do not take effect.** `skill`, `prompt`, `admin_plugin`, `admin_policy`, `admin_agent_upstream`. Operator gets `200`/`201`; the data plane reads a deploy-time Worker var. **`DELETE /admin/v1/agent-upstreams/{id}` does not withdraw a compromised upstream** | 31 | **HIGH (upstream DELETE) / MEDIUM** | each has a real `state.upsert_*`: persist → rebuild candidate → `validate()` → hot-reload → rollback on failure (`state.rs:1334`, `:674`, `:1223`, `:1404`, `:774`). `skill` even re-reads the committed config and answers `409` if the write did not take | cert2-controlplane §4.1 |
| **A4** | **`billing`'s six read feeds are empty, and `replay` is worse than inert.** `POST /admin/v1/billing-outbox-dead-letters/{id}/replay` requires a *document* before it re-arms, but the sweeper dead-letters the *row* — so **a real dead letter answers 404 and can never be replayed**. The data plane writes `billing_events` / `billing_ledger` / `billing_report_outbox` in the same control DB this Worker already binds | 7 | **HIGH — money** | `local.rs:9317` pages `state.metering_events_page(...)` with the #185 tenant filter | cert2-controlplane §4.8 |
| **A5** | **`executeFunction` is `501`, and the recorded reason is factually false about the Rust.** The marker claims an out-of-process sandbox / Containers prerequisite. `handle_function_execute` sandboxes nothing: it is a **broker** — allowlist-authorize, mint a short-lived scoped token, signed HTTPS POST to an already-deployed Supabase Edge Function or CF Worker. That is `fetch` + WebCrypto HMAC, arguably more natural on Workers than in Pingora | 1 | MEDIUM | `local.rs:3219`; `function_egress.rs` (197 lines), `function_token.rs` (200), `supabase_edge_function.rs` (262), `function_egress_cloudflare.rs` (222) — **0 `todo!()`** across all | MISSING-TRIAGE §A2 / cert2-dataplane §2.2 |
| **A6** | **`GET /v1/tools` + `POST /v1/tools/execute` regress to `501` on the gateway.** With zero plugins configured, Rust still returned the tenant's MCP tool catalogue. The capability **already exists in the TS tree** (`apps/mcp` `tools/list`, `fetch_asset`, `tools/call` through the ported managed-action chokepoint) — what is missing is the projection onto the gateway's REST aliases | 2 | MEDIUM | `state_tools.rs:48-57`, `local.rs:3573` (capability → input guardrail → approval → execute → output guardrail) | MISSING-TRIAGE §A3 |
| **A7** | **Cloudflare AI Gateway routing (#406) is unreachable in production.** The library layer is complete and tested; `apps/gateway/src/inference/adapters.ts` builds its own registry and never goes through `ProviderAdapterRegistry`, so capture/apply is skipped on every request. Worse, `providerRecordSchema` is `.strict()` with no `cloudflare_ai_gateway` key, so **a working Rust operator's config is REJECTED, not ignored** | cross-cutting | MEDIUM | `state.rs:1477`/`:4850`, `registry.rs:45,83,104,125`; config side `types.rs:1413` + `validate.rs:291` | cert2-libraries §L1 |
| **A8** | **`admin_provider` / `admin_model` / the `status` counts are empty on every deployment.** An operator is told the gateway has **0 providers and 0 models**. The control schema already declares `gateway_providers` / `gateway_models` with a real FK — the tables exist, the wire does not | 4+4 | MEDIUM | `local.rs:5019`, `:5062` (live per-provider catalog fetch), `:8227` with the #535 field-level redaction | cert2-controlplane §4.2, §4.6 |
| **A9** | **Signed client action-time tokens are issued by the CLI and ignored by the gateway.** The CLI sends `x-ferrogate-action-id` and reads the returned token; `apps/gateway` never reads either header. `ActionIdentity` is declared in `apps/agent-runtime/src/ports.ts:289` with **zero references anywhere** | cross-cutting | LOW-but-A | `client_action_time.rs` (494 lines), a Pingora `HttpModule` on every request; HMAC-SHA256, 30 s TTL, rotation via trusted-key list | MISSING-TRIAGE §A4 |
| **A10** | **`request_logs`, `agent_run`, `tool-sessions`, `GET /admin/v1/tenants`, `site_domain` read stores nothing writes.** `guardrail_evaluations` does not exist in `sql/d1-ts/` **at all**, so guardrail evidence is in-memory-only fleet-wide. `/metrics`'s one substantive gauge is pinned at 0 and heals with `request_logs` | 15 | MEDIUM | `local.rs:4330`, `:4395`, `:9288`; `sites.rs` (1,226) + `site_domains.rs` (1,370) | cert2-controlplane §4.3–4.9 |
| **A11** | **Data-plane error-vocabulary and shape collapse.** `400 invalid_agent_run_id_header` unenforced on ordinary inference; gateway-config profile resolution **fails open** where Rust refuses four ways; `createImage` capability refusal changed status *and* code (`422` → `400`); 3 asset presign codes collapsed; the 6 self-hosted-worker callbacks fold a per-verb 400/500 vocabulary into 2 generic codes; `renderPromptTemplate` writes no audit trail | ~20 | LOW | per-item Rust cites in the source doc | cert2-dataplane §3 (A3–A10) |
| **A12** | **CORS is absent from the entire data plane**, and the shared probes disagree across Workers. Rust `apply_cors_headers` runs on 9 response sites; `grep -ri "access-control-allow" apps/{gateway,mcp,agent-runtime}/src` returns only comments — so a browser client of `/v1/**` that worked against Rust does not work here. `/readyz` answers **three different documents** for one contract operation; `/metrics` is served by two Workers with two different bodies and nothing says which is canonical | ~4 | LOW | `responses.rs:38`, `server/mod.rs:235` | cert2-dataplane §3 (A12–A14) |

**New this wave, found by this integration step, not by any deliverable:**
`cert2-dataplane` §A11 states that `/healthz` lacks `version` on `apps/mcp`
only. The §3.3 boot proof shows it is missing on **three** Workers — `mcp`,
`control-plane` and `telemetry` — and present on `gateway` and
`agent-runtime`. The finding is correct in kind and understated by 2×. This is
recorded here rather than silently corrected because the pattern (a fix-wave's
summary disagreeing with the code) is the one this project keeps repeating.

### 2.2 The HOLD subset — what I would actually block on

Not all ~90 carry equal weight and it would be dishonest to imply they do.
If the owner closes or accepts **only** these four, the deletion argument
changes materially:

> **STATUS, WAVE 20: all four CLOSED.** Each row's fix was verified by this
> integration step's own mutation table (§0.3.1) rather than accepted from the
> agent that wrote it, and the two money items were asserted as EFFECTS —
> one signed webhook per crossing and none on the re-crossing; one ledger row
> per replay and zero on an already-settled one (§0.3.2). **Two residues are
> carried forward and named in §0.3.3–§0.3.4:** the A3 withdrawal covers the
> gateway's discovery surface but not `apps/agent-runtime`'s A2A dispatch
> catalog, and A2 is closed in SHAPE and ENFORCEMENT but still dispatches
> rather than looping turns in-request. **Closing this subset satisfies exit
> condition 1 of §0.2 and nothing else** — the verdict is unchanged.

| | Why it is in the HOLD subset | Wave-20 status |
|---|---|---|
| **A1** budget alerts | The system **affirms the configuration** and then never notifies. Silent, unbounded, money. This is the exact archetype of the wave-15 admission bypass, and the archetype is why this project runs mutation gates at all | **CLOSED** — 8 RED / 12 GREEN. Effect asserted, not just the call |
| **A3**'s `admin_agent_upstream` `DELETE` | Revoking a compromised upstream through the admin API returns `200` and withdraws nothing. Security-shaped, and one of five identical three-line fixes | **CLOSED for discovery** — 12 RED / 14 GREEN, incl. the cross-tenant refusal. **A2A dispatch residue: §0.3.3** |
| **A4** `billing.replay` | A real dead letter is **unrecoverable**. Money, and the failure is silent until reconciliation | **CLOSED** — 11 RED / 22 GREEN. Ledger counted: 1 then 0 |
| **A2** `createAgentRun` | Not a divergence — a *different operation* under the contract's name, with the tool-side workflow gate absent. A client written to the contract gets neither the fields nor the enforcement | **CLOSED for fields + enforcement** — 22 RED (gate) and 1 RED (contract). **Turn loop still async: §0.3.4 item 2** |

**A5–A12 are, in my judgement, acceptable-by-decision.** They are real
regressions and should be recorded as such, but each is either bounded to
operators who configured an off-by-default feature (A5, A9), degrades a
discovery path while the capability stays reachable elsewhere (A6), or is a
vocabulary/shape/observability loss rather than a behavioural one (A8, A10,
A11, A12). A7 is three enumerated edits. **If the owner signs these off, they
become CLASS C and this document's blocker list is the four rows above.**

### 2.3 Blast radius of getting this wrong

If the Rust is deleted and the HOLD subset is *not* closed: the alert webhook
scheme, the metering-path call site, the dead-letter row addressing and the
turn-loop/graph-gate semantics all have to be re-derived from prose in these
markdown files rather than from source. Three of the four involve money.

---

## 3. The full seam pass (§ step 2 of the brief)

### 3.1 Result

**Every row in the re-derived `MOUNT-SEAMS.md`, not incremental.** The
inventory itself names two triggers for a full pass — *before the live deploy*
and *before deleting the Rust* — and this is that gate.

| App | Rows | RED | GREEN | Σ failing assertions |
|---|---:|---:|---:|---:|
| `apps/gateway` | 61 | **61** | 0 | 1,826 |
| `apps/control-plane` | 41 | **41** | 0 | 3,415 |
| `apps/agent-runtime` | 34 | **34** | 0 | 1,280 |
| `apps/mcp` | 32 | **32** | 0 | 1,063 |
| `apps/telemetry` | 17 | **16** | 1 | 243 |
| `apps/cli` | 9 | **9** | 0 | 86 |
| **Total** | **194** | **193** | **1** | **7,913** |

194 rather than 188 because six rows were split into their two documented
variants and run separately (`AR-T2b`, `AR-T5b`, `CP-C4b`, `MCP-R6b`,
`MCP-T6b`, `MCP-T7b`).

**Coverage was verified by diffing IDs, not asserted.** 191 IDs appear in
`MOUNT-SEAMS.md`. Two are unrunnable by construction and both are documented as
such: `GW-C11` is retired (wave 18 fixed the dead route and it is now `GW-R16`,
proven RED here), and `AR-T11` is the *absence* of a `[[d1_databases]]` stanza —
there is nothing to remove. Every one of the other 189 ran.

### 3.2 Why each RED is a real behaviour change and not an artefact

The brief requires satisfying oneself that each mutation changes behaviour and
is not a semantic no-op. Four independent controls, all mechanical:

1. **The edit landed.** `sha256sum` before and after; an unchanged file is
   reported `MUT-NOOP` and never counted. **0 rows.**
2. **The edit was read back OFF DISK.** Every row carries a `grep -F` CONFIRM
   assertion (marker present, or anchor absent) executed against the file after
   the write, guarding against a concurrent overwrite. Rows that failed CONFIRM
   were corrected and re-run, never counted. **0 rows remain failing.**
3. **A semantic no-op cannot produce a RED.** This is the decisive one. 193 rows
   went RED, so 193 mutations demonstrably changed observable behaviour. The
   `GW-C11` trap of wave 15 — a mutation that looked real but was unreachable
   because the fall-through already won — is *precisely* the case that shows up
   as GREEN, and it did not occur.
4. **A RED from a parse error proves nothing.** Recipes that would orphan a
   block were written as `if (false as boolean)` guards or `/*MUT*/ void <sym>;`
   statements so the tree still compiles. **0 rows** matched a transform/esbuild
   failure.

Six rows went RED with **zero counted assertions**; each was individually
inspected and each has a legitimate, distinct mechanism, not a flake:

| Row | Mechanism |
|---|---|
| `AR-T2`, `CP-T6`, `GW-T19`, `TEL-T6` | deleting `compatibility_date` makes **workerd refuse to start** (`MiniflareCoreError ERR_RUNTIME_FAILURE`, 6–109 pool-start failures). The documented **WORKERD-REFUSAL** channel |
| `CP-R1` | module-load throw: `Error: no route module for contract group(s): admin_api_key`, exactly as the row predicts |
| `GW-T4` | `test/setup-d1.ts` throws by name: *"expected both the `DB` binding … and `TEST_D1_SCHEMA`"* — the documented expected RED |

**A correction this pass made to its own method.** Six `wrangler.toml` stanza
rows (`GW-T3`–`T7`, `CP-T3`) were first mutated by commenting out only the
table header, which orphaned the stanza's remaining keys onto the preceding
table — and for `GW-T5`/`GW-T6` produced **`Error: Invalid TOML document`**,
i.e. a parse-level RED that proves nothing under the protocol's own rule 4. All
six were re-run as clean whole-stanza deletions. The re-run REDs (26, 0, 49,
231, 27, 5 assertions) are the ones recorded above; the invalid-TOML runs were
discarded. Had this not been checked, two T1 Durable-Object/D1 rows would have
been recorded as proven on evidence that was worthless.

### 3.3 (§ step 3) Real boot — five Workers under workerd

`bunx wrangler dev --local` on distinct ports; "Ready on" observed in each log;
`/healthz` fetched over real HTTP; process killed.

| Worker | Port | Ready on | `/healthz` | Body |
|---|---:|---|---:|---|
| `gateway` | 8801 | yes | **200** | `{"status":"ok","service":"ferrogate-gateway","version":"0.0.0","runtime":"workers"}` |
| `control-plane` | 8802 | yes | **200** | `{"status":"ok","service":"ferrogate-control-plane","runtime":"workers"}` |
| `mcp` | 8803 | yes | **200** | `{"status":"ok","service":"ferrogate-mcp","runtime":"workers","protocol":"2026-07-28"}` |
| `agent-runtime` | 8804 | yes | **200** | `{"status":"ok","service":"ferrogate-agent-runtime","version":"0.0.0","runtime":"workers"}` |
| `telemetry` | 8805 | yes | **200** | `{"status":"ok","service":"ferrogate-telemetry","runtime":"workers"}` |

Three of the five bodies carry no `version` — see the correction in §2.1.

### 3.4 What the seam pass proves, and what it does not

It proves that **every mount seam in the deployed composition roots is held by a
test that fails when the mount is removed** — the defect class that has bitten
this project eleven times is, as of this pass, comprehensively closed. That is a
genuine and significant result and it is the strongest single piece of evidence
for a GO.

It does **not** speak to CLASS A at all. A seam gate answers *"does the wired
thing run?"*. Every CLASS A item in §2 is a case where the wired thing runs
correctly and **there is no wire** — a store nothing reads, a threshold nothing
compares, a header nothing verifies. No mount gate can see those, which is why
the certifications exist and why the seam pass being perfect does not settle
the decision.

---

## 4. (d) What remains UNVERIFIED — provable only by the live deploy

Everything below is offline-only evidence. No `wrangler deploy` has been run,
no Cloudflare resource created or mutated, no upstream LLM called.

1. **The RPM window is one counter on `apps/gateway` only.** `apps/mcp` and
   `apps/agent-runtime` carry the cross-script `RATE_LIMIT` stanza **commented
   out**, because workerd cannot resolve a `script_name` binding offline. A
   credential capped at 60 rpm is today charged 60 on the gateway **plus 60×N
   across N MCP isolates plus 60×M across M agent-runtime isolates**. The other
   four ladder legs (quota scope, monthly budget, wallet hold, counter-key
   derivation) are shared and durable. **CLASS C locally, CLASS A on a deployed
   tree**, and nothing mechanical forces the uncommenting. Now recorded as
   **B10** in `CLOUD-VERIFICATION.md`.
2. **Three seams have no local proof channel of any kind** and were confirmed as
   such again this pass: `TEL-T4` (`[observability]` — Workers Logs config has no
   local effect; the single GREEN in §3.1, and its GREEN means *unobservable
   locally*, not *dead in production*), `MCP-T8`'s missing `migrations_dir`, and
   `AR-T11`'s absent `[[d1_databases]]`.
3. **Two are WORKERD-REFUSAL by nature**: the cross-script `RATE_LIMIT` bindings
   on `mcp` and `agent-runtime` cannot be exercised locally at all — uncommenting
   takes the suite to 0 collected tests.
4. **Deploy-time posture flips are human steps nothing can enforce**:
   `FG_DEV_IN_MEMORY_PORTS` → `"0"` (B1), `FG_REQUIRE_PRODUCTION_MTLS` → `"1"`
   (B6), R2 bucket existence (B2), KV token rights (B3), agent-runtime D1
   stanzas (B4), Analytics Engine (B5), `ADMIN_CONSOLE_JWT_SECRET` (B7), the
   per-tenant SSO `env://` secrets (B8), and both control migrations (B9).
5. **Live upstream provider behaviour** — streaming relay, failover and circuit
   breaking are proven against fakes only.
6. **`apps/agent-runtime` and `apps/telemetry` are not covered by `e2e/`** (only
   gateway and mcp are), so their DEPLOY-ONLY rows have no CI fallback either.
7. Per `cert2-controlplane` §6: per-operation **field** parity for ~60
   collections, envelope keys beyond the three named, per-collection search
   field sets, and 56 ops verdicted EQUIVALENT from the consumer graph without a
   fresh mutation this wave.

---

## 5. (e) The irreversibility note

`legacy-rs` recovers the **bytes**. It does not recover the **workflow**.

Every finding this wave produced came from operations that need the tree on
disk: `grep -rn` across `crates/**` to prove `AgentMemoryClient` has zero
callers; `grep -c "todo!"` per file to separate a finished Rust handler from an
abandoned one; walking a handler → its `state.*` method → its repository call to
qualify a regression; and the `.rs`-path citation grep that caught **9 of 9**
stale `MISSING` rows. `MODULE-OWNERSHIP.md` itself was derived by walking the
tree. None of that survives as `git show legacy-rs:crates/...` in practice, and
the agents doing this work diff against the working copy.

So deletion does not merely make regression-hunting harder — **it ends it**. The
next wave that asks "did Rust enforce X, and how?" gets an answer from these
markdown files or gets no answer. Those files are good, and this wave improved
them substantially, but they are a summary of a 220,000-line production system
written by readers who have already been wrong in both directions **within this
same wave**.

That asymmetry — cheap to keep, unrecoverable to lose, at a moment when the
catalogue is still moving ~25% per pass — is the whole argument, and it is why
the merge is a GO and the deletion is not.

---

## 6. Scope statement

This wave ran **local only**. No `wrangler deploy`, no live Cloudflare
resource, no real upstream LLM call. `crates/**` and `workers/**` were **not**
deleted and `main-ts` was **not** merged to `main` — executing the cutover is a
separate step, gated on this verdict. The Rust tree was read as a reference
only; no Rust was compiled and `cargo` was never invoked.

---


# APPENDIX H — the wave-15 → wave-18 document, preserved verbatim

Kept for the audit trail. **Superseded by §0 above.** Its verdict was NO-GO on
both acts; wave 19 splits them and upgrades the merge to GO. Where its finding
lists disagree with §2, §2 is current — in particular its §0.2 claim that
`admin_agent_upstream` is CLOSED is **false** and is the reason wave 19
re-derived rather than inherited.

---

## (archived) CUTOVER READINESS — waves 15-18

**Date:** 2026-08-01 · **Wave 15**, amended by **waves 16, 17 and 18** · **Branch:** `main-ts`
**Question:** may we delete `crates/**`, `workers/**` and `Cargo.*`, and merge
`main-ts` → `main`?

> **Wave-16 amendment (2026-08-01).** Wave 16 fixed defects this document
> found. **§0.1 records exactly which findings are CLOSED and which are not.**
> The verdict below is UNCHANGED and was not re-litigated: closing findings is
> not the same as re-certifying, this document's own §6.6 requires all three
> parity certifications and the full seam pass to be re-run before the verdict
> moves, and the argument for NO-GO was never only the finding list — it was the
> shape of the evidence (sixteen specification-bearing items; a discovery curve
> that had not flattened). Only a fresh certification can change it.
>
> **Wave-17 amendment (2026-08-01).** Wave 17 took the entire remaining §0.1
> "NOT closed" list except the two items that need a live account.
> **§0.2 records what is now CLOSED, with the RED/GREEN the integrate step
> observed itself.** The verdict is again **UNCHANGED and not re-litigated**,
> for the same reason and for one more: wave 17's own integrate step found
> **three first-order defects that the delivering agents' green suites did not
> show** (§0.2's "found during integration" table), one of them a HIGH
> policy-bypass residue that made the wave's own D2 fix unreachable on the
> deployed Worker. That is direct evidence that **the discovery curve still has
> not flattened** — which is the second of the two arguments the NO-GO rests on.
> Only wave 18's fresh certification can move it; §0.2 ends by naming exactly
> what that certification must check.
>
> **Wave-18 amendment (2026-08-01).** Wave 18 did NOT run that certification. It
> ported the enterprise-identity surface that had no TypeScript at all, mounted
> it, fixed the one DEAD production route (`GW-C11`), and — the part that
> matters — ran `MODULE-OWNERSHIP.md`, the first **module-granularity** audit of
> the Rust tree. **§0.3 records what closed and what that audit opened: 37
> MISSING modules (27,644 lines) and 46 UNVERIFIED (23,040 lines).** The verdict
> is **UNCHANGED**, and §0.3.4 explains why the new evidence makes it firmer
> rather than closer to a GO.

---

## 0. The verdict

### (archived verdict) **NO-GO.**

Do **not** delete the Rust tree and do **not** merge `main-ts` → `main` on the
strength of this wave's evidence.

This is not a close call and it is not a quality complaint about the TypeScript.
The port is good. It is mounted, it boots, it is heavily and — as of this wave —
**exhaustively** mutation-tested at every composition seam. The reason for NO-GO
is narrower and harder:

> **Three independent certifications, run by three agents against three different
> surfaces, each independently concluded "do not delete `crates/**` yet" — and
> each found first-order defects that no previous wave had recorded.**

The most severe of them is a live control bypass: **the admission half of Rust's
`authenticate()` — rate limit, monthly budget, wallet balance, quota scope — was
silently dropped from `apps/mcp` and `apps/agent-runtime` when the Rust single
process was split into five Workers.** A key that is rate-limited and
budget-exhausted on `POST /v1/chat/completions` is admitted on
`POST /v1/agent-jobs` and on MCP `tools/call`, and both then spend real provider
money. That is not a fidelity gap. It is the product's spend controls being
optional at the client's choosing, and it affects **20 of the 54 data-plane
operations**.

Equally decisive is the shape of the evidence: the marker ledger recorded **+25
new portable markers appearing in ninety minutes**, all written by concurrent
audits, including eight of the most severe findings in the whole ledger. **The
defect-discovery curve has not flattened.** A GO taken today would be taken on
the premise that we know what is missing, and the last two waves have repeatedly
shown that we do not — we know what has been *noticed*.

**What a GO would cost if wrong:** the Rust is the only specification for
sixteen enumerated items, several of them security- and money-relevant. Deleting
the working tree ends practical parity checking (§5), so a defect found after
cutover is re-derived from behaviour, not read off a reference.

**What NO-GO costs:** one more wave. That asymmetry is the entire argument.

### What IS certified by this wave

| Gate | Result |
|---|---|
| `bun install` | clean, 260 installs / 336 packages, no changes |
| `bun run typecheck` | **clean** across all 24 workspaces |
| `bun run test` per package/app | **5679 passed · 0 failed · 0 skipped · 9 todo** across 24 vitest projects (baseline ~5607) |
| **FULL mount-seam pass** | **161/161 inventory rows re-proved by mutation; 150 RED, 13 GREEN, 0 CONFIRM-FAIL, 163/163 restored byte-identical** |
| Real boot, all five Workers | `wrangler dev --local` → "Ready on" + `/healthz` **200** on all five |
| E2E | `playwright test` → **21 passed**, exit 0 |

Every one of those is a *necessary* condition for cutover and every one is met.
None of them is *sufficient*, because all of them measure whether the TypeScript
does what the TypeScript's own tests say it should — not whether that matches the
Rust. The three parity certifications are the only documents that ask the second
question, and all three answer no.

---

## 0.1 WAVE 16 — which findings are CLOSED, and which are not

Wave 16 took §6 items 1–4. Everything below was verified by the integrate step
**independently of the delivering agents**: for each fix, the fix was reverted or
neutralised in place, a `grep` confirmed the edit had actually landed (a
concurrent write silently reverting a mutation is a known failure mode here), the
named test was required to go RED, the file was restored and required to go
GREEN again. A fix whose test was never *seen* red is not recorded as closed.

### CLOSED

| Finding | What landed | RED-before / GREEN-after, observed by the integrate step |
|---|---|---|
| **D1 — admission bypass** (the live control bypass; 20 of 54 data-plane ops) | The `finalize_auth` admission ladder — quota-scope chain, monthly USD budget, prepaid-wallet no-oversell hold, RPM window — ported onto `apps/mcp` (`src/admission/`, called from `src/http.ts::authenticateRequest`) and `apps/agent-runtime` (`src/admission/`, called from `src/middleware/auth.ts`). Both import `@ferrogate/policy`'s `QuotaScopeSelector.counterKey` rather than re-deriving it, so the counter key cannot drift between Workers | MCP: neutralising the `ports.admission.admit` call ⇒ **6 RED** in `apps/mcp/test/admission.test.ts`, restored **33/33 GREEN**. agent-runtime: neutralising `deps.admission.admit` ⇒ **6 RED** in `test/admission.test.ts` **and 4 RED** in `test/durable/admission.spec.ts` (real migrated D1), restored **8/8 + 8/8 GREEN**. Gateway leg re-proved on the same run: removing `rateLimit()` from `GATEWAY_MIDDLEWARE` ⇒ **16 RED** in the deployed-app suites |
| **D1 cross-Worker consistency** — the half that three green suites cannot show | `apps/gateway/test/admission-consistency.test.ts` (new, 7 cases): the three Workers' refusal tables must agree on status, on message text, and on every code two of them share; and all three must derive the counter key from the ONE `@ferrogate/policy` site | Proven RED by two mutations: MCP `quota_scope_disabled` 403→429 ⇒ **2 RED**; agent-runtime `rate_limit_exceeded` message reworded ⇒ **1 RED**. Restored **7/7 GREEN** |
| **D4 — asset egress** (money) | `apps/gateway/src/assets/egress.ts`: the fail-closed monthly egress BYTE budget and the download-RPM cap ahead of any byte served, then `recordAssetEgress` metering + the pull-side audit row. Wired through `AssetService`, so a `206` bills its slice and a `304`/`416`/`HEAD` bills nothing | Neutralising `#egressDenial`'s refusal ⇒ **4 RED** in `test/assets/egress.test.ts` (over-budget pull, over-RPM pull, the range request gated on FULL object size, the presigned-URL issuance). Restored **24/24 GREEN** |
| **D5 — asset publish gate 1** (security; the `mcp_manifest` **stdio** refusal) | `apps/gateway/src/assets/content-gate.ts`, called DIRECTLY by `AssetService` on `putAsset` and `commitUpload` ahead of the screener — deliberately not as an `AssetScreener` decorator, so no operator configuration and no injected test double can switch it off | Neutralising `#contentGate`'s rejection ⇒ **7 RED** in `test/assets/content-gate.test.ts`, including "REFUSES a stdio manifest", "refuses regardless of case" and "is NOT disableable through the screener seam". Restored **17/17 GREEN** |
| **Control plane — `rbac` write half** (a granted role authorized nothing; `DELETE` answered 200 and revoked nothing) | `apps/control-plane/src/store/rbac_registry.ts` + the route projections, ordered so a crash mid-write leaves a visible-but-unauthorizing binding rather than an invisible grant, and revokes the GRANT before the document | Neutralising `projectTenantRoleBinding` ⇒ **8 RED** in `test/rbac-write-half.test.ts`, incl. "DELETE stops authorizing on the very next request". Restored **12/12 GREEN** |
| **Control plane — `admin_api_key` write half** (the group could neither mint a working credential nor revoke one; both answered 200) | `apps/control-plane/src/store/static_keys.ts` + mint/revoke projection, with the minted key clamped so it can never exceed the caller that minted it | Neutralising `projectStaticApiKey` ⇒ **13 RED** in `test/api-keys-write-half.test.ts`, incl. "the minted secret authenticates on the very next request" and "the secret stops authenticating on the very next request". Restored **14/14 GREEN** |
| **Control plane — the tenant WRITE fence** (a tenant admin holding `admin.write` could PATCH or DELETE any un-attributed PLATFORM row) | `tenantWriteScopeSql` (D1) and `query.ts::writableBy` (memory) split from the READ predicate: strict `tenant_id = ?`, no `IS NULL` disjunct. Reads keep the disjunct, which `resolved-defaults` depends on | Both implementations mutated back to the read predicate, separately. D1 ⇒ **4 RED** in `test/tenant-write-fence.test.ts` (8/8 restored); memory ⇒ **6 RED** in `test/store-conformance.test.ts` (98/98 restored). The first mutation of `writableBy` left `tenant-write-fence.test.ts` GREEN — that file drives the D1 store — which is why both twins were mutated rather than one |
| **Guardrail evidence-fingerprint keying** (test-only; two real mutations used to leave 407/407 + 112/112 green) | `packages/guardrails/test/fingerprint-keying.test.ts` (32 cases) over all four fingerprint sites, checked against an INDEPENDENT `node:crypto` oracle rather than the package's own `hash.ts` | key → empty bytes at `hmacEvidenceFingerprint` ⇒ **12 RED**; key → a hard-coded constant in `DeterministicDetector#hmacFingerprint` ⇒ **3 RED**. Both restored **32/32 GREEN** |

### NOT closed — carried forward unchanged

| Finding | Why it is still open |
|---|---|
| **D1's shared counter, on the RPM leg only** | The four other legs (quota scope, monthly budget, wallet hold, and the counter-KEY derivation) are shared and durable across all three Workers today. The RPM WINDOW is not: it needs `apps/gateway`'s `RateLimiterDurableObject` bound cross-script into the other two, and **workerd cannot resolve a `script_name` binding offline**. Committed uncommented, `apps/mcp`'s suite collapses to 0 collected tests / 23 errors on a correct tree and `wrangler dev --local` never reaches "Ready on" (measured this wave). The stanza is therefore written out IN FULL but COMMENTED in both `wrangler.toml`s, pinned by both apps' `env-var-drift` gates (status, `script_name`, and the absence of a migration claiming the class), and is a **DEPLOY-ONLY** seam. Until it is uncommented the RPM cap is enforced per isolate — 60 rpm becomes 60·N across N isolates — versus **none** of the five legs enforced before this wave |
| **Control plane — `guardrail_policy` write half** (10 ops) | Deliberately NOT projected, and the reason is now written into `routes/guardrail_policy.ts`: `binding.ts::policySourceFromStore` calls `compilePolicyChecks` EAGERLY at construction with no `try`/`catch`, so projecting today's partially-validated revision documents would take the gateway's whole guardrail source down **at boot**. Closing it requires tightening the ADMISSION (a revision the data plane could never enforce must be a 400, not a 201 followed by silence), which is a behaviour change to two create operations and moves existing accepted cases with it |
| **Control plane — `wallets` write half** (10 ops) | Untouched. Admin writes `balance_cents` in the CONTROL db; the reader is `wallets.balance_credits` + `wallet_reservations` in the TENANT db. Crediting a wallet still does not fund a request |
| **D2, D3, D6, D7**, the three MISSING ops, `/metrics`, `/healthz` `version`, agent-runtime `/readyz` | Untouched by this wave |
| **`ferrogate-cloudflare` — the 21st crate** (§6 item 5) | Untouched. Still the single strongest argument against deleting the Rust: four slices with no TS equivalent anywhere and no `PORT-PLAN.md` row |
| **The other §2.2 DURABLE-BUT-UNREAD groups**, §2.3's AI-Gateway routing (#406), `sync-bridge`, the credits `number`/`bigint` boundary, §2.4's IN-MEMORY-ONLY postures | Untouched |
| **§4.1 — everything only a real deploy can settle** | Unchanged, and now one row longer: the cross-script `RATE_LIMIT` binding above |
| **§6 items 6, 7, 8** — re-run all three parity certifications and the full seam pass; scope `ferrogate-auth-service`'s 11,474 unported lines; the four newly-unproven seams | Untouched. **Item 6 is what gates the verdict**, and it has not been done |

**Net effect on the verdict: none, by design.** Wave 16 closed the four §6 items
that were nominated as closable, and did not touch the two arguments the NO-GO
actually rests on — the sixteen specification-bearing items, and a
defect-discovery curve that had not flattened. Wave 16 is itself weak evidence
about the curve: it was a *fix* wave, not an *audit* wave, so it was not looking.

---

## 0.2 WAVE 17 — which findings are CLOSED, and what wave 18 must still check

Wave 17 took the whole remaining §0.1 "NOT closed" list except the two rows that
require a live Cloudflare account. Six agents delivered; the integrate step
verified **every** fix independently, by the §0.1 protocol: neutralise the fix in
place, `grep` the mutation back OFF DISK to prove it landed, require the named
test RED, restore, `sha256sum`-verify the restore, require GREEN. **A fix whose
test was never *seen* red is not recorded as closed.** Nothing below is taken on
a delivering agent's word.

### CLOSED — verified by the integrate step's own mutations

| Finding | What landed | RED-before / GREEN-after, observed by the integrate step |
|---|---|---|
| **`wallets` write half** (MONEY — "crediting a wallet still does not fund a request") | `apps/control-plane/src/store/wallet_projection.ts`: the admin movement now projects into the TENANT database's `wallets.balance_credits` through `@ferrogate/storage`'s `D1WalletStore.settleWalletBalance` — **the same class `apps/gateway/src/ratelimit/wallet.ts` calls** — inside one `batch()` claimed by a `wallet_settlements` row. Cents→credits is `bigint` end to end. CREDIT writes the ledger claim first, DEBIT writes the enforced row first | **END-TO-END, asserted as the effect and not the status code:** seed an EXHAUSTED wallet, run the gateway's own `reserveWalletCredits` ⇒ `insufficient`; `POST /admin/v1/wallets/{t}/adjust {amount_cents:500}` ⇒ 200; run the SAME decision ⇒ **`reserved`**, balance exactly `5_000_000` credits. Neutralising the tenant leg ⇒ **10 RED** in `test/wallet-funding.test.ts`; restored **15/15 GREEN**. **Double-submit:** the same `reference` twice ⇒ both 200, balance moves **once**, ONE ledger entry; making `walletLedgerEntryId` non-deterministic ⇒ **3 RED**. Cross-tenant control included: crediting `tenant_a` leaves `tenant_b` at 0 and still `insufficient`. Two-implementation trap CHECKED: `MemoryWalletStore` exists in `@ferrogate/storage` but **no app constructs it** — all four (`gateway`, `mcp`, `agent-runtime`, `control-plane`) build `D1WalletStore`, so there is no green twin |
| **D2 — the workflow GRAPH gate** (HIGH; policy bypass. `[[agent_workflows]]` was parsed by `packages/config` and read by nothing) | `packages/policy/src/workflow-graph.ts` (all thirteen Rust refusals) + `apps/gateway/src/inference/workflow.ts` (Rust header names, the `control_plane_resources` catalog, a durable step ledger), enforced from `handlers.ts::admitWorkflowStep` ahead of dispatch | Neutralising the gate mount ⇒ **19 RED** across `test/inference/workflow-graph.test.ts` + `workflow-ledger.test.ts`. Replacing the composition root's env-resolved catalog with an empty one ⇒ **RED** (see the trap row below for what that mutation showed BEFORE the new gate). Restored GREEN |
| **`guardrail_policy` write half** (10 ops; previously refused on purpose because projecting a bad row took the gateway's guardrail source down at BOOT) | Admission tightened first — `packages/guardrails/src/admission.ts::admitPolicyRevision`, a revision the data plane could never compile is now a **400**, not a 201 followed by silence — then projection into `guardrail_policy_revisions` / `guardrail_policy_bindings` (`apps/control-plane/src/store/guardrail_registry.ts`), plus per-policy boot resilience on the read side so a pre-existing bad row fails **that one policy CLOSED** instead of the Worker | Neutralising `admitPolicyRevision` ⇒ **7 RED** in `test/guardrail-write-half.test.ts`; neutralising `projectGuardrailRevision` ⇒ **7 RED** in the same file (activate/rollback/archive all move the binding row). Read side: unmounting `D1GuardrailPolicyStore.fromEnv` from `guardrailDepsFromEnv` ⇒ **3 RED** in `test/guardrails/d1.test.ts`. Restored **1875/1875 GREEN**. Two-implementation trap CHECKED: `InMemoryGuardrailPolicyStore` is the var half and `loadGuardrailPolicyStore` layers the durable half onto it — the D1 leg has its own gate, so mutating one does NOT leave the other silently green |
| **`ferrogate-cloudflare` — the 21st crate** (§6 item 5; "the single strongest argument against deleting the Rust") | `packages/cloudflare` — S1–S5: account-scoped client with the retry schedule, D1 management, R2 buckets, bucket-scoped R2 token minting, scopes/envelope/errors. 146 tests | Narrowing `RETRYABLE_STATUSES` to `[429]` ⇒ **5 RED** across `test/retry.test.ts` + `test/client.test.ts`. **Wired, not merely written:** `packages/storage/src/tenant-rest.ts` now routes the D1 REST transport through `executeWithRetry`; forcing `isRetryableOutcome` to `false` ⇒ **5 RED** in `packages/storage/test/d1/rest-retry.test.ts`. `r2-token.ts` (S2) stays deliberately UNMOUNTED and says so — it needs the bucket-per-tenant decision and R2 enabled on the account |
| **D3** — the agent run that caused the spend never reached the metering row | `apps/gateway/src/metering/agent-run.ts`, threaded through `middleware.ts` (read off the request) and `event.ts` (`agent_run_id`, absent-stays-absent) | Dropping the header read ⇒ **1 RED** in `test/metering/agent-run-correlation.test.ts` ("a declared `x-ferrogate-agent-run-id` reaches the settled `event_json`"). Restored **13/13 GREEN** |
| **D6** — no per-request drain gate | `apps/gateway/src/routes/drain.ts`, mounted `app.use("*", options.nodeDrain ?? nodeDrainGate())` | Unmounting it ⇒ **3 RED** in `test/routes/drain.test.ts` (503 `node_draining` on all five spend-producing ops; re-read PER REQUEST; the same flag `/readyz` uses) |
| **D7** — agent-job event-feed divergences | `apps/agent-runtime/src/runs/events.ts` — discriminator, `400 invalid_event_cursor`, the resume cursor surviving its own event, the `/result` `work_products` projection | Making a non-integer `?limit` fall back instead of refusing ⇒ **2 RED** in `test/event-feed.test.ts` |
| **Contract gaps — `/metrics`, `/healthz` `version`, agent-runtime `/readyz`** | `apps/gateway/src/routes/metrics.ts` (`getMetrics`, Prometheus exposition over this isolate's counters) and `apps/agent-runtime/src/routes/health.ts` (the shared health document + the Rust readiness decision table) | Unregistering `getMetrics` ⇒ **5 RED** (`test/routes/metrics.test.ts` **and** `test/contract.test.ts`'s "mounts ALL 31 gateway-owned operations"). `/healthz` `version`: caught by `e2e/tests/gateway.spec.ts` over real HTTP. agent-runtime `/readyz`: see the "wired during integration" row below |
| **Remaining DURABLE-BUT-UNREAD control-plane groups + the 3 MISSING ops** | `admin_agent_cost_burn`, `admin_agent_upstream`, `admin_agent_workflow`, `admin_request_log` now read the durable rows | Dropping the tenant fence from the cost-burn query ⇒ **10 RED** in `test/agent-cost-burn-read.test.ts` (incl. "never shows one tenant another tenant's burn"). Dropping the audit-trail fence ⇒ **3 RED** in `test/audit-events-read.test.ts` |
| **`sync-bridge` deleted** | `packages/sync-bridge/**` removed; the root `workspaces` glob picks the removal up with no manifest edit | Verified by the integrate step: `grep -rn "sync-bridge"` over `apps/`, `packages/`, `e2e/` and every `package.json`/`tsconfig.json` returns **nothing** (only historical prose in `docs/`); `bun.lock` contains **0** references; `bun run typecheck` clean; full suite green |

### FOUND DURING INTEGRATION — defects the delivering agents' green suites did not show

These are the reason this wave is *not* evidence that the discovery curve has
flattened. All three were found by the integrate step's own mutations, and all
three are fixed and gated here.

| Defect | How it hid | Fix + observed RED |
|---|---|---|
| **The D2 gate was UNREACHABLE on the deployed Worker** (HIGH — the wave's own headline security fix did nothing in production for reference-shaped clients) | `src/ratelimit/workflow.ts::workflowDeclarationFrom` (wave 16's budget envelope) required `x-ferrogate-workflow-run-id` among three headers that must appear together. The graph gate uses Rust's `x-ferrogate-agent-run-id`. A reference-shaped client therefore met the RATE-LIMIT middleware first and got `400 invalid_workflow_declaration` before the gate ran. Invisible because **every** workflow test built its own router (`fixtures.ts::harness` → `createInferenceRouter`) and none ran the middleware chain. `src/inference/workflow.ts` documented the residue and wrote out the fix, but as "not this module's to fix" | The recipe applied verbatim (the run-id alias, with its load-bearing `workflowId === ""` guard so a bare correlation id on assets/MCP traffic stays `absent`), plus a NEW SELF-driven gate `apps/gateway/test/inference/workflow-mount.test.ts` (9 cases). **Measured: all nine answered `400 invalid_workflow_declaration` before the alias.** Removing the alias again ⇒ **6 RED**; replacing the composition root's catalog with an empty one ⇒ **7 RED** (was **1** of 1866 before this file existed, i.e. no HTTP-level proof at all). `test/ratelimit/guards.test.ts` green either way, as the residue note predicted |
| **Three DO binding NAMES had no gate** (GW-T8/T10/T12) | `test/wrangler-bindings.test.ts` asserted `class_name` three ways and `name` **zero** ways — and `name` is the half `src/` reads (`env.RATE_LIMIT`, `env.PROVIDER_CIRCUIT`, `env.SHADOW_BUDGET`). The cited escalation gate `test/ratelimit/durable-object.spec.ts` runs under `test/ratelimit/harness/vitest.config.ts`, which points at **`harness/wrangler.toml` — a different file**. Each read degrades SILENTLY when unbound: the RPM limiter falls back per isolate (the quieter form of the wave-16 admission bypass), the provider circuit becomes a per-isolate `Map`, the shadow budget stops being a cross-isolate cap | New `it("binds each namespace under the NAME src/ reads it by")`. Renaming any of the three ⇒ **1 RED** each |
| **`compatibility_flags`, `main`, and MCP's DO migrations had no gate in 4 of 5 Workers** (GW-T2, CP-T1/T2, AR-T2, MCP-T1/T2/T6/T7, TEL-T1/T5) | MOUNT-SEAMS recorded GW-T2's *Expected RED* as "whole suite". Measured: commenting `compatibility_flags` out left **every** suite in every app GREEN — `@cloudflare/vitest-pool-workers` supplies its own runtime flags. Same for `main` and for `new_sqlite_classes` in `apps/mcp` (already known NO-GATE, now closed) | Drift assertions added to `apps/gateway/test/wrangler-bindings.test.ts`, `apps/agent-runtime/test/wrangler-bindings.test.ts`, and the `env-var-drift.test.ts` of control-plane, mcp and telemetry. Each mutation ⇒ **1 RED** |
| **MCP-P6 — the identity CIPHER seam had no gate** (security) | `resolvePorts`'s durable branch sets `cipher: identityCipherFrom(env.FERROGATE_MCP_IDENTITY_KEY)`. Deleting that line left all 359 mcp tests GREEN — every assertion in the block was about `ports.credentials`. Without it the durable credential store seals OAuth grants under `webCryptoIdentityCipher()`'s **ephemeral per-isolate key**: every stored grant becomes undecryptable on the next isolate recycle, and the operator's configured key sits unread | New case in `test/durable-identity.test.ts`: seal with a cipher built from the fixture key, open with the one `resolvePorts` chose. Deleting the line ⇒ **1 RED** |

### NOT closed — carried forward

| Finding | Why it is still open |
|---|---|
| **D1's shared counter, on the RPM leg only** | Unchanged from §0.1. Needs a cross-script `script_name` binding, which **workerd cannot resolve offline**; committed uncommented, `apps/mcp` collapses to 0 collected tests and `wrangler dev --local` never reaches "Ready on". Still DEPLOY-ONLY, still pinned commented by both apps' `env-var-drift` gates |
| **§4.1 — everything only a real deploy can settle** | Unchanged. `packages/cloudflare` narrows the *code* gap but every one of its five slices talks to the Cloudflare API and **none has been run against the live account**; the tests are transport-level fakes by construction. `r2-token.ts` additionally needs R2 enabled, which it is not |
| **§2.3's AI-Gateway routing (#406), the credits `number`/`bigint` boundary at the remaining call sites, §2.4's IN-MEMORY-ONLY postures** | Untouched by this wave |
| **`ferrogate-auth-service`'s 11,474 unported lines** (§6 item 7) | Untouched. Not scoped, not ported, not certified |
| **§6 item 6 — re-run all three parity certifications and the full seam pass** | **Untouched, and it is what gates the verdict.** See below |

### What wave 18's certification must check — explicitly

The verdict cannot move until §6.6 is satisfied. Concretely, wave 18 must:

1. **Re-run all three parity certifications** (`cutover-parity-dataplane.md`,
   `cutover-parity-controlplane.md`, `cutover-parity-libraries.md`) against the
   CURRENT tree, by fresh agents. Waves 16 and 17 were *fix* waves, not *audit*
   waves — neither was looking for new defects, and wave 17 still tripped over
   four. The specific new surface that has never been parity-certified at all:
   `packages/policy/src/workflow-graph.ts`, `packages/guardrails/src/admission.ts`,
   `packages/cloudflare/**` (all 21 modules), `packages/storage/src/credits.ts`,
   `apps/control-plane/src/store/{wallet_projection,guardrail_registry}.ts`,
   `apps/gateway/src/{inference/workflow,metering/agent-run,routes/drain,routes/metrics,routes/service}.ts`,
   and `apps/agent-runtime/src/routes/health.ts`.
2. **Re-run the FULL mount-seam pass** — all rows, not the §4(a)/(b) incremental
   policy. Wave 17 ran the incremental policy (touched files + every T1) and that
   is what found the ten ungated config rows above; a full pass is mandatory
   before the Rust tree is deleted, per `MOUNT-SEAMS.md` §4 exception 2.
   **The inventory itself must be re-derived mechanically first**: wave 17 added
   rows (AR-C10) and corrected the *Expected RED* of ten others, so a pass run
   off the old table would re-assert corrections that are now wrong.
3. **Re-audit the two escalation-config apps for the harness trap.** The
   `test/ratelimit/harness/` finding above is a class, not an instance: any
   `*.spec.ts` project pointed at its own `wrangler.toml` or its own
   `worker.ts` proves nothing about the deployed config. `apps/gateway`'s
   tenancy harness and `apps/agent-runtime`'s durable harness have not been
   checked for it.
4. **Decide the two deferred sub-questions the code now names**: whether the
   budget envelope's `x-ferrogate-workflow-version` may be optional (Rust's is
   `Option<u32>`; ours is part of a primary key), and whether R2 goes
   bucket-per-tenant (which is what unmounts-or-mounts `r2-token.ts`).
5. **Answer the question no local wave can**: run the §4.1 live-deploy list.
   `packages/cloudflare` existing does not make it verified.

**Net effect on the verdict: none, by design.** Wave 17 closed nine of the ten
remaining findings and found four more while doing it. The second of those two
numbers is the one that matters.

---

## 0.3 WAVE 18 — what this wave CLOSED, and the much larger thing it OPENED

> **The verdict in §0 is UNCHANGED and was not re-litigated.** Per §6.6 only a
> fresh three-way certification plus a full seam pass can move it, and wave 18
> produced neither: it produced a *port*, an *integration*, and — decisively —
> a **new control that had never been run before**, whose first result is the
> largest single piece of bad news in this document's history.

### 0.3.1 CLOSED by wave 18

| # | What was closed | Evidence the integrate step observed ITSELF |
|---|---|---|
| C1 | **Enterprise identity existed nowhere in TypeScript.** SAML 2.0 (`packages/sso`), OIDC RP + SCIM 2.0 (`packages/identity`) and the admin-console session surface (`apps/control-plane/src/session/`) are now implemented AND MOUNTED on the deployed control-plane Worker | `apps/control-plane/test/identity-mount.test.ts` — 23 `SELF`-driven cases. Mount seams `CP-S1`/`CP-S2`/`CP-S3` mutated: **18 / 10 / 12 RED**, restored GREEN. Confirmed again on a real `wrangler dev --local` boot: `POST /v1/admin/login` → `503 admin_console_unconfigured`, `GET /scim/v2/Users` → `401`, `GET /v1/admin/auth/saml/acs` → `422 missing_relay_state` — three surfaces answering, none `404` |
| C2 | **`GW-C11` — the gateway's `/version` was DEAD IN PRODUCTION**, registered after the `app.all("*")` fall-through, for seventeen waves. It was the only one of the five Workers not serving `/version` | Moved inside `createGatewayApp`, above the fall-through. Re-proven by deletion: **2 RED**. Confirmed on a real boot: `GET /version` → `200 {"api":"v1"}` (it was `404 not_found`) |
| C3 | **Eight mount lines that had never been a row in any wave's table**, plus three T1 rows whose only cited gate was a harness that builds its own Worker | `docs/rewrite/MOUNT-SEAMS.md` was re-derived mechanically from the composition roots rather than patched. Five new T1 rows (`CP-S1`…`CP-S5`) were added by the integrate step for its own mounts |
| C4 | **The SSO replay defence had no durable proof.** `packages/{sso,identity}` prove single-use `take` against an in-memory map; the D1 twin was unproven | `apps/control-plane/test/sso-store-contract.test.ts` runs the package's OWN exported `samlPendingFlowStoreContract` against the D1 implementation. Mutating the `DELETE … RETURNING` to a `SELECT` is **5 RED** across that file and the mount suite |

### 0.3.2 Found DURING integration — the curve still has not flattened

Wave 17's amendment rested on this same observation, and wave 18 reproduces it.
Every item below was green in the delivering agent's own suite.

1. **The D1 pending-flow store diverged from the package's own exported contract
   in two ways**, and one of them is replay-adjacent: the first implementation
   filtered expiry in SQL (`… AND expires_at_unix > ?`), so **presenting an
   expired state did not BURN it** — the row survived for a second attempt under
   a different clock. Caught only because the contract is exported from `src/`
   and could be run against the durable twin; **no test in `packages/sso` or
   `packages/identity` could have seen it.** Fixed to `DELETE … WHERE state = ?
   RETURNING *` with the expiry decided in TypeScript on a row that no longer
   exists either way.
2. **`test/console-session.test.ts` is a FACTORY test**, not a mount test: it
   builds its own `Hono` app and calls `app.request(...)`. Measured — it stays
   **fully green with the console-session surface unmounted from the deployed
   Worker**. That is `MOUNT-SEAMS.md` §4's rule firing for the twelfth time.
3. **`ADMIN_CONSOLE_JWT_SECRET` was read by `src/` and named nowhere in the
   deploy config.** The env-var drift gate caught it the moment the surface was
   mounted; it is now a documented `wrangler secret` and a new **B7** blocker in
   `CLOUD-VERIFICATION.md`, alongside **B8** (per-tenant IdP secret references)
   and **B9** (the control migrations are now two files).

### 0.3.3 OPENED by wave 18 — `MODULE-OWNERSHIP.md`, and why it is the headline

`docs/rewrite/MODULE-OWNERSHIP.md` is the first control this project has ever run
at **module** granularity. `PORT-PLAN.md` maps CRATES, and
`docs/openapi/runtime-api-contract.json` enumerates OPERATIONS — and
`crates/ferrogate-auth-service/src/server.rs` serves **34 routes, none of which is
in that contract**. Two independent controls therefore had the *same* blind spot,
which is why an entire enterprise-identity crate could be missing for seventeen
waves with every audit green.

Its verdict, over **363 product modules / 275,295 lines** of Rust:

| Class | Modules | Lines |
|---|---:|---:|
| PORTED | 245 | 197,756 |
| OBSOLETE-ON-CF | 24 | 19,677 |
| DELIBERATELY-DROPPED | 11 | 7,178 |
| **MISSING** | **37** | **27,644** |
| **UNVERIFIED** | **46** | **23,040** |

**Do not net wave 18's work off that 37.** The audit ran while the identity
packages were being written and states its own rule: *"a row does not become
PORTED because a package directory appeared."* Wave 18 has now delivered
implementations **and mutation-proven mounts** for the 8-module / 5,345-line
enterprise-identity group, so a wave-19 **behaviour-level re-derivation** may
reclassify those eight. It has not happened yet. What is certain today is the
other number:

> **29 MISSING modules / ~22,300 lines that no wave has touched, plus 46
> UNVERIFIED modules / 23,040 lines that this pass explicitly declines to call
> PORTED.**

The unfunded MISSING work is not cosmetic. It includes the 4-module,
11,371-line **external-action capability boundary** (TypeScript models it as
`requiredCapabilities: string[]`, which cannot express a per-variant decision),
the 11-module **coding-agent five-phase contract** including its credential
broker, **evidence redaction** (`recorded_evidence.rs` — evidence rows can carry
unredacted upstream bytes), **tether-bypass detection**, **agent memory**, the
**brokered edge-function egress** family, and the **budget-alert webhook** that
never fires. Several are security- or money-relevant and **none of them was in
any wave's task list**.

### 0.3.4 What this means for the verdict

It strengthens **NO-GO** rather than weakening it, and for a new reason: until
wave 18 the argument was *"the discovery curve has not flattened."* It is now
*"we have measured the residue for the first time, and it is 37 modules we
cannot see the bottom of plus 46 we have not looked at."* §5's irreversibility
note applies with full force — deleting `crates/**` deletes the only
specification for every one of them.

**Wave 19 cannot certify on this evidence.** The minimum before a GO is
re-litigated:

1. re-derive the 8 enterprise-identity rows at BEHAVIOUR level and reclassify
   them honestly (they are the only rows wave 18 could have moved);
2. take the **46 UNVERIFIED** rows to a decision — each is a claim that this
   pass did not prove presence, not a claim of absence, and shipping on them is
   shipping on "probably";
3. fund or explicitly drop, with a recorded decision, the **29 untouched
   MISSING** modules — starting with `recorded_evidence.rs`,
   `cloudflare_container_tether_audit.rs` and the external-action boundary,
   which are the security-relevant ones;
4. everything §0.2 already listed, which is unchanged.

**Net effect on the verdict: none, by design — but the gap to a plausible GO got
measurably larger, because for the first time it was measured.**

---

## 1. Evidence produced by this wave

### 1.1 The full mount-seam pass

`MOUNT-SEAMS.md` §4 mandates a FULL pass — not the incremental §4(a)/(b) policy —
**before deleting the Rust tree**. This wave is that gate; it is executed and
recorded in `MOUNT-SEAMS.md` §16.

**161 of 161 inventory rows re-proved by mutation.** 163 runs (GW-A1/GW-A1b share
one mutation; three extra `new_sqlite_classes → new_classes` substitution
variants were added). Every file restored and `sha256sum -c`-verified; a
whole-tree check confirmed **827/827** `.ts`/`.toml` files byte-identical to the
pre-pass snapshot.

Two guards were added beyond the §2 protocol, both because of prior burns:

- **Marker uniqueness** — every replacement carries a `/*MUT*/` token and the
  driver refuses any row whose replacement text already exists in the pristine
  file. A CONFIRM that could not fail is not a CONFIRM.
- **Behaviour, not bytes** — recipes that would only have produced a *parse
  error* were rewritten as `if (false as boolean) …` guards so the mutated tree
  still compiles and RED means an assertion failed. The wave-14 lesson (a recipe
  that applies but does nothing) was the reason.

That second guard immediately paid: **five recipes recorded in `MOUNT-SEAMS.md`
were themselves defective** (GW-A3's CONFIRM could never fire; MCP-R3, TEL-A3,
TEL-A5, TEL-A6 orphaned blocks; GW-C7 inserted a middleware that never calls
`next()` and would have broken every request rather than only guardrails). All
five are repaired and recorded in §16.4.

**Result: 150 RED, 13 GREEN.**

| App | rows | RED | GREEN |
|---|---:|---:|---:|
| `apps/gateway` | 55 (54 runs) | 52 | 2 |
| `apps/control-plane` | 28 | 26 | 2 |
| `apps/mcp` | 26 (28 runs) | 25 | 3 |
| `apps/agent-runtime` | 30 (31 runs) | 30 | 1 |
| `apps/telemetry` | 14 | 11 | 3 |
| `apps/cli` | 8 | 6 | 2 |

Nine of the 13 GREEN are documented-and-expected (the four `compatibility_flags`
rows and two `main =` rows are DEPLOY-ONLY; `TEL-T4` has no local effect;
`MCP-P6` is the known weakly-gated row; `CLI-8` is a known NO-GATE).

**Four are newly-found unproven seams:**

| ID | Tier | What is unproven |
|---|---|---|
| **GW-C11** | T3 | `app.get("/version", …)` is asserted by nothing — `grep -rn "/version" apps/gateway/test` → 0 |
| **MCP-R4** | T2 | the `app.onError` 500 envelope code is asserted by nothing — `grep -rn internal_error apps/mcp/test` → 0 |
| **AR-C2** | T2 | `app.notFound(notFoundHandler)` is dead for every path the suite probes: `middleware/auth.ts:574,585` throws the identical `404 not_found` first, so the handler only fires outside `/v1/*` |
| **CLI-7** | T2 | the composition root's `--ca-bundle` transport. `test/transport.test.ts:360,367` builds its OWN transport and never calls `createDefaultRuntime()` — the exact factory-vs-mount confusion that made GW-A1 a fake mount last wave |

Each GREEN was hand-checked to confirm the mutation genuinely changed behaviour
rather than being a semantic no-op (§16.3). **None of the four is money, auth or
tenant isolation**; all are T2/T3. Three of the four sit in the set §15.5
recorded as SKIPPED by wave 14's incremental policy — the cost of that trade,
now measured rather than asserted.

**One genuine improvement to record:** the new `test/env-var-drift.test.ts` gates
in all five Workers **closed six holes §15.3 had recorded as ungated** —
`GW-T17`, `GW-T18`, `GW-TS`, `CP-T5`, `AR-T9` and `TEL-T3` all now go RED. They
remain *drift* gates, not behavioural ones (pinned miniflare bindings still win
over committed values), but a deleted or renamed var is no longer invisible.

### 1.2 Real boot

All five Workers were booted in real workerd via `bunx wrangler dev --local` on
distinct ports, each printed "Ready on", each answered `/healthz` **200**, each
was killed. No live Cloudflare resource was created or mutated; no
`wrangler deploy` was run.

```
gateway        ready /healthz 200 {"status":"ok","service":"ferrogate-gateway","runtime":"workers"}
control-plane  ready /healthz 200 {"status":"ok","service":"ferrogate-control-plane","runtime":"workers"}
mcp            ready /healthz 200 {"status":"ok","service":"ferrogate-mcp","runtime":"workers","protocol":"2026-07-28"}
agent-runtime  ready /healthz 200 {"ok":true}
telemetry      ready /healthz 200 {"status":"ok","service":"ferrogate-telemetry","runtime":"workers"}
```

Note `agent-runtime`'s `{"ok":true}` — a *different document* from the other
four and from the Rust. That is finding op-53/54 in the data-plane certification
and it is visible right here in the boot proof.

### 1.3 E2E

`bunx playwright test --config e2e/playwright.config.ts` → **21 passed**, exit 0,
unchanged from the previous wave. E2E covers `apps/gateway` and `apps/mcp` only;
`control-plane`, `agent-runtime` and `telemetry` are not in it.

---

## 2. Every DIVERGENT / MISSING / IN-MEMORY-ONLY finding, with blast radius

Consolidated from `cutover-parity-dataplane.md`, `cutover-parity-controlplane.md`
and `cutover-parity-libraries.md`. Nothing is summarised away.

### 2.1 Data plane — 27 DIVERGENT, 3 MISSING of 54 operations

| ID | Finding | Ops | Blast radius |
|---|---|---:|---|
| **D1** | **CLOSED (wave 16) except the shared RPM counter — see §0.1.** **The admission half of `authenticate()` did not cross the Worker split.** `403 tenant_identity_required` · lifecycle suspension · `503 quota_resolution_unavailable` · `403 quota_scope_disabled` · `429 monthly_budget_exceeded` · `429 wallet_balance_exhausted` · `429 rate_limit_exceeded` are mounted on `apps/gateway` only. `grep -rn "rate_limit_exceeded\|monthly_budget_exceeded" apps/mcp/src apps/agent-runtime/src` → nothing | **20** | **CRITICAL — money + abuse.** Rate limits and spend caps bypassable by calling a different verb on the same key. Exploitable with no special knowledge. Not a platform limit; the fix needs all three Workers to share ONE counter namespace, or a per-Worker counter hands each surface a full quota (a different bug) |
| **D2** | **The workflow GRAPH gate is unported.** `[[agent_workflows]]` is parsed and validated by `packages/config` and read by nothing (`grep -rn "agent_workflows\|agentWorkflows" apps/` → nothing). 13 Rust refusal codes absent. Header set also renamed (`…-node-id`/`…-iteration` have no reader; `…-run-id` is new and required) | 5 | **HIGH — policy bypass.** Node pinning, edge transitions, iteration/model-call limits and workflow timeout all stop being enforced while the config is accepted. A Rust-shaped workflow client is refused `400` outright |
| **D3** | `x-ferrogate-agent-run-id` is read on assets and MCP but **not** on the inference path (`grep -rn "agent-run-id" apps/gateway/src/inference/ apps/gateway/src/metering/` → nothing) | 5 | **MEDIUM — evidence.** Model spend cannot be joined to the agent run that caused it. Cost attribution has a hole exactly where the cost is |
| **D4** | **CLOSED (wave 16) — see §0.1.** **Asset egress: no quota gate, no metering, no pull audit.** `monthly_egress_bytes_budget` / `download_rpm_limit` are parsed, persisted and served by the admin API and read by nothing; `asset_egress_price_per_gb` has no consumer | 1 | **HIGH — money.** Unlimited bandwidth served and none of it billed. An operator can configure an egress budget, see it echoed back, and have it enforce nothing |
| **D5** | **CLOSED (wave 16) — see §0.1.** **Asset publish gate 1 unported**: the per-`asset_type` content-type allowlist, and the `mcp_manifest` **stdio refusal** | 2 | **HIGH — security.** Any byte stream publishable under any asset type; a tenant can publish an `mcp_manifest` declaring `stdio`, which makes a *consuming* agent spawn an arbitrary local process. Pure function of two strings and a buffer — no platform limit |
| **D6** | `503 node_draining` is advertised by `/readyz` and honoured by nothing (`grep -rn "node_draining" apps/` → nothing). Rust re-checks the flag per AI request on 5 handlers | 5 | **MEDIUM — operational.** Draining a deployment before a migration still takes new billable traffic |
| **D7** | Agent-job event feed, three divergences: `object` is `"list"` not `"agent_job_event_page"`; `?limit=0` / `?limit=abc` answer 200 with 100 rows where Rust answers `400 invalid_event_cursor`; the resume cursor regressed to the bare event id, so a poll loop **re-delivers its whole retained history** after a retention pass. Plus `getAgentJobResult` drops `work_products` | 2 | **MEDIUM — correctness.** Pagination clients break three ways |
| **MISSING** | `listTools`, `executeTool`, `executeFunction` answer **501** | 3 | Contract operations that do not exist. `executeFunction` additionally needs Containers (paid-plan prerequisite) |
| — | `/healthz` lost `version`; **`agent-runtime` `/readyz` answers a flat 200 unconditionally** — no revision check, no drain check, never 503 | 2 | **MEDIUM.** A load balancer gets "ready" from a Worker that cannot serve, forever; a health-checked rollout of a broken agent-runtime is never rolled back |
| — | `GET /metrics` renders 2 gauges where Rust rendered 47 `ferrogate_*` series | 1 | **MEDIUM.** Every existing FerroGate dashboard and alert goes blank at cutover |
| — | Smaller: three asset-validation codes collapsed to `invalid_request`; `renderPromptTemplate` writes no audit trail; `listAgentSkills` needs `skills.read` where Rust needed `tools.read`; a misspelled `x-ferrogate-config` silently selects the DEFAULT posture instead of erroring; `semantic_cache.rs` has no TS counterpart while the `semantic_hit` metric series is still rendered | — | LOW each, real in aggregate |

### 2.2 Control plane — 15 groups / 87 of 197 ops DURABLE-BUT-UNREAD

There are **0 MISSING routes and 0 IN-MEMORY-ONLY groups** here (`resolveStore`
*throws* rather than silently degrading — the silent-data-loss shape was
deliberately removed). The defect is one level deeper: mounted, reached,
authorized, audited, tenant-fenced — and writing to a store nothing reads.

| Group | Ops | The reader looks somewhere else | Blast radius |
|---|---:|---|---|
| `rbac` **— CLOSED (wave 16)** | 11 | `tenant_role_bindings ⋈ roles`, read by 4 modules across 3 Workers | **HIGH — security.** A granted role authorizes nothing; **`DELETE /admin/v1/tenant-roles/{t}/{r}` answers 200 and revokes nothing** |
| `wallets` | 10 | `wallets.balance_credits` + `wallet_reservations` in the TENANT db (admin writes `balance_cents` in the CONTROL db) | **HIGH — money.** Crediting a wallet does not fund a request |
| `guardrail_policy` **— STILL OPEN; blocker documented in place, §0.1** | 10 | `guardrail_policy_revisions` / `guardrail_policy_bindings` | **HIGH — safety.** An activated policy is never evaluated |
| `admin_api_key` **— CLOSED (wave 16)** | 6 | `static_api_keys` — and no secret is minted at all | **HIGH — security.** The group cannot produce a working credential and cannot revoke one; both answer 200 |
| `admin_request_log` | 5 | `request_logs` has no writer at all | MEDIUM — evidence |
| `admin_provider` / `admin_model` | 4 | Rust reads live config + dispatches a catalog per provider | MEDIUM |
| `agent_run` | 3 | the `AgentRunState` Durable Object | MEDIUM — evidence |
| `admin_agent_cost_burn` | 1 | `agent_cost_burn` in the TENANT db | MEDIUM |
| `prompt` / `admin_agent_upstream` | 12 | the `GATEWAY_PROMPT_TEMPLATES` / `GATEWAY_AGENT_UPSTREAMS` **vars** | MEDIUM — admin CRUD needs a redeploy to take effect |
| `skill` / `admin_plugin` / `admin_policy` / `admin_agent_workflow` | 25 | no reader | LOW — the Rust surfaces were also thin config CRUD |

Plus three PARTIAL findings that are not "unread":

- **CLOSED (wave 16) — see §0.1.** ~~The tenant WRITE fence is wider than Rust.~~ The write fence is now `tenant_id = ?` in both the D1 and the memory store, split from the read predicate and mutation-pinned in both. The original finding, for the record: `tenantScopeSql` is
  `tenant_id IS NULL OR tenant_id = ?`. For SELECT the widening is deliberate,
  argued and pinned. **It is also on `#update`, `remove` and the `atomic` batch,
  and no test pins the write side** — so a tenant-scoped credential holding
  `admin.write` can PATCH or DELETE any un-attributed platform row: a global
  `role`, a shared `policy`, a `plan` other tenants are billed against. Rust
  makes that unreachable. **HIGH — cross-tenant integrity.**
- **`billing.replay` can never replay a real dead letter.** It requires a
  `billing-outbox-dead-letters` DOCUMENT before it will re-arm; the sweeper
  dead-letters the ROW. A genuine dead letter answers **404**. MEDIUM — money.
- **Three mutation-receipt envelope keys are wrong on the wire**
  (`api_key`/`key`, `mcp_server`/`server`, `tenant_account`/`tenant`), and
  **`apps/cli`'s receipt harvester is blind to the admin envelope** — it searches
  only the top level where Rust searches top level *then* `wrapped_resource`, so
  against a real control-plane response every harvested receipt field collapses
  to its absence code and a guardrail revision mutation emits **no reversal
  command at all**. 339 CLI tests stay green because the fixture uses a bare body
  the control plane never returns. MEDIUM — operator tooling.

### 2.3 Libraries — 12 of 13 packages faithful; four unported slices; one unheld invariant

The library layer is the strongest part of the tree: the six correctness-critical
algorithm families (quota merge + counter-key namespacing, billing settled-cost /
`price_not_found` / bigint credits / idempotency, wallet no-oversell, guardrail
detector families, provider retry/breaker/failover/canary, the 56/56 portable
config validators) are all reproduced, and five of six are held by tests proven
RED by mutation. The counter-key port even **closes a reachable hole the Rust
still has** (`auth.rs:225 tpm_window` falls back to the raw, un-namespaced key id).

What is not there:

| Finding | Blast radius |
|---|---|
| **`ferrogate-cloudflare` is the 21st crate and appears in NO row of `PORT-PLAN.md`.** Four slices have no TS equivalent anywhere: (1) per-tenant R2 bucket provisioning; (2) minting SCOPED temporary R2 S3 credentials; (3) the required token-permission-group list + the `preflight` GET that names WHICH group is missing; (4) the shared retry/backoff honouring Cloudflare's ~1,200 req/5 min API limit plus the typed auth/missing-scope code mapping | **The single strongest argument against deleting the Rust.** These are account-MANAGEMENT operations, so no request path misses them — which is exactly why they would be most painful to re-derive. There are instead **three independent partial Cloudflare v4 clients**, each decoding the `{success,errors,result}` envelope itself |
| **CLOSED (wave 16) — see §0.1.** **Guardrail evidence-fingerprint KEYING is held by nothing.** Two semantically-real mutations (key → empty bytes; key → the constant `"FIXED"`) both left **407/407 guardrails + 112/112 gateway guardrail tests GREEN**. Every assertion is the SHAPE `/^hmac-sha256:[0-9a-f]{64}$/`, which an *unkeyed* SHA-256 also satisfies | **Security, test-integrity.** An unkeyed digest of a short secret is reversible by dictionary attack. Removing the key is precisely the regression the keying exists to prevent. **Test-only to close; hours of work** |
| **Cloudflare AI Gateway routing (#406) is unreachable in production.** `packages/providers` applies it; `apps/gateway/src/inference/adapters.ts` builds its own registry and never goes through that class. Not even *configurable* — `providerRecordSchema` is `.strict()` with no `cloudflare_ai_gateway` key, so a provider carrying the Rust block is REJECTED | MEDIUM — a live product feature (free caching, rate-limiting, observability) is off for every tenant. The textbook instance of this project's defect class, correctly identified and still open |
| `packages/sync-bridge` — zero importers, inventory target is literally `Deleted` | Recommend deleting the package. No risk |
| `packages/storage` carries credit amounts as `number`, `packages/billing` as `bigint`. Nothing asserts the boundary | LOW — unreachable below ~9.0e15 credits, but the two layers do not share an integer type |

### 2.4 IN-MEMORY-ONLY, as committed

| Worker | As committed | Consequence |
|---|---|---|
| `apps/mcp` | `FG_DEV_IN_MEMORY_PORTS = "1"` (`wrangler.toml:37`) | Auth, approvals, guardrails and secrets ARE durable in every posture. But `resolvePorts` short-circuits at `ports.ts:1723`, so `DurableCredentialStore` and the identity cipher stay in-memory: **OAuth grants die with the isolate** |
| `apps/agent-runtime` | `FG_DEV_IN_MEMORY_PORTS = "1"` (`wrangler.toml:64`); both D1 stanzas commented out | Real `d1ApiKeyPort` / `d1WorkerIdentityPort` exist and win when bound, and `resolveDeps` fails CLOSED when neither is — but **as committed, both are the dev bundle**. `governance` and `upstreams` have no durable leg in any posture |
| `apps/agent-runtime` | `FG_REQUIRE_PRODUCTION_MTLS = "0"` | Committed OFF. Must be `"1"` in production |
| `apps/agent-runtime` | `CONTAINER_SANDBOX` / `[[containers]]` commented out | `@cloudflare/sandbox` is a declared dependency; the binding is commented because Containers need a paid account. `agent-worker`'s only portable isolation backend is declared and unbound |
| `packages/guardrails` | `guardrail_evaluations` / `guardrail_check_evaluations` **do not exist in `sql/d1-ts/`** | Guardrail evidence is in-memory only |

`CLOUD-VERIFICATION.md` §B1 covers the two `FG_DEV_IN_MEMORY_PORTS` flags by
*procedure*. **Nothing mechanical stops a deploy inheriting any of the three.**
Seams `MCP-T9`, `AR-T6` and `AR-T7` prove the values are the committed ones; they
do not prevent them shipping.

---

## 3. The true portable marker residue, and what of it blocks cutover

From `MARKER-LEDGER.md`, which classified all 170 `PORT-TODO(` occurrences.

### 3.1 The count is not the story

| | |
|---|---|
| Repo-wide grep | 170 — **has never been the residue** |
| Canonical (`packages/*/src` + `apps/*/src`) | 130 at 05:40 |
| **P — PORTABLE** | 48 at 05:40 → **65 by 06:17** |
| **L — PLATFORM LIMIT** | 51, each naming a specific falsifiable limitation |
| **D — DEPRIORITIZED** (x402/Solana, by standing directive) | 10 |
| **N — NOT A MARKER** (epitaphs, cross-refs) | 20, de-marked to `PORT_TODO(` |
| **True portable residue** | **~43 distinct work items ≈ 100–145 dev-days** — *a floor, not an estimate* |

**The single most important number in this document is not any of those. It is
`+25 portable markers in ninety minutes`** — all written by concurrent
certification passes, including the eight most consequential findings in the
ledger (§3.1b: D1, D2, D4, D5, D6, D7 above, plus the guardrail-keying gap).
A fifth of the total residue, and the most severe fifth, was discovered by ONE
targeted audit of ONE surface, *while the ledger that was supposed to bound the
residue was being written*.

De-marking, prefixing and classification are genuinely useful and permanent work
— separating the 51 real platform limits from everything else will not have to
be done again. But **marker burndown has not hit diminishing returns**, and any
cutover decision framed as "130 markers, mostly platform limits" would rest on a
false premise.

### 3.2 What of it blocks deleting `crates/**`

Sixteen items. Deleting the Rust destroys the only specification for each.

- **Admission / money / abuse (4):** P39 + P40 (the dropped admission ladder on
  `apps/mcp` and `apps/agent-runtime` = finding D1) · P43 (asset egress quota +
  download RPM = D4) · P41 (workflow graph gate = D2).
- **Security (4):** P42 (asset content-type allowlist + `mcp_manifest` stdio
  refusal = D5) · P13 (self-hosted worker transport AEAD seal unverified) ·
  P21 (cross-tenant publish-approval + malware scan legs) · P6 (eligibility gate
  admits candidates Rust refuses).
- **Behavioural regressions (5):** P1 (CORS entirely absent — Rust ran
  `apply_cors_headers` on 9 response sites) · P2/P3/P4 (three ops answer 501) ·
  P5 (profile-resolution errors silently downgraded) · P8
  (`[[models]].cache_enabled` silently ignored) · P44 (drain honoured on 1 route
  of 31) · P46 (`?limit=0` → 200 instead of 400).
- **Specification-bearing (3):** P7 (Rust embeds the `cl100k_base` / `o200k_base`
  vocabularies — the TS estimates `chars/4`, and it feeds budget admission) ·
  P10 (the Rust extractor defines what a legitimate payload is) · P20
  (Rust `asset_bucket.rs` is the multipart contract).
- **Test-integrity (1):** P45 (guardrail evidence-fingerprint keying — the Rust
  is the only statement of what the key is FOR).

The remaining ~26 items are internal wiring, dead-code removal and duplication
cleanup. **They do not need the Rust and can proceed in parallel with it in the
tree.** Blocking on them would be over-caution; blocking on the sixteen is not.

### 3.3 Items with non-engineering prerequisites

These cannot be scheduled at all until something outside the repo changes:

- **R2 is not enabled on the live Cloudflare account** → P26 (MCP asset reader),
  and the `ferrogate-cloudflare` R2 provisioning slices.
- **Containers / `@cloudflare/sandbox` need a paid plan and a published image** →
  P4 (`executeFunction`), P27 (the `governance` port).
- **Secrets Store bindings resolve at DEPLOY time** and are unexercisable under
  `wrangler dev --local` → P14.

---

## 4. What is still UNVERIFIED — provable only by the live deploy

Every result in this repository, in every wave, comes from
`@cloudflare/vitest-pool-workers` or `wrangler dev --local`. The following are
believed correct and are **not** certified.

### 4.1 Only a real `wrangler deploy` can settle these

1. **The three DEPLOY-ONLY seams** — `GW-T2`, `CP-T2`, `MCP-T2`, `TEL-T5`
   (`compatibility_flags`) and `CP-T1`, `TEL-T1` (`main = "src/worker.ts"`).
   Confirmed GREEN under the full local suite this wave: nothing in the tree
   imports a `node:` builtin on a path the suites reach, and the local pool does
   not run workerd's entrypoint-shape check on `main`.
2. **`[[migrations]]` acceptance.** The local pool builds a DO namespace from the
   BINDING alone and never reads `[[migrations]]`. The gates ported in wave 14
   now assert the stanzas *textually* (all seven `new_sqlite_classes` rows went
   RED, including the `new_classes` substitution variants), but whether
   Cloudflare accepts them is a deploy fact.
3. **Secrets Store bindings** (P14) — deploy-time by construction.
4. **The `FG_DEV_IN_MEMORY_PORTS = "0"` override** required by
   `CLOUD-VERIFICATION.md` §B1. The committed `"1"` is what a naive deploy
   inherits (§2.4).
5. **Per-tenant D1 provisioning and binding**, incl. `GATEWAY_TENANT_DB_ROUTING`
   flipped away from its committed `"off"`. Deploy-time binding is the standing
   open constraint on the whole one-database-per-tenant design.
6. **Queue producer/consumer delivery** on the `BILLING` queue, and the
   `TELEMETRY_COLLECTOR` service binding across two deployed Workers.
7. **Analytics Engine write and read.** The read side is account-scoped REST with
   no offline emulation, which is why `observability()` returns `[]`.
8. **Cron trigger delivery.** `[triggers] crons` is asserted textually and the
   `scheduled` handler is invoked directly; that Cloudflare actually fires it on
   schedule is unproven.
9. **The ~1,200 req / 5 min Cloudflare API rate limit** and the typed
   auth / missing-scope code mapping (`ferrogate-cloudflare` slice 4).

### 4.2 Unverified for reasons a deploy would NOT fix

10. **Per-operation request/response *field* parity for ~60 control-plane
    collections** — bodies validate against a shared `passthrough()` base.
11. **Envelope keys beyond the three found.** Only Rust structs named
    `*MutationResponse` were swept.
12. **Search/filter field sets per collection.** Rust's `matches_search` uses a
    per-handler field list; the TS store applies `search` uniformly.
13. **Streaming SSE framing byte-for-byte** against Rust `messages_stream.rs` /
    `responses_stream.rs` — the suites are thorough but no normalised-frame diff
    was run.
14. **`sigv4` (Bedrock) and Vertex OAuth signing** against real AWS/GCP canonical
    request vectors.
15. **Three storage CAS / state-machine items not mutation-tested**: the
    workflow-budget optimistic CAS, the guardrail-binding generation CAS, and the
    payment-attempt state machine — **which has no dedicated test file at all**.
16. **`crates/ferrogate-auth-service`'s non-contract surface** — `/v1/admin/*`
    console identity, `/v1/auth/*`, `/scim/v2/*`, SAML/SSO: **11,474 LOC, a real
    and large unported cluster**, and the control plane's own `admin_users` /
    `sso_provider_configs` / `sso_pending_flows` tables have no writer. Outside
    every audit's declared scope so far. **This must not be forgotten at
    cutover.**
17. **The 51 `L` platform-limit claims were spot-checked, not exhaustively
    re-derived** (~15 checked, all held). If any single `L` is wrong, it is a `P`.
18. **The eight mid-wave §3.1b findings** are recorded on their author's
    authority; their `grep` evidence is quoted in each marker but was not
    independently re-run in the ledger (two spot-checks did hold).

---

## 5. The irreversibility note

`crates/**` is tagged `legacy-rs` and every byte is recoverable from git. **That
is not the same as the deletion being reversible in the way that matters.**

What the working-tree copy actually provides is a *diffable* reference. Every
certification in this wave was produced by an agent reading a Rust handler body
and a TypeScript handler body side by side, in one workspace, with `grep -rn`
spanning both. That is how D1 was found — not from a marker, not from a failing
test, but because someone read `finalize_auth` next to `contractAuth` and noticed
half of it was missing. The marker ledger states the same conclusion in one line:
*"half the severe defects in this ledger had no marker at all until someone read
the Rust handler next to the TS handler and compared them line by line."*

After deletion, that workflow ends. Recovering a tag into a scratch directory is
mechanically easy and practically almost never done: it is not in the workspace,
agents do not `grep` it, and the reference stops being consulted. Parity checking
degrades from *comparison* to *archaeology* — a defect found post-cutover gets
re-derived from observed behaviour, which is exactly what produced the
`?limit=0` divergence (the TS carries a comment asserting *"Rust: silently
clamped, never rejected"* which is **factually wrong about the Rust**, and which
survived precisely because nobody re-read the Rust).

So the deletion is best understood as **the irreversible step in this project,
even though the bytes are recoverable.** It should be taken once, deliberately,
after the sixteen specification-bearing items of §3.2 are either closed or
transcribed into this repository as ratified divergences — because transcription
is the only thing that survives the delete.

**Corollary, worth doing regardless of the verdict:** the four `ferrogate-cloudflare`
slices (§2.3) and a Rust-generated golden bucket table for `rolloutBucket` are
cheap to extract *now* and impossible to extract later. They should be written
down before any GO is reconsidered, not after.

---

## 6. What would turn this into a GO

Ordered by what unblocks the decision, not by size. Items 1–5 are the cutover
gate; the rest is ordinary work that can proceed alongside.

> **Wave-16 status line.** Items 1–4 are **DONE except one leg of item 1 and two
> of the four groups in item 3**; see §0.1 for exactly what was closed, and for
> the RED-before/GREEN-after each closure was verified with. **Item 6 is what
> gates the verdict and has not been started.** Items marked DONE below are kept
> in place rather than deleted, because the list is also the record of what the
> cutover gate WAS.

1. ~~**Close D1**~~ — **DONE except the shared RPM counter (wave 16).** The
   ladder is mounted on `apps/mcp` and `apps/agent-runtime`, and the quota
   chain, monthly budget, wallet hold and the counter-KEY derivation are one
   shared, durable answer across all three Workers. The RPM WINDOW is not yet
   one counter: it needs `apps/gateway`'s `RateLimiterDurableObject` bound
   cross-script, which **workerd cannot resolve offline**, so the stanza is
   committed COMMENTED in both `wrangler.toml`s and is DEPLOY-ONLY. Per-isolate
   RPM until then. This was the only finding that is a live control bypass
   rather than a fidelity gap, and the bypass itself is closed.
2. ~~**Close D4 and D5**~~ — **DONE (wave 16).** Asset egress quota + metering
   (`src/assets/egress.ts`); the content-type allowlist and the `mcp_manifest`
   stdio refusal (`src/assets/content-gate.ts`, enforced ahead of the screener
   and not through it).
3. **Close the control-plane write half for `rbac`, `admin_api_key`,
   `guardrail_policy` and `wallets`** (37 ops) — the four groups where a 200
   response means "nothing happened" on a security or money surface. Plus the
   one-line `tenantScopeSql` write-fence split, with a mutation test.
   **PARTLY DONE (wave 16): `rbac` (11) and `admin_api_key` (6) are closed and
   mutation-pinned, and the write fence is split in BOTH stores. `wallets` (10)
   is untouched. `guardrail_policy` (10) is deliberately still open — projecting
   today's partially-validated revisions would take the gateway's guardrail
   source down at boot, because `policySourceFromStore` compiles checks eagerly
   with no `try`/`catch`; closing it means tightening the create-revision
   ADMISSION first. The reason is written into `routes/guardrail_policy.ts` so
   it is not rediscovered.**
4. ~~**Close the guardrail evidence-fingerprint keying gap**~~ — **DONE
   (wave 16).** `packages/guardrails/test/fingerprint-keying.test.ts`, 32 cases
   over all four fingerprint sites, checked against an independent `node:crypto`
   oracle. No source change was needed; the code was always correct, only unheld.
5. **Extract the four `ferrogate-cloudflare` slices** into `@ferrogate/cloudflare`
   or into a document that survives the deletion, and add the missing 21st-crate
   row to `PORT-PLAN.md`.
6. **Re-run all three parity certifications** afterwards, and re-run the FULL
   seam pass. Do not inherit either.
7. **Scope `crates/ferrogate-auth-service`'s 11,474 unported lines** (§4.2 item
   16) — decide explicitly whether SSO/SCIM is in or out of the cutover, because
   right now it is neither.
8. Close the four newly-unproven seams (GW-C11, MCP-R4, AR-C2, CLI-7); mutation-
   test the three storage CAS/state-machine items; give
   `payment-attempt.ts` a test file; mount AI Gateway routing (#406); delete
   `packages/sync-bridge`; move `FG_DEV_IN_MEMORY_PORTS` into an `[env.dev]`
   block so a deploy cannot inherit it.

**Then, and only then**, run the single authorised live deploy against the §4.1
list — because half of that list is unprovable any other way, and a deploy is
also the only way to find out what §4.1 does not yet know it is missing.

---

## 7. Scope statement

This wave: **local only.** No `wrangler deploy` was run. No live Cloudflare
resource was created, read or mutated. No real upstream LLM was called. No
`crates/**` or `workers/**` file was modified or deleted; none was read except
for comparison. Every one of the 163 seam mutations was reverted and verified
byte-identical by `sha256sum -c`, and the whole 827-file tree was re-verified
against a pre-pass snapshot. No test was weakened, skipped or deleted.

The cutover itself remains a separate, human-gated decision. This document is
evidence for it, not an execution of it.

**Wave 16 (the amendment in §0.1): local only, on the same terms.** No
`wrangler deploy`, no live Cloudflare resource, no real upstream LLM call, and no
`crates/**` or `workers/**` file created, modified or deleted. Every fix
verification in §0.1 was a mutation that was reverted and re-verified GREEN, and
every mutation was `grep`-confirmed to have landed before its RED was believed.
No test was weakened, skipped or deleted; the two `env-var-drift` exception lists
that changed were made STRICTER (a name moved from "not even mentioned in
`wrangler.toml`" to "mentioned but undeclared", and three new assertions were
added pinning the `RATE_LIMIT` stanza's commented state, its `script_name`, and
the absence of a migration claiming a class the script does not export).

---

# APPENDIX S — the wave-19 full seam pass, row by row

Every row of `MOUNT-SEAMS.md`, mutated in place, confirmed off disk, run, restored and sha256-verified. `—` in the *Failing assertions* column means the RED came from a runtime/module-load refusal rather than an assertion (mechanism named in §3.2).

| Row | App | Verdict | Failing assertions | RED mechanism |
|---|---|---|---:|---|
| `AR-C1` | agent-runtime | RED | 112 | assertion RED |
| `AR-C10` | agent-runtime | RED | 6 | assertion RED |
| `AR-C11` | agent-runtime | RED | 195 | assertion RED |
| `AR-C2` | agent-runtime | RED | 3 | assertion RED |
| `AR-C3` | agent-runtime | RED | 5 | assertion RED |
| `AR-C4` | agent-runtime | RED | 149 | assertion RED |
| `AR-C5` | agent-runtime | RED | 73 | assertion RED |
| `AR-C6` | agent-runtime | RED | 15 | assertion RED |
| `AR-C7` | agent-runtime | RED | 99 | assertion RED |
| `AR-C9` | agent-runtime | RED | 1 | assertion RED |
| `AR-E1` | agent-runtime | RED | 194 | assertion RED |
| `AR-E2` | agent-runtime | RED | 77 | assertion RED |
| `AR-E3` | agent-runtime | RED | 93 | assertion RED |
| `AR-P1` | agent-runtime | RED | 13 | assertion RED |
| `AR-P2` | agent-runtime | RED | 11 | assertion RED |
| `AR-P3` | agent-runtime | RED | 4 | assertion RED |
| `AR-P4` | agent-runtime | RED | 3 | assertion RED |
| `AR-P5` | agent-runtime | RED | 15 | assertion RED |
| `AR-P6` | agent-runtime | RED | 4 | assertion RED |
| `AR-P7` | agent-runtime | RED | 3 | assertion RED |
| `AR-P8` | agent-runtime | RED | 4 | assertion RED |
| `AR-T1` | agent-runtime | RED | 1 | assertion RED |
| `AR-T10` | agent-runtime | RED | 1 | assertion RED |
| `AR-T2` | agent-runtime | RED | — | runtime/module refusal |
| `AR-T2b` | agent-runtime | RED | 1 | assertion RED |
| `AR-T3` | agent-runtime | RED | 81 | assertion RED |
| `AR-T4` | agent-runtime | RED | 97 | assertion RED |
| `AR-T5` | agent-runtime | RED | 1 | assertion RED |
| `AR-T5b` | agent-runtime | RED | 1 | assertion RED |
| `AR-T6` | agent-runtime | RED | 4 | assertion RED |
| `AR-T7` | agent-runtime | RED | 4 | assertion RED |
| `AR-T8` | agent-runtime | RED | 4 | assertion RED |
| `AR-T9` | agent-runtime | RED | 4 | assertion RED |
| `AR-V1` | agent-runtime | RED | 2 | assertion RED |
| `CLI-1` | cli | RED | 16 | assertion RED |
| `CLI-2` | cli | RED | 16 | assertion RED |
| `CLI-3` | cli | RED | 16 | assertion RED |
| `CLI-4` | cli | RED | 16 | assertion RED |
| `CLI-5` | cli | RED | 16 | assertion RED |
| `CLI-6` | cli | RED | 1 | assertion RED |
| `CLI-7` | cli | RED | 3 | assertion RED |
| `CLI-8a` | cli | RED | 1 | assertion RED |
| `CLI-8b` | cli | RED | 1 | assertion RED |
| `CP-A1` | control-plane | RED | 427 | assertion RED |
| `CP-A10` | control-plane | RED | 2 | assertion RED |
| `CP-A11` | control-plane | RED | 2 | assertion RED |
| `CP-A2` | control-plane | RED | 328 | assertion RED |
| `CP-A3` | control-plane | RED | 21 | assertion RED |
| `CP-A4` | control-plane | RED | 19 | assertion RED |
| `CP-A5` | control-plane | RED | 121 | assertion RED |
| `CP-A6` | control-plane | RED | 131 | assertion RED |
| `CP-A7` | control-plane | RED | 26 | assertion RED |
| `CP-A8` | control-plane | RED | 3 | assertion RED |
| `CP-A9` | control-plane | RED | 3 | assertion RED |
| `CP-C1` | control-plane | RED | 171 | assertion RED |
| `CP-C10` | control-plane | RED | 4 | assertion RED |
| `CP-C11` | control-plane | RED | 1 | assertion RED |
| `CP-C12` | control-plane | RED | 2 | assertion RED |
| `CP-C13` | control-plane | RED | 1 | assertion RED |
| `CP-C2` | control-plane | RED | 3 | assertion RED |
| `CP-C3` | control-plane | RED | 3 | assertion RED |
| `CP-C4` | control-plane | RED | 1 | assertion RED |
| `CP-C4b` | control-plane | RED | 385 | assertion RED |
| `CP-C5` | control-plane | RED | 1 | assertion RED |
| `CP-C6` | control-plane | RED | 2 | assertion RED |
| `CP-C7` | control-plane | RED | 324 | assertion RED |
| `CP-C8` | control-plane | RED | 285 | assertion RED |
| `CP-C9` | control-plane | RED | 3 | assertion RED |
| `CP-E1` | control-plane | RED | 398 | assertion RED |
| `CP-E2` | control-plane | RED | 3 | assertion RED |
| `CP-E3` | control-plane | RED | 399 | assertion RED |
| `CP-R1` | control-plane | RED | — | runtime/module refusal |
| `CP-R2` | control-plane | RED | 284 | assertion RED |
| `CP-S1` | control-plane | RED | 18 | assertion RED |
| `CP-S2` | control-plane | RED | 11 | assertion RED |
| `CP-S3` | control-plane | RED | 12 | assertion RED |
| `CP-S4` | control-plane | RED | 2 | assertion RED |
| `CP-S5` | control-plane | RED | 5 | assertion RED |
| `CP-T1` | control-plane | RED | 1 | assertion RED |
| `CP-T2` | control-plane | RED | 1 | assertion RED |
| `CP-T3` | control-plane | RED | 5 | assertion RED |
| `CP-T4` | control-plane | RED | 3 | assertion RED |
| `CP-T5` | control-plane | RED | 4 | assertion RED |
| `CP-T6` | control-plane | RED | — | runtime/module refusal |
| `GW-A1` | gateway | RED | 21 | assertion RED |
| `GW-A2` | gateway | RED | 3 | assertion RED |
| `GW-A3` | gateway | RED | 3 | assertion RED |
| `GW-A4` | gateway | RED | 6 | assertion RED |
| `GW-A5` | gateway | RED | 6 | assertion RED |
| `GW-A6` | gateway | RED | 4 | assertion RED |
| `GW-A7` | gateway | RED | 5 | assertion RED |
| `GW-A8` | gateway | RED | 3 | assertion RED |
| `GW-C1` | gateway | RED | 2 | assertion RED |
| `GW-C10` | gateway | RED | 1 | assertion RED |
| `GW-C2` | gateway | RED | 57 | assertion RED |
| `GW-C3` | gateway | RED | 19 | assertion RED |
| `GW-C4` | gateway | RED | 3 | assertion RED |
| `GW-C5` | gateway | RED | 3 | assertion RED |
| `GW-C6` | gateway | RED | 16 | assertion RED |
| `GW-C7` | gateway | RED | 130 | assertion RED |
| `GW-C8` | gateway | RED | 1 | assertion RED |
| `GW-C9` | gateway | RED | 78 | assertion RED |
| `GW-E1` | gateway | RED | 181 | assertion RED |
| `GW-E2` | gateway | RED | 3 | assertion RED |
| `GW-E3` | gateway | RED | 5 | assertion RED |
| `GW-E4` | gateway | RED | 5 | assertion RED |
| `GW-E5` | gateway | RED | 3 | assertion RED |
| `GW-E6` | gateway | RED | 184 | assertion RED |
| `GW-R1` | gateway | RED | 130 | assertion RED |
| `GW-R10` | gateway | RED | 25 | assertion RED |
| `GW-R11` | gateway | RED | 5 | assertion RED |
| `GW-R12` | gateway | RED | 38 | assertion RED |
| `GW-R13` | gateway | RED | 196 | assertion RED |
| `GW-R14` | gateway | RED | 2 | assertion RED |
| `GW-R15` | gateway | RED | 13 | assertion RED |
| `GW-R16` | gateway | RED | 2 | assertion RED |
| `GW-R2` | gateway | RED | 6 | assertion RED |
| `GW-R3` | gateway | RED | 15 | assertion RED |
| `GW-R4` | gateway | RED | 3 | assertion RED |
| `GW-R5` | gateway | RED | 10 | assertion RED |
| `GW-R6` | gateway | RED | 171 | assertion RED |
| `GW-R7` | gateway | RED | 39 | assertion RED |
| `GW-R8` | gateway | RED | 3 | assertion RED |
| `GW-R9` | gateway | RED | 16 | assertion RED |
| `GW-T1` | gateway | RED | 10 | assertion RED |
| `GW-T10` | gateway | RED | 6 | assertion RED |
| `GW-T11` | gateway | RED | 1 | assertion RED |
| `GW-T12` | gateway | RED | 6 | assertion RED |
| `GW-T13` | gateway | RED | 1 | assertion RED |
| `GW-T14` | gateway | RED | 4 | assertion RED |
| `GW-T15` | gateway | RED | 2 | assertion RED |
| `GW-T16` | gateway | RED | 8 | assertion RED |
| `GW-T17` | gateway | RED | 7 | assertion RED |
| `GW-T18` | gateway | RED | 11 | assertion RED |
| `GW-T19` | gateway | RED | — | runtime/module refusal |
| `GW-T2` | gateway | RED | 1 | assertion RED |
| `GW-T3` | gateway | RED | 26 | assertion RED |
| `GW-T4` | gateway | RED | — | runtime/module refusal |
| `GW-T5` | gateway | RED | 49 | assertion RED |
| `GW-T6` | gateway | RED | 231 | assertion RED |
| `GW-T7` | gateway | RED | 27 | assertion RED |
| `GW-T8` | gateway | RED | 5 | assertion RED |
| `GW-T9` | gateway | RED | 1 | assertion RED |
| `GW-W1` | gateway | RED | 8 | assertion RED |
| `GW-W2` | gateway | RED | 6 | assertion RED |
| `MCP-C1` | mcp | RED | 97 | assertion RED |
| `MCP-C2` | mcp | RED | 32 | assertion RED |
| `MCP-C3` | mcp | RED | 124 | assertion RED |
| `MCP-E1` | mcp | RED | 137 | assertion RED |
| `MCP-E2` | mcp | RED | 9 | assertion RED |
| `MCP-E3` | mcp | RED | 10 | assertion RED |
| `MCP-P1` | mcp | RED | 113 | assertion RED |
| `MCP-P2` | mcp | RED | 11 | assertion RED |
| `MCP-P3` | mcp | RED | 5 | assertion RED |
| `MCP-P4` | mcp | RED | 4 | assertion RED |
| `MCP-P5` | mcp | RED | 3 | assertion RED |
| `MCP-P6` | mcp | RED | 1 | assertion RED |
| `MCP-P7` | mcp | RED | 89 | assertion RED |
| `MCP-R1` | mcp | RED | 8 | assertion RED |
| `MCP-R2` | mcp | RED | 1 | assertion RED |
| `MCP-R3` | mcp | RED | 2 | assertion RED |
| `MCP-R4` | mcp | RED | 124 | assertion RED |
| `MCP-R5` | mcp | RED | 1 | assertion RED |
| `MCP-R6` | mcp | RED | 1 | assertion RED |
| `MCP-R6b` | mcp | RED | 2 | assertion RED |
| `MCP-T1` | mcp | RED | 2 | assertion RED |
| `MCP-T10` | mcp | RED | 1 | assertion RED |
| `MCP-T2` | mcp | RED | 1 | assertion RED |
| `MCP-T3` | mcp | RED | 48 | assertion RED |
| `MCP-T4` | mcp | RED | 12 | assertion RED |
| `MCP-T5` | mcp | RED | 13 | assertion RED |
| `MCP-T6` | mcp | RED | 2 | assertion RED |
| `MCP-T6b` | mcp | RED | 2 | assertion RED |
| `MCP-T7` | mcp | RED | 2 | assertion RED |
| `MCP-T7b` | mcp | RED | 2 | assertion RED |
| `MCP-T8` | mcp | RED | 118 | assertion RED |
| `MCP-T9` | mcp | RED | 86 | assertion RED |
| `TEL-A1` | telemetry | RED | 5 | assertion RED |
| `TEL-A2` | telemetry | RED | 1 | assertion RED |
| `TEL-A3` | telemetry | RED | 49 | assertion RED |
| `TEL-A4` | telemetry | RED | 11 | assertion RED |
| `TEL-A5` | telemetry | RED | 3 | assertion RED |
| `TEL-A6` | telemetry | RED | 1 | assertion RED |
| `TEL-A7` | telemetry | RED | 3 | assertion RED |
| `TEL-A8` | telemetry | RED | 3 | assertion RED |
| `TEL-C1` | telemetry | RED | 61 | assertion RED |
| `TEL-E1` | telemetry | RED | 42 | assertion RED |
| `TEL-P1` | telemetry | RED | 31 | assertion RED |
| `TEL-T1` | telemetry | RED | 1 | assertion RED |
| `TEL-T2` | telemetry | RED | 25 | assertion RED |
| `TEL-T3` | telemetry | RED | 6 | assertion RED |
| `TEL-T4` | telemetry | **GREEN** | 0 | **no local proof channel** — Workers Logs config has no local effect (DEPLOY-ONLY; §4.2) |
| `TEL-T5` | telemetry | RED | 1 | assertion RED |
| `TEL-T6` | telemetry | RED | — | runtime/module refusal |
