# Cloudflare Agent Memory Integration (issue #427)

FerroGate reads, writes, and queries a Cloudflare agent's built-in per-instance
memory as a **governed FerroGate operation**. All memory of a named agent
instance lives inside one Durable Object (per-instance isolated SQLite + state,
single-writer), and Cloudflare exposes **no first-party memory REST API** —
so every access goes through the authenticated `/memory/*` routes of the
agent-gateway Worker (issue #413), never as a direct agent-to-store call
(the *tethered principle*).

Code map:

- Worker routes + layer verbs: `workers/agent-gateway/src/memory.ts`
  (dispatched from `src/index.ts`; shared bearer auth in `src/auth.ts`)
- Rust client + naming scheme: `crates/ferrogate-runtime/src/cloudflare_agent_memory.rs`
  (`AgentMemoryClient`, `AgentInstanceIdentity`; reuses the #413/#414
  `GatewayControlTransport` seam and its block-on production bridge)

## Memory layers

| Layer | Cloudflare primitive | Gateway route | Rust verb |
|---|---|---|---|
| 1. Synced JSON state | `this.state` / `setState` (persists to SQLite, whole-object replace) | `POST /memory/state/get`, `POST /memory/state/set` | `state_get`, `state_set` |
| 2. Embedded SQLite | DO `SqlStorage` (`this.ctx.storage.sql.exec`) | `POST /memory/sql/query` | `sql_query`, `sql_query_with_prune_on_full` |
| 3. Chat history | `cf_ai_chat_agent_messages` (the `AIChatAgent` table) | `POST /memory/chat/append`, `POST /memory/chat/get`, `POST /memory/chat/prune` | `chat_history_append`, `chat_history_append_with_prune_on_full`, `chat_history_get`, `chat_history_prune` |
| Semantic (pilot, beta) | Vectorize + Workers AI embeddings | `POST /memory/semantic/query` | `semantic_query` |

All routes are POST + bearer-gated with the same `GATEWAY_CONTROL_TOKEN`
credential and constant-time check as the `/control/*` lifecycle routes.
Bodies (never query strings) carry the instance name, since names embed tenant
identity.

State writes are validated **server-side** before `setState` (the
`validateStateChange` principle: a violation aborts the write, HTTP 422). The
gateway state is a whole-object replace, so the validator checks the full
`AgentGatewayState` shape and the 2 MB value limit.

Durable Object RPC strips a thrown error's class identity, so the memory RPC
verbs return a discriminated `MemoryResult` envelope; the route maps codes to
HTTP statuses: `invalid_state` → 422, `sqlite_full` → 507, `sql_error` → 400,
`sql_forbidden` → 403.

### `/memory/sql/query` cannot reach the SDK's control tables

Caller SQL naming an `cf_agents_*` table is refused with 403 `sql_forbidden`
(Rust: `AgentMemoryError::SqlForbidden`, kept distinct from `Denied` so a
refused statement is not read as a bad credential). Without that guard the
route is a hole under two invariants this surface documents as enforced:

- the SDK persists synced state in `cf_agents_state`, so an
  `insert or replace into cf_agents_state …` would write state that
  `validateStateChange` never saw;
- the SDK's alarm dispatches `this[row.callback]` from a `cf_agents_schedules`
  row, so an INSERT there would defeat the `SCHEDULE_DISPATCH_METHOD` pin and
  re-open arbitrary-verb dispatch.

The rule is deliberately blunt — a reserved identifier **anywhere** in the
statement is refused, reads included — because deciding "is this position a
write" needs a real SQL parser, and a partial parser is how such guards fail.

A refusal is also **audited**, not just status-coded: the verb emits a
`memory.sql_forbidden` log carrying the instance name (which embeds the
tenant) and the refusal reason (which names the reserved table). The caller's
statement is deliberately **not** logged — it can carry tenant data. This is
what makes memory access a governed auth/quota/**audit** operation rather than
a 403 that leaves no trace of which tenant probed the control tables.

The scan tokenizes where SQLite does, and reads **every quoted form**:
`"x"`, `` `x` ``, `[x]` and `'x'` alike. Single quotes are included because
SQLite accepts a single-quoted token as an *identifier* wherever an identifier
is legal and a string is not, so `insert into 'cf_agents_schedules' …` really
does name the control table. The blunt consequence is that a string literal
merely *mentioning* a reserved name is refused too; pass such text as a **bound
parameter**, which the scan never reads. Inside a quoted region, `--`, `/*` and
`'` are ordinary characters — treating them otherwise desynchronizes the
scanner from SQLite's tokenizer, and the swallowed span is exactly where a
reserved name hides. A statement whose quoting or block comment never closes is
**refused rather than scanned past the end**: the guard fails closed.

Nothing legitimate is lost: layer 1 has `/memory/state/*`, layer 3 has
`/memory/chat/*`, and schedules have the #426 `/schedule/*` routes — each
applying its own governance. FerroGate's own tables (`fg_*`, the chat table)
are unaffected.

## Identity mapping: memory isolation == tenant isolation

The DO instance **name** is the isolation unit: the same name always resolves
to the same instance and its memory; a different name gets disjoint memory.
FerroGate mints names Rust-side (`AgentInstanceIdentity::instance_name`):

```
fg.{tenant_id}.{session_id}.{run_id}
```

- Components must match `[A-Za-z0-9_-]{1,64}`. The `.` separator is
  **excluded** from the component charset, so the identity → name mapping is
  injective: no two distinct (tenant, session, run) triples can mint the same
  name, hence two tenants can never address the same instance.
- Validation is strict — invalid components are **rejected, never sanitized**.
  Lossy sanitizing could fold two tenants onto one name and silently break
  isolation.
- `tenant_id` leads, so per-instance isolation is per-tenant isolation by
  construction. The Worker never derives names itself; it only addresses the
  instance the Rust side minted.
- The `/control/*` lifecycle routes currently address instances by the caller
  supplied `runId`/`runRef`. Callers that want lifecycle and memory to share
  one isolation unit should pass the minted `fg.…` name as the run reference.

Live two-tenant isolation proof (two names, disjoint memory on a deployed
Worker) is the test agent's to run; it is not locally provable.

## Size and eviction handling

- **10 GB per DO / SQLITE_FULL**: when the embedded SQLite is full, writes
  fail but reads and `DELETE` still succeed. The Worker surfaces the condition
  as HTTP 507 / `sqlite_full`; the Rust client maps it to
  `AgentMemoryError::SqliteFull`, and `sql_query_with_prune_on_full` runs the
  prune path (chat-history DELETE) and retries the statement once.
  `chat_history_append_with_prune_on_full` does the same for the layer-3
  writer — append is the only path that grows the chat table, so it meets the
  wall first, and leaving it without recovery would have made layer 2
  self-heal while the writer that filled the table returned a bare 507. Both
  retries are bounded to ONE attempt: a second `SQLITE_FULL` after a prune
  means the space is held by something the retention cap does not govern, and
  looping would report that as a hang instead of an error.
- **2 MB row/value limit**: state replaces are measured and rejected (422)
  before `setState`; oversized SQL string params and oversized
  `/memory/chat/append` messages are rejected (413) before they reach the DO.
  Every check measures **UTF-8 bytes** (`TextEncoder`) on the JSON actually
  persisted, not `String.length` — a code-unit count would let a multi-byte
  payload several times over the limit through. `chat/append` also bounds the
  caller-chosen message `id` at 256 characters (400).
- **Client-side pre-check (append)**: `chat_history_append` mirrors the
  route's three append limits — 100-message batch, 256-character `id`, 2 MB
  per message — and rejects locally with `AgentMemoryError::InvalidRequest`
  before sending. The Worker remains the enforcement point (a client check can
  never be the boundary for a network API); the local check exists so the
  caller learns **which** message was too large, which the HTTP 413 does not
  say. The constants are pinned to the Worker's in both files.
- **`maxPersistedMessages` cap**: the pinned Agents SDK (`agents` 0.0.109)
  predates the SDK-side `maxPersistedMessages` option, so the gateway enforces
  the cap itself: `MEMORY_MAX_PERSISTED_MESSAGES` (default 200) bounds
  `/memory/chat/prune`, and a caller-supplied cap can only tighten it. Pruning
  deletes oldest-first by insertion order, and the reported `pruned`/
  `remaining` counters come from a **re-COUNT after the DELETE** rather than
  from `min(total, cap)` arithmetic — the eviction outcome FerroGate records is
  an observation, not an assumption. `/memory/chat/append` applies the cap in
  the same call, so history cannot exceed it between an append and a later
  prune — on **both** paths: the batch is one `transactionSync`, so a failure
  mid-batch rolls the whole append back, and the failure path prunes before
  returning. A per-row loop would have persisted the rows before the failure
  and skipped the prune, parking the table above the cap while reporting
  failure. When the SDK option graduates into the pinned version, defer to it
  and keep this route as the governed surface.
- **A blank `MEMORY_MAX_PERSISTED_MESSAGES` means UNCONFIGURED, not zero.**
  `Number("")` is `0` and a cap of zero makes every prune delete the entire
  history, so a declared-but-empty var falls back to the default; an explicit
  `"0"` still selects a retain-nothing policy.

The chat table schema is byte-identical to the one `AIChatAgent` creates, so
on a chat-capable agent class these routes read/prune the SDK's own persisted
`this.messages` history (which also backs the SDK's built-in `/get-messages`
and resumable streaming).

**Layer 3 has its own writer.** The deployed class is a plain `Agent`, not
`AIChatAgent`, so nothing else in the Worker ever INSERTs into the chat table.
`POST /memory/chat/append` (Rust: `chat_history_append`) is what makes the
table grow on the deployed artifact — and therefore what makes prune able to
delete anything and `sql_query_with_prune_on_full` able to free any bytes. A
repeated message id REPLACEs the row, so the id is the caller's idempotency
key; a batch is capped at 100 messages per call.

## Semantic memory pilot (Vectorize) — BETA, default OFF

Long-term semantic memory is piloted behind a **default-off flag on both
sides**:

- Worker: `MEMORY_SEMANTIC_ENABLED = "false"` in `wrangler.toml`, and the
  `VECTORIZE` (Vectorize index) + `AI` (Workers AI embeddings,
  `@cf/baai/bge-m3`) bindings are commented out. Disabled requests return
  501 `semantic_memory_disabled` with `beta: true`.
- Rust: `AgentMemoryClient` requires an explicit
  `.with_semantic_enabled(true)`; when off it sends **no HTTP** and returns
  `AgentMemoryError::SemanticDisabled`.

When enabled, queries embed via Workers AI and search the Vectorize index
scoped to the instance's **namespace**, so semantic recall inherits the same
per-tenant isolation as layers 1–3.

The namespace is NOT the minted instance name verbatim. Vectorize caps a
namespace at **64 bytes**, while `fg.{tenant}.{session}.{run}` reaches 197 in
the worst case (a realistic UUID triple is ~110), so passing the name through
would make every real query fail at the platform. `vectorizeNamespace`
(`memory.ts`) / `vectorize_namespace` (`cloudflare_agent_memory.rs`) therefore
use the name verbatim when it fits and otherwise collapse it to `fgh_` + 60
hex characters of its SHA-256 — exactly 64 bytes, and unable to collide with a
verbatim name because minted names always contain `.`. The response reports the
`namespace` actually searched.

**Both sides derive this independently**, so the recipe is pinned by a shared
literal in `test/memory.test.ts` and `cloudflare_agent_memory_test.rs`: a
divergence would silently partition writes from reads instead of failing, and
the write side is still a follow-up (the pilot is query-only).
Vectorize is an open beta; AI Search was considered as an alternative binding
and can replace Vectorize behind the same flag later without changing the
route shape. Scope decision: the pilot implements **query** only; write-side
indexing (embedding + `VECTORIZE.insert` of memories) is deliberately left to
a follow-up once the pilot flag is exercised live.

## Decision: experimental Session memory layer — DEFERRED

The `agents/experimental/memory/session` layer is **deferred, not flagged
in**. The pinned SDK version (`agents` 0.0.109) does not ship the
`experimental/memory/session` export at all (verified against the package's
`exports` map), so there is nothing to gate a flag around without an SDK
upgrade — and upgrading the SDK is outside #427's scope. Revisit when the
worker's `agents` dependency is next bumped; if the layer is still
pre-graduation then, gate it behind a default-off `MEMORY_SESSION_ENABLED`
var in the same style as the semantic pilot.

## Verification (2026-07-24)

- `cargo fmt --all -- --check` — pass
- `cargo build -p ferrogate-runtime` — pass
- `cargo test -p ferrogate-runtime` — 238 passed (17 new memory tests)
- `cargo clippy -p ferrogate-runtime -- -D warnings` — pass
- `workers/agent-gateway`: `npx tsc --noEmit` — pass (also fixes the
  pre-existing type errors in `index.ts` against the pinned SDK)

Not locally provable (needs a deployed Worker / live Cloudflare): actual DO
SQLite behavior (real SQLITE_FULL, hibernation persistence), Vectorize/Workers
AI calls, and the live two-tenant isolation proof.
