# FerroGate — route map (274 operations → Hono apps)

Derived from the authoritative contract `docs/openapi/runtime-api-contract.json`
(`version: 1`, 274 operations, 40 route groups). **That JSON is the source of
truth** — this document only assigns each operation to a Worker and records the
auth/visibility invariants the Hono port must preserve.

## Split by app

| App | Ops | Surface |
|---|---:|---|
| `apps/control-plane` | **211** | `/admin/v1/**` (206) + `/admin`, `/admin/`, `/admin/dashboard`, `/admin/status`, `/metrics` |
| `apps/gateway` | **40** | inference (14): `/v1/{chat/completions,messages,messages/count_tokens,responses,responses/{response_id} (GET+DELETE),embeddings,rerank,images/generations,audio/transcriptions,audio/translations,audio/speech,models,models/{model}}`, assets `/v1/assets/**` (18), tools/skills/prompts/functions + `/.well-known/agent.json` (7), sites `/sites/{*rest}` (1) |
| `apps/agent-runtime` | **15** | `/v1/agent-jobs/**` (5), `/v1/agents/**` (3), `/v1/agent-runs` (1), `/v1/self-hosted-workers/**` (6) |
| `apps/mcp` | **6** | `/v1/mcp`, `/v1/mcp/tool/execute`, `/v1/mcp/identity/**` |
| shared | **2** | `/healthz`, `/readyz` — implemented in **every** Worker |
| **total** | **274** | |

`apps/telemetry` owns no contract route: it is the observability sink
(Analytics Engine / Logpush), fed by the other Workers.

## Invariants the port MUST preserve

**Auth kinds** (274): `bearer` 260 · `internal` 6 · `anonymous` 7 · `method_dependent` 1.
**Visibility**: `admin` 207 · `public` 60 · `internal` 7.
**Methods**: GET 125 · POST 85 · DELETE 28 · PUT 20 · PATCH 16.

> `anonymous` is 7 and not 6 because of `serveSite` (`GET /sites/{*rest}`,
> issue #737). It is the one operation whose credential requirement is DATA —
> a site is private by default and anonymous serving is a per-site, per-channel
> operator opt-in — which `auth.kind` cannot express. Its handler runs the
> middleware's OWN `authenticateBearer`, so the ladder is deferred, not skipped.

> Every figure above is **re-derived from the JSON**, not carried forward. This
> document is the third place a count lives (after `src/contract.ts` and
> `packages/schemas`), and two branches that each add operations will each write
> a plausible-but-wrong total.
>
> Seven slices landed on top of the 251-operation baseline, four of them
> developed in parallel:
>
> - `countMessageTokens` (`POST /v1/messages/count_tokens`, issue #671): the
>   Anthropic-native token-count pre-flight. It is bearer-`messages.create` —
>   the SAME scope as the `createMessage` it pre-flights, so no
>   already-provisioned key has to be re-scoped and no unauthenticated counting
>   oracle exists. `public`; `apps/gateway`.
> - The prompt deployment labels (issue #694):
>   `GET /admin/v1/prompt-templates/{id}/labels`, and `PUT`/`DELETE` on
>   `.../labels/{label}`. All `admin`; `apps/control-plane`.
> - The BYOK provider-credential aliases (issue #682):
>   `GET /admin/v1/provider-credentials`, and `PUT`/`DELETE` on
>   `.../provider-credentials/{alias}`. All `admin`; `apps/control-plane`.
> - The semantic-cache policy surface (issue #695):
>   `GET`/`POST /admin/v1/semantic-cache-policies`, `GET`/`PUT`/`DELETE` on
>   `.../{scope_type}/{scope_id}`, and
>   `POST .../{scope_type}/{scope_id}/invalidate`. All `admin` and
>   `admin.read`/`admin.write`; `apps/control-plane`.
> - `getModel` (`GET /v1/models/{model}`, issue #670): the single-model
>   catalogue read beside `listModels`. Bearer-`models.read`, `public`;
>   `apps/gateway`.
> - The per-request chargeback surface (issue #677):
>   `GET /admin/v1/cost-records` and `GET /admin/v1/cost-record-exports`, a new
>   `admin_cost_record` group (39 → 40). Both `admin` / `admin.read`;
>   `apps/control-plane`. They are READS over a join of `request_logs` (#664)
>   and `billing_events` (#663/#667) — no new table, so no third figure for a
>   cost that could disagree with `billing_ledger`.
> - `createRerank` (`POST /v1/rerank`, issue #676): the reranking ingress,
>   served by Workers AI reranker models. Bearer-`embeddings.create` — the same
>   reuse `countMessageTokens` made of `messages.create`, and for the same
>   reason: reranking is the second half of the retrieval pipeline whose first
>   half is embedding, so no already-provisioned RAG key has to be re-minted and
>   no unauthenticated reranking oracle exists. `public`; `apps/gateway`.
> - `createTranscription` / `createTranslation` / `createSpeech`
>   (`POST /v1/audio/{transcriptions,translations,speech}`, issue #703): the
>   audio ingress, served by Workers AI Whisper/MeloTTS and by an
>   OpenAI-compatible passthrough. Bearer on a NEW `audio.create` scope — audio
>   is its own family with nothing to reuse (there is no `audio.*` scope to
>   inherit the way `createRerank` inherited `embeddings.create`), and minting
>   one fails CLOSED for every key issued before audio existed, which is the safe
>   direction. `public`; `apps/gateway`.
>
> - `getResponse` / `deleteResponse` (`GET`/`DELETE /v1/responses/{response_id}`,
>   issue #689): the server-side conversation state `previous_response_id`
>   continues. Bearer on the EXISTING `responses.create` scope — a key that can
>   create a response already holds every byte the read returns, and can only
>   delete state it created, so minting `responses.read`/`responses.delete` would
>   widen nothing and would break continuation for every key already in the
>   field. `public`; `apps/gateway`.
>
> `apps/control-plane` went 197 → 211 (197 + 3 + 3 + 6 + 2) and `apps/gateway`
> went 31 → 40 (31 + 1 + 1 + 1 + 3 + 1 + 2).
>
> #677 and #676 were themselves parallel, and this is the merge that proves the
> warning is not theoretical: the #676 branch was cut before #677 landed, wrote
> a coherent 266-operation census against the contract it could see, and every
> single one of those figures was wrong by the time it merged. All of them —
> total, per-app split, auth/visibility/method census, group count — were
> RE-COUNTED off the merged JSON at resolution time rather than reconciled hunk
> by hunk.
>
> Because those slices were parallel, several per-app and per-census figures
> were written IDENTICALLY on branches that had each seen only their own delta
> (`apps/gateway` 31→32 twice; `public` 51→52 twice; the inference family 6→7
> twice; `apps/control-plane` 197→200 twice; GET/DELETE/PUT 117/25/18 three
> times). Git merges identical text with no conflict marker, so these pins must
> be RE-COUNTED off the JSON after every merge rather than reviewed as a diff.

1. **Every operation carries `visibility`, `auth.kind`, `auth.scope`, and
   `rbac_action`.** Port these as Hono middleware driven by the contract, not as
   hand-written per-route guards — one table-driven middleware keeps all 274 in sync.
2. **`auth.kind: "internal"`** — the 6 `/v1/self-hosted-workers/*` operations
   (`artifacts`, `checkpoints`, `events`, `heartbeat`, `runs/ack`, `runs/poll`)
   are worker-plane callbacks. They must NOT be reachable with a normal tenant
   bearer key.
3. **`auth.kind: "anonymous"`** — exactly 7, counted off the JSON: `/healthz`,
   `/readyz`, `/admin`, `/admin/`, `/admin/dashboard`,
   `GET /v1/mcp/identity/callback` (the OAuth redirect target, which cannot
   carry a bearer) and `GET /sites/{*rest}` (see the note above the invariants).
   Nothing else may be unauthenticated.
4. **`method_dependent`** — 1 operation authenticates differently per method;
   read the contract entry rather than assuming.
5. **`GET /metrics` is `visibility: internal` but `auth.kind: bearer`** — internal
   surface, still bearer-guarded. Do not expose publicly, do not leave unauthenticated.
6. **401 vs 403**: preserve the Rust semantics — a *suspended* native API key
   returns 401, not 403 (see `docs/legacy/inventory-edge-control.md`; this was a
   real defect class in the Rust tree).
7. **`/control/v1/*` → `/admin/v1/*` alias canonicalization** must be kept
   (`ferrogate-admin`'s naming contract).

## Dynamic surfaces (NOT in the 274)

From `dynamic_surfaces` in the contract — these are data, not contract:

- **Operator-defined reverse-proxy routes** (`configured host/path routes`):
  matched at runtime from config, dispatched to arbitrary upstreams. In the Rust
  tree this was the `matchit` radix tree; in Hono use a catch-all resolved
  against the config snapshot.
- **`OPTIONS /admin/{*rest}`** — CORS preflight, exists only when an admin-console
  allowed origin is configured.

## Porting guidance

- Generate the route table from the JSON at build time (or import it directly)
  so a contract change can't silently drift from the implementation. Add a test
  asserting **`routes.length === 274`** and that every contract `operation_id`
  has a handler — this is the anti-drift gate.
- Zod schemas per operation live in `@ferrogate/schemas`; the validator is
  `@hono/zod-validator`.
- Streaming operations (`/v1/chat/completions`, `/v1/messages`, `/v1/responses`,
  `/v1/agents/{name}/message:stream`, `/v1/agent-jobs/{run_id}/events`) must
  preserve upstream SSE framing byte-for-byte — see `docs/rewrite/TESTING.md`
  for the MSW-based streaming test approach.
