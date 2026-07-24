# Function Egress Broker — enterprise-grade Supabase edge-function invocation

Status: design (2026-07-03, Cloudflare Worker branch added 2026-07-24) ·
Owner: jamesduan · Tracks: #115 and its children; #416/#435 for the
Cloudflare Worker target

## 1. Problem

Agents (both cloud-managed and self-hosted workers) need to invoke serverless
"functions" implemented as Supabase edge functions at
`{project}/functions/v1/{slug}`. Today there is **no** live invocation path, and
the existing external-action model makes the gateway an *authorizer* only — the
worker executes the action itself after receiving an allow/deny decision.

For enterprise security that model is inadequate:

- **Secret sprawl.** Worker-side execution requires the Supabase auth key on the
  worker host. Self-hosted workers run on customer-owned machines, so this means
  handing a high-value credential to untrusted hosts.
- **Authorization ≠ enforcement.** A decision the worker may ignore is not a
  control. `self_hosted_worker.rs` already notes reported telemetry "are not
  proof that FerroGate enforced the local execution environment."
- **No central egress control.** Direct worker egress defeats allowlisting,
  payload governance, per-tenant rate limiting, and unified audit/billing.

## 2. Principle

Separate **authorization** ("who may call which function") from **execution**
("who holds the credential and makes the network call"), and centralize
execution in the gateway as a governed **egress broker**. Credentials never
leave the gateway trust boundary; the worker cannot reach the function except
through the gateway.

## 3. Target flow

```
agent/worker ──(1) POST /v1/functions/execute {slug, body, tenant ctx}──▶ AI Gateway
                                                                           │
                                     (2) authenticate caller identity (existing AEAD/mTLS transport)
                                     (3) governance: tenant + capability policy + egress allowlist
                                     (4) mint a short-lived, scoped credential (JWT) — NOT a static key
                                     (5) gateway executes TLS POST {project}/functions/v1/{slug}
                                     (6) record audit + billing → control plane → DB
                                                                           │
                                                                           ▼
                                                              Supabase Edge Function
                                                              (validates JWT claims + RLS)
              ◀──(7) result / error ────────────────────────────────────┘
```

## 4. Trust-domain policy

| Worker type | Execution | Rationale |
|---|---|---|
| Self-hosted (customer host, low trust) | **Must** be gateway-brokered | Credential must never land on customer hosts; worker-side execution is unenforceable |
| Cloud-managed (FerroGate isolation backend) | Gateway-brokered (recommended, uniform). If worker-side, isolation MUST physically force egress through the gateway (`direct_public_egress=false`, `governed_egress`, `gateway_control_channel` are already modeled) | No special cases on shared infra |

Decision: **both** worker types use gateway-brokered execution. No special case.

## 5. Components

1. **`/v1/functions/execute` route** (ferrogate-cli gateway): authenticate →
   govern → mint token → execute → audit. Reuses the external-action authorizer
   governance logic (`GatewayExternalActionAuthorizer`) so policy/tenant checks
   are identical to other governed actions.
2. **Egress allowlist** (this increment): fail-closed policy of which project
   base URLs + function slugs are permitted, evaluated per tenant. Non-allowlisted
   targets are denied before any credential is minted or call made.
3. **Credential minting**: short-lived, scoped JWT (claims: `iss=ferrogate`,
   `aud=<function>`, `tenant`, `capability`, `exp` ≤ small TTL). Replaces static
   service-role keys. (Follow-up: requires a JWT/HMAC primitive; `subtle` is
   present, JWT signing crate TBD in the JWT child issue.)
4. **TLS egress executor** (ferrogate-cli gateway): real `reqwest` (rustls)
   POST with the minted credential. `reqwest` is already a workspace dep used by
   `gateway/dispatch.rs`; this replaces the GET/local raw-TCP smoke executor for
   the function path.
5. **Request builder** (`ferrogate-runtime::supabase_edge_function`, landed in
   06b7f74): target validation (https-only, clean slug), `functions/v1/{slug}`
   URL, header injection, and a governed-action adapter carrying only a secret
   *reference* (`auth_key_ref`) — never key material.

> **Implementation status (2026-07-03).** The `auth_key_ref` on
> `SupabaseEdgeFunctionTarget` is **reserved, not yet dereferenced**. It is
> validated non-empty (fail-closed) but the broker does not resolve it against a
> tenant secret store — no such store exists yet. Today the gateway sources the
> apikey and JWT signing secret from process-wide environment config
> (`FG_FN_APIKEY`, `FG_FN_JWT_SECRET`), so the broker is **single-project**: one
> shared apikey and one shared signing secret for all allowlisted targets.
> Per-tenant/per-project secret resolution (making `auth_key_ref` a live lookup)
> is future work, coupled to the multi-project credential decision (TOK-6). The
> step-4 "mint scoped JWT" flow above is implemented; the secret it signs with is
> the shared env secret, not a per-project one.
>
> **Enforced (TOK-6):** because a single shared apikey/signing secret can only
> serve one Supabase project, `FunctionEgressGatewayConfig::from_values` refuses
> to enable the broker when `FG_FN_ALLOWLIST` lists rules spanning **more than
> one distinct `base_url`** (after trailing-slash normalization). The broker
> logs a warning and stays disabled (fail-closed 503) rather than silently
> handing the wrong project's credentials to a call. To allowlist a second
> project, run a separate gateway process with that project's `FG_FN_APIKEY` /
> `FG_FN_JWT_SECRET`, or wait for per-project credential resolution.
>
> **Config parsing (TOK-7):** if `FG_FN_ALLOWLIST` is present but is not valid
> JSON for the allowlist rule array, the broker logs a warning and stays
> disabled. An absent allowlist still means an empty deny-by-default ruleset; a
> malformed allowlist is treated as an operator error instead of silently
> degrading into "deny everything".

## 5a. Cloudflare Worker targets (#416/#435)

The broker can host its function on a deployed Cloudflare Worker instead of a
Supabase project. Governance is identical by construction: the runtime's
`prepare_governed_worker_invocation` (#416) composes the same fail-closed
pipeline (per-tenant egress allowlist authorize → mint scoped JWT → build the
governed request) and emits the same transport-agnostic request shape the
gateway's TLS egress executor already runs. The `/v1/functions/execute` route
dispatches to the Worker branch when — and only when — the operator declared it
in config (#435).

Config surface (env, `FG_FN_*`; shared names reused where semantics match):

| Variable | Meaning |
|---|---|
| `FG_FN_TARGET_KIND` | Target-platform discriminant: `supabase` (default when unset — pre-#435 behavior is byte-identical) or `cloudflare_worker`. Any other value disables **both** branches (fail-closed) with a warning. Exactly one branch is active per process. |
| `FG_FN_CF_WORKER` | Required for the Worker branch. JSON `CloudflareWorkerTarget`: `{"base_url":"https://<worker>.<account>.workers.dev","invoke_path":"<segment>","auth_key_ref":"secret:<ref>"}`. Validated fail-closed at startup (https-only base, clean single-segment invoke path, non-empty secret-ref). |
| `FG_FN_JWT_SECRET` | Reused — signs the short-lived scoped bearer JWT the Worker verifies. |
| `FG_FN_ALLOWLIST` | Reused — the same per-tenant rule array; `function_slugs` match the Worker `invoke_path`. **Single-worker rule** (mirror of TOK-6): every rule's `base_url` must equal the declared `FG_FN_CF_WORKER` base URL (after trailing-slash normalization), otherwise the branch stays disabled. |
| `FG_FN_APIKEY` | Supabase-only. Workers have no `apikey` concept; the Worker request carries the scoped bearer only and never emits an `apikey` header. |

On the wire the route accepts the runtime's `WorkerInvocationRequest`
(`{"target":{"base_url","invoke_path","auth_key_ref"},"method","body_json"}`).
The wire `auth_key_ref` is **never trusted**: the broker replaces it with the
operator-declared `FG_FN_CF_WORKER` secret-ref before the governed pipeline
runs, so a (future) credential dereference cannot be steered by the caller.
Like the Supabase `auth_key_ref`, the secret-ref is reserved — validated
non-empty but not yet dereferenced; the minted scoped JWT is the credential the
Worker receives today.

Deny/audit behavior matches the Supabase branch exactly: disabled config →
`503 function_egress_disabled`; allowlist/validation denial → `403
function_denied` with a `denied` audit event (target
`cloudflare_worker:<invoke_path>`); upstream failure → `502
function_upstream_error`; success → bounded outcome plus an `executed` audit
event.

## 6. Defense in depth

- Edge function re-validates the JWT (issuer, audience, tenant claim) and relies
  on Supabase **RLS** for tenant isolation on any DB access it performs.
- Worker↔gateway transport keeps XChaCha20Poly1305 AEAD + identity, with the
  server-clock expiry (#113) and constant-time secret comparison (#114) fixes.
- Per-tenant + per-function rate limiting, request timeouts, idempotency keys,
  and credential/signing-key rotation.

## 7. Incremental delivery

1. **(this increment)** Egress allowlist governance model + broker
   request/response contract types + credential abstraction — all pure and
   fully unit-tested, no network/new-crypto. Sets the fail-closed policy layer.
2. Short-lived scoped JWT minting (crypto primitive + claims).
3. `/v1/functions/execute` route wired to the external-action authorizer.
4. `reqwest`-based TLS POST executor at the gateway.
5. End-to-end `ferrogate-test` scenario: agent → gateway route → (mock/real)
   edge function, control-plane audit → DB.

## 8. Non-goals

- Running the edge function itself (customer-owned Supabase project).
- Replacing MCP tool execution (`/v1/mcp/tool/execute`), which is a separate,
  already-live path.
