# Function Egress Broker — enterprise-grade Supabase edge-function invocation

Status: design (2026-07-03) · Owner: jamesduan · Tracks: #115 and its children

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
   *reference* — never key material.

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
