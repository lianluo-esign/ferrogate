# Inbound x402 monetization via a pay.sh sidecar (issue #356)

Charging an external agent to call **one** fixed-price FerroGate-hosted API.

```
external x402 client ──▶ pay.sh `pay server` sidecar ──▶ PRIVATE FerroGate upstream
     (pays USDC)              (verifies + settles)          (verifies again, forwards once)
```

This is the mirror of the outbound agent-spend stack (#350–#354, where FerroGate
is the *payer*). Here FerroGate is the *merchant*.

The sidecar is a **reverse proxy, not in-process middleware**. Embedding pay.sh's
axum middleware into Pingora, or reusing the outbound wallet state machine, would
couple the data plane to an unproven demand hypothesis. When inbound
monetization is proven, that coupling is a decision to make deliberately; it is
not one to inherit from a spike.

## What is in this slice

| | |
|---|---|
| **Enabled surface** | Exactly one fixed-price, non-streaming route |
| **Price model** | One flat atomic amount per call |
| **Networks** | Solana devnet by default; mainnet is a separate operator decision |
| **Tenant model** | Maps to one pre-existing product tenant declared in config |
| **Runtime wiring** | ❌ **NOT landed** — see below |

### Runtime wiring is NOT landed

This slice ships the decision gate and its config surface as **libraries with no
caller**. Nothing in `ferrogate-gateway` constructs an `InboundX402Gate`, nothing
calls `load_inbound_x402_toml`, and the root `Config` has no `x402_inbound`
field — so a `ferrogate run --config ferrogate-x402-inbound.toml` parses,
ignores the `[x402_inbound]` section, and serves the route **unmonetized**.

Read that literally before deploying anything here:

- an unpaid request to the priced route is **not** answered with 402;
- the sidecar credential is **not** checked on the upstream hop;
- forward-once is **not** enforced on the real request path.

The network isolation in `deploy/x402-sidecar/docker-compose.yaml` is real and
does hold; it is the *only* thing that holds today. Every payment property in
this document is a property of the library, proven by unit and property tests in
`ferrogate-billing`, and is not yet reachable from a running gateway.

What wiring requires — and why it is a separate change rather than a few lines
here — is a `SidecarTransport` derived from the listener (which listener the
connection arrived on, whether mTLS terminated, and the peer subject). No such
classification exists in the request path today, and inventing one inline is the
part that needs its own review — getting it wrong fails *open*, because
classifying every connection as `PrivateNetwork` makes the admission gate a
no-op. **Tracked in #625.** This slice is deliberately "the decision is correct
and tested" rather than "the decision is installed".

**Not** in this slice, and not claimed anywhere: token-accurate inference
billing, streaming settlement, subscriptions, multi-party payments, catalog
publishing, mainnet defaults.

## The two identities, and why they never mix

| Identity | Source | Used for |
|---|---|---|
| **Payer wallet** | The on-chain settlement evidence | Revenue attribution evidence on the record |
| **FerroGate tenant** | `[x402_inbound.attribution]` in operator config | Authorization, quota, audit |

The payer wallet is *never* mapped into a `TenantContext`. Inbound x402 does not
mint tenants and does not let a payer choose one. The enforcement is not a
convention: `RESERVED_ATTRIBUTION_HEADERS` refuses any forwarded request that
carries a FerroGate attribution header at all, and the tenant on an
`AdmittedRequest` is copied from the policy, so there is no code path from a
caller-supplied byte to a tenant id.

## Threat model

Every row states what actually enforces the mitigation and what residual risk
remains. A row whose "Handled by" is a comment in a file rather than a mechanism
is a row that is not mitigated.

| # | Attack | Handled by | Residual |
|---|---|---|---|
| 1 | **Bypass** — caller reaches the protected upstream directly, skipping payment | Two independent layers: the upstream publishes no port and sits on an `internal: true` Docker network (`deploy/x402-sidecar/docker-compose.yaml`); *and* the upstream's own gate maps `SidecarTransport::Untrusted` to 403 before it reads a single header (`x402_inbound_admission.rs`). The transport is observed by the listener, not asserted by the request | The gate's refusal is only as good as the listener's transport classification. A deployment that marks every connection `PrivateNetwork` (e.g. terminating the sidecar hop at an untrusted L7 proxy) collapses layer two to layer one |
| 2 | **Spoofed forwarding headers** — caller asserts `x-ferrogate-tenant`, `x-ferrogate-payer`, … to be billed as, or attributed to, someone else | The request is **refused**, not stripped (`ReservedHeaderPresent`). Refusing rather than stripping is deliberate: a silently-stripped spoof and an honest request are indistinguishable in a log, so stripping destroys the only evidence that an attack happened. `headers_to_strip()` still removes them as defence in depth | The reserved list is a fixed set. A future FerroGate header that carries identity must be added to it; nothing mechanically fails if it is forgotten |
| 3 | **Duplicate forwarding** — the sidecar forwards one settled payment twice | Forward-once claim keyed on the revenue record id (challenge hash + transaction signature). Exactly one `ClaimOutcome::Admitted` per key per TTL, proven by a proptest over generated `(key, request_id, now)` sequences and by a 16-thread race test | In-memory guard: per-process, per-replica. See "Durability" below and #601 |
| 4 | **Replay** — a stolen `PAYMENT-RESPONSE` presented on a different request | The claim's owner is the **sidecar** request id, which is stable across a sidecar retry and different for a different call. Matching id → `DuplicateRetry` (409, idempotent); different id → `ProofReplay` (402, re-challenged). Backstopped by the durable revenue record when the claim has expired | Two calls that genuinely share a sidecar request id would be treated as one. That id's uniqueness is the sidecar's obligation, stated in `pay-server.yaml` |
| 5 | **Sidecar compromise** — the sidecar process is taken over | The sidecar can reach the monetized upstream and **nothing else**: it is joined to `edge` and `paid-upstream` only, and `ferrogate-admin` is joined to `admin` only, so the two share no network and no route exists between them. Verify with `docker compose exec pay-sidecar getent hosts ferrogate-admin` — it must fail | **A compromised sidecar can forward unpaid calls to the monetized route**, because it holds the credential that authenticates the hop. It can also **fabricate revenue records**: `settle_inbound_payment` verifies the `PAYMENT-RESPONSE` header's self-reported network, amount, success flag and signature *shape*, but performs no on-chain or facilitator-side re-check, so a header the sidecar authored itself is accepted. What it cannot do is reach the admin service, and it cannot forward a payment to any path or method other than the priced one (row 13) |
| 6 | **Secret rotation** | Active + rotating-out secrets, compared in constant time, with the matched slot on every admission's evidence (`sidecar_credential=active\|rotating_out`). An operator retires the old secret when that field has read `active` for a full deployment window. The config refuses an "identity rotation" (both names resolving to the same value) | Rotation is observable but not automated; nothing forces the old secret to be retired |
| 7 | **Timeout after settlement** — payment settled, the client gave up, the sidecar retries | The retry carries the same sidecar request id → `AlreadyForwarded` (409), idempotent, revenue counted once. FerroGate mints a fresh request id per HTTP request, so ownership is decided on the **sidecar** id at both layers — the live claim and the durable revenue record (`InboundX402RevenueRecord::sidecar_request_id`). Comparing FerroGate ids here would classify every genuine retry as a replay; two tests pin this and both fail if the comparison is changed back | The payer paid and, on a genuine timeout, may receive a 409 rather than the response. Refunds are out of scope for this slice; the revenue record retains the full evidence needed to issue one manually. A record written before that field existed carries an empty sidecar id and so refuses as a replay — fails closed, not open |
| 8 | **Upstream 5xx** — the handler fails after the payment is consumed | `InboundX402Gate::release_claim` gives the claim back so the payer can retry | **Incompletely closed.** The revenue record is deliberately not deleted (deleting settled-payment evidence would make a refund unprovable), so the durable backstop re-refuses the retried proof. Releasing the claim therefore only helps while the sink is non-durable. Closing this properly needs the durable claim/refund work tracked in #601 |
| 9 | **Wrong network** | The settlement header is parsed with the endpoint's network pinned, then re-verified: `settle_inbound_payment` refuses a `network` that is not the endpoint's, an unsuccessful settlement, a missing signature, a missing amount, and any amount that is not exactly the fixed price. Any mismatch records nothing | None known at this layer, given a truthful facilitator report — see row 9b |
| 9b | **Wrong mint / wrong recipient** — settlement in a different SPL token, or to a different wallet, at the right amount on the right network | **Nothing on the FerroGate side.** `SettlementEvidence` (`ferrogate-payments::wire`) carries no mint and no recipient field, so `settle_inbound_payment` has nothing to compare; the `mint` and `recipient` on the revenue record are copied from the endpoint config, not read back from the settlement. Verifying them is the facilitator's responsibility | **A compromised or misconfigured facilitator that reports a settlement in the wrong token, or to the wrong payee, is accepted and recorded as revenue at face value.** Closing this needs mint/recipient on `SettlementEvidence` plus a comparison in `settle_inbound_payment` — a change to the frozen wire contract, out of scope here |
| 10 | **Secret leakage into logs/config** | No config field can hold a secret value (`*_secret_env` names only). `SidecarCredential`'s `Debug` is hand-written and redacted, and `evidence_fields()` excludes the credential and the raw proof | A caller who can read the process environment reads the secret; that is the ambient trust boundary of any env-var secret |
| 11 | **Free call** — an unpaid request to the monetized route | 402 with the `PAYMENT-REQUIRED` challenge built from the same fixed price the settlement is later verified against | None known |
| 12 | **Resource exhaustion of the claim guard** | Bounded capacity, and when full the gate **fails closed** (503) rather than evicting a live claim — evicting is precisely how a replay would be admitted under load | An attacker who can mint distinct valid payments can fill the guard and deny service to legitimate payers. Bounded by the cost of paying for each |
| 13 | **Proof presented against another resource** — a payment quoted and settled for the priced route is forwarded to a different path or method | `InboundX402Gate::evaluate` compares the arriving `path` against the path component of `endpoint.resource_url`, and the arriving `method` against `endpoint.allowed_methods` (default `POST`), before the proof is even parsed. A mismatch is `ResourceMismatch` → **403**, not 402: paying again buys nothing, because the price was never quoted for that resource. Both are derived once at config validation, so the comparison cannot fail open on a parse error at request time | "Only one fixed-price route is enabled" is enforced by the gate rather than resting on the sidecar's route list. The path comparison is exact — an operator who wants to price a path prefix, or a route with path parameters, is not served by this model |

## Durability — stated, not closed

The forward-once claim guard is `InMemoryForwardClaimGuard`: process-local,
TTL-bounded, lost on restart. The gate compensates by consulting the
`RevenueSink` for an existing record before it claims, which closes replay across
a claim loss **exactly as far as the configured sink is durable**. The sink
shipped with this slice is `InMemoryRevenueSink`, which is not durable at all.

Concretely, today:

- a single-process restart loses both the claims and the in-memory revenue
  records, so a proof replayed after a restart **would** be forwarded again;
- a multi-replica deployment has one guard per replica, so the same proof sent
  to two replicas **would** be forwarded twice.

Durable claim/revenue persistence and the Admin query surface over it are
**explicitly out of scope for #356** and tracked as #601. Until they land,
this slice is a validated sandbox topology, not a production merchant path — do
not run it against mainnet.

## Configuration

See `deploy/x402-sidecar/ferrogate-x402-inbound.toml`. That exact file is loaded
and validated by a committed test (`crates/ferrogate-config/src/x402_inbound_test.rs`),
so it cannot drift from the schema.

Cross-field rules the config refuses rather than warns about:

- `forward_claim_ttl_secs` **must be ≥** the endpoint's `max_timeout_seconds`.
  A claim that expired while its own payment was still spendable would re-open
  the replay window it exists to close. This is the replay floor.
- `require_mutual_tls` and `pinned_client_subjects` must both be set or both be
  absent. mTLS with no pin accepts any certificate the trust store chains; a pin
  without mTLS is never consulted. Either alone reads as protection that is not
  there.
- The active and rotating-out secrets must come from **different** environment
  variables, or the rotation is a no-op that looks in-progress.

## Local sandbox run

```bash
cd deploy/x402-sidecar
export FERROGATE_X402_INBOUND_SIDECAR_SECRET="$(openssl rand -hex 24)"
export FERROGATE_ADMIN_JWT_SECRET="$(openssl rand -hex 32)"
export PAY_RECIPIENT=<your devnet USDC wallet>
docker compose up -d

# 1. Unpaid call -> 402 with a PAYMENT-REQUIRED challenge
curl -i -X POST http://localhost:8402/v1/priced/report

# 2. Paid call via a pay.sh-compatible client, devnet sandbox, no mainnet funds
pay --sandbox curl -X POST http://localhost:8402/v1/priced/report

# 3. Boundary checks that must FAIL
docker compose exec pay-sidecar getent hosts ferrogate-admin
curl -i --max-time 2 http://localhost:8080/v1/priced/report
```

Steps 1–3 exercise the shipped topology and are **not** run by CI in this slice:
they need a pinned `pay` image and a devnet wallet.

Two separate caveats, and neither is "we just did not get around to running it":

1. **Steps 1 and 2 do not hold on this code.** The gate is not wired into the
   request path (see "Runtime wiring is NOT landed" above), so the unpaid call in
   step 1 is served by the handler instead of being answered with 402, and the
   paid call in step 2 succeeds without the upstream verifying anything. They
   describe the *intended* end state and become true when the wiring lands.
2. **Step 3's boundary checks do hold**, because they test Docker networking
   rather than gate logic. The first must fail (no shared network with the admin
   service); the second must fail (the paid upstream publishes no host port).

The compose topology itself was corrected to start — the previous revision
referenced a `ferrogate health` subcommand and a `ferrogate admin --listen`
subcommand, neither of which exists, and bound the gateway to loopback inside its
own container. A committed test in `ferrogate-config` now loads both shipped
config files and pins those three regressions. That the containers *start* has
not been executed here; it is a static claim about the manifests.
