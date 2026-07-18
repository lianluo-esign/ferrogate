# Self-hosted worker production mTLS transport — design

Status: **design + Phase 1 (policy/downgrade scaffolding) landed; verified-mTLS
admission DEFERRED to a reviewed Phase 2.**

Tracking: GitHub issue #243 (Gap 2 of
`docs/plans/2026-07-18-self-hosted-worker-gaps.md`).

This document is the design that issue #243 requires **before** a real mTLS
listener is built. It is security-critical: a half-built secure transport is
worse than an honestly-gated one, so the current build ships only the
non-risky policy/downgrade scaffolding and keeps a clear `not_implemented`
boundary around the parts that need PKI infrastructure and a security review.

## 0. What exists today (the starting point)

Self-hosted workers are **pull** clients: the customer-owned node's
`agent-worker` dials **outbound** to the gateway and drives the transport
(`transport_shape: worker_initiated_outbound_polling`). There is no inbound path
to the customer host. Every transport request carries the identity 4-tuple
(`tenant_id / workspace_id / worker_id / token_id`) plus a 256-bit
`token_secret` (server-provisioned, hex, constant-time compared).

Two transport modes are selected by the `x-ferrogate-transport-security`
request header
(`crates/ferrogate-runtime/src/self_hosted_worker.rs`,
`crates/ferrogate-cli/src/gateway/local.rs`):

| Header value    | What it actually is today                                                                 |
| --------------- | ----------------------------------------------------------------------------------------- |
| `symmetric_aead`| Application-layer XChaCha20-Poly1305 AEAD frame keyed by `token_secret` via HKDF; the 4-tuple + protocol version are the AEAD AAD. Confidentiality + integrity + identity-binding of the *payload*, over an otherwise unauthenticated channel. |
| `mutual_tls`    | **A marker only.** The body is sent as plaintext JSON. The gateway does **not** validate a client certificate, does not verify a TLS handshake, and does not prove the channel is encrypted. It is a wire-shape contract placeholder. |

`production_mtls_transport_implemented` was a hardcoded `false` in the admin
runtime listing. It is now sourced from
`ferrogate_runtime::production_mtls_transport_implemented()` (a `const fn`
returning `false`) so the honesty is code-enforced rather than a magic literal.

The core problem: **`mutual_tls` claims a security property the gateway never
verifies.** A production deployment that believes it requires mTLS is, today,
either (a) accepting unauthenticated plaintext under a reassuring header, or
(b) relying on the AEAD path whose transport-auth secret is the same
`token_secret` used for identity — with no channel-level mutual authentication.

## 1. Threat model

Assets: worker identity (the 4-tuple + `token_secret`), lease/dispatch
integrity, telemetry/evidence integrity, and the confidentiality of workload
references and reported payloads.

| # | Threat | Today's exposure | Required mitigation |
| - | ------ | ---------------- | ------------------- |
| T1 | **MITM / passive eavesdrop** on the `mutual_tls` (plaintext) path. | Full: body is cleartext; an on-path attacker reads and rewrites it. | A real TLS channel (server auth at minimum, mutual auth for production) must terminate at the gateway; plaintext transport must be impossible in production. |
| T2 | **Downgrade** to the marker/AEAD path when mTLS is expected. | Full: the client picks the header; a MITM can strip a TLS layer and present `mutual_tls`/`symmetric_aead` and the gateway accepts it. | Server-side posture: in production mode the gateway MUST reject any request not arriving on a verified mTLS channel — regardless of the header. **(Phase 1 landed: the marker/AEAD paths are rejected; verified-mTLS admission is Phase 2.)** |
| T3 | **Replay** of a captured frame/request. | Partial: AEAD binds the 4-tuple but the nonce is a process-local counter, not a server-tracked anti-replay window; lease/ack semantics catch some replays but heartbeat/telemetry do not. | mTLS gives channel-level freshness; additionally bind transport tokens to a short TTL + monotonic/nonce anti-replay checked server-side. |
| T4 | **Stolen client cert or transport token.** | N/A (no certs; `token_secret` theft = full impersonation until manual rotation). | Short-lived transport tokens issued *after* an mTLS handshake, bound to the presented cert; fast rotation + revocation; cert theft still bounded by cert validity + CRL/OCSP-style revocation. |
| T5 | **Expired identity** used past its validity. | Partial: `identity_expires_at_unix` is checked in `validate_identity` when the client supplies `observed_at_unix`, i.e. self-reported. | Server-clock-stamped expiry on both the cert (notAfter) and the transport token; never trust client-supplied time for the security decision. |
| T6 | **Cross-tenant / cross-worker cert reuse.** | N/A. | The client cert MUST cryptographically bind to the exact 4-tuple; a cert issued for worker A cannot authenticate worker B (§3). |
| T7 | **Rogue/forged CA.** | N/A. | A single, explicitly configured trust anchor per deployment; no system trust store; no fallback to unauthenticated on trust-anchor load failure (fail closed). |

## 2. CA / certificate model

- **Trust anchor.** Each deployment configures exactly one FerroGate
  self-hosted worker **issuing CA** (or an intermediate chaining to a
  configured root). The gateway's mTLS verifier trusts *only* this anchor for
  the self-hosted worker ingress — never the OS trust store, never the
  general web PKI. Trust-anchor load failure is fail-closed (the ingress does
  not start / rejects all requests).
- **Who issues node certs.** Node client certs are minted by the FerroGate
  control plane at (or after) worker registration — the same authority that
  provisions `token_id`/`token_secret`. The customer never mints their own
  cert against our CA; issuance is gated by the existing registration
  authorization.
- **Cert ↔ identity binding.** The leaf cert MUST bind to the full 4-tuple so a
  cert cannot be replayed for a different worker/tenant/workspace:
  - Subject / SAN encodes a canonical identity URI, e.g.
    `spiffe://ferrogate/self-hosted/{tenant_id}/{workspace_id}/{worker_id}/{token_id}`
    (URI SAN), or an equivalent custom OID carrying the 4-tuple.
  - On handshake the gateway parses this binding and requires it to **exactly
    equal** the 4-tuple in the enclosed request identity envelope (mirroring
    today's frame-identity check in
    `validate_self_hosted_transport_frame_identity`).
  - Validity: `notBefore`/`notAfter` bounded to a short lifetime; the server
    clock — not client time — is authoritative (mitigates T5).
- **Revocation.** Because certs are short-lived, revocation is primarily
  expiry-driven; additionally a control-plane revocation list (checked at
  handshake) covers early compromise (mitigates T4). Deactivating a worker
  (`active = false`) MUST also refuse its cert.

## 3. Transport-token issuance + rotation lifecycle

The transport token is a **short-lived bearer credential issued after a
successful mTLS handshake**, distinct from the long-lived `token_secret`. This
keeps the high-value `token_secret` off the hot path and gives us fast,
cert-bound rotation.

1. **Handshake.** Node presents its client cert; gateway validates it against
   the trust anchor, checks revocation + `notAfter` (server clock), and extracts
   the 4-tuple binding.
2. **Bind.** Gateway confirms the cert binding equals the registered worker
   (reusing `validate_self_hosted_worker_identity`) and that the worker is
   `active`.
3. **Issue.** Gateway mints a short-TTL transport token bound to
   `(4-tuple, cert fingerprint, notAfter, issued_at server clock)`. This token —
   not `token_secret` — authenticates subsequent requests on the established
   channel.
4. **Rotate.** Before expiry the node re-presents its cert (or a still-valid
   token) to obtain a fresh transport token. This reuses the existing
   `SelfHostedWorkerRegistry::rotate_token` rotation machinery and its
   invariants (non-empty new secret, validate-before-rotate), extended so the
   new material is cert-bound and the old token is invalidated atomically.
   Long-lived `token_secret` rotation remains the break-glass path and continues
   to flow through the existing `/rotate` admin surface.
5. **Expire / revoke.** Token TTL is short; a revoked cert or deactivated worker
   invalidates outstanding tokens immediately.

## 4. Mutual verification + downgrade protection

Two postures, decided **server-side** (never by the client header alone):

- `MarkerContract` (default, pre-production): accept the AEAD path and the
  `mutual_tls` marker path — the shape shipped today. The marker is explicitly
  *not* treated as proof of mTLS.
- `RequireProductionMtls` (production): a **verified** mutual-TLS channel is
  required. Any request that did not arrive on such a channel — including the
  `symmetric_aead` frame path and the unverified `mutual_tls` marker — is
  rejected. The client's header is advisory; the decision is made from what the
  gateway *observed* about the channel, closing T2.

**Phase 1 (landed) behavior in `RequireProductionMtls`:** because verified-mTLS
admission is not yet implemented, both currently shippable channels are
rejected — `symmetric_aead` as an explicit **downgrade** (`403`,
`self_hosted_worker_transport_downgrade_rejected`) and `mutual_tls` as an
**unverifiable marker** (`501`,
`self_hosted_worker_production_mtls_not_implemented`). Enabling production mode
today therefore fails closed for every channel. That is intended: we would
rather refuse traffic than accept an unverifiable claim as production-grade.

## 5. Channel-enforcement — proving encryption, not claiming it

The header is a claim; the design requires **proof**. In production the
admission decision is driven by a `SelfHostedTransportChannel` value that the
gateway can only construct from something it actually verified:

- Today the enum has exactly two variants — `UnverifiedMutualTlsMarker` and
  `SymmetricAead` — and *neither* is admissible in production. There is
  deliberately **no** `VerifiedMutualTls` variant yet, because nothing in this
  build can honestly produce one.
- Phase 2 adds a `VerifiedMutualTls { peer_cert_binding, .. }` variant that is
  **only** constructible from a completed, verified TLS handshake at the
  gateway's mTLS listener (peer cert chained to the trust anchor, not expired,
  not revoked, 4-tuple binding extracted). Admission in production requires that
  variant. This makes "the channel is encrypted + mutually authenticated" a
  type-level fact, not a header string.

## 6. Phased implementation plan

**Phase 1 — policy + downgrade scaffolding (landed this pass; no PKI infra).**
- `SelfHostedTransportPosture` { `MarkerContract`, `RequireProductionMtls` },
  `SelfHostedTransportChannel` { `UnverifiedMutualTlsMarker`, `SymmetricAead` },
  and `SelfHostedTransportPolicy` with a pure `admit()` decision function
  (`crates/ferrogate-runtime/src/self_hosted_worker.rs`).
- `production_mtls_transport_implemented()` `const fn` → `false`, now the single
  source of truth for the admin contract flag.
- Config flag `FERROGATE_SELF_HOSTED_REQUIRE_PRODUCTION_MTLS` → gateway builds
  the policy and enforces downgrade-rejection in
  `handle_self_hosted_worker_transport` before dispatch.
- Honest error surface: `403 downgrade_rejected` / `501 not_implemented`.

**Phase 2 — verified mTLS listener (DEFERRED; needs PKI infra + security review).**
- Trust-anchor config + loader (fail-closed).
- mTLS listener terminating client certs at the gateway; chain + expiry +
  revocation validation; 4-tuple binding extraction.
- `VerifiedMutualTls` channel variant constructed only from a verified
  handshake; production admission requires it.
- Flip `production_mtls_transport_implemented()` → `true` only when this lands
  with green conformance tests.

**Phase 3 — transport-token issuance + rotation.**
- Post-handshake short-TTL cert-bound token issuance; rotation reusing
  `rotate_token`; revocation on cert revoke / worker deactivate; server-clock
  anti-replay window.

## 7. Conformance test list

Phase 1 (implemented now — pure, infra-free):
- `default_transport_policy_admits_both_marker_paths`
- `marker_contract_policy_admits_both_marker_paths`
- `production_policy_rejects_symmetric_aead_as_downgrade` (downgrade reject)
- `production_policy_rejects_unverified_mtls_marker_as_not_implemented`
- `production_mtls_transport_is_not_yet_implemented` (honest boundary)
- gateway wiring: `parses_truthy_require_production_mtls_values`,
  `parses_falsey_or_absent_require_production_mtls_values`,
  `maps_transport_security_to_observed_channel`,
  `production_policy_rejects_marker_and_aead_channels`

Phase 2/3 (to add when the mTLS listener + token lifecycle land):
- **cert-valid pass**: a request on a verified mTLS channel with a
  correctly-bound leaf cert is admitted in production mode.
- **cert-invalid reject**: wrong CA / expired / revoked / malformed cert →
  handshake rejected, request refused.
- **downgrade reject** (channel-level): a plaintext/AEAD request against the
  production listener is refused even with a `mutual_tls` header.
- **cert↔4-tuple mismatch reject**: cert bound to worker A used for worker B →
  rejected.
- **token rotation**: issue → rotate before expiry → old token invalidated →
  new token accepted; rotation ties into `rotate_token`.
- **expired-identity reject**: cert past `notAfter` (server clock) or
  transport token past TTL → rejected, ignoring any client-supplied time.
