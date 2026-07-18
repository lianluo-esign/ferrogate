# Self-hosted worker production mTLS transport — design

Status: **design + Phase 1 (policy/downgrade scaffolding) + Phase 2/3 (verified
mutual-TLS transport core: trust anchor, handshake + cert validation, 4-tuple
binding, `VerifiedMutualTls` admission, and cert-bound transport-token
issuance/rotation/expiry) landed.** The verified-mTLS core lives in
`crates/ferrogate-runtime/src/self_hosted_mtls.rs` and is covered by the
conformance tests in `self_hosted_mtls_conformance_test.rs` (real rustls
handshakes over loopback with rcgen-generated certs). What remains is *deployment*
wiring: binding this verified-mTLS terminator onto a concrete production ingress
socket and control-plane cert issuance at worker registration.

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

**Behavior in `RequireProductionMtls`:** the policy admits a `VerifiedMutualTls`
channel (produced only by a real, verified handshake) and rejects the two marker
paths — `symmetric_aead` as an explicit **downgrade** (`403`,
`self_hosted_worker_transport_downgrade_rejected`) and the bare `mutual_tls`
header over the plaintext marker path as an **unverified marker** (`501`,
`self_hosted_worker_production_mtls_not_implemented`; the error code is retained
for wire-contract stability). A request that did not arrive on a verified channel
therefore still fails closed: we refuse traffic rather than accept an
unverifiable claim as production-grade.

## 5. Channel-enforcement — proving encryption, not claiming it

The header is a claim; the design requires **proof**. In production the
admission decision is driven by a `SelfHostedTransportChannel` value that the
gateway can only construct from something it actually verified:

- The enum now has three variants — `UnverifiedMutualTlsMarker`, `SymmetricAead`,
  and `VerifiedMutualTls(..)`. Only the last is admissible in production.
- The `VerifiedMutualTls` variant carries a
  `ferrogate_runtime::VerifiedMutualTls` proof that is **only** constructible from
  a completed, verified TLS handshake at `SelfHostedMtlsServer::accept` (peer cert
  chained to the single configured trust anchor, not expired against the server
  clock, 4-tuple binding extracted from the SPIFFE URI SAN). `VerifiedMutualTls`
  has no public constructor, so admission in production requires an actually
  verified channel. This makes "the channel is encrypted + mutually
  authenticated" a type-level fact, not a header string.

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

**Phase 2 — verified mTLS listener (LANDED, `self_hosted_mtls.rs`).**
- `SelfHostedMtlsTrustAnchor` config + loader (single CA, fail-closed on any
  parse/load error; never the OS trust store).
- `SelfHostedMtlsServer` terminates a real rustls mutual-TLS handshake, requiring
  + validating the client cert chain against the configured anchor (rustls/webpki
  chain + signature + validity), with an additional server-clock `notAfter`
  re-check, and extracts the SPIFFE 4-tuple binding.
- `VerifiedMutualTls` channel variant constructed only from a verified handshake;
  production admission requires it (`SelfHostedTransportPolicy::admit`).
- `production_mtls_transport_implemented()` flipped → `true`, backed by green
  conformance tests.
- Remaining (deployment): binding the terminator onto a concrete production
  ingress socket + control-plane cert issuance at registration; CRL/OCSP-style
  revocation list (currently expiry-driven only).

**Phase 3 — transport-token issuance + rotation (LANDED, `self_hosted_mtls.rs`).**
- `SelfHostedTransportTokenIssuer` mints post-handshake short-TTL tokens bound to
  `(4-tuple, cert fingerprint, notAfter, issued_at server clock)`; the token TTL
  is capped by the cert `notAfter`.
- `SelfHostedTransportTokenStore` handles validate-before-rotate rotation with
  atomic invalidation of the prior token, refuses rotation presenting a different
  certificate, and supports immediate `revoke` on cert revoke / worker
  deactivate. Server-clock expiry throughout.

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

Phase 2/3 (implemented in `self_hosted_mtls_conformance_test.rs`, real handshakes):
- **cert-valid pass** — `cert_valid_request_is_admitted_in_production`: a request
  on a verified mTLS channel with a correctly-bound leaf cert is admitted in
  production mode.
- **cert-invalid reject** — `cert_from_untrusted_ca_is_rejected`,
  `expired_cert_is_rejected`, `trust_anchor_load_is_fail_closed_on_garbage`:
  untrusted-CA / expired / malformed anchor → handshake or load refused.
- **downgrade reject** (channel-level) —
  `production_posture_rejects_marker_and_aead_downgrade` (plus the Phase 1
  `production_policy_rejects_*` tests): marker/AEAD refused under production
  posture.
- **cert↔4-tuple mismatch reject** —
  `cross_worker_cert_is_rejected_for_mismatched_identity`: cert bound to worker A
  used for worker B → rejected.
- **token issuance / rotation / expiry** —
  `transport_token_issuance_binds_to_cert_and_expires`,
  `transport_token_rotation_invalidates_the_old_token`,
  `transport_token_rotation_rejects_a_different_certificate`,
  `expired_transport_token_is_rejected_and_rotation_refused`,
  `transport_token_ttl_is_bounded_and_capped_by_cert_notafter`: issue → rotate
  before expiry → old token invalidated → new token accepted; expiry/TTL bounds
  enforced by the server clock, ignoring any client-supplied time.
