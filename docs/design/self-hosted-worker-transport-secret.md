# Self-hosted worker transport: independent secret + HKDF key derivation

Round-4 adversarial audit, crypto-secrets surface (skeptic-verified HIGH).

## Problem

The `symmetric_aead` self-hosted worker transport authenticates and encrypts
data-plane frames (`/v1/self-hosted-workers/{heartbeat,events,artifacts,
checkpoints,runs/poll,runs/ack}`) with a shared secret that is the worker's
`identity_fingerprint`:

- `self_hosted_worker_runtime_identity` (state.rs) sets both `token_id` **and**
  `token_secret` to `registration.identity_fingerprint`.
- `self_hosted_worker_transport_secret` (state_agent_runtime.rs) returns
  `registration.identity_fingerprint` as the AEAD/bearer secret.
- `self_hosted_transport_aead_cipher` (self_hosted_worker.rs) derives the 32-byte
  XChaCha20Poly1305 key by zero-padding/truncating that string with **no KDF**.

The fingerprint is **not secret**: it is returned to `admin.read` callers in
`AdminSelfHostedWorkerRecord.identity_fingerprint`, and it is carried in the
**cleartext** `token_id` field of every frame it protects. An attacker who learns
a fingerprint (admin listing, logs, or a single passively-observed frame on the
non-mTLS channel) can forge and decrypt frames: full worker impersonation
(heartbeats/telemetry/artifacts/checkpoints) plus run-lease theft/cancellation.

The dispatch layer (`RegisteredSelfHostedWorker`) already models a **distinct**
`token_secret` and compares it in constant time — the flaw is purely that the CLL
wiring collapses the secret onto the public fingerprint.

## Fix

Provision an independent, high-entropy transport secret per worker, never derived
from or equal to any public value, and derive the AEAD key from it with HKDF.

1. **Generate** a 256-bit random `token_secret` (hex, 64 chars) at registration
   and re-generate it on rotation. Source: OS CSPRNG (`getrandom`).
2. **Persist** it on `StoredSelfHostedWorkerRegistration.token_secret`
   (`#[serde(default)]` for back-compat) + a `token_secret` column on
   `self_hosted_worker_registrations` (`ALTER TABLE ... ADD COLUMN IF NOT EXISTS`).
   Legacy rows default to empty → **fail closed** (see min-length below).
3. **Return once**: expose the secret only in the register/rotate responses
   (`transport_token_secret`), never in `AdminSelfHostedWorkerRecord` (GET/list),
   never in a frame. `token_id` stays the fingerprint (a non-secret lookup key).
4. **Wire**: `self_hosted_worker_runtime_identity.token_secret` and
   `self_hosted_worker_transport_secret` return the stored `token_secret`, not the
   fingerprint. The `token_id == fingerprint` equality stays a lookup check only.
5. **KDF**: replace zero-padding with `HKDF-SHA256(ikm = secret bytes, salt =
   fixed domain tag, info = "ferrogate-self-hosted-worker-transport-v1")`.
6. **Fail closed**: `validate_self_hosted_transport_shared_secret` requires a
   minimum secret length (32 chars), so an empty/legacy/short secret can never
   key the cipher.

## Security property (regression-tested)

- A frame encrypted with the **public fingerprint** is **rejected** (cannot
  decrypt/authenticate) — the exploit no longer works.
- A frame encrypted with the **provisioned secret** is accepted.
- The secret never appears in `AdminSelfHostedWorkerRecord` / GET / list.
- Rotation issues a fresh secret; the old secret stops working.

## Not in scope (follow-up)

Wiring a real external worker client (`agent-worker`) to consume the returned
secret and speak the transport. No such client exists in-repo today; the transport
is exercised only by the gateway + tests. Tracked separately.
