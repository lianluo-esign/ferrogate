<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-18
  description: Token4AI Cloud, FerroGate AI Gateway, Rust API Gateway, agent-native AI traffic infrastructure.
-->

---
title: Customer-VPC Hybrid Deployment
description: Reference deployment for the signed customer-VPC data plane and offline policy loop (issue #206).
permalink: /deploy/customer-vpc/
---

# Customer-VPC Hybrid Deployment (signed data plane + offline policy loop)

This kit deploys FerroGate in the hybrid operating model: **sensitive AI
traffic stays inside the customer VPC** while a control plane distributes
policy as **ed25519-signed, monotonically-versioned snapshots** that the data
plane verifies before activation and keeps enforcing across control-plane
outages.

```
managed / operator side          |  customer VPC boundary
                                 |
 control-plane gateway           |   data-plane gateway(s)
 (holds the PRIVATE signing key) |   (hold only the PUBLIC trust anchors)
        |                        |        ^
        | publishes signed       |        | reads + verifies signed
        v snapshot               |        | snapshot (outbound-initiated)
   snapshot channel  ----------- sync --> snapshot channel (in-VPC copy)
                                 |
                                 |   durable store (customer Postgres/Supabase)
                                 |   provider keys, prompts, logs, evidence
```

Files in this kit:

| File | Purpose |
|---|---|
| `control-plane.toml` | Control-plane (publisher) config template. Contains the **private** signing key: deploy as a secret. |
| `data-plane.toml` | Customer-VPC data-plane config template. Contains only **public** trust anchors: safe in a ConfigMap. |
| `docker-compose.yaml` | Two-process reference deployment (evaluation / single host). |
| `k8s.yaml` | Kubernetes manifests for the split control-plane/data-plane deployment. |

The behavior this kit configures is proven end-to-end by
`crates/ferrogate-cli/tests/vpc_offline_loop_e2e.rs`, which spawns real
`ferrogate` processes in exactly these two roles and exercises interruption,
last-known-good enforcement, reconnect pickup, and replay rejection.

## 1. Generate and place the signing keys

The snapshot signature is ed25519. The config consumes standard base64 of the
raw 32-byte seed (private, control plane only) and of the raw 32-byte public
key (data plane trust anchor):

```sh
openssl genpkey -algorithm ed25519 -out snapshot-signing.pem

# base64 32-byte seed  -> cluster.snapshot_signing_key   (control plane, SECRET)
openssl pkey -in snapshot-signing.pem -outform DER | tail -c 32 | base64

# base64 32-byte pubkey -> cluster.snapshot_trusted_keys (data plane, public)
openssl pkey -in snapshot-signing.pem -pubout -outform DER | tail -c 32 | base64
```

Config placement (see the templates for the full sections):

- Control plane: `cluster.snapshot_signing_key`, `cluster.snapshot_signing_key_id`,
  `cluster.snapshot_tenant_id`, `cluster.snapshot_deployment_id`,
  `cluster.snapshot_max_age_secs` (snapshot TTL; expired snapshots can never be
  activated by a data plane).
- Data plane: `[[cluster.snapshot_trusted_keys]]` entries (`key_id`,
  `public_key`) plus the SAME `snapshot_tenant_id`/`snapshot_deployment_id`.
  The signature binds tenant + deployment identity, so a snapshot signed for
  another tenant or deployment is rejected (`IdentityMismatch`) even under the
  same key.

The private key never enters the customer VPC. The data plane holds public
material only.

### Key rotation

1. Add the new public key as a second `[[cluster.snapshot_trusted_keys]]`
   entry (new `key_id`) on every data plane and roll them.
2. Switch the control plane's `snapshot_signing_key`/`snapshot_signing_key_id`
   to the new key. Snapshots select the verification key by `key_id`.
3. After the next successful activation everywhere, remove the retired
   `key_id` from the data planes' trust lists.

### Authorized rollback

The data plane rejects any snapshot whose revision is not **strictly greater**
than the highest revision it has ever accepted (the replay floor), so an old
snapshot file can never be re-served — even by an attacker with write access
to the channel. To roll back *content*, re-publish the desired earlier
configuration through the control plane as a **new, higher** revision (e.g.
re-apply the old keys/policies via the Admin API). Rollback is an authorized
re-publish, never a replay.

## 2. What crosses the VPC boundary (data locality)

**Stays inside the customer VPC (never sent to the control plane):**

- Prompts, model responses, embeddings inputs, and tool-call arguments —
  provider traffic goes directly from the data plane to the model providers
  using provider credentials that exist only in the VPC (`api_key_env` on the
  data plane's `[[providers]]`).
- Provider API keys, client API-key secrets in use, TLS keys.
- Request logs, audit events, metering events, and Guardrail evidence — stored
  in the data plane's own storage backend (`[storage]`, e.g. the customer's
  Postgres/Supabase), which also carries retention configuration.
- The durable control-plane store (including the snapshot replay floor).

**Crosses the boundary (the only control signal):**

- The signed policy snapshot: a JSON document containing the API-key and
  policy set plus the signature envelope (`schema_version`, `tenant_id`,
  `deployment_id`, `key_id`, monotonic `revision`, `not_after_unix`,
  `signature`). It flows **into** the VPC; the reference channel is a shared
  file (`cluster.state_backend = "file"`) whose in-VPC copy is refreshed by an
  outbound-initiated transfer (object-store pull, rsync over an egress-only
  link, or a shared volume in the single-site compose layout). The data plane
  only ever **reads** the channel and verifies before activating; nothing in
  the gateway pushes VPC data back through it.
- Nothing else. The default deployment exports no prompt/response/tool bodies
  and no secrets to the control plane. Metrics/telemetry export is opt-in and
  separately configured; leaving it unconfigured exports nothing.

The snapshot itself contains policy metadata (API-key definitions including
their secrets-or-hashes as configured on the control plane, and policy rules).
Prefer `key_hash`/`key_env` API-key definitions on the control plane so the
snapshot carries no plaintext client secrets across the boundary.

## 3. Offline survival runbook

The verification order on every load is fail-closed: signature → identity →
schema → strictly-newer revision → expiry. Any failure keeps the running
last-known-good policy and surfaces the reason; there is no fail-open path.

**Symptom: control plane unreachable / channel stale or corrupted.**

- The data plane keeps serving and keeps enforcing the last activated
  (verified) policy. Issued keys keep working; revoked/unknown keys keep
  failing. This is the tested offline mode.
- Detection: `GET /admin/v1/status` on the data plane —
  `cluster.last_sync_error` becomes non-null (e.g. `invalid file cluster state
  JSON`, `failed to read file cluster state`, or `file cluster state rejected
  by signature verification: <reason>`), `cluster.stale` becomes `true`, and
  `cluster.active_revision` stops advancing. `/readyz` also carries the
  cluster block. Alert on `stale = true` for longer than your publish cadence.

**Recovery.**

1. Restore the channel (repair the transfer job / volume).
2. Publish a fresh snapshot from the control plane (any Admin mutation, e.g.
   a no-op key upsert, publishes a new signed revision).
3. Confirm on each data plane that `cluster.active_revision` advanced and
   `last_sync_error` returned to `null`. Pickup requires no restart.

**Expiry (fail-closed limit of offline mode).**

Signed snapshots carry `not_after_unix = publish_time + snapshot_max_age_secs`.
An expired snapshot is rejected (`Expired`) and can never be (re)activated —
so an outage longer than the TTL means: the running process continues on its
in-memory last-known-good, but any data-plane **restart** during the outage
comes back on its durable last-known-good baseline only if a durable
`[storage]` backend is configured (see below), and no stale channel content
can be re-adopted. Choose `snapshot_max_age_secs` as your maximum acceptable
policy staleness; publish (or republish) more frequently than it.

**Data-plane restart during an outage (replay window).**

The replay floor — the highest accepted revision — is persisted write-through
to the data plane's durable store and reloaded fail-closed at startup. With a
durable `[storage]` backend (Postgres/Supabase, as in the templates), a
restart therefore does NOT reopen the window: an older-but-authentically-
signed snapshot placed in the channel while the node was down is rejected as
`revision is stale or replayed`, and the node continues on its durably
persisted last-known-good policy. With the pure in-memory storage backend the
floor dies with the process (bounded rollback window of at most the snapshot
TTL after a restart) — configure durable storage for production VPC pilots.

**Verification rejections (tamper/replay/misconfig).**

`cluster.last_sync_error` names the exact reason: missing signature, no
trusted key for `key_id` (rotation not rolled out yet), signature failed
verification (tampered channel), identity mismatch (wrong tenant/deployment),
stale-or-replayed revision, expired, unsupported schema. Last-known-good stays
active in every case.

## 4. Deploy

Compose (single host, evaluation):

```sh
cd docs/deploy/customer-vpc
# fill in the two TOML templates (signing key, trusted key, tenant/deployment)
FERROGATE_CONTROL_DSN=postgresql://... docker compose up -d
```

Kubernetes: edit the same values inside `k8s.yaml` (the control-plane config
ships as a Secret because it embeds the private signing key; the data-plane
config is a ConfigMap), then:

```sh
kubectl apply -f docs/deploy/customer-vpc/k8s.yaml
```

In a real hybrid split, run the control-plane Deployment in the operator
cluster and the data-plane Deployment in the customer cluster; replace the
shared `ReadWriteMany` channel volume with your outbound-initiated replication
of the snapshot file into the VPC. General cluster guidance (drain, probes,
Redis counters, scaling) is unchanged from `docs/cluster-deployment.md`.
