# Plan — self-hosted worker path: close the execution/transport/durability gaps

Surfaced by the 2026-07-18 architecture review of the self-hosted microVM worker
model (pull / self-registering agent; customer owns the host + enforcement
boundary; FerroGate owns identity + dispatch + observability). Three real,
code-evidenced gaps remain before the self-hosted path is production-usable.

## Confirmed model (context)
- Self-hosted = **pull**: the node's `agent-worker` connects outbound, heartbeats,
  polls `/v1/self-hosted-workers/runs/poll` → lease → `runs/ack`. No inbound path
  to the customer host (`transport_shape: worker_initiated_outbound_polling`).
- Managed/cloud = **push**: `ManagedWorkerScheduler` dials out to the agent-worker
  management API and owns host lifecycle.
- Auth: 4-tuple (`tenant/workspace/worker/token` ids) + 256-bit `token_secret`
  (minted once, constant-time compared); transport mTLS or symmetric AEAD.
- self-hosted semantics: `execution_owner: customer`,
  `enforcement_boundary: customer_owned_host`, capability actions **report-only**.

## Gap 1 (P1) — self-hosted execution is fail-closed, not implemented
`reject_unsupported_self_hosted_execution` (agent-worker/src/main.rs:~305) bails
for every real subcommand under `--worker-type self-hosted`; only the
`worker-type` diagnostic runs. So a self-hosted node agent cannot actually run a
workload — it only *labels* events/evidence as self-hosted.

**Deliverable (first slice):** wire report-only execution for the
management-serving path (`ServeManagementUnix/Http`, `AcceptManagementJson`) and
the governed execution entrypoint under self-hosted policy: run through the
**local-process isolation backend** (landed for #205) with capability actions
**recorded as report-only** (not hard-enforced/blocked), identity expiry stamped
by the server clock, telemetry/evidence emitted with the `customer_owned_host`
enforcement boundary. Replace the blanket fail-closed with per-command support;
keep fail-closed only for commands genuinely not yet covered. Tests: a
self-hosted management session executes a workload through the local-process
backend and emits report-only capability evidence; the cloud path stays
enforced (regression).

## Gap 2 (P1, needs design) — production mTLS transport not implemented
`production_mtls_transport_implemented: false`; the
`x-ferrogate-transport-security` header is a contract marker only — no cert
validation, token issuance, rotation, or channel-enforcement. Security-critical;
**write a design doc first** (cert/CA model, token issuance+rotation, mutual
verification, downgrade protection) before implementing. Do NOT half-build a
security transport.

## Gap 3 (P2) — self-hosted dispatch lease queue is in-memory
The lease queue is in-memory, rebuilt from storage on registration changes. On a
gateway restart, in-flight lease state (assignment, attempt counts, ack windows)
is lost and relies on redelivery. **Deliverable:** persist lease
assignment/attempt/ack state durably (reuse the now schema-pinned control-plane
storage patterns) so restarts don't drop or double-deliver in-flight leases;
DSN-gated test proving lease state survives a simulated restart.

## Sequencing
1. Gap 1 (self-hosted execution) — highest value, leverages the #205 backend; do first.
2. Gap 3 (durable leases) — moderate, independent; can parallelize.
3. Gap 2 (mTLS) — design doc first, then implement in a later pass.
