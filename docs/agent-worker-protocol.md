---
title: Agent Worker Protocol
description: Ferrogate control-plane and execution-plane contract for self-hosted and Ferrogate-managed agent workers.
permalink: /agent-worker-protocol/
---

# Agent Worker Protocol

This document defines the execution contract for commercial agent workloads in
FerroGate.

The goal is not to standardize one framework. The goal is to standardize the
boundary between:

- a unified FerroGate control plane;
- pluggable execution backends;
- replaceable isolation layers;
- evolving worker languages and agent frameworks.

## Problem

FerroGate needs to support two commercial execution modes:

1. **Customer-hosted workers**: the customer provides a VM or host and installs
   a supported agent runtime such as Claude Code or Codex. FerroGate connects to
   that worker remotely and governs it.
2. **FerroGate-hosted workers**: FerroGate schedules and starts a worker runtime
   on behalf of the customer and manages its lifecycle.

Both modes must preserve the same tenant, policy, quota, audit, and observability
contract.

## Design Goals

- One control plane for all agent execution.
- Multiple execution backends behind the same API.
- Swappable isolation layers: VM, container, microVM, sandbox, or self-hosted.
- Framework-neutral worker protocol.
- Tenant isolation by default.
- Commercial readiness: quotas, audit trails, billing evidence, rollback,
  versioning, and customer-visible lifecycle state.

## Non-Goals

- Hard-coding one framework into the protocol.
- Letting the gateway hot path own planning or memory.
- Embedding execution-specific logic into the control plane.
- Requiring the same runtime model for self-hosted and managed workers.

## Reference Architecture

### 1. Control Plane

FerroGate owns:

- tenant and workspace identity;
- worker registration and versioning;
- policy and approval rules;
- quota, billing, and settlement;
- run lifecycle state;
- artifact and log indexing;
- audit and trace evidence;
- routing to a worker backend.

### 2. Execution Plane

A worker backend executes the agent. It may be:

- a customer VM with Claude Code or Codex installed;
- a FerroGate-managed container;
- a microVM-backed runtime;
- a sandboxed in-process runtime for low-risk workloads.

### 3. Isolation Plane

The isolation layer is an adapter, not a product decision. Supported isolation
targets should include:

- bare VM;
- Docker / rootless Docker;
- gVisor;
- Kata Containers;
- Firecracker or equivalent microVM;
- local sandbox for low-risk developer usage.

## Protocol Model

The protocol should be event-driven and session-scoped.

### Gateway-To-Agent-Worker Management API

Managed FerroGate execution uses a separate `agent-worker` process. The
gateway/control plane makes the scheduling decision, then calls the
`agent-worker` management API. The gateway must not probe adapter binaries,
spawn Codex, Claude Code, or Hermes, or manage Firecracker lifecycle details.

This protocol is an internal API boundary, not an implementation shortcut. The
gateway and `agent-worker` can be upgraded independently only if every request
and response remains versioned, authenticated, replay-resistant, deadline-bound,
idempotent, and encoded with stable wire values. Any new transport or lifecycle
action must preserve this contract instead of adding side-channel arguments or
transport-specific behavior.

Every gateway-to-`agent-worker` management request is either a local plaintext
JSON envelope or a standard `AgentWorkerManagementFrame`. The plaintext form is
allowed only for same-host Unix socket contract smokes. Network-capable
transports should send a frame with `encoding=encrypted_json`; the frame carries
the routing identity in clear associated data and the signed envelope as an
AEAD-authenticated encrypted payload.

The signed envelope uses stable snake_case enum values and carries:

- `protocol_version`
- `action`
- `request_id`
- `idempotency_key`
- `issued_at_unix_millis`
- `deadline_unix_millis`
- `tenant_id`
- `workspace_id`
- `worker_id`
- optional `session_id`
- optional `run_id`
- `security.key_id`
- `security.nonce`
- `security.signature`
- `security.algorithm`
- `security.transport_security`
- `security.encrypted`

Lifecycle actions (`provision`, `exec_or_attach`, `stop`, `cleanup`,
`stream_status`, and `collect_artifacts`) must include both `session_id` and
`run_id`. Discovery actions (`probe_handlers` and `list_backends`) may omit
them. This prevents a lifecycle command from being detached from the durable run
record the gateway will audit and bill.

The initial standard actions are `probe_handlers`, `list_backends`,
`provision`, `exec_or_attach`, `stop`, `cleanup`, `stream_status`, and
`collect_artifacts`.

Every response uses the same envelope identity fields (`request_id`,
`idempotency_key`, `action`, `tenant_id`, `workspace_id`, `worker_id`,
`session_id`, and `run_id`) plus `accepted`, `duplicate_idempotency_key`, an
optional action-specific `result`, and an
optional standardized error object. Successful action payloads are tagged with a
stable `result.kind` value so future actions can add typed data without changing
the response envelope. The current executable `probe_handlers` action returns
`result.kind=framework_handlers` with normalized handler readiness records.
`list_backends` returns `result.kind=isolation_backends` with
`registry_implemented=true` and worker-side backend readiness records. The
initial registry reports the Firecracker backend as ready only when
`AGENT_WORKER_FIRECRACKER_BIN` points to a configured local file; the worker
does not scan `PATH` or execute the binary during readiness reporting.
Lifecycle dispatch now reaches worker-owned action branches for `provision`,
`exec_or_attach`, `stop`, `cleanup`, `stream_status`, and `collect_artifacts`.
`provision` fails closed with `incompatible_backend` when Firecracker is not
configured and with `provision_failed` when the binary is configured but the
real microVM provision/start implementation is still absent. `cleanup` and
`stream_status` can return `result.kind=lifecycle` with explicit `not_started`
evidence before any Firecracker instance exists; this is lifecycle evidence, not
microVM boot proof. The worker also keeps a process-local management state store
for bounded contract smokes: accepted idempotency retries replay the first stored
action outcome instead of re-dispatching lifecycle logic, and lifecycle result
events are recorded behind the worker-owned store boundary. This is intentionally
not a production durability claim; Postgres/Supabase-backed nonce, idempotency,
session, run, and evidence persistence is still required before long-running
deployment.
Stable error codes include `invalid_request`, `unsupported_protocol_version`,
`unsupported_action`, `transport_security_required`, `policy_denied`,
`quota_exceeded`, `incompatible_backend`, `handler_unavailable`, `worker_busy`,
`provision_failed`, `run_failed`, `timeout`, `cancelled`, `cleanup_failed`,
`invalid_signature`, `unknown_key`, `nonce_replay`, and
`idempotency_conflict`, `message_too_large`, `invalid_frame`, and
`decryption_failed`. Callers must use the structured `retryable` flag instead of
string-matching error messages.

The management API fails closed:

- unsupported protocol versions are rejected;
- missing identity or security fields are rejected;
- expired deadlines and excessive clock skew are rejected;
- unknown `key_id` values are rejected;
- invalid signatures are rejected with constant-time comparison;
- replayed nonces are rejected;
- reused idempotency keys are accepted only when they bind to the same
  lifecycle fingerprint.
- authenticated lifecycle actions are still dispatched by action; authentication
  success never implies Firecracker execution support.

The supported MAC algorithms are `shared_secret_blake2b` and
`mtls_bound_blake2b`. The MAC proves request authenticity and integrity. It
does not encrypt payloads.

The `security.transport_security` value is part of the signed canonical input.
Supported values are:

- `local_unix_socket`: same-host process boundary only. This is acceptable for
  the local gateway-to-worker control plane because the socket path is local to
  the host and the request is still MAC-verified.
- `mutual_tls`: network-capable management channel bound to mutual TLS.
- `symmetric_aead`: network-capable management channel with authenticated
  symmetric payload encryption. These requests must also set
  `security.encrypted=true`.

Network or cross-host management traffic must use `mutual_tls` or
`symmetric_aead`; a shared-secret MAC alone is not payload encryption. Requests
that do not present an accepted transport security mode fail closed with
`transport_security_required`.

`symmetric_aead` uses `AgentWorkerManagementFrame` with
`encoding=encrypted_json`. The current standard algorithm is
`xchacha20poly1305`. The frame's associated data is the newline-joined
`protocol_version`, `action`, `request_id`, `tenant_id`, `workspace_id`,
`worker_id`, optional `session_id`, and optional `run_id`. The encrypted payload
contains the signed `AgentWorkerManagementEnvelope` JSON. Decryption must fail
closed when the frame identity is changed, the wrong shared secret is used, the
nonce is malformed, or the decrypted envelope identity does not match the frame.

Management messages have a 1 MiB maximum encoded size. Production key rotation
and durable nonce/idempotency storage are still required before unbounded
cross-host deployments; in-memory verifier state is acceptable only for local
contract smokes.

Nonce replay and idempotency state must eventually be durable for long-running
servers. In-memory state is acceptable only for deterministic local contract
smokes; production worker management must survive process restarts well enough
to avoid accepting replayed lifecycle requests inside the configured request
validity window.

The standalone worker binary exposes a local contract entrypoint for this
wire format:

```bash
agent-worker accept-management-json \
  --key-id "$AGENT_WORKER_MANAGEMENT_KEY_ID" \
  --shared-secret "$AGENT_WORKER_MANAGEMENT_SHARED_SECRET"
```

The command reads one signed management envelope or management frame from stdin
and writes one `AgentWorkerManagementResponse` JSON object to stdout. It
verifies the same contract future HTTP, gRPC, or Unix-socket transports must
use; it does not execute Firecracker lifecycle actions by itself.

The first concrete process transport is a Unix-domain socket contract smoke:

```bash
agent-worker serve-management-unix \
  --socket-path "$AGENT_WORKER_MANAGEMENT_SOCKET" \
  --key-id "$AGENT_WORKER_MANAGEMENT_KEY_ID" \
  --shared-secret "$AGENT_WORKER_MANAGEMENT_SHARED_SECRET" \
  --max-requests 1 \
  --idle-timeout-millis 1000
```

This command accepts signed JSON envelopes over the socket, verifies them
through the same management verifier, writes one JSON response per request,
removes the socket file, and exits after `--max-requests` requests. The default
is one request for deterministic contract smokes. When
`--idle-timeout-millis` is set, the server exits cleanly after that idle period
without a new connection and still removes the socket file. The same server
instance keeps verifier state across accepted connections, so nonce replay and
idempotency checks are not reset per connection. The same process also keeps
worker-owned management state, so an accepted retry with the same scoped
idempotency key and lifecycle fingerprint returns the stored action result with
`duplicate_idempotency_key=true` instead of executing the action branch again.
Accepted connections are handled independently, so one slow client cannot block
the listener from accepting a later management request during the same bounded
server run. The envelope should use
`security.transport_security=local_unix_socket` for this transport.

This proves the `agent-worker` process can receive management requests over an
explicit same-host process boundary and can shut down cleanly without leaving a
stale socket. It is not the final unbounded concurrent lifecycle server, does
not provide cross-host encryption, and does not boot Firecracker.

The server dispatches every authenticated request by action instead of treating
authentication as execution support.
`probe_handlers` returns a `framework_handlers` result payload. `list_backends`
returns an `isolation_backends` result with explicit Firecracker readiness, so
the gateway can distinguish a configured worker backend from a transport or
authentication failure. A ready Firecracker report only means the configured
binary path exists; it must not be treated as evidence that a microVM can boot.
Lifecycle, status, and artifact actions such as `provision`, `exec_or_attach`,
`stop`, `cleanup`, `stream_status`, and `collect_artifacts` now reach
worker-owned lifecycle dispatch. The dispatch still does not boot Firecracker:
`provision` fails closed until real microVM lifecycle code exists, while
`cleanup` and `stream_status` can report typed lifecycle `not_started` evidence
for sessions that never provisioned. Adding real lifecycle success requires both
the Firecracker handler implementation and contract coverage for the reported
response.

The gateway/control-plane side uses the same local wire contract through
`AgentWorkerUnixManagementClient`. The client serializes an
`AgentWorkerManagementEnvelope`, enforces the management message size limit,
sends it to the configured Unix socket, shuts down the request side of the
stream, reads one `AgentWorkerManagementResponse`, and maps IPC failures to
`AgentWorker` control errors. It does not verify signatures or execute lifecycle
actions; those remain worker-side responsibilities behind the management API.

### Gateway-Mediated External Actions

Managed worker handlers must not execute framework-requested external actions
directly. The standard adapter-facing request is `ManagedExternalActionRequest`.
It binds the current `FrameworkAdapterSession` to one typed action spec and
routes that action through `authorize_managed_external_action` before any
handler touches tools, MCP, shell, filesystem, browser automation, REST, secrets,
memory, or network egress.

The standalone `agent-worker` process now has a handler-facing external action
gate for this contract. Framework handlers prepare typed action specs inside the
worker, but `authorize_handler_external_action` requires a gateway authorization
client before the handler may continue. If that client is unavailable, if the
session is not a managed worker session, or if the gateway decision is denied or
approval-required, the gate fails closed before the handler executes the
requested action. This keeps Codex, Claude Code, Hermes, MCP, CLI, and REST
adapter code behind the same gateway-mediated boundary instead of letting
worker-local sandbox execution become an authorization shortcut.

The local smoke entrypoint is:

```bash
agent-worker external-action-smoke
```

It emits the normalized `capability.allowed` event JSON for a built-in native
tool authorization smoke and does not execute the tool. Real managed execution
must replace the smoke authorizer with the gateway/control-plane authorizer and
append the resulting timeline event through the durable run evidence path.

The current typed action specs are:

- `ManagedToolAction`: governed built-in or plugin tool call with argument
  policy.
- `ManagedMcpToolAction`: governed MCP server/tool call with argument policy.
- `ManagedCliAction`: command, args, working directory, env policy, timeout,
  stdout/stderr limits, and artifact capture policy.
- `ManagedSkillAction`: skill id and declared capability list.
- `ManagedFilesystemAction`: path, access mode, and workspace-relative flag.
- `ManagedBrowserAction`: browser operation, URL, and timeout.
- `ManagedRestAction`: method, URL, headers policy, body policy, timeout, and
  retry limit.
- `ManagedSecretAction`: secret id and use purpose.
- `ManagedMemoryAction`: read/write access, namespace, and key.
- `ManagedNetworkEgressAction`: host, port, and protocol.

Each action maps to the stable `CapabilityAction` policy surface and produces a
normalized framework event with `capability.allowed`, `capability.denied`, or
`capability.requested`. The event metadata preserves both the generic
authorization fields (`action`, `target`, `decision`, tenant/workspace/worker,
and isolation backend) and the action-specific policy shape such as CLI limits
or REST body/header policy. Invalid action specs fail before authorization so
operators do not see malformed worker requests as policy decisions.

Self-hosted workers use `self_hosted_external_action_report` for the same action
shape, but the event remains reported telemetry with
`trust_level=reported_by_self_hosted_worker`. It is not FerroGate-enforced
evidence unless the customer explicitly routes the action through a governed
callback path.

### Core Objects

- `tenant`
- `workspace`
- `worker`
- `session`
- `run`
- `artifact`
- `checkpoint`
- `policy_decision`
- `tool_call`

### Required Operations

- `register_worker`
- `probe_worker`
- `start_session`
- `submit_run`
- `cancel_run`
- `resume_run`
- `heartbeat`
- `stream_events`
- `upload_artifact`
- `fetch_checkpoint`
- `close_session`

### Required Worker Capabilities

- planning / reasoning loop;
- tool execution;
- checkpoint and resume;
- structured logs;
- artifact export;
- external callback for approvals;
- memory read/write hooks;
- optional framework-specific adapters.

## Gateway-Mediated Capability Boundary

Managed workers must not get ambient authority just because they run inside a
sandbox. The worker sandbox is an execution boundary, not a trust boundary.

Self-hosted workers are different: the customer owns the host and controls the
agent process, local tools, filesystem, network, and credentials. FerroGate
cannot and should not claim hard enforcement over that environment. For
self-hosted workers, the protocol boundary is registration, identity,
telemetry ingestion, lifecycle evidence, and optional customer-configured
governance callbacks.

Every external action produced by an agent must be mediated by the FerroGate AI
gateway control plane:

- ordinary tool calls;
- MCP tool calls;
- CLI and shell command execution;
- skill invocation;
- filesystem access beyond the prepared workspace;
- browser or network automation;
- third-party REST API calls;
- secret and credential access;
- memory reads and writes that cross the current session boundary.

For managed workers, the worker runtime should request a capability. FerroGate
decides whether the capability is allowed for the tenant, workspace, worker
template, session, run, adapter, and isolation backend.

For self-hosted workers, the worker daemon reports observations and lifecycle
events back to FerroGate. Any local enforcement is the customer's
responsibility unless the customer explicitly routes the action through
FerroGate.

Required enforcement layers:

- **Auth**: the request is bound to a tenant, workspace, worker identity,
  session, run, and API key or service principal.
- **Policy**: tenant and workspace rules decide allowed tools, MCP servers,
  CLI commands, skills, domains, methods, paths, and resource limits.
- **Guardrails**: request, response, prompt, command, tool arguments, and
  outbound REST payloads can be inspected or rejected before execution.
- **Approval**: high-risk operations can pause the run and require human or
  policy-driven approval.
- **Audit**: every allowed, denied, failed, and approved external action leaves
  immutable evidence.
- **Billing**: token, tool, network, runtime, and third-party API usage can be
  attributed to tenant, workspace, session, and run.
- **Egress control**: managed workers should default to no direct public
  network access. External API calls go through a gateway egress proxy or
  equivalent governed dispatch path.

The worker adapter may implement the framework-specific mechanics, but managed
adapters must not bypass this capability boundary. Direct unmanaged network
access, unmanaged CLI execution, direct MCP execution, and direct secret access
are rejected for managed workers unless a policy explicitly grants a controlled
gateway-mediated path.

Self-hosted worker events should preserve enough evidence for operators to see
what happened, but FerroGate treats those events as customer-provided telemetry,
not as proof that FerroGate enforced the action.

## Worker Backend Types

### A. Self-Hosted Remote Worker

Customer owns the host. FerroGate provides:

- registration token;
- TLS identity;
- protocol client;
- optional policy hints and governed callback endpoints;
- run dispatch when the customer opts into remote orchestration;
- status and telemetry collection.

The customer runs the worker daemon, chooses the local framework, and controls
local tool, network, filesystem, credential, and process access.

### B. FerroGate-Managed Worker

FerroGate provisions the backend, injects the runtime config, and recovers it
on failure.

This is the default commercial managed path.

### C. Hybrid Worker

The customer owns the execution image, FerroGate owns the orchestration and
observability layer.

This is the cleanest path for enterprise adoption.

## Agent Framework Strategy

The worker protocol should adapt to the framework, not the other way around.

Recommended support order:

1. Claude Code / Claude Agent SDK for code-oriented workers.
2. Codex SDK for OpenAI-native coding workers.
3. Hermes for general-purpose multi-step workers and memory-heavy flows.
4. A minimal native worker harness for fallback and testing.

Do not expose framework-specific semantics in the control-plane API.

## Lifecycle

1. Tenant registers a worker template or connects a self-hosted worker.
2. FerroGate issues a worker identity and capability envelope.
3. A run is scheduled against a session and isolation target.
4. Worker starts or resumes.
5. Tool calls and approvals flow through FerroGate governance.
6. Logs, artifacts, checkpoints, and traces are persisted.
7. Run completes, fails, or is cancelled.
8. Session is closed and resources are reclaimed.

## Commercial Requirements

- Per-tenant worker quotas.
- Per-workspace concurrency caps.
- Worker runtime version pinning.
- Signed worker images or package checksums.
- Runtime capability allowlists.
- Audit logs for every external action.
- Retry and recovery semantics.
- Clear usage and billing dimensions per tenant, workspace, worker, and run.

## API Surface Sketch

### Control Plane

- `POST /admin/v1/worker-templates`
- `GET /admin/v1/worker-templates`
- `GET /admin/v1/workers`
- `POST /admin/v1/workers`
- `GET /admin/v1/workers/{id}`
- `POST /admin/v1/workers/{id}/rotate`
- `POST /admin/v1/workers/{id}/disable`

### Runtime Plane

- `POST /v1/worker-sessions`
- `POST /v1/worker-sessions/{id}/runs`
- `POST /v1/worker-sessions/{id}/cancel`
- `POST /v1/worker-sessions/{id}/resume`
- `GET /v1/worker-sessions/{id}/events`
- `GET /v1/worker-sessions/{id}/artifacts`

This is a sketch, not a final API contract.

## Implementation Stages

### Stage 1: Protocol And Identity

- define protocol schema;
- define worker identity and session lifecycle;
- add self-hosted worker registration flow.

### Stage 2: Self-Hosted Execution

- add remote worker transport;
- add heartbeat, event streaming, and artifact upload;
- add cancellation and resume hooks.

### Stage 3: Managed Execution

- add managed-worker backend interface;
- add managed session scheduling and cleanup;
- add per-tenant and per-workspace concurrency control.

### Stage 4: Gateway-Mediated Capability Boundary

- add capability authorization for managed workers;
- route managed tool, MCP, CLI, skill, REST, secret, memory, and browser access
  through the AI gateway policy path;
- ingest self-hosted worker telemetry with explicit trust level.

### Stage 5: Framework Adapters

- add runtime adapters for Claude Code, Codex, and Hermes;
- normalize framework events into one worker event schema;
- preserve framework-specific configuration outside the public API.

### Stage 6: Isolation Backends

- add managed provisioning backend;
- add stronger isolation backends;
- add billing dimensions and operator dashboards;
- add enterprise policy controls.

## Tracking Issues

- #81 Agent Worker Protocol and commercial execution boundary.
- #83 Self-hosted worker registration, remote transport, and telemetry
  ingestion.
- #85 FerroGate-managed worker sessions and lifecycle.
- #86 Gateway-mediated capability boundary for managed worker tool, MCP, CLI,
  skill, REST, secret, memory, and network access.
- #84 Pluggable worker framework adapters for Claude Code, Codex, Hermes, and
  future frameworks.
- #82 Replaceable isolation backends for managed worker execution.

## Success Criteria

The design is commercially viable only when:

- a tenant can run multiple agents concurrently without cross-tenant leakage;
- the same control plane can route to self-hosted or managed workers;
- the worker backend can be swapped without changing client contracts;
- every run has an audit trail, usage record, and failure timeline;
- framework upgrades do not require control-plane redesign.
