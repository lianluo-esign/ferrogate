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

The primary gateway-to-`agent-worker` management path is an HTTP API over an
encrypted channel:

```text
POST /v1/agent-worker/management
content-type: application/json
x-ferrogate-transport-security: mutual_tls | symmetric_aead
```

Production deployments should use mTLS or an equivalent encrypted transport.
When symmetric application encryption is used, the HTTP body is an
`AgentWorkerManagementFrame` with `encoding=encrypted_json`; the frame carries
the routing identity in clear associated data and the signed envelope as an
AEAD-authenticated encrypted payload. Same-host development and contract smokes
may send a signed plaintext JSON envelope only when the transport is explicitly
marked as a local-only path. Do not treat local Unix sockets as the product
protocol; they are an optimization/test transport over the same envelope.

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
- optional `framework_adapter`
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
record the gateway will audit and bill. `framework_adapter` is optional for
backward-compatible discovery and native-harness smokes, but lifecycle requests
from the scheduler should set it to the selected adapter, such as
`native-harness`, `codex`, `claude-code`, or `hermes`. The field is part of the
signed envelope and encrypted-frame associated data so a request cannot be
retargeted to a different handler after authorization.

The initial standard actions are `probe_handlers`, `list_backends`,
`provision`, `exec_or_attach`, `stop`, `cleanup`, `stream_status`, and
`collect_artifacts`.

Every response uses the same envelope identity fields (`request_id`,
`idempotency_key`, `action`, `tenant_id`, `workspace_id`, `worker_id`,
`session_id`, `run_id`, and optional `framework_adapter`) plus `accepted`,
`duplicate_idempotency_key`, an optional action-specific `result`, and an
optional standardized error object. Successful action payloads are tagged with a
stable `result.kind` value so future actions can add typed data without changing
the response envelope. The current executable `probe_handlers` action returns
`result.kind=framework_handlers` with normalized handler readiness records.
`list_backends` returns `result.kind=isolation_backends` with
`registry_implemented=true` and worker-side backend readiness records. The
initial registry reports the Firecracker backend as ready only when
`AGENT_WORKER_FIRECRACKER_BIN`, `AGENT_WORKER_FIRECRACKER_KERNEL`, and
`AGENT_WORKER_FIRECRACKER_ROOTFS` all point to configured local files; the
worker does not scan `PATH` or execute the binary during readiness reporting.
Lifecycle dispatch now reaches worker-owned action branches for `provision`,
`exec_or_attach`, `stop`, `cleanup`, `stream_status`, and `collect_artifacts`.
`provision` fails closed with `incompatible_backend` when Firecracker is not
configured. When the full Firecracker bundle is configured but the real microVM
provision/start implementation is still absent, `provision` returns a typed
`result.kind=lifecycle` record with `status=failed` and
`outcome=not_implemented` so callers can persist the failed lifecycle evidence.
`exec_or_attach`
now has a worker-owned native harness execution smoke, but the worker must have
a gateway external-action HTTP authorizer configured before the handler may
continue. Without that gateway authorization client, `exec_or_attach` fails
closed with `run_failed` before `run.completed` is emitted. With an allowed
gateway decision, the result returns `result.kind=handler_events` with
normalized framework events such as `session.started`, `capability.allowed`,
`run.started`, `model.requested`, `artifact.created`, `run.completed`, and
`session.closed`.
`stream_status` can replay stored native-harness events as `handler_events`,
and `collect_artifacts` can return
`result.kind=handler_artifacts` with an artifact manifest plus the related
events. When `framework_adapter` selects `codex`, `claude-code`, or `hermes`,
the current worker path runs the process-shim contract and emits normalized
prepared events such as `session.started`, `capability.allowed`,
`run.started`, `model.requested`, `artifact.created`, and `session.closed`
without executing a real vendor binary or SDK. This is handler selection and
event-contract proof inside `agent-worker`, not Firecracker boot proof and not
Codex/Claude/Hermes process execution proof. The worker also
keeps a process-local management state store for bounded contract smokes:
accepted idempotency retries replay the first stored action outcome instead of
re-dispatching lifecycle logic, and lifecycle/handler outcomes are recorded
behind the worker-owned store boundary. This is intentionally not a production
durability claim; Postgres/Supabase-backed nonce, idempotency, session, run, and
evidence persistence is still required before long-running deployment.
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

The primary local process transport smoke is HTTP:

```bash
agent-worker serve-management-http \
  --listen 127.0.0.1:7777 \
  --external-action-authorizer-http-endpoint 127.0.0.1:7778 \
  --key-id "$AGENT_WORKER_MANAGEMENT_KEY_ID" \
  --shared-secret "$AGENT_WORKER_MANAGEMENT_SHARED_SECRET" \
  --max-requests 1 \
  --idle-timeout-millis 1000
```

This command accepts `POST /v1/agent-worker/management`, requires
`content-type: application/json`, requires
`x-ferrogate-transport-security=mutual_tls` or `symmetric_aead`, verifies the
signed envelope or encrypted frame, dispatches the requested management action,
writes one JSON `AgentWorkerManagementResponse`, and exits after
`--max-requests` requests. It is a std-library bounded smoke server for the HTTP
contract, not the final async production HTTP/mTLS server. Handler execution
actions such as `exec_or_attach` require the
`--external-action-authorizer-http-endpoint` gateway callback before the native
harness or a future Codex/Claude/Hermes handler may continue past its first
managed external action. Omitting that endpoint is valid for discovery and
non-execution lifecycle smokes, but managed handler execution fails closed.

There is also a Unix-domain socket local-only contract smoke:

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
`security.transport_security=local_unix_socket` for this transport. This path
must not be documented or implemented as the product gateway-to-worker protocol;
it exists for same-host development, deterministic contract tests, and local
optimization only.

The HTTP smoke proves the `agent-worker` process can receive management
requests over the intended API shape. The Unix smoke proves the same envelope can
also cross an explicit same-host process boundary and can shut down cleanly
without leaving a stale socket. Neither smoke is the final unbounded concurrent
production server, and neither boots Firecracker.

The server dispatches every authenticated request by action instead of treating
authentication as execution support.
`probe_handlers` returns a `framework_handlers` result payload. `list_backends`
returns an `isolation_backends` result with explicit Firecracker readiness, so
the gateway can distinguish a configured worker backend from a transport or
authentication failure. A ready Firecracker report only means the configured
worker bundle exists: `AGENT_WORKER_FIRECRACKER_BIN`,
`AGENT_WORKER_FIRECRACKER_KERNEL`, and `AGENT_WORKER_FIRECRACKER_ROOTFS` all
point to files. It must not be treated as evidence that a microVM can boot.
For operator/debug evidence, `agent-worker firecracker-prepare-plan` can emit
the worker-owned prepare plan for that configured bundle without starting
Firecracker. The plan reports `process=agent-worker`,
`host_lifecycle_owner=agent-worker`, `gateway_controls_firecracker=false`, the
configured bundle paths, planned host lifecycle steps, default resource policy,
no-direct-egress network policy, read-only rootfs/workspace filesystem policy,
and `proves_microvm_boot=false`. This is a preflight planning contract for #82,
not a provision success signal.
Lifecycle, status, and artifact actions such as `provision`, `exec_or_attach`,
`stop`, `cleanup`, `stream_status`, and `collect_artifacts` now reach
worker-owned lifecycle or handler dispatch. The dispatch still does not boot
Firecracker: configured-bundle `provision` returns failed lifecycle evidence
with `outcome=not_implemented` until real microVM lifecycle code exists,
while `exec_or_attach`, `stream_status`, and `collect_artifacts` can exercise
the selected framework handler inside `agent-worker` only after the worker
receives a `capability.allowed` decision from the configured gateway HTTP
authorizer. The requested capability is framework-specific: the native harness
uses a managed tool dispatch capability, Codex and Claude Code use a managed
CLI capability with gateway-controlled environment policy and output limits, and
Hermes uses managed memory-read capability for run context. The native harness
can complete deterministically. Codex, Claude Code, and Hermes first run a
bounded worker-owned configured binary smoke after the gateway returns
`capability.allowed`, then continue through process-shim contract adapters that
emit prepared run/model/artifact events. The binary smoke records a normalized
`cli.requested` event with `handler_owner=agent-worker`,
`gateway_handler_probe=false`, `real_binary_probe=true`, the configured env var,
binary path, probe args, status code, and output excerpts. The recorded handler
events therefore prove the managed action gate was crossed, `agent-worker`
started the configured adapter binary, and the selected adapter contract was
used; they still do not prove real agent task execution or microVM boot. Adding
real lifecycle success requires the Firecracker handler implementation,
HTTP/mTLS production transport, and contract coverage for Codex/Claude/Hermes
binary or SDK task launch.

When an adapter dependency is available on the worker host, `agent-worker` can
run a bounded binary smoke with `agent-worker smoke-handler-binary --adapter
codex|claude-code|hermes`. The smoke is owned by the worker process and reads
only the worker-owned binary configuration variables:
`AGENT_WORKER_CODEX_BIN`, `AGENT_WORKER_CLAUDE_CODE_BIN`, and
`AGENT_WORKER_HERMES_BIN`. It does not scan `PATH`, and the gateway must not run
the same probe itself. The current smoke executes a short version-style probe
with a timeout and returns JSON evidence for the adapter, configured binary
path, probe arguments, exit status, and output excerpts. A passing binary smoke
proves only that the configured handler binary can be started by `agent-worker`;
it is not Firecracker boot proof, SDK integration proof, or proof that a real
agent task completed.

The gateway/control-plane side uses `AgentWorkerHttpManagementClient` for the
primary worker management path. The client sends `POST
/v1/agent-worker/management`, sets `content-type: application/json`, sets
`x-ferrogate-transport-security` to `mutual_tls` or `symmetric_aead`, enforces
the management message size limit, reads one `AgentWorkerManagementResponse`,
and maps HTTP/framing failures to `AgentWorker` control errors. The mTLS-bound
path sends a signed plaintext envelope only when the caller has already
established the encrypted mutual-TLS channel. The symmetric path sends an
`AgentWorkerManagementFrame` with `encoding=encrypted_json`; nonce generation
and key rotation remain caller/control-plane responsibilities.

For same-host development and deterministic smokes, the gateway/control-plane
may still use `AgentWorkerUnixManagementClient`. That client serializes an
`AgentWorkerManagementEnvelope`, sends it to the configured Unix socket, shuts
down the request side of the stream, reads one response, and maps IPC failures
to `AgentWorker` control errors. Unix socket transport is local-only and must
not replace the HTTP encrypted-channel product protocol.

Neither client verifies signatures or executes lifecycle actions; those remain
worker-side responsibilities behind the management API.

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

The JSON contract smoke for handler-to-gateway authorization is:

```bash
agent-worker accept-external-action-json
```

It reads one managed external action authorization request from stdin and writes
one response with `accepted`, `decision`, optional normalized framework `event`,
and optional error object. The JSON contract supports the same managed action
surface as the runtime contract: `tool`, `mcp_tool`, `cli`, `skill`,
`filesystem`, `browser`, `rest`, `secret`, `memory`, and `network_egress` action
specs. Allowed responses prove only that the handler may continue to the next
execution step; the command itself still does not execute the external action.
Denied, approval-required, invalid, or self-hosted requests fail closed before
handler execution. Gateway policy decisions that are denied or
approval-required still preserve the normalized framework event in the response,
so management callers can store `capability.denied` or `capability.requested`
evidence in the run timeline instead of reducing the result to a worker-local
error string.

The worker-side transport contract for the real gateway/control-plane
authorizer uses HTTP as the primary path:

```text
POST /v1/agent-worker/external-actions/authorize
content-type: application/json
```

The request body is the same shared JSON envelope wrapped as
`GatewayExternalActionTransportRequest`:

- `request_id`: stable request identity derived from run, session, worker,
  adapter, and action kind.
- `authorization`: the `ExternalActionAuthorizationRequest` body.

The gateway replies with `GatewayExternalActionTransportResponse`, echoing the
same `request_id` and carrying the same authorization response shape used by the
stdin smoke. The standalone worker client rejects mismatched response ids,
missing accepted-event evidence, malformed canonical event JSON, denied
decisions, approval-required decisions, and transport failures before handler
execution. Gateway authorizer transport failures and timeouts are normalized as
`capability.denied` events with `failure_source=gateway_authorizer_transport`,
so the management caller can still persist timeline evidence for the blocked
action instead of seeing only a worker-local I/O error. Same-host Unix socket
transport remains available for local
development and deterministic tests, but it is not the product callback
protocol. Production deployments must run this HTTP callback path inside the
same encrypted gateway-to-worker channel family as the management API.

The worker-side HTTP transport smoke is:

```bash
agent-worker external-action-http-transport-smoke \
  --gateway-authorizer-http-endpoint 127.0.0.1:7778
```

It calls the gateway HTTP authorizer, requires a `capability.allowed` response,
prints the normalized event JSON, and still does not execute the requested tool.

For a local execution smoke that proves the CLI action is not spawned until
after gateway authorization, `agent-worker` also provides:

```bash
agent-worker governed-cli-execution-smoke
```

The smoke uses a built-in allow-only CLI policy, requests a managed `cli`
capability, executes a bounded `/bin/sh -c` command only after
`capability.allowed`, and prints both the authorization event and the resulting
`cli.requested` execution evidence. This is a deterministic local CLI smoke; it
is not a general-purpose shell runner, not Codex/Claude/Hermes task execution,
and not Firecracker boot proof.

The equivalent local tool and MCP tool execution smokes are:

```bash
agent-worker governed-tool-execution-smoke
agent-worker governed-mcp-tool-execution-smoke
```

The tool smoke requests a managed `tool` capability, then runs the built-in
`native.echo` smoke handler only after `capability.allowed` and emits
`tool.requested` evidence. The MCP smoke requests a managed `mcp_tool`
capability, then runs the local `local-smoke/echo` handler only after
authorization and emits `mcp.tool.requested` evidence. These are deterministic
local contract smokes; they are not a general plugin runner, not a live MCP
server connection, and not Firecracker boot proof.

The equivalent local skill invocation smoke is:

```bash
agent-worker governed-skill-execution-smoke
```

It requests a managed `skill` capability, then invokes the built-in
`builtin.skill.echo` smoke handler only after `capability.allowed` and emits
`skill.requested` evidence with declared capabilities. This is deterministic
local skill contract coverage; it is not an external skill package runtime,
not ambient host skill execution, and not Firecracker boot proof.

The equivalent local memory read/write smoke is:

```bash
agent-worker governed-memory-execution-smoke
```

It requests managed `memory.write` and `memory.read` capabilities before writing
and reading a local session-scoped smoke value, then emits `memory.write` and
`memory.read` evidence with `executed_after_authorization=true`. This is local
session-memory contract coverage; it is not durable memory storage, cross-run
memory indexing, or Firecracker boot proof.

The equivalent local REST execution smoke is:

```bash
agent-worker governed-rest-execution-smoke
```

It starts a one-shot loopback HTTP server, requests a managed `rest`
capability, sends a bounded GET request only after `capability.allowed`, and
prints the `rest.requested` execution evidence plus the served request line.
This proves the managed REST execution gate and local evidence path; it is not
unrestricted public egress, browser automation, or Firecracker boot proof.

The equivalent local filesystem read smoke is:

```bash
agent-worker governed-filesystem-execution-smoke
```

It creates a temporary workspace file, requests a managed `filesystem`
capability, reads that workspace-relative file only after
`capability.allowed`, and prints `filesystem.requested` evidence with the
resolved path, access mode, byte count, and bounded content excerpt. This proves
the managed filesystem execution gate for local read-only workspace access; it
is not broad host filesystem access, write/delete coverage, or Firecracker boot
proof.

The gateway/control-plane side can serve this HTTP authorizer when
managed runtime is enabled with:

```yaml
agent_runtime:
  enabled: true
  provider: managed_worker
  managed_worker:
    external_action_authorizer_http_listen: 127.0.0.1:7778
    # Optional local-only development/test path.
    external_action_authorizer_socket: /run/ferrogate/agent-actions.sock
    # Optional test/smoke limit. Omit for the long-running gateway service.
    external_action_authorizer_max_requests: 1
    allowed_actions: [tool, mcp_tool]
    approval_required_actions: [cli, rest, network_egress]
    allow_direct_network_egress: false
```

The gateway service owns the shared
`GatewayExternalActionTransportRequest`/`GatewayExternalActionTransportResponse`
contract, applies the gateway capability authorizer, and appends the normalized
capability event to the agent run timeline before replying. Operator policy can
grant low-risk actions, require approval for high-risk actions, and explicitly
opt in to direct managed-worker network egress. Unlisted actions remain denied.
That means the socket path is a real control-plane enforcement boundary, but it
still does not run the handler action or manage the Firecracker microVM
lifecycle.

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
- `poll_run`
- `ack_run`
- `stream_events`
- `upload_artifact`
- `fetch_checkpoint`
- `close_session`

### Self-Hosted Dispatch Transport

Self-hosted worker dispatch follows the mature GitHub Actions runner shape:
the worker initiates the transport session, polls for work, receives a leased
run, and acknowledges the lease. FerroGate does not require an inbound network
path to the customer host for the primary remote-worker flow.

The product transport is HTTP over a mutually authenticated encrypted channel.
The contract is:

1. The worker registers and obtains a tenant/workspace-scoped identity.
2. The worker sends `poll_run` with its identity, framework adapter, supported
   capabilities, current time, and requested lease duration.
3. FerroGate validates the identity, tenant/workspace scope, adapter, and
   capability match.
4. FerroGate returns either no work or a `SelfHostedRunLease` containing
   `dispatch_id`, `lease_id`, `session_id`, `run_id`, `workload_ref`, attempt,
   and `lease_expires_at_unix`.
5. The worker sends `ack_run` with the same identity, `dispatch_id`, `lease_id`,
   `run_id`, status, and report time.
6. If a lease is not acknowledged before expiry, FerroGate may redeliver the
   same dispatch with a higher attempt number.

The current runtime contract includes an in-memory lease queue and gateway-side
HTTP poll/ack endpoints to lock the worker-initiated wire shape:

```text
POST /v1/self-hosted-workers/heartbeat
POST /v1/self-hosted-workers/events
POST /v1/self-hosted-workers/artifacts
POST /v1/self-hosted-workers/checkpoints
POST /v1/self-hosted-workers/runs/poll
POST /v1/self-hosted-workers/runs/ack
```

The gateway endpoints require the `x-ferrogate-transport-security` contract
header. `mutual_tls` keeps the request body as the typed JSON payload when the
caller is already inside an encrypted mTLS channel. `symmetric_aead` wraps
request payloads and successful response payloads in a self-hosted worker
transport frame with `encoding=encrypted_json`; the clear frame identity is AEAD
associated data and is used to find the registered worker identity secret before
decryption. The
heartbeat endpoint validates the worker identity envelope before writing
reported heartbeat evidence through the same storage-backed worker record path
used by the Admin API. The events endpoint validates the
same identity envelope before writing normalized lifecycle/log/tool/MCP/CLI/
skill/artifact/checkpoint/usage telemetry evidence through the storage-backed
event record path. The artifacts endpoint validates the same identity envelope
before writing reported artifact metadata through the storage-backed artifact
record path. The checkpoints endpoint validates the same identity envelope
before writing reported checkpoint metadata through the storage-backed
checkpoint record path. The run endpoints decode the same JSON request bodies
from either mTLS plaintext or symmetric AEAD frames and return
`SelfHostedRunLease` / `SelfHostedRunAck` responses. This proves scope
matching, adapter matching, capability matching,
active lease ownership, idempotent dispatch identity, fail-closed identity
errors, heartbeat ingestion, telemetry event ingestion, artifact metadata
ingestion, checkpoint metadata ingestion, and ack semantics through the real
local gateway HTTP path.

This is still not the production mTLS listener. The current header is a
contract marker for local wire-shape tests; it does not validate certificates,
issue transport tokens, rotate secrets, or prove encrypted channel enforcement.

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
