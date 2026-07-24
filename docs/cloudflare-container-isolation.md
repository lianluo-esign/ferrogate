# Cloudflare Containers / Sandbox Isolation Tier (issue #415)

FerroGate treats **Cloudflare Containers** (and the **`@cloudflare/sandbox`
SDK**) as just another isolation backend alongside Firecracker / Docker /
local-process — a per-tenant isolated tier for agent runs that must execute
arbitrary / untrusted code. Because Cloudflare exposes **no public container
lifecycle REST API**, the whole lifecycle is driven **remotely through the
fronting agent-gateway Worker** (issue #413, the *tethered principle*), never as
a direct call into a container.

Code map:

- Worker routes + verbs + dispatch: `workers/agent-gateway/src/container.ts`
  (dispatched from `src/index.ts`; shared bearer auth in `src/auth.ts`)
- Rust control client: `crates/ferrogate-runtime/src/cloudflare_container.rs`
  (`ContainerControlClient`; reuses the #427 `AgentInstanceIdentity` naming
  scheme and the #413/#414 `GatewayControlTransport` transport seam)
- agent-worker isolation backend:
  `crates/agent-worker/src/cloudflare_container_backend.rs`
  (`CloudflareContainerIsolationBackend`, implements the runtime
  `IsolationBackendLifecycle` contract) + registration in `src/backends.rs`
- Runtime kind + capabilities + descriptor:
  `crates/ferrogate-runtime/src/isolation.rs`
  (`IsolationBackendKind::CloudflareContainer`) and
  `cloudflare_container_descriptor` / `cloudflare_container_capabilities`

## Platform facts (Containers GA, April 2026)

- A container class is `class X extends Container` (`@cloudflare/containers`),
  backed by a Durable Object; the image is built/pushed by Wrangler and the
  Worker is deployed via `PUT`. There is **no public REST lifecycle** — the
  low-level surface is only reachable from Worker code. On the `Container` base:
  `start({ envVars, entrypoint, enableInternet, labels })`, **`stop(signal)`**
  (signal ∈ `'SIGTERM' | 'SIGKILL' | 'SIGINT'` or an integer; default SIGTERM),
  `destroy()` (SIGKILL teardown), `getState()`, and the egress controls
  `enableInternet` (a class field), `setAllowedHosts(hosts)` /
  `setDeniedHosts(hosts)`. There is **no `signal(...)` method** and **no
  `configureEgress(...)`** — those two fabricated calls were the #415 live
  crashes.
- The **Sandbox SDK** (`@cloudflare/sandbox@0.12.4`): `getSandbox(ns, id)`
  returns the fully-typed `Sandbox` DO stub →
  `exec(cmd, { timeout? })`, `runCode(src, { language, timeout? })`,
  `createSession` / `getSession`, `setEnvVars`, `listFiles`, `exposePort` /
  `unexposePort`, `stop(signal)`, `destroy()` — ideal for untrusted
  agent-generated code, the primary use of this tier. A non-zero / abnormal exit
  takes the session shell down and surfaces as a thrown **`SessionTerminatedError`**
  (a real export carrying `.exitCode`), which the Worker catches and maps to a
  governed exec result rather than a 5xx. For a **shell-wrapped** exit
  (`sh -c "exit N"`) the SDK leaves `.exitCode` null and embeds the code in the
  message (`… shell exited (exit code: N)`); the Worker extracts it either way, so
  the direct-command and shell-wrapped paths both return `{ exitCode: N }`.
- **argv contract / injection safety.** `/container/exec` takes `step.command` as
  an **argv array**, but `Sandbox.exec` accepts only a command *string* (there is
  no argv/`string[]` overload in `@cloudflare/sandbox@0.12.4`). Naively joining the
  argv with spaces would re-subject every token to the container shell
  (word-splitting, globbing, `;`/`$(…)`/backtick/redirection) — a command-injection
  surface on this untrusted-code backend. The Worker therefore **POSIX
  single-quote quotes each token** (embedded `'` → `'\''`) before joining, so
  argument boundaries are preserved and no token is shell-interpreted:
  `["printf","[%s]","a b","c"]` yields `[a b][c]`, not `[a][b][c]`.
- **Workers Paid only**; instances scale to zero; instance tiers
  `lite`→`standard-4` (≤ 4 vCPU / 12 GiB).

Because there is no REST lifecycle, **everything is fronted by the Worker**, and
FerroGate speaks to it over the same authenticated, bearer-gated channel as the
#413 control, #427 memory, and #426 schedule surfaces.

## Route surface

All POST + bearer-gated; the per-tenant instance name is in the body (never a
query string), minted by the Rust naming scheme `fg.{tenant}.{session}.{run}` —
per-instance Durable Object isolation **is** tenant isolation.

| Route | Body | Effect |
|-------|------|--------|
| `POST /container/prepare`   | `{ instance, container: { image, tier, workspacePath? } }` | validate + pin image/tier (create is lazy) |
| `POST /container/start`     | `{ instance, entrypoint?, env?, enableInternet?, egressAllowlist? }` | launch with governed egress |
| `POST /container/exec`      | `{ instance, step: { mode, command?/language?+source?, timeoutMillis? } }` | run a command or code step; capture stdout/stderr/exit |
| `POST /container/stop`      | `{ instance, signal }` | `Sandbox.stop(SIGTERM/SIGKILL)`, time-bounded |
| `POST /container/logs`      | `{ instance, tail? }` | recent instance logs (empty tail: the session surface has no aggregate log RPC) |
| `POST /container/artifacts` | `{ instance, path? }` | `Sandbox.listFiles` under the workspace |
| `POST /container/cleanup`   | `{ instance }` | `Sandbox.destroy()` in **bounded time** (see below) |

Error vocabulary (mapped to typed Rust errors by `ContainerControlClient`):
`invalid_spec` → 422, `container_unbound` → 501, `not_running` → 409, plus
401/403 for a bad bearer credential.

## Fail-closed by construction

- **Egress is deny-by-default.** The `@cloudflare/containers` base defaults
  `enableInternet = true` (full internet), so the Worker **subclasses** the SDK
  `Sandbox` as `AgentSandbox` and pins `enableInternet = false` (see
  `src/index.ts`). Every container start — including the lazy auto-start on the
  first `exec` — is therefore sealed. Any egress must ride a **governed
  allowlist** (mirroring the #117 function-egress broker), applied at runtime via
  `sandbox.setAllowedHosts(allowlist)` (the Container base grants those hosts
  egress even while `enableInternet` stays false). The allowlist path needs the
  Worker to export `ContainerProxy` from `@cloudflare/sandbox` (done in
  `src/index.ts`) so the DO can build outbound-interception fetchers via
  `ctx.exports.ContainerProxy`. Defense in depth: `enableInternet=true` with an
  empty `egressAllowlist` is rejected **client-side before any HTTP**
  (`ContainerControlError::EgressNotGoverned`) and again on the Worker (422
  `invalid_spec`).
- **Cleanup is bounded (resource-leak fix).** `Sandbox.destroy()` coalesces
  concurrent teardowns and, per the SDK's own docs, can **hang until the Durable
  Object is evicted** when the Containers control plane is unresponsive. So
  `/container/cleanup` races `destroy()` against a hard timeout and returns
  success either way (`destroyed:false` when unconfirmed) — a wedged instance is
  reported cleaned in bounded time and reclaimed by platform idle-sleep, instead
  of burning paid resources while the route blocks 60–90s. `/container/stop`
  is likewise time-bounded.
- **Capability gating.** `cloudflare_container_capabilities()` is the single
  source of truth and advertises a **strict subset** of the implemented
  lifecycle ops. `snapshot_or_checkpoint` is advertised `false` (Cloudflare
  exposes no container checkpoint primitive) and `secret_injection` is `false`
  (left to the gateway-mediated capability path), so `select_isolation_backend`
  can never route those ops here. The backend's `snapshot_or_checkpoint` method
  returns an honest `IsolationError::Backend` rather than fabricating a
  checkpoint.
- **Gateway-driven registration.** In the agent-worker registry the backend is
  marked `GatewayDriven`: it is advertised in the wire report (so the gateway /
  control plane sees the replaceable contract, with real capabilities and
  readiness) but the **on-host** provisioning path never selects it — the worker
  cannot provision a Cloudflare container locally; it drives one remotely. It is
  opt-in via `AGENT_WORKER_ENABLE_CF_CONTAINER_BACKEND=1`.
- **Optional binding.** The Worker's `CONTAINER_SANDBOX` DO binding is optional
  (like the semantic-memory pilot's `VECTORIZE`/`AI`). Absent it, every verb
  fails closed with `container_unbound` (501). `container.ts` binds the **real**
  `@cloudflare/sandbox@0.12.4` `Sandbox` type via `getSandbox(...)`, so
  `tsc --noEmit` type-checks every lifecycle call against the installed SDK — a
  fabricated method (e.g. the old `configureEgress`/`signal`) now fails the
  build instead of only crashing live.

## Lifecycle mapping

The agent-worker `CloudflareContainerIsolationBackend` maps the runtime
`IsolationBackendLifecycle` contract onto the client verbs:

| `IsolationBackendLifecycle` | `ContainerControlClient` | Worker route |
|---|---|---|
| `prepare`            | `prepare`          | `POST /container/prepare` |
| `start`             | `start`           | `POST /container/start` |
| `exec_or_attach`     | `exec`            | `POST /container/exec` |
| `stop`              | `stop`            | `POST /container/stop` |
| `collect_logs`       | `collect_logs`      | `POST /container/logs` |
| `collect_artifacts`  | `collect_artifacts`  | `POST /container/artifacts` |
| `cleanup`           | `cleanup`          | `POST /container/cleanup` |
| `snapshot_or_checkpoint` | *(none)* | *(unimplemented; advertised `false`)* |

## Configuration

Worker (`wrangler.toml`):

- `CONTAINER_MAX_OUTPUT_BYTES` — cap on captured stdout/stderr (default 1 MB).
- `CONTAINER_SANDBOX` — the Container/Sandbox DO binding (commented out by
  default; requires a Container/Sandbox class + image + a `new_sqlite_classes`
  migration + a `[[containers]]` block). Workers Paid only.

agent-worker (environment):

- `AGENT_WORKER_ENABLE_CF_CONTAINER_BACKEND=1` — opt in to the tier.
- `AGENT_WORKER_CF_CONTAINER_GATEWAY_URL` — the fronting Worker base URL.
- `AGENT_WORKER_CF_CONTAINER_CONTROL_TOKEN` — the DIY bearer control token.
- `AGENT_WORKER_CF_CONTAINER_IMAGE` (default `ferrogate/agent-sandbox:latest`)
  and `AGENT_WORKER_CF_CONTAINER_TIER` (default `standard-1`; one of
  `lite`..`standard-4`).

## Testing status

- **Unit-tested, offline (no network):** the `ContainerControlClient` verbs,
  wire shapes, egress governance, identity validation, and error mapping
  (`cloudflare_container_test.rs`); the full backend lifecycle against a scripted
  mock transport, evidence, and the fail-closed snapshot error
  (`cloudflare_container_backend_test.rs`); the registry gating
  (`backends_test.rs`); and `tsc --noEmit` for `container.ts`.
- **Not-tested (LIVE-CF, the test gate owns it):** the end-to-end run of a code
  step in a real Cloudflare sandbox capturing stdout/exit needs a bound
  `CONTAINER_SANDBOX` + a Workers-Paid account + network. After the #415 rework
  the gate must re-run, against a real CF sandbox: (1) `/container/start` no
  longer throws `configureEgress`; (2) `/container/exec` of a step that exits
  non-zero returns a governed result with the propagated `exitCode` (no
  `SessionTerminatedError` 5xx) — for **both** a direct-command exit and a
  shell-wrapped `sh -c "exit N"` (both must yield `{ exitCode: N }`); (3)
  `/container/exec` preserves **argv fidelity / injection safety**: argv
  `["printf","[%s]","a b","c"]` yields `[a b][c]` (not `[a][b][c]`), and shell
  metacharacters in a token (`;`, `$(…)`, backticks, redirections) are passed
  literally, not interpreted; (4) `/container/stop` no longer throws `signal` and
  stops the instance; (5) `/container/cleanup` on an instance whose session
  terminated abnormally completes in **bounded time** (≤ the cleanup timeout, not
  60–90s); (6) sealed-by-default egress (`enableInternet=false`) blocks internet
  and a governed `egressAllowlist` opens only the allowed hosts (verify the
  container image trusts the interception CA so `setAllowedHosts` enforces).
- **Remaining (follow-up slice):** wiring the backend into the agent-worker
  management **remote-provisioning dispatch** (constructing it from a production
  `BlockingHttpControlTransport` and driving it from `lifecycle.rs` with
  per-session storage in `state.rs`, mirroring `provision_docker`).
