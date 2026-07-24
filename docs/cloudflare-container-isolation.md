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
  low-level surface is only reachable from Worker code via `this.ctx.container`:
  `start({ env, entrypoint, enableInternet })`, `signal(SIGTERM|SIGKILL)`,
  `exec(cmd)`, `monitor()` (resolves on exit), `destroy()`,
  `getTcpPort(p).fetch()`, and a `running` boolean.
- The **Sandbox SDK** (`@cloudflare/sandbox`): `getSandbox(env.Sandbox, id)` →
  `exec`, `createCodeContext` + `runCode`, file ops, `.stop()` — ideal for
  untrusted agent-generated code, the primary use of this tier.
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
| `POST /container/stop`      | `{ instance, signal }` | SIGTERM/SIGKILL |
| `POST /container/logs`      | `{ instance, tail? }` | recent instance logs |
| `POST /container/artifacts` | `{ instance, path? }` | list files under the workspace |
| `POST /container/cleanup`   | `{ instance }` | destroy the instance |

Error vocabulary (mapped to typed Rust errors by `ContainerControlClient`):
`invalid_spec` → 422, `container_unbound` → 501, `not_running` → 409, plus
401/403 for a bad bearer credential.

## Fail-closed by construction

- **Egress is deny-by-default.** The runtime `IsolationNetworkPolicy` never
  grants direct public egress for a managed worker (it fail-closes in
  `validate`), which maps to `enableInternet=false`. Any egress must ride a
  **governed allowlist** (mirroring the #117 function-egress broker):
  `enableInternet=true` with an empty `egressAllowlist` is rejected
  **client-side before any HTTP** (`ContainerControlError::EgressNotGoverned`)
  and again on the Worker (422 `invalid_spec`, defense in depth).
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
  fails closed with `container_unbound` (501). The SDK surface is declared
  **structurally** in `container.ts`, so `tsc --noEmit` needs neither
  `@cloudflare/sandbox` nor `@cloudflare/containers` as a build dependency.

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
  `CONTAINER_SANDBOX` + a Workers-Paid account + network.
- **Remaining (follow-up slice):** wiring the backend into the agent-worker
  management **remote-provisioning dispatch** (constructing it from a production
  `BlockingHttpControlTransport` and driving it from `lifecycle.rs` with
  per-session storage in `state.rs`, mirroring `provision_docker`).
