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
- Enforced egress posture (#471):
  `crates/ferrogate-runtime/src/cloudflare_container_egress.rs`
  (`ContainerEgressPosture`, `GovernedEgressAllowlist`,
  `PROVIDER_EGRESS_DENYLIST`, `EgressPostureAttestation`)
- Tether-bypass detection (#471):
  `crates/ferrogate-runtime/src/cloudflare_container_tether_audit.rs`
  (`TetherAuditor`, `TetherReconciliation`, `TetherVerdict`)
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

## What Cloudflare actually enforces for egress (issue #471)

Issue #471 asked whether the tether is a **control** or a **request**. Answer:
for the Containers/Sandbox tier it is a real control — Cloudflare enforces
egress outside the container — but only within the limits below. Everything in
this section was fetched from the Cloudflare developer docs on **2026-07-25**;
each row is labelled **verified** (a direct documented statement, quoted) or
**assumed** (our inference, which no Cloudflare doc confirms). Nothing inferred
is presented as a guarantee.

Sources:

- [Containers → Handle outbound traffic](https://developers.cloudflare.com/containers/platform-details/outbound-traffic/)
- [Sandbox SDK → Handle outbound traffic](https://developers.cloudflare.com/sandbox/guides/outbound-traffic/)
- [`cloudflare/containers` `docs/egress.md`](https://github.com/cloudflare/containers/blob/main/docs/egress.md)
- [Containers → Container class](https://developers.cloudflare.com/containers/container-class/)

| Question | Answer | Status |
|---|---|---|
| Is there a deny-all egress mode? | Yes. "Use `enableInternet = false` to block public internet access by default"; then "only traffic you explicitly allow … through `allowedHosts` or outbound handlers can leave the container". | **verified** |
| Is it the default? | **No — the platform default is open.** "By default, a Container will allow internet access". FerroGate pins it off in the `AgentSandbox` subclass. | **verified** |
| What survives `enableInternet = false`? | "Only ports `80`, `443`, and DNS are available, and DNS queries use Cloudflare's DNS servers." | **verified** |
| Raw TCP/UDP on other ports? | Denied. "Traffic on ports other than `80` and `443` is never routed through `outbound`… If you set `enableInternet = false`, that traffic is denied." | **verified** |
| Is there a host allowlist? | Yes, deny-by-default. "When `allowedHosts` is set, it becomes a deny-by-default allowlist"; "any host or IP not in the list is denied"; non-matching hosts "are blocked with HTTP 520". | **verified** |
| Does the allowlist survive a wide/incorrect config? | `deniedHosts` does: matching hosts are "blocked unconditionally (HTTP 520)… This overrides everything else in the chain, including per-host handlers". | **verified** |
| Where is it enforced? | Outside the container: handlers are "programmable egress proxies that run on the same machine as the container"; the local-dev emulation "spawn[s] a sidecar process … inside the container's network namespace" applying "`TPROXY` rules … mirroring production behavior". | **verified** |
| Can code *inside* the container turn egress back on? | No documented mechanism to. `enableInternet` is a Worker-side class field that "takes effect when the container starts", and enforcement is proxy-side. We treat in-container bypass of the flag as impossible. | **assumed** — Cloudflare does not state this in the negative |
| Can wildcards/IPs be listed? | Both lists "support simple glob patterns where `*` matches any sequence of characters"; the Sandbox page accepts CIDR entries and says "any host **or IP**" is denied when unlisted. `egress.md` describes the lists as hostname patterns only. | **verified for Sandbox; ambiguous for the Container base** |
| What happens to HTTPS from a client that does NOT trust the interception CA? | Undocumented. The docs only say trusting `/etc/cloudflare/certs/cloudflare-containers-ca.crt` is required "for HTTPS interception to work". We assume such a connection fails TLS validation (fail-closed) rather than passing through uninspected. | **assumed — unverified, and the most important open question** |
| Does the allowlist match SNI or the decrypted request host? | Undocumented. The Sandbox class ships `interceptHttps = true` and "makes a best effort to trust this CA automatically", so in the Sandbox tier matching is on the intercepted request. | **assumed** |
| Is DNS constrained? | Partly. DNS remains available while sealed but "only go[es] to Cloudflare's DNS servers… That prevents using arbitrary DNS destinations for data exfiltration". | **verified** — note this bounds, but does not eliminate, DNS as a channel (see residual risk) |

**Conclusion.** `direct_public_egress = false` is *enforceable* on this tier, at
the network layer, by the platform — this is not a cooperative base-URL. What
remains FerroGate's job is making sure the posture is always configured
correctly, which is what the enforcement below does, and being honest about the
channels the platform does not close, which is what the residual risk section
does.

## Enforcing the posture (issue #471)

The posture is enforced at five independent points, so no single mistake
produces an untethered agent:

1. **The type.** `ContainerStartSpec` no longer has `enable_internet: bool` +
   `egress_allowlist: Vec<String>`. It has one field,
   `egress: ContainerEgressPosture`
   (`crates/ferrogate-runtime/src/cloudflare_container_egress.rs`), and **no
   variant of that type grants direct public egress** —
   `direct_public_egress()` returns `false` unconditionally. The previous shape
   let a caller legally request `enable_internet = true` with an allowlist of
   `["api.anthropic.com"]`, i.e. exactly the bypass. That state is now
   unrepresentable, not merely discouraged.
2. **The allowlist constructor.** `GovernedEgressAllowlist` has a private field
   and validating constructors: an entry that contains a `*`, names an endpoint
   in `PROVIDER_EGRESS_DENYLIST`, or is not a bare host (scheme, path, port,
   credentials, whitespace, bad labels) is refused. So is an empty tether —
   "tethered to nothing" must be spelled `Sealed`.
3. **Policy derivation.** The agent-worker backend derives the posture from the
   session's `IsolationNetworkPolicy` via
   `ContainerEgressPosture::from_network_policy`, which fails the start on
   `direct_public_egress = true` or `governed_egress = false` rather than
   downgrading. Default posture is **sealed**; an operator tethers the tier to
   exactly one validated host with
   `AGENT_WORKER_CF_CONTAINER_EGRESS_GATEWAY_HOST`.
4. **The Worker re-enforces independently.** `/container/start` rejects
   `enableInternet: true` / `directPublicEgress: true` **unconditionally** (422,
   no allowlist makes it acceptable any more), requires every allowlist entry to
   be in the operator-authorized `CONTAINER_GOVERNED_EGRESS_HOSTS` var (**unset
   or empty ⇒ no host may be opened, i.e. sealed**), re-runs the wildcard /
   provider / host-shape checks, and applies its **own** provider denylist via
   `setDeniedHosts` before `setAllowedHosts` — a caller-supplied denylist can
   only widen it, never shrink it. Cloudflare evaluates `deniedHosts` first and
   it overrides everything, so an over-broad allowlist still cannot reach a
   provider.

   **Runtime prerequisite.** `setAllowedHosts` / `setDeniedHosts` resolve their
   outbound interceptor through `ctx.exports.ContainerProxy`, and `ctx.exports`
   is off by default before compatibility date **2025-11-17**. This Worker pins
   `2025-06-01`, so `wrangler.toml` requests the `enable_ctx_exports`
   compatibility flag explicitly. Without it every tethered start rejects with
   `container_error` — fail-closed, but the gateway-tethered posture could never
   be applied at all. `test/container-egress.test.ts` fails if the flag is
   dropped, and the vitest harness reads the date and flags out of
   `wrangler.toml` so the suite can never run on different runtime settings
   than the deployment.
5. **Attestation.** The start response carries the posture the Worker *actually
   applied* (`egress: { directPublicEgress, posture, allowedHosts, deniedHosts }`)
   and `ContainerControlClient::start` **fails the start**
   (`ContainerControlError::EgressNotGoverned`) if it is missing, reports direct
   public egress, or diverges from the requested posture. A Worker that silently
   dropped the egress configuration — or a deployment predating this contract —
   therefore surfaces as a failed start, never as a running unfenced agent. The
   denylist is compared as a *superset* so a Worker carrying a newer provider
   list is accepted; the allowlist is compared exactly.

## Detection: making a bypass loud (issue #471)

Prevention is only as good as its configuration, and several of its failure
modes are outside the type system: `CONTAINER_SANDBOX` bound to a class that is
not an `AgentSandbox` subclass (so `enableInternet` reverts to the platform
default of `true`), a stale Worker deployment, an allowed host that itself
proxies to a provider, or the DNS channel Cloudflare leaves open. So the tier
also reconciles.

`crates/ferrogate-runtime/src/cloudflare_container_tether_audit.rs` lands the
typed representation and the seam:

- `RunUsageSource` — one implementation over FerroGate's own meter, one per
  provider usage/billing API.
- `TetherAuditor::audit(identity, window)` — joins them for one run and emits a
  `TetherReconciliation`.
- `TetherVerdict` — `Tethered`, `Breached { unmetered_requests,
  unmetered_input_tokens, unmetered_output_tokens }`, or **`Unattested`**.

Two decisions matter more than the arithmetic:

- **`Unattested` is a distinct verdict, and is never a pass.** Until a provider
  usage source is actually wired (explicitly *not* in this slice — each provider
  has its own attribution key and reporting lag), every run reconciles to
  `Unattested`. `TetherVerdict::is_proven_tethered()` is `true` only for
  `Tethered`, so "we could not check" can never be rendered as "we checked and
  it was clean".
- **Only provider excess is a breach.** The gateway legitimately meters more
  than the provider bills (guardrail-blocked requests, cache hits, gateway-side
  retries); the reverse — the provider served tokens the gateway never saw — is
  by definition traffic that did not traverse the governed path, and that is the
  alarm (`severity = critical`).

A gateway-side source failure propagates as an error rather than being read as
zero (which would manufacture a false total-bypass); a provider-side failure
degrades to `Unattested` carrying the reason (a provider outage must not
manufacture a false breach *or* a false pass).

## Residual risk — read this before choosing this tier

**Enforced.** With the shipped configuration (the `AgentSandbox` subclass
pinning `enableInternet = false`, an allowlist that is empty or contains only
the governed gateway host, and the provider denylist), Cloudflare blocks direct
outbound connections from inside the container at the platform layer, including
all non-80/443 ports. Model-authored code running in the container cannot
re-enable it. This is a genuine network control, not a base-URL convention.

**Not enforced, and an operator must know it.** (1) The control is only as good
as the deployment: binding `CONTAINER_SANDBOX` to a class that does not extend
`AgentSandbox`, or setting `CONTAINER_GOVERNED_EGRESS_HOSTS` to something wider
than the gateway, silently converts the tier back to cooperative — the type
system cannot reach into `wrangler.toml`. (2) DNS stays available while sealed;
Cloudflare constrains it to its own resolvers, which stops arbitrary-destination
exfiltration but not a low-bandwidth covert channel through an
attacker-controlled zone — enough to leak a secret, not enough to run an LLM
conversation. (3) Anything reachable through an *allowed* host is reachable,
period: if the allowlisted gateway host can be made to proxy arbitrary
destinations, the fence is moot. (4) We could not verify from Cloudflare's docs
what happens to an HTTPS connection from a client that does not trust the
interception CA; we assume it fails closed, and that assumption is untested by
us — the live-CF gate item below exists precisely to settle it. (5) Nothing here
constrains what the agent does *through* the gateway; guardrails and #428 spend
caps own that. (6) The bypass **detection** path is a typed seam with no live
provider usage source wired, so today every run is `Unattested`: FerroGate can
prove the posture it applied and that the Worker attested it, but cannot yet
prove from provider-side accounting that no bypass occurred.

**Dependency to note in #428.** The cost-governance engine
(`crates/ferrogate-runtime/src/cloudflare_agent_cost.rs`) only meters traffic
that reached the gateway. Its ceilings, kill-switch and burn ledger are
therefore accurate **only while the tether holds** — a bypassed request is
invisible to the budget, not merely mis-priced. The tether-audit verdict is the
signal that tells an operator whether the budget numbers can be trusted.

## Route surface

All POST + bearer-gated; the per-tenant instance name is in the body (never a
query string), minted by the Rust naming scheme `fg.{tenant}.{session}.{run}` —
per-instance Durable Object isolation **is** tenant isolation.

| Route | Body | Effect |
|-------|------|--------|
| `POST /container/prepare`   | `{ instance, container: { image, tier, workspacePath? } }` | validate + pin image/tier (create is lazy) |
| `POST /container/start`     | `{ instance, entrypoint?, env?, egressPosture?, egressAllowlist?, egressDenylist? }` | launch with a governed egress posture, and **attest** it back (#471). `enableInternet`/`directPublicEgress` are rejected outright if true |
| `POST /container/exec`      | `{ instance, step: { mode, command?/language?+source?, timeoutMillis? } }` | run a command or code step; capture stdout/stderr/exit |
| `POST /container/stop`      | `{ instance, signal }` | `Sandbox.stop(SIGTERM/SIGKILL)`, time-bounded |
| `POST /container/logs`      | `{ instance, tail? }` | recent instance logs (empty tail: the session surface has no aggregate log RPC) |
| `POST /container/artifacts` | `{ instance, path? }` | `Sandbox.listFiles` under the workspace |
| `POST /container/cleanup`   | `{ instance }` | `Sandbox.destroy()` in **bounded time** (see below) |

Error vocabulary (mapped to typed Rust errors by `ContainerControlClient`):
`invalid_spec` → 422, `container_unbound` → 501, `not_running` → 409, plus
401/403 for a bad bearer credential.

## Fail-closed by construction

- **Egress is deny-by-default and `direct_public_egress = false` is enforced
  (#471).** The `@cloudflare/containers` base defaults `enableInternet = true`
  (full internet), so the Worker **subclasses** the SDK `Sandbox` as
  `AgentSandbox` and pins `enableInternet = false` (see `src/index.ts`). Every
  container start — including the lazy auto-start on the first `exec` — is
  therefore sealed by the platform. Any egress must ride a **governed
  allowlist** (mirroring the #117 function-egress broker), applied at runtime via
  `sandbox.setAllowedHosts(allowlist)` (the Container base grants those hosts
  egress even while `enableInternet` stays false). The allowlist path needs the
  Worker to export `ContainerProxy` from `@cloudflare/sandbox` (done in
  `src/index.ts`) so the DO can build outbound-interception fetchers via
  `ctx.exports.ContainerProxy`. Open internet is no longer expressible at all:
  see [Enforcing the posture](#enforcing-the-posture-issue-471) for the five
  layers and [Residual risk](#residual-risk--read-this-before-choosing-this-tier)
  for what is *not* covered.
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
- `CONTAINER_GOVERNED_EGRESS_HOSTS` — comma-separated set of hosts
  `/container/start` is allowed to open egress to (#471). **Empty/unset means no
  host may be opened: every container is sealed.** Set it to the tenant's
  gateway hostname, and nothing else.
- `CONTAINER_SANDBOX` — the Container/Sandbox DO binding (commented out by
  default; requires a Container/Sandbox class + image + a `new_sqlite_classes`
  migration + a `[[containers]]` block). Workers Paid only. **It must be bound to
  a class that extends `AgentSandbox`** — binding the SDK `Sandbox` directly
  restores the platform's `enableInternet = true` default and silently un-fences
  the tier.

agent-worker (environment):

- `AGENT_WORKER_ENABLE_CF_CONTAINER_BACKEND=1` — opt in to the tier.
- `AGENT_WORKER_CF_CONTAINER_GATEWAY_URL` — the fronting Worker base URL.
- `AGENT_WORKER_CF_CONTAINER_CONTROL_TOKEN` — the DIY bearer control token.
- `AGENT_WORKER_CF_CONTAINER_IMAGE` (default `ferrogate/agent-sandbox:latest`)
  and `AGENT_WORKER_CF_CONTAINER_TIER` (default `standard-1`; one of
  `lite`..`standard-4`).
- `AGENT_WORKER_CF_CONTAINER_EGRESS_GATEWAY_HOST` (#471) — the single governed
  gateway host the container is tethered to. Unset ⇒ **sealed** (no egress at
  all). The value is validated: a wildcard or a provider endpoint is rejected
  and the start fails.

## Testing status

- **Unit-tested, offline (no network):** the `ContainerControlClient` verbs,
  wire shapes, egress governance, identity validation, and error mapping
  (`cloudflare_container_test.rs`); the full backend lifecycle against a scripted
  mock transport, evidence, and the fail-closed snapshot error
  (`cloudflare_container_backend_test.rs`); the registry gating
  (`backends_test.rs`); and `tsc --noEmit` for `container.ts`.
- **Worker-side enforcement, offline in workerd (`workers/agent-gateway/test/container-egress.test.ts`).**
  The first #471 pass tested only the side that *sends* the configuration, and
  7 of 7 mutations to the Worker half survived — including flipping
  `AgentSandbox { enableInternet = false }` to `true`. This suite boots a real
  `AgentSandbox` Durable Object under `@cloudflare/vitest-pool-workers` (no
  Docker, no CF account) and observes the **applied** posture instead:
  `enableInternet` is read off the live instance; the allow/deny lists are read
  back through the SDK's `effectiveAllowedHosts` / `effectiveDeniedHosts` after
  `/container/start` ran; the verdicts come from `ContainerProxy` — Cloudflare's
  own egress decision function, reached through the interceptor the SDK actually
  registered — so a denial is Cloudflare's documented 520 and anything else means
  the request left; the returned attestation is compared against that applied
  state; and `wrangler.toml` is asserted to bind `AgentSandbox` (the one failure
  mode attestation provably cannot detect). Each of these was verified by
  mutating the enforcing line and watching the suite fail.
- **Not observable from any test (platform behaviour, LIVE-CF only).** Whether
  Cloudflare *honours* `enableInternet = false` outside the container, and
  whether root inside the container can defeat the filter, cannot be observed in
  workerd: a container engine is required, and workerd provides none. The suite
  above pins everything up to that boundary — the value the platform is handed,
  and what Cloudflare's own decision function does with it — and stops there.
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
- **Not-tested (LIVE-CF, #471 — the acceptance proof the issue asks for).** The
  claim "a process inside the container cannot reach a provider endpoint
  directly" is **unverified by us**; only a live run can settle it. The gate must,
  against a real CF sandbox: (a) start a **sealed** instance and exec
  `curl -sS https://api.anthropic.com/v1/models` — it must fail (HTTP 520 /
  connection refused), not return a provider response; (b) repeat on the
  **tethered** posture with `CONTAINER_GOVERNED_EGRESS_HOSTS` set to only the
  gateway host — the gateway host must be reachable and `api.anthropic.com` must
  still fail, proving `setDeniedHosts` overrides; (c) try a raw non-HTTP socket
  (e.g. port 8443 / a UDP send) and confirm it is denied; (d) confirm an HTTPS
  client that does **not** trust
  `/etc/cloudflare/certs/cloudflare-containers-ca.crt` fails closed rather than
  passing through uninspected — this is the one assumption in the table above
  that no Cloudflare doc confirms; (e) confirm `/container/start` with
  `enableInternet: true` returns 422; (f) confirm the start response carries the
  `egress` attestation and that a Worker without it fails the Rust-side start.
- **Remaining (follow-up slice):** wiring the backend into the agent-worker
  management **remote-provisioning dispatch** (constructing it from a production
  `BlockingHttpControlTransport` and driving it from `lifecycle.rs` with
  per-session storage in `state.rs`, mirroring `provision_docker`); and wiring a
  real provider usage source into the #471 `TetherAuditor` so runs stop
  reconciling to `Unattested`.
