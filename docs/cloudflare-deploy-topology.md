<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-24
  description: Token4AI Cloud, FerroGate AI Gateway, Cloudflare deploy-topology
  decision (issue #424): Containers-hosted FerroGate vs edge-Worker+origin vs
  status quo, bindings-vs-REST access, cost model, DB choice, PoC runbook.
-->

# Cloudflare Deploy Topology: hosting the FerroGate runtime ON Cloudflare (decision #424)

This document decides **where the FerroGate runtime itself runs** relative to
Cloudflare (CF) compute. It compares three topologies:

- **(a) Containers-hosted** — the FerroGate binary runs inside Cloudflare
  Containers, fronted by a Worker + Durable Object (DO).
- **(b) Edge-Worker + origin (hybrid)** — a thin CF Worker at the edge
  (auth pre-check / cache / routing / guardrail pre-check) forwards to a
  FerroGate origin running on Containers or external VMs/k8s.
- **(c) Status quo** — FerroGate on VMs/k8s
  ([`deploy/kubernetes/`](../deploy/kubernetes/), [`charts/ferrogate`](../charts/ferrogate),
  `docs/cluster-deployment.md`), consuming CF products only as upstreams via
  REST and FerroGate-deployed fronting Workers.

It also makes the **bindings-vs-REST access decision** a first-class part of the
recommendation (§6).

Read [`docs/cloudflare-integration.md`](cloudflare-integration.md) (#421) first
for the CF product survey and the FerroGate plug-in seams; this document does
not repeat that material. Related decisions:
[`docs/cloudflare-agent-gateway.md`](cloudflare-agent-gateway.md) (#413,
fronting-Worker architecture and the no-first-party-REST constraint),
[`docs/cloudflare-secrets-resolution.md`](cloudflare-secrets-resolution.md)
(#423, `cf://` resolution is binding-scoped; REST is write/manage-only),
[`docs/cloudflare-secrets-tenancy.md`](cloudflare-secrets-tenancy.md) (#418,
beta caps and tenancy split),
[`docs/cloudflare-agent-memory.md`](cloudflare-agent-memory.md) (#427).

All Cloudflare numbers below were verified against the CF developer docs on
2026-07-24; each carries its source URL in §10. Where a fact is **not**
documented by CF, this doc says so explicitly rather than guessing.

## Contents

- [1. What the FerroGate runtime actually is (grounded)](#1-what-the-ferrogate-runtime-actually-is-grounded)
- [2. Why plain Workers cannot host the data plane](#2-why-plain-workers-cannot-host-the-data-plane)
- [3. Option (a): Containers-hosted FerroGate](#3-option-a-containers-hosted-ferrogate)
- [4. Option (b): edge-Worker + FerroGate origin (hybrid)](#4-option-b-edge-worker--ferrogate-origin-hybrid)
- [5. Option (c): status quo — VM/k8s + CF as upstream](#5-option-c-status-quo--vmk8s--cf-as-upstream)
- [6. Bindings vs REST: the container↔Worker shim decision](#6-bindings-vs-rest-the-containerworker-shim-decision)
- [7. Cost model](#7-cost-model)
- [8. Recommendation and phased adoption](#8-recommendation-and-phased-adoption)
- [9. PoC runbook (pending execution)](#9-poc-runbook-pending-execution)
- [10. Verified sources](#10-verified-sources)

---

## 1. What the FerroGate runtime actually is (grounded)

Every constraint in this doc follows from what the runtime concretely does.
Citations are against the current tree.

**Pingora data plane, native listeners.** The gateway is a Pingora HTTP proxy
service: `serve()` at `crates/ferrogate-cli/src/gateway/mod.rs:186` builds a
`Server::new_with_opt_and_conf` (`mod.rs:244`), wraps the `FerroGateway`
proxy in `http_proxy_service_with_name` (`mod.rs:248`), binds either a TLS
listener via `service.add_tls_with_settings(&listen, ...)` (`mod.rs:255`) or a
plain TCP listener via `service.add_tcp(&listen)` (`mod.rs:265`), and blocks in
`server.run_forever()` (`mod.rs:276`). This is native tokio + raw socket
territory — a process, not a request handler.

**Config model.** The listen address is a plain `String` in the config root —
`pub listen: String` at `crates/ferrogate-config/src/types.rs:16` — defaulting
to `127.0.0.1:8080` in `config/ferrogate.example.toml:9`; the shipped container
Caddyfile binds `0.0.0.0:8080` (`Ferrogate/Caddyfile:12`). The config path
comes from `--config` or the `FERROGATE_CONFIG` env var
(`crates/ferrogate-cli/src/cli.rs:38`), dispatched by `Commands::Run` at
`crates/ferrogate-cli/src/main.rs:58`.

**Postgres control plane over deadpool/tokio-postgres.** The async pool is
constructed in `AsyncPostgresPool::new` at
`crates/ferrogate-storage/src/async_postgres.rs:96` (imports
`deadpool_postgres::{Manager, ManagerConfig, Object, Pool, RecyclingMethod}` at
`:13`), parsing a DSN into `tokio_postgres::Config` (`:98`) with TLS modes
disable/prefer/require/verify-ca/verify-full (`:102-108`, `:112-124`) and a
sized pool (`:125-127`). This is a **long-lived raw-TCP connection pool**, the
antithesis of an isolate-friendly database client.

**Always-on background loops.** `serve()` spawns resident sweepers before
binding: OTLP + analytics senders, ACME renewal, MCP health scheduler, external
action authorizer, billing outbox sweeper, agent schedule sweeper, asset
lifecycle sweeper, x402 TTL sweeper and settlement reconciler
(`crates/ferrogate-cli/src/gateway/mod.rs:223-237`). These assume the process
is **continuously running**; any scale-to-zero topology silently pauses them.

**Own TLS/ACME stack.** The runtime can terminate TLS itself and run an ACME
issuance/renewal loop, merging bound site custom domains into the certificate
SAN set (`mod.rs:197-226`, `crates/ferrogate-cli/src/acme.rs`). Behind
Cloudflare (which terminates TLS at the edge) this whole subsystem is
redundant — an on-CF profile runs plain `add_tcp` on 8080.

**Container packaging already exists.** The repo root
[`Dockerfile`](../Dockerfile) is a two-stage build: `rust:bookworm` builder
compiling `ferrogate-cli` + `ferrogate-auth` with `--locked` (`Dockerfile:7-20`),
`debian:bookworm-slim` runtime with `ca-certificates` + `curl`
(`Dockerfile:22-30`), binaries at `/usr/local/bin/ferrogate{,-auth}`
(`Dockerfile:31-32`), `EXPOSE 8080`, `ENV FERROGATE_CONFIG=/etc/ferrogate/Caddyfile`,
entrypoint `CMD ["ferrogate", "run"]` (`Dockerfile:34-36`).

**Health/readiness routes exist.** `/healthz` maps to `RouteGroup::Health`
(asserted in `crates/ferrogate-cli/src/gateway/route_groups_test.rs:134`), is
short-circuited early in request handling
(`crates/ferrogate-cli/src/gateway/handlers.rs:132-135`) into `handle_healthz`
at `crates/ferrogate-cli/src/gateway/local.rs:256` (returns
`{"status":"ok","service":...,"version":...,"runtime":"pingora"}`); `handle_readyz`
(`local.rs:270`) additionally exercises control-plane state — i.e. proves the
Postgres path.

## 2. Why plain Workers cannot host the data plane

Confirmed, and it is structural, not incremental:

- Workers are V8 isolates (JS/WASM). Pingora is a **native** Rust proxy: it owns
  its tokio runtime, binds OS listen sockets (`add_tcp`/`add_tls_with_settings`,
  §1), manages upstream connection pools, and calls native TLS. None of that
  exists in an isolate; "porting" means **rewriting the data plane** against
  `fetch` semantics and losing Pingora entirely.
- `deadpool`/`tokio-postgres` (§1) requires long-lived raw TCP sockets and a
  resident pool. Isolates offer neither the socket model nor the resident
  process lifetime the pool assumes.
- The resident background loops (§1) have no home in a per-request isolate.

Workers therefore appear in this decision only as (i) the **thin edge layer**
of the hybrid and (ii) the **fronting/binding layer** for Containers — never as
the FerroGate runtime itself. This restates the scoping in
[`cloudflare-integration.md` §4](cloudflare-integration.md#4-managed-agents) and
[`cloudflare-agent-gateway.md` §1](cloudflare-agent-gateway.md).

## 3. Option (a): Containers-hosted FerroGate

Cloudflare Containers run arbitrary `linux/amd64` Docker images, each instance
in its own VM, attached to a Durable Object (the `Container` class extends DO).
The existing `Dockerfile` (§1) deploys essentially unchanged. Verified platform
facts (URLs in §10):

**Instance types and account limits.**

| Type | vCPU | Memory | Disk |
|------|------|--------|------|
| lite | 1/16 | 256 MiB | 2 GB |
| basic | 1/4 | 1 GiB | 4 GB |
| standard-1 | 1/2 | 4 GiB | 8 GB |
| standard-2 | 1 | 6 GiB | 12 GB |
| standard-3 | 2 | 8 GiB | 16 GB |
| standard-4 | 4 | 12 GiB | 20 GB |

Custom types up to 4 vCPU / 12 GiB / 20 GB. Account-level concurrency caps:
6 TiB memory, 1,500 vCPU, 30 TB disk; image size ≤ the instance's disk;
50 GB total image storage per account. Workers **Paid** plan required (no free
tier). **Ceiling implication:** 4 vCPU / 12 GiB per instance is far below what
a high-throughput FerroGate node would get on a VM; scaling is horizontal only,
and built-in autoscaling is "not today" (planned) — instance selection is
manual (`getContainer`/`getRandom` helpers).

**Ingress: always Worker → DO → container, HTTP only.** Every request passes
through a Worker (at the lowest-latency datacenter), then the container's DO,
then the container process on `defaultPort`. CF states plainly that
"end-users cannot make non-HTTP TCP or UDP requests" to instances. The DO and
container are **not guaranteed co-located**: the container starts at the
nearest location with a pre-fetched image, and after a restart routing may pick
a different location. Consequences for FerroGate:

- Two extra hops (Worker, DO) are in **every** proxied request path.
- FerroGate's TLS listener + ACME loop (§1) are disabled — CF terminates TLS;
  custom domains attach at the Worker layer. The container binds plain
  `0.0.0.0:8080`.
- A DO sits in the path of **long-lived streaming responses** (LLM traffic),
  which accrues DO duration billing for the life of each stream (§7).

**Lifecycle: scale-to-zero vs always-on.** Billing is per active 10 ms and
stops when the instance sleeps. `sleepAfter` keeps an instance alive
approximately that long after activity; without it, an instance shuts down
shortly after requests cease, but `onActivityExpired()` can be overridden to
keep instances running indefinitely. However, CF explicitly does **not
guarantee** any instance runs for a set period: host restarts happen, instances
get `SIGTERM` then `SIGKILL` after 15 minutes and are "rebooted elsewhere
shortly after". Cold starts are typically **1–3 s** (image-size dependent).
For FerroGate this means:

- The background sweepers (§1) require an effectively-always-on instance —
  i.e. paying the always-on floor (§7) — and must still tolerate restarts
  (they already do on k8s; `terminationGracePeriodSeconds: 45` in
  `deploy/kubernetes/deployment.yaml`).
- **All disk is ephemeral** — a restarted instance gets a fresh disk from the
  image. Fine for FerroGate (state lives in Postgres/object storage), but rules
  out any on-disk durability assumptions.

**DB choice.**

- **External Postgres over the internet** (Neon/Supabase/RDS/self-managed):
  zero code change — the deadpool path (§1) supports `require`/`verify-full`
  TLS. Open platform question: CF documents that with internet disabled only
  ports 80/443/DNS are reachable, and that outbound handlers never see
  non-80/443 traffic, but does **not explicitly document** whether arbitrary
  outbound TCP (e.g. 5432) works with default internet access enabled. This is
  a hard prerequisite — **PoC step P6 (§9) verifies it first**. Mitigations if
  blocked: Postgres-over-WebSocket drivers, a TCP-over-HTTPS tunnel, or
  pgbouncer on 443.
- **D1**: only after #419/#420 add a D1 `RuntimeControlPlaneBackend` variant
  (seam: `crates/ferrogate-storage/src/lib.rs:10357`, repository traits
  `:723`) — a real porting effort (SQLite semantics, no `tokio-postgres`), and
  per [`cloudflare-integration.md` §6](cloudflare-integration.md#6-d1) hot-path
  access must go through a binding, not the rate-limited REST query API. From a
  container, that binding is reached via the shim (§6).
- **Verdict:** external Postgres for any near-term Containers deployment; D1
  is a separate workstream for a CF-native tier.

**Egress.** NA/EU $0.025/GB after 1 TB included/mo (500 GB included elsewhere;
$0.04–0.05/GB). LLM proxy egress (responses to clients + requests to
providers) at, say, 100 M requests × 20 KB ≈ 2 TB/mo ≈ $25/mo NA/EU — minor.

## 4. Option (b): edge-Worker + FerroGate origin (hybrid)

A thin Worker on the custom domain performs cheap, isolate-friendly work —
API-key pre-validation/deny-list, response cache lookups, static asset serving,
guardrail pre-checks (e.g. the Workers AI Llama Guard detector already
integrated via #422/#430), coarse routing — then forwards to a FerroGate origin
(VM/k8s today; Containers later). Why this is attractive:

- **No rewrite.** FerroGate is untouched; the Worker is additive and can be
  rolled out per-route.
- **Cheap at the edge.** Workers Standard: $5/mo base, 10 M requests included,
  +$0.30/M, 30 M CPU-ms included +$0.02/M CPU-ms, and — decisive for LLM
  streaming — "no charge or limit for **duration**". A streaming pass-through
  proxy burns near-zero CPU-ms, so 100 M req/mo ≈ **$27 + small CPU** with
  **no DO in the request path** (contrast §7's DO duration line for Containers).
- **Bindings at the edge, where they belong.** The Worker layer natively holds
  D1/KV/R2/Workers AI/Secrets Store bindings — consistent with the
  already-decided pattern that binding reads live in Workers (#423) and agent
  lifecycle goes through the fronting Worker (#413). The origin keeps using
  the `crates/ferrogate-cloudflare` REST client only for write/manage paths.
- **TLS/custom-domain story:** CF terminates TLS on the Worker route; the
  origin can keep its own ACME/TLS (`mod.rs:197-226`) for direct access or run
  behind CF-only ingress (authenticated origin pulls) — no change forced.
- Cost/risk: the origin still costs what it costs today (§5); the Worker adds
  a small increment and one extra hop for cache misses.

## 5. Option (c): status quo — VM/k8s + CF as upstream

Today's shape: `deploy/kubernetes/` (2-replica Deployment) and
`charts/ferrogate`; FerroGate reaches CF products from **outside** via the
`ferrogate-cloudflare` REST client, whose retry/backoff explicitly models the
global API limit (comment at `crates/ferrogate-cloudflare/src/client.rs:11`,
policy `:98-105`, 429 short-circuit `:286`), plus FerroGate-deployed fronting
Workers (`workers/agent-gateway/`, `workers/mcp-server/`) for everything with
no first-party REST. Verified platform numbers that bound this option:

- Global CF API limit: **1,200 requests / 5 minutes / user** (~4 req/s
  sustained), cumulative across dashboard/key/token; exceeding it blocks the
  API for 5 minutes with 429. Enterprise can request raises.
- Token sprawl caps: 50 tokens/user, 500/account; GraphQL 320/5 min.

So off-CF, REST is viable **only** for low-frequency control-plane operations
(exactly how #423 scoped it), and every hot-path CF interaction must go through
a fronting Worker over public HTTPS with a managed bearer token
(`GATEWAY_CONTROL_TOKEN`, `workers/agent-gateway/wrangler.toml:60-64`). This
works — it is what ships today — but pays public-internet RTT per call and
carries token lifecycle burden.

## 6. Bindings vs REST: the container↔Worker shim decision

**The nuance flagged in the issue is confirmed.** Bindings live at the
Worker/DO layer; a container process gets **no direct binding access**. But the
shim is not something FerroGate must invent — it is a **documented first-class
platform feature**: *Outbound Workers*.

**Mechanism (verified).** The container makes a plain HTTP request to a
virtual hostname (e.g. `http://my.kv/some-key`); a static `outboundByHost`
handler (or catch-all `outbound`) on the Container class intercepts it and runs
**inside the Workers runtime, outside the container sandbox**, receiving `env`
with "access to every binding declared in your Wrangler configuration" — KV,
R2, D1, DOs "and others". "No SDK or client library is required inside the
container." HTTPS interception is opt-in (`interceptHttps` + trusting an
ephemeral CA at `/etc/cloudflare/certs/cloudflare-containers-ca.crt`); handlers
only ever see ports 80/443. Zero-trust credential injection is supported: "no
token is ever passed into the sandbox" — the handler attaches credentials
Worker-side and secret rotation applies immediately without restart. Requires
`@cloudflare/containers` ≥ 0.2.0. Inbound direction: the fronting Worker/DO
reaches the container via `fetch()`/`containerFetch()` on `defaultPort`.

**Quantified comparison.**

| Dimension | Public REST (off-CF or naive on-CF) | Bindings via shim (on-CF) |
|---|---|---|
| Rate limit | 1,200 req/5 min/user global (~4 req/s), 5-min 429 lockout | Not subject to the API rate limit; bounded only by per-product binding limits and billing |
| Latency | Public-internet RTT to `api.cloudflare.com` per call, plus token auth | In-runtime handler → binding call; container→handler hop is local HTTP. CF does not publish a number — **PoC step P8 measures it**; expect order-of-magnitude better than public RTT |
| Token management | Account API token(s): scope union, rotation, 50/user–500/account caps, secret distribution to every FerroGate node | None in the container ("no token is ever passed into the sandbox"); Worker-side secrets rotate live |
| Failure modes | 429 storms block ALL API use for 5 min account-wide | Isolated per-binding errors |
| Availability | Anywhere (incl. self-hosted) | Only when the runtime is deployed on CF Containers |

**Decision.** Adopt the shim as the **standard CF-access path whenever the
runtime runs on Cloudflare**: define a fixed set of FerroGate virtual hosts
(e.g. `cf-d1.internal`, `cf-kv.internal`, `cf-secrets.internal`,
`cf-ai.internal`) served by `outboundByHost` handlers, and a small Rust client
that speaks plain HTTP to them (no CF SDK in-container). This composes cleanly
with #423 (`cf://` resolution is already binding-scoped — the shim is how a
containerized runtime reaches those bindings) and #413 (control routes stay on
the fronting Worker). Self-hosted deployments keep the existing
`ferrogate-cloudflare` REST client as the fallback, still confined to
write/manage-frequency operations. REST is never used on a hot path from
inside CF.

## 7. Cost model

Verified unit prices (Workers Paid, $5/mo base; URLs §10): memory
$0.0000025/GiB-s beyond 25 GiB-h/mo included; vCPU $0.000020/vCPU-s (active
usage only) beyond 375 vCPU-min; disk $0.00000007/GB-s beyond 200 GB-h.
DO: $0.15/M requests beyond 1 M; duration $12.50/M GB-s beyond 400k GB-s.
Workers: +$0.30/M requests beyond 10 M; +$0.02/M CPU-ms beyond 30 M; duration
free. A month = 2,628,000 s.

**Always-on container floor (the FerroGate case, per instance/month):**

| Instance | Memory | Disk | vCPU @100% active | vCPU @~25% | Total (25–100% active) |
|---|---|---|---|---|---|
| standard-1 (½ vCPU, 4 GiB, 8 GB) | ~$26.1 | ~$1.4 | ~$25.8 | ~$6.4 | **~$34–53** |
| standard-4 (4 vCPU, 12 GiB, 20 GB) | ~$78.6 | ~$3.6 | ~$209.8 | ~$52.4 | **~$135–292** |

(Memory/disk are provisioned-while-running; CPU is active-usage. Arithmetic:
e.g. standard-4 memory = 12 GiB × 2,628,000 s − 90,000 GiB-s included ≈
31.45 M GiB-s × $0.0000025 ≈ $78.6.)

**The hidden line item: DO duration on streaming.** Every request to a
container transits its DO. If DO active-duration accrues for the life of each
streamed LLM response (est., not separately documented for containers): 100 M
req/mo × 2 s avg stream × 0.125 GB = 25 M GB-s → ≈ **$307/mo**, plus $14.85 DO
requests and $27 Worker requests. This potentially **exceeds the container
compute cost** at scale and is the sharpest cost argument against topology (a)
for the high-throughput data plane. PoC step P8 should observe actual DO
duration billing on streamed responses.

**Hybrid edge layer:** 100 M req/mo ≈ $27 + negligible CPU-ms (streaming
duration is free on Workers), no DO. **Status quo origin:** a comparable
4 vCPU/16 GiB VM runs ~$25–60/mo (budget providers) to ~$100–150/mo
(hyperscaler on-demand) — unverified market prices, order-of-magnitude only.
Egress: §3 (~$25/mo at 2 TB NA/EU).

**Cold-start/hibernation cost lens:** scale-to-zero only pays off for
idle-heavy workloads (dev/preview/single-tenant instances) and costs 1–3 s
first-request latency plus paused background sweepers (§1). For the always-on
gateway, hibernation is a non-feature; you pay the floor above.

## 8. Recommendation and phased adoption

**Go — for the hybrid (b) now and a scoped Containers beachhead (a) next.
No-go — for migrating the high-throughput production data plane to Containers
today.** Reasons: 4 vCPU/12 GiB instance ceiling with no built-in autoscaling;
Worker+DO hops and DO-duration billing on every streamed response (§7); no
always-on guarantee (host restarts); external-Postgres egress unconfirmed
(§3). None of these block the hybrid, and none block Containers for
lower-throughput, managed, per-tenant/dev-tier FerroGate instances where
scale-to-zero is an asset, bindings come for free via the shim (§6), and the
existing Dockerfile deploys as-is.

**Phases:**

1. **Hybrid edge Worker (now).** Thin Worker on the custom domain: auth
   pre-check, cache, guardrail pre-check, forward to the existing k8s origin.
   Additive, per-route rollout, ~\$27/100 M req.
2. **Containers PoC (next).** Execute §9 on a live account: confirm image
   boots, `/healthz`, `/readyz` against external Postgres (the 5432-egress
   question), one proxied `/v1/chat/completions`, cold-start and DO-duration
   measurements, shim latency.
3. **Managed/dev-tier FerroGate on Containers.** `basic`/`standard-1`
   per-tenant instances with `sleepAfter`, external Postgres, shim-based
   bindings, on-CF config profile (no ACME/TLS, `0.0.0.0:8080`).
4. **CF-native tier (conditional).** D1 control-plane backend (#419/#420) and
   deeper binding integration — only if phase 3 demonstrates demand.

**Follow-up implementation issues to file (list only — deliberately not
created here):**

1. *Edge Worker for hybrid topology* — thin auth/cache/guardrail pre-check
   Worker forwarding to the FerroGate origin; per-route rollout config.
2. *Execute the #424 Containers PoC runbook* — run §9 on a live CF account;
   record cold start, 5432 egress result, DO-duration billing on streams, shim
   latency; update this doc's "pending verification" notes.
3. *On-CF config profile* — a documented config preset: `listen = "0.0.0.0:8080"`,
   TLS/ACME disabled, readiness tuned for `startAndWaitForPorts`, sweeper
   behavior under restart documented.
4. *Rust binding-shim client* — small crate/module speaking plain HTTP to the
   `outboundByHost` virtual hosts; integrate with the `cf://` resolver seam
   (#423) and `AgentMemoryClient` (#427); REST fallback preserved off-CF.
5. *Containers deploy pipeline* — extend the #413 Worker deploy pipeline with
   `wrangler deploy` of the container app + image push; CI image build for
   `linux/amd64`.
6. *D1 control-plane backend spike* — `RuntimeControlPlaneBackend::D1` variant
   feasibility against the repository traits (depends on #419/#420).

## 9. PoC runbook (pending execution)

**Status: NOT executed.** This sandbox has no Docker and no live CF account.
The runbook below is written to be executed verbatim by an operator/test agent
with a Workers Paid account and Docker. Until then the PoC acceptance box is
**pending-execution**.

**P1 — build the image (operator machine).** CF requires `linux/amd64`.

```sh
docker build --platform linux/amd64 -t ferrogate:poc .
```

Uses the repo-root `Dockerfile` unchanged (§1). Expect a release build of
`ferrogate` + `ferrogate-auth`; final image is `debian:bookworm-slim`-based,
comfortably under the 8 GB `standard-1` disk/image cap.

**P2 — PoC config layer.** The stock image defaults to the Caddyfile config;
the PoC overlays a minimal TOML (CF terminates TLS, so no `tls` section; bind
all interfaces; one upstream provider; Postgres control plane pointing at an
external DSN, e.g. Neon):

```dockerfile
# Dockerfile.poc
FROM ferrogate:poc
COPY poc.toml /etc/ferrogate/poc.toml
ENV FERROGATE_CONFIG=/etc/ferrogate/poc.toml
```

`poc.toml` (derive from `config/ferrogate.example.toml`; key lines):

```toml
listen = "0.0.0.0:8080"
# [storage] postgres DSN with tls_mode = "require" -> external Postgres
# one [providers.*] entry with an env-sourced API key
```

Local smoke test: `docker run --rm -p 8080:8080 ferrogate:poc-cfg` then
`curl -s localhost:8080/healthz` → expect
`{"status":"ok","service":"...","version":"...","runtime":"pingora"}`
(shape grounded at `crates/ferrogate-cli/src/gateway/local.rs:256-266`).

**P3 — Containers app.** New directory (suggested `workers/ferrogate-poc/`,
created by the executing agent, not this spike):

`wrangler.toml`:

```toml
name = "ferrogate-container-poc"
main = "src/index.ts"
compatibility_date = "2025-06-01"

[[containers]]
class_name = "FerroGateContainer"
image = "./Dockerfile.poc"
max_instances = 1
instance_type = "standard-1"

[[durable_objects.bindings]]
name = "FERROGATE"
class_name = "FerroGateContainer"

[[migrations]]
tag = "v1"
new_sqlite_classes = ["FerroGateContainer"]
```

`src/index.ts` (pin `@cloudflare/containers` ≥ 0.2.0; verify helper names
against the pinned version, same caveat discipline as
`workers/agent-gateway/wrangler.toml:26-32`):

```ts
import { Container, getContainer } from "@cloudflare/containers";

export class FerroGateContainer extends Container {
  defaultPort = 8080;
  sleepAfter = "10m";
  // P7 shim probe: virtual-host binding access from inside the container.
  static outboundByHost = {
    "cf-kv.internal": async (request: Request, env: Env) => {
      const key = new URL(request.url).pathname.slice(1);
      return new Response(await env.POC_KV.get(key));
    },
  };
}

export default {
  async fetch(request: Request, env: Env) {
    return getContainer(env.FERROGATE, "poc").fetch(request);
  },
};
```

**P4 — deploy.** `npx wrangler deploy` (Workers Paid). Expected: image pushed
to the CF registry, Worker + DO class deployed, a `*.workers.dev` URL printed.

**P5 — health + proxy checks.**

```sh
curl -s https://ferrogate-container-poc.<subdomain>.workers.dev/healthz
# expect {"status":"ok",...,"runtime":"pingora"} — first call measures cold start (expect 1-3 s + app boot)
curl -s https://.../v1/chat/completions \
  -H "Authorization: Bearer <virtual-key>" -H "Content-Type: application/json" \
  -d '{"model":"<configured-model>","messages":[{"role":"user","content":"ping"}]}'
# expect an OpenAI-shaped chat completion proxied through Pingora
```

**P6 — external-Postgres egress (the open platform question, §3).**
`curl -s https://.../readyz` — readiness exercises control-plane state
(`local.rs:270`), so a 200 with the Postgres backend configured proves
outbound 5432 works from a container with default internet access. If it
fails with connect timeouts, record that Containers block non-80/443 egress
and fall back to a 443-fronted Postgres proxy; this changes the DB
recommendation in §3.

**P7 — shim probe.** From inside the container
(`wrangler containers exec`, or a temporary debug route):
`curl -s http://cf-kv.internal/hello` after `wrangler kv key put hello world`
→ expect `world`, proving binding access with no token in the container.

**P8 — measurements to record.** Cold-start (P5 first-call), warm p50/p99 via
the Worker vs direct-origin baseline, shim round-trip latency (P7 repeated),
and the DO duration line on the next billing/usage report after streaming
~1k requests (validates or refutes the §7 estimate).

## 10. Verified sources

All fetched 2026-07-24:

- Containers pricing (tiers, unit rates, includes, egress): <https://developers.cloudflare.com/containers/pricing/>
- Containers platform details (amd64, ephemeral disk, cold start 1–3 s, SIGTERM/SIGKILL, Worker→DO fronting, no non-HTTP ingress): <https://developers.cloudflare.com/containers/platform-details/>
- Containers limits (instance types, 6 TiB/1,500 vCPU/30 TB account caps, 50 GB image storage): <https://developers.cloudflare.com/containers/platform-details/limits/>
- Containers FAQ (no guaranteed always-on, host restarts, autoscaling "not today", cold starts): <https://developers.cloudflare.com/containers/faq/>
- Container class interface (`fetch`/`containerFetch`, `defaultPort`, ports/readiness, no direct bindings in-container): <https://developers.cloudflare.com/containers/container-package/>
- Outbound traffic (handlers see only 80/443; internet-off = 80/443/DNS only; `interceptHttps` + ephemeral CA; `allowedHosts`/`deniedHosts`): <https://developers.cloudflare.com/containers/platform-details/outbound-traffic>
- Workers connections / bindings-from-containers (virtual hostname pattern, "every binding declared", no SDK required): <https://developers.cloudflare.com/containers/platform-details/workers-connections/>
- Outbound Workers changelog (handlers run in the Workers runtime outside the sandbox; `env` binding access; `@cloudflare/containers` ≥ 0.2.0): <https://developers.cloudflare.com/changelog/post/2026-03-26-outbound-workers>
- Credential injection / TLS interception changelog ("no token is ever passed into the sandbox"; live secret rotation): <https://developers.cloudflare.com/changelog/post/2026-04-13-sandbox-outbound-workers-tls-auth/>
- Workers + DO pricing ($5 base; 10 M req; $0.30/M; 30 M CPU-ms; duration free; DO $0.15/M req, $12.50/M GB-s beyond 400k): <https://developers.cloudflare.com/workers/platform/pricing/>
- CF API rate limits (1,200 req/5 min/user cumulative; 5-min 429 lockout; 50/500 token caps; GraphQL 320/5 min): <https://developers.cloudflare.com/fundamentals/api/reference/limits/>

Not documented by CF (stated as unverified above): arbitrary non-80/443
outbound TCP with default internet access (P6); container↔handler shim latency
(P7/P8); whether DO duration accrues for full stream lifetimes on container
requests (P8). Market VM prices in §7 are order-of-magnitude, unverified.
