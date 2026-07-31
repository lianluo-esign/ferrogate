<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-31
  description: Token4AI Cloud, FerroGate AI Gateway, the #424 Cloudflare
  Containers feasibility PoC: a deployable Worker + container application, and
  the docker-free workerd harness that exercises it against the real binary.
-->

# ferrogate-poc (#424)

The proof-of-concept for [`docs/cloudflare-deploy-topology.md`](../../docs/cloudflare-deploy-topology.md):
**does the FerroGate/Pingora binary actually run under Cloudflare Containers,
behind a fronting Worker, and still reach its database and an upstream?**

This directory is the runnable artifact. §9 of the topology doc is the operator
runbook that deploys it; everything the runbook used to quote inline now lives
here as real files, so it can be typechecked, gated and diffed.

## Layout

| File | Role |
|---|---|
| `src/index.ts` | The **deployable** entrypoint: `ContainerProxy` re-export, the `FerroGateContainer` class, `outboundByHost` wiring, request forwarding. |
| `src/origin.ts` | Forwarding + the container-hop timing header. Shared by the deployed Worker and the harness, so the harness tests the real transport. |
| `src/shim.ts` | The `outboundByHost` handler table — how a container with **no binding objects** reaches D1/KV/R2/Vectorize (topology doc §6). |
| `src/env.ts` | The one binding surface both entrypoints agree on. |
| `src/harness-entry.ts` | workerd-only entrypoint: same `origin.ts`/`shim.ts`, container binding replaced by loopback. |
| `wrangler.toml` | Containers app: DO binding, `[[containers]]`, KV namespace, migration. |
| `Dockerfile.poc` | Thin config overlay on the **unmodified** repo-root `Dockerfile`. |
| `poc.toml` | The gateway config baked into the PoC image. |

## Running it without Docker or a Cloudflare account

```bash
cargo build -p ferrogate-cli      # produces target/debug/ferrogate
npm ci
npm run typecheck
npm test
```

`npm test` boots the PoC Worker in **workerd** (via
`@cloudflare/vitest-pool-workers` + miniflare, the same runtime
`wrangler dev --local` uses) in front of a **real spawned `ferrogate run`** and a
stub OpenAI-shaped upstream, then asserts:

- `/healthz` returns `{"status":"ok",…,"runtime":"pingora"}` — `runtime` is
  emitted by the Pingora ingress, so a Worker answering health checks itself
  cannot produce it;
- `/readyz` reports a loaded control-plane backend;
- one `POST /v1/chat/completions` comes back carrying **bytes that exist only in
  the stub upstream**, proving Worker → Pingora → upstream end to end;
- an unauthenticated call is rejected **by the origin**, proving the Worker is
  pure transport;
- the `outboundByHost` handlers resolve a **real workerd KV binding** and
  distinguish a miss from an empty value.

The suite **fails, and does not skip**, when no `ferrogate` binary is present:
a Worker talking to a mock is not this PoC. `scripts/check-workers.sh` gates it
and locates `target/{debug,release}/ferrogate` (or `$FERROGATE_BIN`). The
Node-only CI lane sets `WORKERS_SKIP_POC_ORIGIN=1` and prints what went unproven,
because that lane must not run cargo.

## What the local run does NOT prove

Stated here so a green local suite is never mistaken for a platform verdict:

1. **The container binding.** miniflare cannot back a Durable Object with a real
   container without Docker, so the harness reaches the origin over loopback.
2. **Outbound interception.** That a container's plain HTTP request to
   `cf-kv.internal` is *routed* to an `outboundByHost` handler is a Cloudflare
   behaviour with no local equivalent. The harness proves the handlers are
   correct, not that they are reached — runbook step **P7a** is the only thing
   that can establish that.
3. **Outbound TCP on 5432.** Whether a long-lived Postgres connection holds from
   inside a container is the single weakest-sourced, load-bearing claim in the
   topology assessment. Runbook step **P6**.
4. **Cold start, hibernation, DO duration billing, and shim latency.** Runbook
   steps **P5/P8/P9**. `src/origin.ts` ships the instrument
   (`x-ferrogate-poc-origin-ms`); only a deployment can produce the number.

## Deploying it for real

Follow §9 of the topology doc. In short: build `ferrogate:poc` for
`linux/amd64`, `wrangler kv namespace create POC_KV` and paste the id into
`wrangler.toml`, `wrangler secret put FERROGATE_POC_PG_DSN` and
`FERROGATE_POC_PROVIDER_KEY`, then `wrangler deploy`. Requires **Workers Paid**;
there is no free tier for Containers.
