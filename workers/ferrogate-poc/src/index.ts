// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-31
// description: Token4AI Cloud, FerroGate AI Gateway, the deployable Cloudflare
// Containers entrypoint for the #424 feasibility PoC: a Worker + Durable Object
// fronting the real Pingora binary, with the container->Worker binding shim
// wired in. Deployed with `wrangler deploy`; see README.md.

import { Container, ContainerProxy, getContainer } from "@cloudflare/containers";

import type { PocEnv } from "./env";
import { forwardToOrigin } from "./origin";
import { OUTBOUND_BY_HOST } from "./shim";

// REQUIRED -- not optional, and not covered by any other line in this file.
// Cloudflare: "Export `ContainerProxy` from your Worker entrypoint for outbound
// interception to work." Mechanism: `ContainerProxy extends WorkerEntrypoint`,
// and the runtime can only dispatch to a WorkerEntrypoint that is a named export
// of the entry module. Omit this line and `OUTBOUND_BY_HOST` below is dead code:
// the container's request to cf-kv.internal is never seen by a handler, and the
// shim probe fails for a reason that has nothing to do with bindings.
//
// This is a RUNTIME requirement -- `tsc` does not catch its absence, which is
// why `scripts/check-workers.sh` greps for it (issue #484).
// <https://developers.cloudflare.com/containers/platform-details/outbound-traffic/>
export { ContainerProxy };

/**
 * The container class.
 *
 * `sleepAfter` is left at the documented default rather than stretched: the PoC
 * is meant to *observe* the hibernation behaviour §3 of the topology doc costs
 * out, not to hide it.
 */
export class FerroGateContainer extends Container<PocEnv> {
  defaultPort = 8080;
  sleepAfter = "10m";

  // `ConstructorParameters` rather than a spelled-out `DurableObjectState`: the
  // exact state type the SDK's base constructor expects is its own business,
  // and pinning a guess here breaks on every SDK bump for no gain.
  constructor(ctx: ConstructorParameters<typeof Container<PocEnv>>[0], env: PocEnv) {
    super(ctx, env);
    // Secrets reach the container through `envVars`, sourced from Worker
    // secrets at start time -- never baked into the image, and never committed
    // here. The image carries `poc.toml`, which references these by name.
    //
    // Recorded limitation, because it is a real finding and not a detail:
    // `envVars` is a snapshot taken when the container starts, so rotating the
    // underlying Worker secret does NOT reach a running instance. Only the
    // outbound-shim path (below) gets live rotation.
    this.envVars = {
      FERROGATE_CONFIG: "/etc/ferrogate/poc.toml",
      FERROGATE_POC_PG_DSN: readSecret(env, "FERROGATE_POC_PG_DSN"),
      FERROGATE_POC_PROVIDER_KEY: readSecret(env, "FERROGATE_POC_PROVIDER_KEY"),
    };
  }
}

// Assignment, NOT a static class field. The package implements `outboundByHost`
// as an inherited static accessor pair (see its typings); an ES2022 static class
// field would define an own property that shadows the setter, leaving the runtime
// registry empty. The probe would then fail with a DNS or network error even
// though the code type-checks -- a false negative on the one step that backs the
// §6 decision. `scripts/check-workers.sh` greps for this shape too.
FerroGateContainer.outboundByHost = OUTBOUND_BY_HOST;

function readSecret(env: PocEnv, name: string): string {
  const value = (env as unknown as Record<string, unknown>)[name];
  if (typeof value !== "string" || value.length === 0) {
    // Fail loudly at container start rather than shipping an instance that
    // answers /healthz and then 401s or 502s for a reason no probe explains.
    // A PoC that boots but cannot reach its DB or upstream would report a
    // topology verdict it did not earn.
    throw new Error(
      `ferrogate-poc: required secret ${name} is not set; run \`wrangler secret put ${name}\``,
    );
  }
  return value;
}

export default {
  async fetch(request: Request, env: PocEnv): Promise<Response> {
    if (!env.FERROGATE) {
      return new Response(
        "ferrogate-poc: FERROGATE container binding is not declared in wrangler.toml",
        { status: 500 },
      );
    }
    // A single named instance: `max_instances = 1` in wrangler.toml, because
    // this PoC answers a feasibility question, not a scaling one. Containers
    // have no autoscaling primitive anyway (topology doc §3).
    return forwardToOrigin(request, getContainer(env.FERROGATE, "poc"));
  },
};
