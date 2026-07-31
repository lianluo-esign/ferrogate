// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-31
// description: Token4AI Cloud, FerroGate AI Gateway, the docker-free workerd
// entrypoint for the #424 PoC. Same forwarding code and same shim handler table
// as src/index.ts, with the container binding replaced by a locally spawned
// `ferrogate run` -- because miniflare cannot back a Durable Object with a real
// container without Docker.

import type { PocEnv } from "./env";
import { forwardToOrigin } from "./origin";
import { OUTBOUND_BY_HOST } from "./shim";

/**
 * Harness-only prefix used to drive the outbound handler table directly.
 *
 * Be precise about what this does and does not prove. It invokes the *real*
 * handler functions from `src/shim.ts` against a *real* workerd KV binding, so
 * it proves the handlers resolve bindings correctly and that their status
 * discrimination behaves as the runbook table claims. It does NOT prove
 * Cloudflare's outbound *interception* -- that a container's plain HTTP request
 * to `cf-kv.internal` is routed to these handlers at all. Interception is a
 * platform behaviour that exists only on Cloudflare, and runbook step P7a is
 * the only thing that can establish it. Claiming otherwise here would be the
 * false-positive this PoC is supposed to eliminate.
 */
export const SHIM_PROBE_PREFIX = "/__shim/";

export default {
  async fetch(request: Request, env: PocEnv): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname.startsWith(SHIM_PROBE_PREFIX)) {
      return driveShim(request, env, url);
    }

    const originBaseUrl = env.FERROGATE_ORIGIN_URL;
    if (!originBaseUrl) {
      // Fail closed and by name. A harness that quietly answered from the
      // Worker when the origin was missing would report a green PoC while
      // never having started FerroGate at all.
      return new Response(
        "ferrogate-poc harness: FERROGATE_ORIGIN_URL is not set; no origin was started",
        { status: 503 },
      );
    }

    return forwardToOrigin(request, { fetch: (req) => fetch(req) }, originBaseUrl);
  },
};

/**
 * `/__shim/<virtual-host>/<path>` -> the handler registered for that host.
 *
 * The request handed to the handler is rebuilt at `http://<virtual-host>/<path>`,
 * i.e. exactly the URL a container would have issued, so the handler's own URL
 * parsing (which is how it derives the KV key) is under test rather than bypassed.
 */
async function driveShim(request: Request, env: PocEnv, url: URL): Promise<Response> {
  const rest = url.pathname.slice(SHIM_PROBE_PREFIX.length);
  const separator = rest.indexOf("/");
  const host = separator === -1 ? rest : rest.slice(0, separator);
  const path = separator === -1 ? "/" : rest.slice(separator);

  const handler = OUTBOUND_BY_HOST[host];
  if (!handler) {
    return new Response(`no outbound handler registered for ${host}`, { status: 404 });
  }
  return handler(new Request(`http://${host}${path}`, request), env, {
    containerId: "harness",
    className: "FerroGateContainer",
    params: undefined,
  });
}
