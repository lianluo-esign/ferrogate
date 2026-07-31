// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-31
// description: Token4AI Cloud, FerroGate AI Gateway, the #424 PoC Worker's
// forwarding path: one transport implementation shared by the deployed
// Containers entrypoint and the docker-free workerd harness, plus the
// container-hop timing header that step P8 of the runbook reads.

/**
 * Anything that can answer a `Request` on behalf of the FerroGate origin.
 *
 * In a real deployment this is the `DurableObjectStub` returned by
 * `getContainer(env.FERROGATE, ...)`. In the workerd harness it is a plain
 * `fetch` against a locally spawned `ferrogate run`. Both satisfy the same
 * structural type on purpose: the forwarding code below is then literally the
 * same code in both, so what the harness proves about it transfers.
 */
export interface OriginFetcher {
  fetch(request: Request): Promise<Response>;
}

/**
 * Response header carrying the wall-clock milliseconds the Worker spent waiting
 * on the origin, measured around the single `origin.fetch` call.
 *
 * This exists because §6 of `docs/cloudflare-deploy-topology.md` has one
 * unquantified row (shim/hop latency) and P8 of the runbook is what fills it in.
 * A number nobody can obtain is not a measurement, so the instrument that
 * obtains it ships with the PoC rather than being described in prose.
 *
 * Caveat, deliberately recorded: on Cloudflare this measures Worker→DO→container
 * plus the origin's own service time; it is NOT the isolated network hop, and
 * subtracting the origin's service time needs the direct-origin baseline from
 * runbook step P2.
 */
export const ORIGIN_TIMING_HEADER = "x-ferrogate-poc-origin-ms";

/**
 * The one route set this PoC claims to prove, mirroring the issue's acceptance
 * criterion: a health check, readiness (which is where the control-plane/DB
 * dependency shows up), and one proxied inference call.
 *
 * It is exported rather than inlined so the harness asserts the same list the
 * Worker enforces; a route added here without a matching assertion is visible.
 */
export const POC_ROUTES = ["/healthz", "/readyz", "/v1/chat/completions"] as const;

/**
 * Forward a request to the FerroGate origin unchanged, and record how long the
 * origin took.
 *
 * Unchanged is the point. The PoC's question is "does the Pingora binary run
 * under a Worker-fronted container and still behave like FerroGate", so the
 * Worker must not answer any part of the request itself -- if it rewrote,
 * validated or short-circuited anything, a green PoC would partly be measuring
 * the Worker. The edge-side veto shell is a different Worker
 * (`workers/gateway-front`, issue #470) and a different question.
 */
export async function forwardToOrigin(
  request: Request,
  origin: OriginFetcher,
  originBaseUrl?: string,
): Promise<Response> {
  const outbound = originBaseUrl ? rewriteToBase(request, originBaseUrl) : new Request(request);

  const startedAt = Date.now();
  const response = await origin.fetch(outbound);
  const elapsedMs = Date.now() - startedAt;

  // `Response` from a subrequest has immutable headers, so clone into a mutable
  // one rather than mutating in place (which silently no-ops in workerd).
  const headers = new Headers(response.headers);
  headers.set(ORIGIN_TIMING_HEADER, String(elapsedMs));
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}

/**
 * Repoint a request at `base`, preserving path, query, method, headers and body.
 *
 * Only the harness needs this: a container stub is addressed by the DO binding
 * and ignores the URL host, whereas a locally spawned `ferrogate` is addressed
 * by a real `http://127.0.0.1:<port>` origin.
 */
function rewriteToBase(request: Request, base: string): Request {
  const source = new URL(request.url);
  const target = new URL(base);
  target.pathname = source.pathname;
  target.search = source.search;
  return new Request(target.toString(), request);
}
