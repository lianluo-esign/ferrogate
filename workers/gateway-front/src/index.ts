// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, the fronting Worker for the
// containerised Pingora data plane (#470 Option B): pure transport plus the
// veto-only shell contract, and the /__conformance/decide route Runner B of the
// governed-decision conformance suite drives.

import {
  canonicalJson,
  decideShell,
  defer,
  type GovernedDecisionRecord,
  type ShellLimits,
} from "./shell";

export interface Env {
  /**
   * Mirrors the origin's `limits.inference_body_max_bytes`. A string because
   * Worker vars are strings; parsed once per request, fail-closed to the
   * documented default when unset or unparseable.
   */
  INFERENCE_BODY_MAX_BYTES?: string;
  /**
   * Newline-separated SHA-256 hex digests of revoked bearer secrets. The only
   * state the shell is allowed to consult, and it can only turn an origin
   * ALLOW into a Worker DENY.
   */
  EDGE_DENY_LIST?: string;
  /**
   * `"1"` enables `/__conformance/decide`. Never set in a production
   * deployment: the route exists so the governed-decision corpus can drive the
   * *same* shell code the request path uses, and nothing else.
   */
  CONFORMANCE?: string;
}

const DEFAULT_BODY_MAX_BYTES = 1_048_576;

function limitsFrom(env: Env): ShellLimits {
  const parsed = Number.parseInt(env.INFERENCE_BODY_MAX_BYTES ?? "", 10);
  return {
    bodyMaxBytes: Number.isFinite(parsed) && parsed > 0 ? parsed : DEFAULT_BODY_MAX_BYTES,
  };
}

function denyListFrom(env: Env): string[] {
  return (env.EDGE_DENY_LIST ?? "")
    .split("\n")
    .map((entry) => entry.trim().toLowerCase())
    .filter((entry) => entry.length > 0);
}

function headersOf(request: Request): Record<string, string> {
  const headers: Record<string, string> = {};
  request.headers.forEach((value, name) => {
    headers[name.toLowerCase()] = value;
  });
  return headers;
}

/**
 * The conformance route. Takes a fixture from
 * `tests/fixtures/governed-decisions/` verbatim and returns the canonical
 * `GovernedDecisionRecord` the shell produces for it.
 *
 * It deliberately reuses `decideShell` rather than reimplementing anything: a
 * conformance route that exercised a copy of the shell would prove nothing
 * about the shell.
 */
async function conformanceDecide(request: Request, env: Env): Promise<Response> {
  const fixture = (await request.json()) as {
    request?: {
      headers?: Record<string, string>;
      body?: unknown;
      body_raw?: string;
      body_over_limit?: boolean;
    };
    worker_shell?: { deny_list?: string[] };
  };
  const fixtureRequest = fixture.request ?? {};
  const bodyText =
    typeof fixtureRequest.body_raw === "string"
      ? fixtureRequest.body_raw
      : fixtureRequest.body === undefined
        ? null
        : JSON.stringify(fixtureRequest.body);
  const record = await decideShell(
    {
      headers: Object.fromEntries(
        Object.entries(fixtureRequest.headers ?? {}).map(([name, value]) => [
          name.toLowerCase(),
          value,
        ]),
      ),
      bodyText: fixtureRequest.body_over_limit === true ? null : bodyText,
      bodyOverLimit: fixtureRequest.body_over_limit === true,
      denyList: (fixture.worker_shell?.deny_list ?? []).map((entry) => entry.trim().toLowerCase()),
    },
    limitsFrom(env),
  );
  return new Response(canonicalJson(record), {
    headers: { "content-type": "application/json" },
  });
}

function errorResponse(record: GovernedDecisionRecord, requestId: string): Response {
  return new Response(
    JSON.stringify({
      error: {
        message: `request rejected at the edge: ${record.code}`,
        type: "ferrogate_error",
        code: record.code,
        request_id: requestId,
      },
    }),
    { status: record.status, headers: { "content-type": "application/json" } },
  );
}

const GOVERNED_AI_PATHS = new Set(["/v1/chat/completions", "/v1/responses"]);

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/healthz") {
      // Carries no tenant decision, so it is transport.
      return new Response("ok", { headers: { "content-type": "text/plain" } });
    }

    if (url.pathname === "/__conformance/decide") {
      if (env.CONFORMANCE !== "1") {
        return new Response("not found", { status: 404 });
      }
      return conformanceDecide(request, env);
    }

    if (request.method === "POST" && GOVERNED_AI_PATHS.has(url.pathname)) {
      // The body is read once here so the shell can see it; the same bytes are
      // forwarded, never re-serialised, so the origin hashes exactly what the
      // client sent (the cache key in #233 depends on that).
      const bodyText = await request.text();
      const record = await decideShell(
        {
          headers: headersOf(request),
          bodyText,
          bodyOverLimit: false,
          denyList: denyListFrom(env),
        },
        limitsFrom(env),
      );
      if (record.outcome === "deny") {
        return errorResponse(record, request.headers.get("x-request-id") ?? "edge");
      }
      // `defer` is the only other outcome `decideShell` can produce -- see the
      // shell contract. Forwarding is transport: the origin re-validates every
      // header this Worker attached.
      return forwardToOrigin(request, bodyText);
    }

    return forwardToOrigin(request, null);
  },
};

/**
 * Transport to the container-hosted Pingora origin.
 *
 * Deliberately a stub in this slice: #470 froze the decision and this Worker's
 * *contract*; the container binding (`getContainer`/`containerFetch`) lands
 * with the deployment work in #472. Returning 501 is the fail-closed answer --
 * a shell that cannot reach the authority must not invent one.
 */
async function forwardToOrigin(_request: Request, _bodyText: string | null): Promise<Response> {
  return new Response(
    JSON.stringify({
      error: {
        message:
          "gateway-front is not yet bound to a container origin; see issue #472 for the deployment slice",
        type: "ferrogate_error",
        code: "origin_unbound",
      },
    }),
    { status: 501, headers: { "content-type": "application/json" } },
  );
}

export { decideShell, canonicalJson, defer };
