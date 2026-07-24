// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-24
// description: DIY bearer auth + JSON helpers for the d1-proxy Worker (issue #450).
//   A local copy of the agent-gateway house pattern (workers/agent-gateway/src/auth.ts):
//   worker dirs never import across each other, so the constant-time bearer check and
//   the JSON helper are duplicated verbatim here.

/**
 * Constant-time-ish bearer check. Returns a 401/403/500 `Response` when the
 * request is NOT authorized, or `null` when it is.
 *
 * DIY auth is required: Cloudflare fronts the Worker but does not authenticate
 * the caller for us. Fail-closed — a Worker with no configured token answers
 * 500 rather than accepting traffic. Bearer-token is the baseline; mTLS
 * (client-cert on a custom domain) and Cloudflare Access (JWT in
 * `Cf-Access-Jwt-Assertion`) are the documented stronger alternatives.
 */
export function requireBearer(request: Request, expected: string | undefined): Response | null {
  if (!expected) {
    return json({ error: "d1-proxy misconfigured: no proxy token bound" }, 500);
  }
  const header = request.headers.get("authorization") ?? "";
  const prefix = "Bearer ";
  if (!header.startsWith(prefix)) {
    return json({ error: "missing bearer token" }, 401);
  }
  const presented = header.slice(prefix.length);
  if (!timingSafeEqual(presented, expected)) {
    return json({ error: "invalid bearer token" }, 403);
  }
  return null;
}

/** Length-independent constant-time string comparison. */
export function timingSafeEqual(a: string, b: string): boolean {
  const enc = new TextEncoder();
  const ab = enc.encode(a);
  const bb = enc.encode(b);
  // Fold length into the accumulator so mismatched lengths still run to the end.
  let diff = ab.length ^ bb.length;
  const max = Math.max(ab.length, bb.length);
  for (let i = 0; i < max; i++) {
    diff |= (ab[i] ?? 0) ^ (bb[i] ?? 0);
  }
  return diff === 0;
}

/** JSON response helper shared by every proxy route. */
export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}
