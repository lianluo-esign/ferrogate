// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-26
// description: Token4AI Cloud, FerroGate AI Gateway — shared-secret gate and tenant
//   resolution for the telemetry-collector Worker (issue #520). Cloudflare authenticates
//   nobody for us, so ingest is DIY bearer auth on a `wrangler secret put` value.

import { UNKNOWN_TENANT } from "./limits";

/** Header FerroGate uses to state the tenant explicitly. Optional. */
export const TENANT_HEADER = "X-FerroGate-Tenant";

/**
 * Attribute keys searched, in order, when the tenant header is absent. First
 * non-empty match wins; resource attributes are searched before record ones
 * because a resource is the stronger statement of ownership.
 */
export const TENANT_ATTRIBUTE_KEYS = [
  "ferrogate.tenant_id",
  "tenant_id",
  "tenant.id",
  "tenant",
  "service.namespace",
] as const;

/**
 * Reject anything that is not `Authorization: Bearer <COLLECTOR_TOKEN>` with
 * **401** — including a wrong token. An ingest endpoint deliberately does not
 * distinguish "no credential" from "bad credential" (403 would confirm to a
 * prober that the endpoint exists and their token shape is right).
 *
 * Returns the denial `Response`, or `null` when the request is authorized.
 */
export function requireBearer(request: Request, expected: string | undefined): Response | null {
  if (!expected) {
    // Fail CLOSED: an unconfigured collector must not accept anonymous telemetry.
    return json({ error: "collector misconfigured: COLLECTOR_TOKEN is not set" }, 500);
  }
  const header = request.headers.get("authorization") ?? "";
  const prefix = "Bearer ";
  if (!header.startsWith(prefix) || !timingSafeEqual(header.slice(prefix.length), expected)) {
    return json({ error: "unauthorized" }, 401);
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

/** The tenant stated by the request header, or `null` when absent/blank. */
export function tenantFromHeaders(request: Request): string | null {
  const value = request.headers.get(TENANT_HEADER)?.trim();
  return value ? value : null;
}

/**
 * Derive the tenant for one record: the header wins, then the resource
 * attributes, then the record attributes, then {@link UNKNOWN_TENANT}.
 *
 * Never returns empty — the tenant becomes the Analytics Engine index, and a
 * point with no index cannot be written.
 */
export function resolveTenant(
  headerTenant: string | null,
  resourceAttributes: Record<string, string>,
  recordAttributes: Record<string, string>,
): string {
  if (headerTenant) return headerTenant;
  for (const key of TENANT_ATTRIBUTE_KEYS) {
    const fromResource = resourceAttributes[key]?.trim();
    if (fromResource) return fromResource;
    const fromRecord = recordAttributes[key]?.trim();
    if (fromRecord) return fromRecord;
  }
  return UNKNOWN_TENANT;
}

/** JSON response helper shared by every collector route. */
export function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
}
