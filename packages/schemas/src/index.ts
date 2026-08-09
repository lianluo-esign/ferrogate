/**
 * `@ferrogate/schemas` — the wire-boundary + OpenAPI-contract surface.
 *
 * Two responsibilities:
 *
 *  1. **Cross-plane wire envelopes** owned here: the tenancy {@link scopeSchema},
 *     the {@link errorEnvelopeSchema}, and the OpenAPI operation count/registry.
 *
 *  2. **The `ferrogate-core` wire schemas**, re-exported from `@ferrogate/core`.
 *     The Rust `ferrogate-core` crate was ported (clean-room) into
 *     `@ferrogate/core` in wave 1 — including the Zod validators for its domain
 *     primitives (tenant/workspace/request context, tool primitives, approval
 *     policy, the secret-shaped-key redaction guard, the boundary error). This
 *     package surfaces that single source of truth as the shared wire vocabulary
 *     rather than re-declaring it.
 *
 *     Re-exporting (instead of copying) is deliberate and load-bearing: the crate
 *     doc for `SECRET_SHAPED_KEY_FRAGMENTS` records that shipping two independent
 *     copies of that list (issue #351) silently made the weaker copy the
 *     effective security bar. One definition, surfaced from both packages, keeps
 *     the wire and the domain in lockstep and cannot drift.
 */

import {
  approvalPolicySchema,
  gatewayErrorSchema,
  requestContextSchema,
  tenantContextSchema,
  toolCallSchema,
  toolDefSchema,
  toolResultSchema,
  workspaceScopeSchema,
} from "@ferrogate/core";
import type { z } from "zod";

import { errorEnvelopeSchema, scopeSchema } from "./wire";

// --- Wire-boundary + OpenAPI surface (owned by this package) ---------------
export {
  OPENAPI_OPERATION_COUNT,
  scopeSchema,
  assertScopeParity,
  errorEnvelopeSchema,
} from "./wire";
export type { ScopeWire, ErrorEnvelope } from "./wire";

// --- ferrogate-core wire schemas (single source: @ferrogate/core) ----------
// JSON value model (`serde_json::Value` twin) used by the tool primitives.
export { jsonValueSchema } from "@ferrogate/core";
export type { JsonValue } from "@ferrogate/core";

// Secret-shaped-key redaction guard (shared so guards cannot drift, issue #351).
export {
  SECRET_SHAPED_KEY_FRAGMENTS,
  REDACTED_PLACEHOLDER,
  isSecretShapedKey,
  redactSecretShapedKeys,
  secretShapedKeyPaths,
  hasSecretShapedKey,
} from "@ferrogate/core";
export type { SecretShapedKeyFragment } from "@ferrogate/core";

// Approval policy (`"never"` default / `"always"`).
export { approvalPolicySchema, DEFAULT_APPROVAL_POLICY } from "@ferrogate/core";
export type { ApprovalPolicy } from "@ferrogate/core";

// Canonical tool primitives.
export { toolDefSchema, toolCallSchema, toolResultSchema } from "@ferrogate/core";
export type { ToolDef, ToolCall, ToolResult } from "@ferrogate/core";

// Tenant / workspace / request attribution.
export {
  tenantContextSchema,
  requestContextSchema,
  workspaceScopeSchema,
  newWorkspaceScope,
  applyWorkspaceScope,
} from "@ferrogate/core";
export type { TenantContext, RequestContext, WorkspaceScope } from "@ferrogate/core";

// Boundary error + result alias.
export { gatewayErrorSchema, GatewayError, newGatewayError } from "@ferrogate/core";
export type { GatewayErrorData, GatewayResult } from "@ferrogate/core";

/**
 * Registry keyed by operationId / type name, resolving a wire schema by name.
 * Seeded with the cross-plane envelopes and the shared `ferrogate-core`
 * primitives.
 *
 * PORT-TODO(P: inventory §1.3/§1.4) — CROSS-SCOPE REGISTRATION, NOT A PLATFORM
 * LIMIT, NOT CLOSED HERE AND NOT CLOSABLE HERE.
 *
 * The remaining per-operation request/response shapes of the committed
 * 281-operation runtime contract (`docs/openapi/runtime-api-contract.json`) are
 * OWNED by the surfaces that serve them — `apps/gateway`, `apps/control-plane`,
 * `apps/mcp`. Defining them in this package would invert the dependency (a
 * shared leaf package would have to know every route's body) and would
 * guarantee drift: the schema and the handler it validates would live in
 * different packages with nothing forcing them to move together.
 *
 * So what this package owes is the REGISTRATION MECHANISM, and that is now
 * closed: {@link registerWireSchema} lets an app register its operations at
 * composition time, and it REFUSES a duplicate name rather than overwriting —
 * a silent overwrite would swap the validator for a route and be invisible.
 * Direct mutation of {@link wireSchemas} still works for reads; prefer the
 * function so collisions are caught.
 *
 * CURRENT STATE, stated exactly so nobody reads this marker as "done": as of
 * this commit **no app calls {@link registerWireSchema}** — `grep -rn
 * registerWireSchema apps/` returns nothing. The registry therefore holds only
 * the 10 names seeded below (2 cross-plane envelopes + 8 `ferrogate-core`
 * primitives) out of {@link OPENAPI_OPERATION_COUNT} contract operations. That
 * does NOT mean 255 operations are unvalidated — every app validates its bodies
 * with co-located Zod schemas today — it means those schemas are not
 * DISCOVERABLE by operationId through this registry. Wiring them in is work in
 * `apps/*`, not here, which is why the marker stays.
 */
export const wireSchemas: Record<string, z.ZodTypeAny> = {
  // cross-plane envelopes (owned here)
  scope: scopeSchema,
  errorEnvelope: errorEnvelopeSchema,
  // ferrogate-core primitives (single source: @ferrogate/core)
  approvalPolicy: approvalPolicySchema,
  tenantContext: tenantContextSchema,
  workspaceScope: workspaceScopeSchema,
  requestContext: requestContextSchema,
  toolDef: toolDefSchema,
  toolCall: toolCallSchema,
  toolResult: toolResultSchema,
  gatewayError: gatewayErrorSchema,
};

/**
 * Register one operation's wire schema under `name`.
 *
 * @throws if `name` is already registered with a DIFFERENT schema. Re-registering
 *   the identical schema object is a no-op, so a module imported twice (two
 *   entry points, a test importing a composition root) is not an error, while
 *   two different bodies claiming one operationId — the drift that silently
 *   swaps a route's validator — is.
 */
export function registerWireSchema(name: string, schema: z.ZodTypeAny): void {
  if (name.trim() === "") {
    throw new Error("wire schema name must not be empty");
  }
  const existing = wireSchemas[name];
  if (existing !== undefined && existing !== schema) {
    throw new Error(
      `wire schema ${JSON.stringify(name)} is already registered with a different schema; an operationId must map to exactly one body, or a route silently validates against the wrong one`,
    );
  }
  wireSchemas[name] = schema;
}

/** Register many at once (an app's whole surface). Fails on the first collision. */
export function registerWireSchemas(schemas: Record<string, z.ZodTypeAny>): void {
  for (const [name, schema] of Object.entries(schemas)) registerWireSchema(name, schema);
}

/** Resolve a registered schema by name, or `undefined`. */
export function resolveWireSchema(name: string): z.ZodTypeAny | undefined {
  return wireSchemas[name];
}

/** Every registered name, sorted — the introspection an app's status route uses. */
export function registeredWireSchemaNames(): string[] {
  return Object.keys(wireSchemas).sort();
}
