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
import { z } from "zod";
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
 * primitives; the per-operation request/response bodies are added incrementally.
 *
 * PORT-TODO(inventory §1.3/§1.4): the remaining per-operation request/response
 * shapes of the committed 251-operation runtime contract
 * (`docs/openapi/runtime-api-contract.json`) are ported by the request-path
 * cluster (gateway/routing/providers/runtime) and registered here. Only the
 * shared cross-plane + `ferrogate-core` primitives are populated so far.
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
