/**
 * Shared external-wire-boundary schemas and the OpenAPI contract surface.
 *
 * These are the cross-cutting envelopes every FerroGate surface agrees on. The
 * per-operation request/response shapes of the committed 251-operation contract
 * (`docs/openapi/runtime-api-contract.json`) are ported incrementally by the
 * request-path cluster ports and registered in {@link wireSchemas}.
 */
import { z } from "zod";
import type { Scope } from "@ferrogate/core";

/**
 * Number of operations in the committed OpenAPI runtime contract.
 *
 * PORT-TODO(inventory §1.3) — THIRD COPY OF ONE CONSTANT. Not a platform limit.
 * Not closed. See `docs/rewrite/parity-audit-dead-packages.md` §3.2.
 *
 * The same number is independently declared as `EXPECTED_OPERATION_COUNT`
 * (`apps/gateway/src/contract.ts:123`) and `EXPECTED_TOTAL_OPERATION_COUNT`
 * (`apps/control-plane/src/contract.ts:119`). Three copies, nothing forcing
 * them to move together — precisely the drift this package's own docstring
 * claims to prevent. Collapse to one; this constant has zero importers today.
 */
export const OPENAPI_OPERATION_COUNT = 251 as const;

/** Tenancy scope, the wire twin of `@ferrogate/core`'s `Scope`. */
export const scopeSchema = z.object({
  tenant: z.string().min(1),
  project: z.string().optional(),
  workspace: z.string().optional(),
});
export type ScopeWire = z.infer<typeof scopeSchema>;

/**
 * Compile-time parity guard: the Zod schema output must stay assignable to the
 * core `Scope` type. If they drift, this stops type-checking.
 */
export const assertScopeParity = (scope: Scope): ScopeWire => scope;

/**
 * Canonical error envelope returned by every FerroGate surface.
 *
 * PORT-TODO(inventory §1.4) — THIS SHAPE IS WRONG AND MUST NOT BE ADOPTED. Not
 * a platform limit. Not closed. See
 * `docs/rewrite/parity-audit-dead-packages.md` §3.2.
 *
 * The envelope every FerroGate surface actually writes — byte-identical to Rust
 * `responses.rs::write_json_error`, and pinned across the gateway suite — is
 *
 *     { "error": { "message": "...", "type": "ferrogate_error",
 *                  "code": "...", "request_id": "..." } }
 *
 * (`apps/gateway/src/inference/errors.ts:54`, and declared as a Zod schema at
 * `apps/gateway/src/assets/schemas.ts:319`). The schema below is a DIFFERENT,
 * unnested shape that also renames `request_id` to `requestId`; it matches no
 * response this system emits. It has zero importers, which is the only reason
 * the divergence has been harmless — wiring it at any boundary would BREAK wire
 * parity. Correct it against the gateway's declaration or delete it; do not
 * "wire the dead package" by adopting this version.
 */
export const errorEnvelopeSchema = z.object({
  code: z.string(),
  message: z.string(),
  requestId: z.string().optional(),
});
export type ErrorEnvelope = z.infer<typeof errorEnvelopeSchema>;
