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

/** Number of operations in the committed OpenAPI runtime contract. */
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

/** Canonical error envelope returned by every FerroGate surface. */
export const errorEnvelopeSchema = z.object({
  code: z.string(),
  message: z.string(),
  requestId: z.string().optional(),
});
export type ErrorEnvelope = z.infer<typeof errorEnvelopeSchema>;
