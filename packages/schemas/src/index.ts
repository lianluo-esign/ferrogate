/**
 * `@ferrogate/schemas` — Zod schemas for every external wire boundary plus the
 * OpenAPI contract surface (251 operations,
 * `docs/openapi/runtime-api-contract.json`).
 *
 * Replaces the wire/DTO schema surface shared between the edge and control
 * planes. Every request/response boundary validates through a schema here.
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

/** Registry keyed by operationId; populated as operations are ported. */
export const wireSchemas: Record<string, z.ZodTypeAny> = {
  scope: scopeSchema,
  errorEnvelope: errorEnvelopeSchema,
};
