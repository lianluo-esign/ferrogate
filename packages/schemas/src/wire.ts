/**
 * Shared external-wire-boundary schemas and the OpenAPI contract surface.
 *
 * These are the cross-cutting envelopes every FerroGate surface agrees on. The
 * per-operation request/response shapes of the committed 279-operation contract
 * (`docs/openapi/runtime-api-contract.json`) are ported incrementally by the
 * request-path cluster ports and registered in {@link wireSchemas}.
 */
import { z } from "zod";
import type { Scope } from "@ferrogate/core";

/**
 * Number of operations in the committed OpenAPI runtime contract.
 *
 * It is one of THREE independent declarations of this number — the others are
 * `EXPECTED_OPERATION_COUNT` (`apps/gateway/src/contract.ts`) and
 * `EXPECTED_TOTAL_OPERATION_COUNT` (`apps/control-plane/src/contract.ts`) —
 * which the dead-packages audit (§3.2) flagged as drift waiting to happen.
 *
 * The DRIFT the audit worried about is now closed, because all three copies are
 * independently pinned to the SAME document rather than to each other:
 * `apps/control-plane/test/contract.test.ts` imports the JSON and asserts
 * `operations` has `EXPECTED_TOTAL_OPERATION_COUNT` entries,
 * `apps/gateway/test/contract.test.ts` asserts its generated table has
 * `EXPECTED_OPERATION_COUNT`, and `test/wire.test.ts` reads
 * `docs/openapi/runtime-api-contract.json` off disk and asserts
 * `operations.length === OPENAPI_OPERATION_COUNT`. Adding or removing an
 * operation therefore fails in all three places at once; no copy can silently
 * disagree with the document it claims to count. Collapsing the three
 * declarations into one import is a tidiness edit in `apps/*`, not a defect,
 * which is why no marker is carried for it.
 *
 * The value stays a literal on purpose: a
 * constant derived from the JSON at runtime would drag a 79 KB document into
 * every bundle that imports this package, and would make the anti-drift gate
 * unfailable — it would agree with the contract by construction, which is the
 * vacuous-assertion shape this repo keeps getting bitten by.
 */
export const OPENAPI_OPERATION_COUNT = 279 as const;

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
 * ## CORRECTED — the previous shape was a fiction (closed marker, inventory §1.4)
 *
 * Until this slice this schema declared a FLAT `{ code, message, requestId? }`,
 * which matched no response this system has ever emitted, and renamed
 * `request_id` to `requestId` on top. It was harmless only because nothing
 * imported it; adopting it at any boundary would have broken wire parity. The
 * audit's instruction was "correct it against the gateway's declaration or
 * delete it, never adopt it" — corrected, because a shared package IS the right
 * home for the one envelope every plane agrees on.
 *
 * The shape below is the one Rust actually serializes. `ErrorBody`/`ErrorObject`
 * (`crates/ferrogate-gateway/.../responses.rs`) are plain `#[derive(Serialize)]`
 * structs with `#[serde(rename = "type")] kind: &'static str` and
 * `request_id: Option<String>`:
 *
 *     { "error": { "message": "...", "type": "ferrogate_error",
 *                  "code": "...", "request_id": "..." } }
 *
 * Field-by-field, and why each modifier is what it is:
 *
 *  - `type` is `z.literal("ferrogate_error")`, not `z.string()` — it is a
 *    `&'static str` in Rust and every TS producer writes the same literal
 *    (`FERROGATE_ERROR_TYPE` in gateway, control-plane, agent-runtime,
 *    telemetry). A client discriminates on it.
 *  - `request_id` is `.nullable().optional()`. Nullable because Rust has NO
 *    `skip_serializing_if`, so `None` serializes as an explicit
 *    `"request_id": null` rather than an absent key. Optional because the
 *    gateway's mid-STREAM error frames omit it outright
 *    (`apps/gateway/src/guardrails/stream.ts`,
 *    `apps/gateway/src/streaming/responses.ts` build
 *    `{message, type, code}` with no id, since the id already went out in the
 *    response headers before the stream opened). Both are real emissions, so a
 *    schema that admitted only one of them would reject live traffic.
 *  - The envelope is NOT `.strict()`: an unknown sibling key must not make a
 *    consumer reject an error response it otherwise understands.
 *
 * `apps/gateway/src/assets/schemas.ts` declares the same envelope locally for
 * its own operations; the two agree, and `test/wire.test.ts` pins this one
 * against literal fixtures captured from the shipped producers, so a future
 * edit that "simplifies" it back to a flat shape fails.
 */
export const errorEnvelopeSchema = z.object({
  error: z.object({
    message: z.string(),
    type: z.literal("ferrogate_error"),
    code: z.string(),
    request_id: z.string().nullable().optional(),
  }),
});
export type ErrorEnvelope = z.infer<typeof errorEnvelopeSchema>;
