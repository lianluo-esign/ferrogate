/**
 * `@ferrogate/core` — foundational types shared across every FerroGate package.
 *
 * Faithful clean-room port of the Rust crate `ferrogate-core`: request identity,
 * tenant/workspace attribution, canonical tool primitives, the approval policy,
 * the secret-shaped-key redaction guard, and the boundary error. Pure
 * TypeScript: no Cloudflare bindings, no I/O.
 *
 * The Rust surface is split into cohesive modules and re-exported below:
 *  - `json`       — `serde_json::Value` twin used by the tool primitives.
 *  - `redaction`  — `SECRET_SHAPED_KEY_FRAGMENTS` + recursive redaction helper.
 *  - `approval`   — `ApprovalPolicy`.
 *  - `tools`      — `ToolDef` / `ToolCall` / `ToolResult`.
 *  - `context`    — `TenantContext` / `RequestContext` / `WorkspaceScope`.
 *  - `errors`     — `GatewayError` (+ `GatewayResult<T>`, defined here).
 *
 * The generic scaffold identifiers below (`Scope`, `Identity`, `ToolRef`,
 * `FerrogateError`, `Result`, the id aliases, `PUBLIC_API_MAJOR`) are the
 * wave-1 foundation the rest of the workspace already imports; they are kept
 * intact alongside the crate port.
 */
import type { GatewayError } from "./errors.js";

/** Public API major version (mirrors `ferrogate-admin::PUBLIC_API_MAJOR`). */
export const PUBLIC_API_MAJOR = "v1" as const;

/** Opaque identifiers used across the control and data planes. */
export type TenantId = string;
export type ProjectId = string;
export type WorkspaceId = string;
export type SubjectId = string;

/** The tenancy scope every request and record is resolved into. */
export interface Scope {
  tenant: TenantId;
  project?: ProjectId;
  workspace?: WorkspaceId;
}

/** Resolved caller identity (virtual API key / console session / service account). */
export interface Identity {
  subject: SubjectId;
  scope: Scope;
  scopes: readonly string[];
}

/** A tool the gateway can expose or execute (native, MCP, or extension). */
export interface ToolRef {
  name: string;
  namespace?: string;
}

/** Stable error classes mirrored from the Rust core error taxonomy. */
export type ErrorKind =
  | "invalid_request"
  | "unauthenticated"
  | "forbidden"
  | "not_found"
  | "conflict"
  | "rate_limited"
  | "upstream"
  | "internal";

/** Canonical FerroGate error carrying a stable machine-readable code. */
export class FerrogateError extends Error {
  readonly kind: ErrorKind;
  readonly code: string;

  constructor(kind: ErrorKind, code: string, message?: string) {
    super(message ?? code);
    this.name = "FerrogateError";
    this.kind = kind;
    this.code = code;
  }
}

/** Result envelope for call paths where throwing is undesirable. */
export type Result<T, E = FerrogateError> =
  | { readonly ok: true; readonly value: T }
  | { readonly ok: false; readonly error: E };

// ---------------------------------------------------------------------------
// Faithful port of the Rust `ferrogate-core` crate.
// ---------------------------------------------------------------------------

export * from "./json.js";
export * from "./redaction.js";
export * from "./approval.js";
export * from "./tools.js";
export * from "./context.js";
export * from "./errors.js";

/**
 * Rust `type Result<T> = std::result::Result<T, GatewayError>`.
 *
 * Named `GatewayResult` because the crate's `Result<T>` alias would collide with
 * the scaffold `Result<T, E>` envelope above; this specializes that envelope to
 * the crate's boundary error.
 */
export type GatewayResult<T> = Result<T, GatewayError>;
