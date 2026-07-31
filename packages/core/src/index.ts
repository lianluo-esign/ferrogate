/**
 * `@ferrogate/core` — foundational types shared across every FerroGate package.
 *
 * Replaces the Rust crate `ferrogate-core` (identity, tenant/workspace scope,
 * tool types, errors). Pure TypeScript: no Cloudflare bindings, no I/O.
 */

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
