/**
 * The response constructors `crates/ferrogate-auth-service/src/http.rs`
 * provides (`unauthorized`, `forbidden`, `not_found`, `unprocessable`,
 * `internal_error`, `storage_error`, `lifecycle_error`), as plain values.
 *
 * Every one of these is a REFUSAL. They exist as a single shared vocabulary so
 * that "fail closed" is a call to one of these functions rather than an ad-hoc
 * object literal per call site — a shape drift between two refusals is how a
 * caller ends up branching on `status === 401` and silently letting a 403
 * through.
 */
import type { IdentityResponse } from "./ports.js";

function refusal(status: number, code: string, message: string): IdentityResponse {
  return { status, body: { error: { type: code, message } } };
}

export function unauthorized(message: string): IdentityResponse {
  return refusal(401, "unauthorized", message);
}

export function forbidden(message: string): IdentityResponse {
  return refusal(403, "forbidden", message);
}

export function notFound(message: string): IdentityResponse {
  return refusal(404, "not_found", message);
}

export function unprocessable(message: string): IdentityResponse {
  return refusal(422, "unprocessable_entity", message);
}

export function badRequest(message: string): IdentityResponse {
  return refusal(400, "invalid_request", message);
}

export function internalError(message: string): IdentityResponse {
  return refusal(500, "internal_error", message);
}

/**
 * A storage failure. 500 like the Rust `storage_error`, and deliberately
 * WITHOUT the underlying message — a repository error can carry a row, a SQL
 * fragment, or a connection string.
 */
export function storageError(_error: unknown): IdentityResponse {
  return refusal(500, "storage_error", "a storage operation failed");
}

/**
 * A tenancy-lifecycle refusal (suspended/deleted tenant, project or
 * workspace). 403 with the gateway's own code — NOT a 500, and never a live
 * credential (#514).
 */
export function lifecycleError(_error: unknown): IdentityResponse {
  return refusal(403, "tenancy_suspended", "this tenancy is not usable");
}

/** A SCIM-shaped error document (RFC 7644 §3.12). */
export function scimError(status: number, detail: string, scimType?: string): IdentityResponse {
  return {
    status,
    scim: true,
    body: {
      schemas: ["urn:ietf:params:scim:api:messages:2.0:Error"],
      status: String(status),
      detail,
      ...(scimType ? { scimType } : {}),
    },
  };
}
