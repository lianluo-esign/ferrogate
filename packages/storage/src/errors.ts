/**
 * The crate-wide `StorageError` taxonomy (ports `ferrogate-storage::StorageError`).
 *
 * Modelled as a discriminated union carried by a single `StorageError` class so
 * callers can `switch (err.kind)` exactly as Rust matches the enum, while still
 * being a real `Error` with a faithful `Display`-equivalent `message`.
 *
 * Every Postgres/runtime error string is scrubbed through
 * {@link sanitizeStorageError} (DSN / secret redaction) before it is surfaced,
 * mirroring the Rust `sanitize_storage_error` guard.
 */
import type { StorageProviderKind } from "./provider.js";

/** The closed tag set of {@link StorageError}. Mirrors the Rust enum variants. */
export type StorageErrorKind =
  | "unsupported_provider"
  | "postgres"
  | "runtime"
  | "serialization"
  | "conflict"
  | "not_found"
  | "operation_deadline_exceeded"
  | "operation_cancelled"
  | "operation_commit_outcome_unknown";

interface StorageErrorData {
  provider?: StorageProviderKind;
  required?: boolean;
  detail?: string;
  operation?: string;
  stage?: string;
  /**
   * The async-storage commit fence bit: whether the commit had *started* when the
   * deadline tripped. Load-bearing so a cancelled/timed-out op can distinguish
   * "never committed" from "outcome unknown".
   */
  commitStarted?: boolean;
}

/** The single crate-wide error. `kind` is the discriminant. */
export class StorageError extends Error {
  readonly kind: StorageErrorKind;
  readonly data: StorageErrorData;

  constructor(kind: StorageErrorKind, message: string, data: StorageErrorData = {}) {
    super(message);
    this.name = "StorageError";
    this.kind = kind;
    this.data = data;
  }

  // --- Constructors mirroring the Rust variants ---------------------------

  static unsupportedProvider(provider: StorageProviderKind, required: boolean): StorageError {
    return new StorageError(
      "unsupported_provider",
      `storage provider ${provider} is not implemented yet (required=${required})`,
      { provider, required },
    );
  }

  /** Postgres error string — ALWAYS scrubbed through {@link sanitizeStorageError}. */
  static postgres(detail: string): StorageError {
    const clean = sanitizeStorageError(detail);
    return new StorageError("postgres", `postgres storage error: ${clean}`, { detail: clean });
  }

  static runtime(detail: string): StorageError {
    return new StorageError("runtime", `storage runtime error: ${detail}`, { detail });
  }

  static serialization(detail: string): StorageError {
    return new StorageError("serialization", `storage serialization error: ${detail}`, { detail });
  }

  static conflict(detail: string): StorageError {
    return new StorageError("conflict", `storage conflict: ${detail}`, { detail });
  }

  static notFound(detail: string): StorageError {
    return new StorageError("not_found", `storage record not found: ${detail}`, { detail });
  }

  static operationDeadlineExceeded(
    operation: string,
    stage: string,
    commitStarted: boolean,
  ): StorageError {
    return new StorageError(
      "operation_deadline_exceeded",
      `storage operation ${operation} exceeded its deadline during ${stage}`,
      { operation, stage, commitStarted },
    );
  }

  static operationCancelled(operation: string, stage: string): StorageError {
    return new StorageError(
      "operation_cancelled",
      `storage operation ${operation} was cancelled during ${stage}`,
      { operation, stage },
    );
  }

  static operationCommitOutcomeUnknown(operation: string, stage: string): StorageError {
    return new StorageError(
      "operation_commit_outcome_unknown",
      `storage operation ${operation} has an unknown commit outcome after ${stage}`,
      { operation, stage },
    );
  }
}

/**
 * Scrub DSN passwords and libpq-style secret markers from an error string
 * before it is ever surfaced (ports `sanitize_storage_error`).
 *
 * Two passes, matching the Rust order:
 *  1. `password=` / `passfile=` / `sslpassword=` marker values → `[redacted]`.
 *  2. `scheme://user:PASS@host` URL passwords → `[redacted]`.
 */
export function sanitizeStorageError(error: string): string {
  let sanitized = error;
  for (const marker of ["password=", "passfile=", "sslpassword="]) {
    sanitized = redactMarkerValue(sanitized, marker);
  }
  return redactUrlPasswords(sanitized);
}

/** Replaces the value that follows `marker` (up to whitespace/quote/`;`) with `[redacted]`. */
function redactMarkerValue(input: string, marker: string): string {
  let output = "";
  let rest = input;
  for (;;) {
    const start = rest.indexOf(marker);
    if (start < 0) break;
    output += rest.slice(0, start + marker.length);
    output += "[redacted]";
    const valueRest = rest.slice(start + marker.length);
    const endMatch = valueRest.search(/[\s'";]/);
    const valueEnd = endMatch < 0 ? valueRest.length : endMatch;
    rest = valueRest.slice(valueEnd);
  }
  return output + rest;
}

/** Replaces the password segment of every `scheme://user:PASS@host` authority. */
function redactUrlPasswords(input: string): string {
  let output = "";
  let rest = input;
  for (;;) {
    const schemeMarker = rest.indexOf("://");
    if (schemeMarker < 0) break;
    const authorityStart = schemeMarker + 3;
    const atRelative = rest.slice(authorityStart).indexOf("@");
    if (atRelative < 0) {
      output += rest;
      return output;
    }
    const at = authorityStart + atRelative;
    const authority = rest.slice(authorityStart, at);
    const colonRelative = authority.lastIndexOf(":");
    if (colonRelative < 0) {
      // No password segment in this authority — emit through the `@` and continue.
      output += rest.slice(0, at + 1);
      rest = rest.slice(at + 1);
      continue;
    }
    const colon = authorityStart + colonRelative;
    output += rest.slice(0, colon + 1);
    output += "[redacted]";
    output += "@";
    rest = rest.slice(at + 1);
  }
  return output + rest;
}
