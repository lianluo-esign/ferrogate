/**
 * Stable exit classes and the CLI error taxonomy.
 *
 * Clean-room port of `ferrogate-control-plane-client::error` (see
 * docs/legacy/inventory-edge-control.md §1.2 / §2.1). The exit codes are a
 * documented contract: scripts branch on them, so they are reproduced exactly.
 */

/** The stable exit classes the CLI terminates with. */
export type ExitClass =
  | "success"
  | "usage"
  | "auth"
  | "not_found_conflict"
  | "validation"
  | "transport"
  | "server";

/** Numeric process exit code for an exit class (matches the Rust contract). */
export function exitCode(exitClass: ExitClass): number {
  switch (exitClass) {
    case "success":
      return 0;
    case "usage":
      return 2;
    case "auth":
      return 3;
    case "not_found_conflict":
      return 4;
    case "validation":
      return 5;
    case "transport":
      return 6;
    case "server":
      return 7;
  }
}

/**
 * Map an HTTP status onto an exit class.
 *
 * Reproduced arm-for-arm from the Rust `ExitClass::from_http_status`, including
 * the deliberate `402 | 405..=499 => Validation` catch-all.
 */
export function exitClassFromHttpStatus(status: number): ExitClass {
  if (status >= 200 && status <= 299) return "success";
  if (status === 401 || status === 403) return "auth";
  if (status === 404 || status === 409 || status === 410) return "not_found_conflict";
  if (status === 408 || status === 425 || status === 429) return "transport";
  if (status === 400 || status === 422) return "validation";
  if (status === 402 || (status >= 405 && status <= 499)) return "validation";
  if (status >= 500 && status <= 599) return "server";
  return "transport";
}

/** A structured Control Plane API error envelope. */
export interface ApiErrorPayload {
  readonly httpStatus: number;
  readonly code: string;
  readonly message: string;
  readonly requestId?: string;
  readonly traceId?: string;
  readonly retryAfterSecs?: number;
  readonly details?: unknown;
}

/** The error every CLI code path raises; carries its own exit class. */
export class CliError extends Error {
  readonly kind: "usage" | "auth" | "transport" | "api";
  readonly api?: ApiErrorPayload;

  private constructor(
    kind: "usage" | "auth" | "transport" | "api",
    message: string,
    api?: ApiErrorPayload,
  ) {
    super(message);
    this.name = "CliError";
    this.kind = kind;
    if (api !== undefined) this.api = api;
  }

  /** The operator mis-typed the command (exit 2). */
  static usage(message: string): CliError {
    return new CliError("usage", message);
  }

  /** No usable credential, or the server refused it (exit 3). */
  static auth(message: string): CliError {
    return new CliError("auth", message);
  }

  /** The request never reached an authoritative answer (exit 6). */
  static transport(message: string): CliError {
    return new CliError("transport", message);
  }

  /** The server answered with a structured error envelope. */
  static api(payload: ApiErrorPayload): CliError {
    const suffix = payload.requestId === undefined ? "" : ` [request_id=${payload.requestId}]`;
    return new CliError(
      "api",
      `control-plane API error ${payload.httpStatus} (${payload.code}): ${payload.message}${suffix}`,
      payload,
    );
  }

  exitClass(): ExitClass {
    switch (this.kind) {
      case "usage":
        return "usage";
      case "auth":
        return "auth";
      case "transport":
        return "transport";
      case "api":
        return exitClassFromHttpStatus(this.api?.httpStatus ?? 0);
    }
  }

  exitCode(): number {
    return exitCode(this.exitClass());
  }
}

/** Narrow an unknown thrown value into a `CliError`. */
export function asCliError(error: unknown): CliError {
  if (error instanceof CliError) return error;
  if (error instanceof Error) return CliError.transport(error.message);
  return CliError.transport(String(error));
}
