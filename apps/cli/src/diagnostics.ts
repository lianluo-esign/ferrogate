/**
 * Error reporting to stderr.
 *
 * Port of `ferrogate-cli::ctl::dispatch::report_error_for`. Diagnostics never
 * go to stdout — a script piping stdout must receive data or nothing — and the
 * server's `details` blob is redacted with the invoked group's secret fields
 * before it is rendered, because an error path is exactly where a rotated key
 * has historically leaked.
 */
import type { JsonValue } from "@ferrogate/core";
import type { CliError } from "./errors.js";
import type { Io } from "./ports.js";
import { redactSecretFields } from "./registry.js";

export function renderDetails(details: JsonValue, secretFields: readonly string[]): string {
  return JSON.stringify(redactSecretFields(details, secretFields));
}

export function reportError(io: Io, error: CliError, secretFields: readonly string[] = []): void {
  io.stderr(`error: ${error.message}\n`);
  const api = error.api;
  if (api === undefined) return;
  io.stderr(`  code: ${api.code}\n`);
  io.stderr(`  http-status: ${api.httpStatus}\n`);
  if (api.requestId !== undefined) io.stderr(`  request-id: ${api.requestId}\n`);
  if (api.traceId !== undefined) io.stderr(`  trace-id: ${api.traceId}\n`);
  if (api.retryAfterSecs !== undefined) io.stderr(`  retry-after: ${api.retryAfterSecs}s\n`);
  if (api.details !== undefined) {
    io.stderr(`  details: ${renderDetails(api.details as JsonValue, secretFields)}\n`);
  }
}
