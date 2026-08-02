/**
 * The fail-closed Control Plane API contract-version gate.
 *
 * Clean-room port of `ferrogate-control-plane-client::version`
 * (docs/legacy/inventory-edge-control.md §2.1: "`version` | CLI/API version +
 * fail-closed contract-version compatibility check").
 *
 * FerroGate versions the API contract on a calendar scheme (`YYYY.M.D`). The
 * client refuses to render a document produced by a server whose contract
 * predates the minimum this build was written against — a status document
 * shaped by an older contract would be *mis-mapped*, and printing a
 * confidently-wrong table with exit 0 is worse than refusing. This is the same
 * honesty rule the cursor/offset notices enforce, applied to the wire contract.
 *
 * Where it runs: `ferrogate-cli::ctl::ops_cmd::status` applied it to the
 * `/admin/v1/status` body after the response landed and before rendering
 * (`version::check_compatibility(server_version)?`, step 5 of that module's
 * documented order). In this port `ops status` is not a second client — it
 * delegates to `ctl system status` — so the gate is bound to the **operation**
 * (`getAdminStatus` / its compat alias) rather than to the `ops` entry point.
 * That is a superset of the Rust placement by exactly one invocation spelling
 * (`ferrogate ctl system status`), which reaches the identical document; a
 * gate that fired for one spelling and not the other would be the drift the
 * delegation exists to prevent.
 */
import type { JsonValue } from "@ferrogate/core";
import { CLI_VERSION } from "./action-identity.js";
import { CliError } from "./errors.js";

/**
 * Oldest Control Plane API contract version this client understands.
 *
 * Ported verbatim from the Rust constant. Bumped deliberately when a breaking
 * contract change lands, so an old server fails closed instead of returning
 * responses the client would silently mis-map.
 */
export const MIN_SUPPORTED_API_VERSION = "2026.6.0";

/** The operations whose response body carries the server's contract version. */
const VERSIONED_STATUS_OPERATIONS: readonly string[] = ["getAdminStatus", "getAdminStatusAlias"];

/** A parsed calendar version: `year.month.day`. */
export interface CalendarVersion {
  readonly year: number;
  readonly month: number;
  readonly day: number;
}

/**
 * Parse a `YYYY.M.D` string.
 *
 * A trailing pre-release/build suffix after a `-` or `+` is ignored, so
 * `2026.7.9-rc1` still parses. Everything else is a usage error: a version the
 * client cannot read is not silently treated as "probably new enough".
 */
export function parseCalendarVersion(raw: string): CalendarVersion {
  const core = (raw.split(/[-+]/)[0] ?? raw).trim();
  const parts = core.split(".");
  const field = (index: number, name: string): number => {
    const part = parts[index]?.trim();
    // `Number("")` is 0 and `Number("7abc")` is NaN; require the digits to be
    // the WHOLE component so '2026.7x.9' cannot parse as month 7.
    if (part === undefined || !/^\d+$/.test(part)) {
      throw CliError.usage(`'${raw}' is not a valid YYYY.M.D calendar version (bad ${name})`);
    }
    return Number(part);
  };
  const year = field(0, "year");
  const month = field(1, "month");
  const day = field(2, "day");
  if (parts.length > 3) {
    throw CliError.usage(`'${raw}' has too many version components; expected YYYY.M.D`);
  }
  if (month === 0 || month > 12) {
    throw CliError.usage(`'${raw}' has an out-of-range month ${month}`);
  }
  return { year, month, day };
}

/** Total order on calendar versions: negative when `left` precedes `right`. */
export function compareCalendarVersions(left: CalendarVersion, right: CalendarVersion): number {
  return left.year - right.year || left.month - right.month || left.day - right.day;
}

/** A version compatibility verdict against the Control Plane API. */
export interface CompatibilityReport {
  readonly cliVersion: string;
  readonly serverVersion: string;
  readonly minSupported: string;
  readonly compatible: true;
}

/**
 * Check whether this client can safely render responses from a server
 * reporting `serverVersion`.
 *
 * Returns a populated report on success and throws an actionable usage error
 * when the server is too old. A server NEWER than this client is compatible:
 * the contract is additive forward, and refusing there would strand operators
 * mid-upgrade.
 */
export function checkCompatibility(serverVersion: string): CompatibilityReport {
  const server = parseCalendarVersion(serverVersion);
  const minimum = parseCalendarVersion(MIN_SUPPORTED_API_VERSION);
  if (compareCalendarVersions(server, minimum) < 0) {
    throw CliError.usage(
      `Control Plane API version ${serverVersion} is older than the minimum supported ` +
        `${MIN_SUPPORTED_API_VERSION}; upgrade the server or use a matching CLI release ` +
        `(this CLI is ${CLI_VERSION})`,
    );
  }
  return {
    cliVersion: CLI_VERSION,
    serverVersion,
    minSupported: MIN_SUPPORTED_API_VERSION,
    compatible: true,
  };
}

/**
 * Apply the gate to a response body, when the operation is one that reports the
 * server's contract version.
 *
 * A body that omits `version` passes: the Rust gate was likewise conditional
 * (`if let Some(server_version) = …`), because an operator running a build that
 * predates the field must still be able to read status. What must NOT happen is
 * a *present* version being ignored.
 */
export function enforceContractVersion(operationId: string | null, body: JsonValue): void {
  if (operationId === null) return;
  if (!VERSIONED_STATUS_OPERATIONS.includes(operationId)) return;
  if (body === null || typeof body !== "object" || Array.isArray(body)) return;
  const reported = (body as Record<string, JsonValue>).version;
  if (typeof reported !== "string") return;
  checkCompatibility(reported);
}
