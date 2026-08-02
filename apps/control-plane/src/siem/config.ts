/**
 * `SIEM_EXPORT_SINKS` — the operator's declaration of where evidence goes
 * (#683).
 *
 * ## Why configuration and not an admin collection
 *
 * A sink names a DEPLOY-TIME resource: an `env://` secret binding for its
 * credential, or an R2 bucket binding for its objects. Both resolve when the
 * Worker is deployed, so a row in `control_plane_resources` could name a
 * credential this Worker cannot reach — an admin surface that accepts a
 * configuration it cannot honour. The list is therefore a var, the same shape
 * `CONTROL_PLANE_STATIC_API_KEYS` and `TENANCY_LIFECYCLE` already use, and the
 * REPLAY control rides in it too (see {@link SiemReplay}).
 *
 * ## The two refusals this parser makes, and why they are refusals
 *
 * Everything else here is ordinary validation. These two are the security
 * boundary, and they are enforced at PARSE time rather than at call time so
 * that no code path downstream can be reached with a configuration that
 * violates them:
 *
 *  1. **A sink without a tenant does not parse.** The tenant fence is then a
 *     property of the type — `SiemSink.tenant` is a `string`, never `null` —
 *     rather than a check some future edit can forget. There is deliberately no
 *     "export everything" mode: an un-attributed `request_logs` row is a
 *     PLATFORM operator's own traffic, and handing it to a customer's SIEM is
 *     exactly the cross-tenant leak `admin_request_log.ts` fences against on
 *     the read side.
 *  2. **A credential must be a `env://` REFERENCE, never a literal.** `[vars]`
 *     in `wrangler.toml` are committed plaintext in a tracked file, so a parser
 *     that accepted an inline token would invite one into git — and a token in
 *     git is a token that has to be rotated at every consumer.
 *
 * Error messages NEVER echo the offending value, for the reason the second
 * refusal exists: the most likely bad value IS a live credential, and a
 * validation error that quoted it would print it into the operator's log.
 */
import { type EnvRef, type SecretRef, parseSecretRef } from "@ferrogate/secrets";

/** The binding name, so the drift gate and the tests read one constant. */
export const SIEM_EXPORT_SINKS_VAR = "SIEM_EXPORT_SINKS";

/** Which evidence table a delivery walks. */
export type SiemStream = "request_logs" | "audit_events";

export const SIEM_STREAMS: readonly SiemStream[] = ["request_logs", "audit_events"];

/**
 * How the credential is presented to the sink.
 *
 * Generic on purpose: Splunk HEC wants `Authorization: Splunk <token>`, Datadog
 * wants `DD-API-KEY: <key>`, a generic collector wants `Authorization: Bearer
 * <token>`. One header name plus one prefix covers all three, which is cheaper
 * than three vendor adapters that would each need their own test.
 */
export interface SiemHttpAuth {
  readonly header: string;
  readonly prefix: string;
  /**
   * ALWAYS an `env://` reference — narrowed at parse time rather than checked
   * at use time, so the "no inline secrets" refusal is carried by the type.
   */
  readonly secretRef: EnvRef;
}

export type SiemDestination =
  | { readonly kind: "http"; readonly endpoint: string; readonly auth: SiemHttpAuth | null }
  /**
   * The R2 destination — the "R2-backed pump" shape the issue names, and the
   * one a customer fronts with S3-compatible tooling. It needs no credential
   * because the bucket is a BINDING; the credential problem moves to the
   * deploy, which is where Cloudflare puts it.
   */
  | { readonly kind: "r2"; readonly prefix: string };

/**
 * A replay instruction. `epoch` is a monotonically increasing token an operator
 * bumps to ask for the rewind; the applied epoch is stored on the cursor row so
 * the same instruction cannot rewind twice.
 */
export interface SiemReplay {
  readonly epoch: number;
  readonly fromUnix: number;
}

export interface SiemSink {
  readonly id: string;
  /** NEVER null — see this module's docblock, refusal (1). */
  readonly tenant: string;
  readonly streams: readonly SiemStream[];
  readonly destination: SiemDestination;
  readonly batchSize: number;
  readonly maxBatchesPerTick: number;
  /**
   * How far behind `now` the cursor is allowed to advance, in seconds.
   *
   * `request_logs` rows are keyed on when a request STARTED and written when it
   * COMPLETED, so a slow request lands BEHIND a cursor that has already moved
   * past its timestamp — and would then never be exported, which is precisely
   * the invisible gap this feature exists to prevent. Holding the horizon back
   * gives an in-flight request time to land before the cursor passes it.
   *
   * It is not a proof: a request that runs longer than the lag can still be
   * missed. That residual is documented in `docs/siem-export.md` rather than
   * papered over, and the lag is configurable so a deployment with long
   * streaming responses can widen it.
   */
  readonly visibilityLagSeconds: number;
  /** Where a brand-new cursor starts. `0` = the whole retained history. */
  readonly startAtUnix: number;
  readonly replay: SiemReplay | null;
}

const DEFAULT_BATCH_SIZE = 500;
const MAX_BATCH_SIZE = 5_000;
const DEFAULT_MAX_BATCHES_PER_TICK = 20;
const DEFAULT_VISIBILITY_LAG_SECONDS = 60;

class SiemConfigError extends Error {
  constructor(message: string) {
    super(`SIEM_EXPORT_SINKS: ${message}`);
    this.name = "SiemConfigError";
  }
}

function requiredString(value: unknown, field: string): string {
  if (typeof value !== "string" || value.trim() === "") {
    throw new SiemConfigError(`${field} is required and must be a non-empty string`);
  }
  return value.trim();
}

function boundedInt(value: unknown, field: string, fallback: number, max: number): number {
  if (value === undefined || value === null) return fallback;
  if (typeof value !== "number" || !Number.isFinite(value) || value < 0) {
    throw new SiemConfigError(`${field} must be a non-negative number`);
  }
  const rounded = Math.floor(value);
  if (rounded > max) throw new SiemConfigError(`${field} must be <= ${max}`);
  return rounded;
}

function parseStreams(value: unknown, sinkId: string): readonly SiemStream[] {
  if (value === undefined || value === null) return SIEM_STREAMS;
  if (!Array.isArray(value) || value.length === 0) {
    throw new SiemConfigError(`sink ${sinkId}: streams must be a non-empty array`);
  }
  return value.map((entry) => {
    if (typeof entry !== "string" || !SIEM_STREAMS.includes(entry as SiemStream)) {
      throw new SiemConfigError(
        `sink ${sinkId}: unknown stream (expected one of ${SIEM_STREAMS.join(", ")})`,
      );
    }
    return entry as SiemStream;
  });
}

function parseAuth(raw: unknown, sinkId: string): SiemHttpAuth | null {
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== "object") {
    throw new SiemConfigError(`sink ${sinkId}: destination.auth must be an object`);
  }
  const record = raw as Record<string, unknown>;
  const header = requiredString(record.header, `sink ${sinkId}: destination.auth.header`);
  const prefix = record.prefix === undefined ? "" : String(record.prefix);
  const rawRef = record.secret_ref;
  if (typeof rawRef !== "string" || rawRef.trim() === "") {
    throw new SiemConfigError(`sink ${sinkId}: destination.auth.secret_ref is required`);
  }
  let secretRef: SecretRef;
  try {
    secretRef = parseSecretRef(rawRef.trim());
  } catch {
    // The VALUE is deliberately absent from this message: the most likely bad
    // value is a live credential someone pasted in.
    throw new SiemConfigError(
      `sink ${sinkId}: destination.auth.secret_ref must be a secret reference (e.g. env://SPLUNK_HEC_TOKEN), not a secret`,
    );
  }
  if (secretRef.kind !== "env") {
    throw new SiemConfigError(
      `sink ${sinkId}: destination.auth.secret_ref must be an env:// secret reference — inside a Worker every other backend arrives as a binding`,
    );
  }
  return { header, prefix, secretRef };
}

function parseDestination(raw: unknown, sinkId: string): SiemDestination {
  if (typeof raw !== "object" || raw === null) {
    throw new SiemConfigError(`sink ${sinkId}: destination is required`);
  }
  const record = raw as Record<string, unknown>;
  const kind = requiredString(record.kind, `sink ${sinkId}: destination.kind`);
  if (kind === "r2") {
    const prefix = record.prefix === undefined ? "" : String(record.prefix);
    return { kind: "r2", prefix };
  }
  if (kind !== "http") {
    throw new SiemConfigError(`sink ${sinkId}: unknown destination.kind (expected http or r2)`);
  }
  const endpoint = requiredString(record.endpoint, `sink ${sinkId}: destination.endpoint`);
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    throw new SiemConfigError(`sink ${sinkId}: destination.endpoint must be an absolute URL`);
  }
  if (url.protocol !== "https:") {
    // Evidence in flight over plaintext is evidence disclosed, and the
    // credential rides in a header on the same connection.
    throw new SiemConfigError(`sink ${sinkId}: destination.endpoint must be https`);
  }
  return { kind: "http", endpoint: url.toString(), auth: parseAuth(record.auth, sinkId) };
}

function parseReplay(raw: unknown, sinkId: string): SiemReplay | null {
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== "object") {
    throw new SiemConfigError(`sink ${sinkId}: replay must be an object`);
  }
  const record = raw as Record<string, unknown>;
  const epoch = boundedInt(
    record.epoch,
    `sink ${sinkId}: replay.epoch`,
    0,
    Number.MAX_SAFE_INTEGER,
  );
  if (epoch <= 0) {
    throw new SiemConfigError(`sink ${sinkId}: replay.epoch must be a positive integer`);
  }
  const fromUnix = boundedInt(
    record.from_unix,
    `sink ${sinkId}: replay.from_unix`,
    0,
    Number.MAX_SAFE_INTEGER,
  );
  return { epoch, fromUnix };
}

/**
 * Parse the declaration. THROWS on anything malformed — deliberately, unlike
 * the key-material vars in `adapters.ts`, which fall back to an empty list.
 *
 * The asymmetry is the direction each failure fails in. An unparseable key list
 * that falls back to "no keys" fails CLOSED: every request is rejected. An
 * unparseable sink list that fell back to "no sinks" would fail SILENTLY —
 * evidence would simply stop flowing, and the destination cannot tell "nothing
 * happened" from "the exporter is misconfigured". The caller catches this and
 * reports it on the tick, where an operator sees it.
 */
export function parseSiemSinks(raw: string | undefined): readonly SiemSink[] {
  if (raw === undefined || raw.trim() === "") return [];
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new SiemConfigError("is not valid JSON");
  }
  if (!Array.isArray(parsed)) throw new SiemConfigError("must be a JSON array of sinks");

  const seen = new Set<string>();
  return parsed.map((entry) => {
    if (typeof entry !== "object" || entry === null) {
      throw new SiemConfigError("every sink must be an object");
    }
    const record = entry as Record<string, unknown>;
    const id = requiredString(record.id, "sink id");
    if (seen.has(id)) {
      // Two sinks with one id would share a cursor row and each would advance
      // past the other's undelivered rows.
      throw new SiemConfigError(`duplicate sink id ${JSON.stringify(id)}`);
    }
    seen.add(id);
    // Refusal (1): no tenant, no sink. See the module docblock.
    const tenant = requiredString(record.tenant, `sink ${id}: tenant`);
    return {
      id,
      tenant,
      streams: parseStreams(record.streams, id),
      destination: parseDestination(record.destination, id),
      batchSize: Math.max(
        1,
        boundedInt(record.batch_size, `sink ${id}: batch_size`, DEFAULT_BATCH_SIZE, MAX_BATCH_SIZE),
      ),
      maxBatchesPerTick: Math.max(
        1,
        boundedInt(
          record.max_batches_per_tick,
          `sink ${id}: max_batches_per_tick`,
          DEFAULT_MAX_BATCHES_PER_TICK,
          1_000,
        ),
      ),
      visibilityLagSeconds: boundedInt(
        record.visibility_lag_seconds,
        `sink ${id}: visibility_lag_seconds`,
        DEFAULT_VISIBILITY_LAG_SECONDS,
        86_400,
      ),
      startAtUnix: boundedInt(
        record.start_at_unix,
        `sink ${id}: start_at_unix`,
        0,
        Number.MAX_SAFE_INTEGER,
      ),
      replay: parseReplay(record.replay, id),
    };
  });
}
