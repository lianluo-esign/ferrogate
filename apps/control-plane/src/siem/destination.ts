/**
 * The write side of the SIEM pump (#683): hand one batch to the customer's
 * sink, and either return normally (ACKNOWLEDGED) or throw (NOT acknowledged).
 *
 * That binary is the entire contract with `pump.ts`, and it is why nothing here
 * is allowed to be clever about partial success: the cursor advances if and
 * only if these functions return, so anything ambiguous MUST throw. Re-sending
 * a batch the sink already stored is a duplicate the destination can
 * de-duplicate on the row id; a cursor advanced past a batch the sink never
 * stored is a hole nobody can see.
 *
 * ## Credentials
 *
 * The resolved credential exists in exactly two places: the `Authorization`-
 * style header of the outbound request, and the {@link redactSecrets} filter
 * every error message passes through. It is deliberately NOT put into the error
 * path by any other route — in particular the sink's RESPONSE BODY is never
 * read, because real HEC and collector endpoints echo the presented token back
 * in their 401 text ("Invalid token: …"), and a pump that pasted that body into
 * its error message would write the customer's credential into the operator's
 * log on every misconfiguration.
 */
import { type EnvLike, EnvSecretResolver } from "@ferrogate/secrets";
import type { ControlPlaneBindings } from "../ports.js";
import type { SiemDestination, SiemSink, SiemStream } from "./config.js";
import type { SiemCursorPosition } from "./cursor.js";

/** Key prefix for every exported object. Versioned, so a format change is a new tree. */
export const SIEM_EXPORT_PREFIX = "siem-exports/v1/";

/** A delivery that did not happen. The message NEVER carries a credential. */
export class SiemDeliveryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "SiemDeliveryError";
  }
}

/**
 * Remove every known credential from a string.
 *
 * Defence in depth rather than the primary control — the primary control is
 * that no message is ever built from material that could contain one. This
 * exists because "no message is ever built from…" is a claim about all future
 * edits to this file, and a thrown `TypeError` from a runtime we do not own
 * could carry a request header into a stack trace without anyone deciding to.
 */
export function redactSecrets(text: string, secrets: readonly string[]): string {
  let out = text;
  for (const secret of secrets) {
    if (secret.length >= 4) out = out.split(secret).join("[redacted]");
  }
  return out;
}

/** What one batch needs in order to be addressable in the destination. */
export interface SiemBatchRef {
  readonly sink: SiemSink;
  readonly stream: SiemStream;
  /** The position of the LAST row in the batch — the batch's identity. */
  readonly position: SiemCursorPosition;
}

/**
 * `siem-exports/v1/<sink prefix><sink id>/<stream>/<zero-padded ts>-<id>.jsonl`
 *
 * DERIVED FROM THE BATCH, not from the wall clock, and that is the point: a
 * re-delivery of the same window after a crash writes the SAME object rather
 * than a near-duplicate beside it. At-least-once then costs the customer one
 * overwrite instead of an ever-growing pile of files they have to reconcile.
 *
 * The timestamp is zero-padded to 20 digits so R2's lexical `list` order IS
 * chronological order — a consumer walking the bucket oldest-first needs no
 * sort — and the row id is percent-encoded so an id containing `/` cannot
 * invent directory levels or collide with another object's key.
 */
export function siemObjectKey(ref: SiemBatchRef): string {
  const padded = String(Math.max(0, ref.position.ts)).padStart(20, "0");
  const prefix = ref.sink.destination.kind === "r2" ? ref.sink.destination.prefix : "";
  return (
    `${SIEM_EXPORT_PREFIX}${prefix}${encodeURIComponent(ref.sink.id)}/${ref.stream}/` +
    `${padded}-${encodeURIComponent(ref.position.id)}.jsonl`
  );
}

/**
 * A batch id the sink can de-duplicate on, sent as a header.
 *
 * At-least-once means a well-behaved sink WILL occasionally see the same batch
 * twice. Giving it a stable name for the batch is what turns that from "the
 * customer's dashboards double-count" into "the customer's collector drops a
 * repeat" — and it costs one header.
 */
export function siemBatchId(ref: SiemBatchRef): string {
  return `${ref.sink.id}:${ref.stream}:${ref.position.ts}:${ref.position.id}`;
}

/**
 * Resolve the sink's credential, or `null` when the destination needs none.
 *
 * Throws when the reference resolves to nothing: an unset secret is a
 * MISCONFIGURATION, and delivering the batch without the header would either be
 * rejected by the sink or — much worse on a permissive collector — accepted
 * unauthenticated. Failing here leaves the cursor where it is, so the rows are
 * still there to deliver once the operator provisions the secret.
 */
export async function resolveSinkCredential(
  destination: SiemDestination,
  env: ControlPlaneBindings,
): Promise<string | null> {
  if (destination.kind !== "http" || destination.auth === null) return null;
  const resolver = new EnvSecretResolver(env as unknown as EnvLike);
  const value = await resolver.resolve(destination.auth.secretRef);
  if (value === null || value === "") {
    // Names the REFERENCE, never the value — the reference is a variable name,
    // which is exactly the actionable half.
    throw new SiemDeliveryError(
      `sink credential env://${destination.auth.secretRef.name} is unset`,
    );
  }
  return value;
}

/** JSON Lines, one complete record per line, trailing newline. */
export function encodeNdjson(documents: readonly unknown[]): string {
  return documents
    .map((document) => JSON.stringify(document))
    .join("\n")
    .concat("\n");
}

/**
 * POST the batch to the customer's collector.
 *
 * Any non-2xx throws. `fetch` rejecting (connection reset, DNS, TLS) throws
 * too, and is treated identically — the sink may well have STORED the batch
 * before the connection died, which is precisely the case at-least-once exists
 * for.
 */
async function deliverHttp(
  endpoint: string,
  auth: { header: string; prefix: string } | null,
  credential: string | null,
  body: string,
  ref: SiemBatchRef,
): Promise<void> {
  const headers: Record<string, string> = {
    "content-type": "application/x-ndjson; charset=utf-8",
    "x-ferrogate-batch-id": siemBatchId(ref),
    "x-ferrogate-stream": ref.stream,
  };
  if (auth !== null && credential !== null) headers[auth.header] = `${auth.prefix}${credential}`;

  let response: Response;
  try {
    response = await fetch(endpoint, { method: "POST", headers, body });
  } catch (error) {
    // The endpoint URL is deliberately absent: some collectors carry a token in
    // their path or query string, so the URL is credential-bearing material.
    throw new SiemDeliveryError(
      `transport failed before an acknowledgement: ${error instanceof Error ? error.name : "unknown error"}`,
    );
  }
  if (!response.ok) {
    // Status only. The BODY is never read — see the module docblock.
    throw new SiemDeliveryError(`sink answered HTTP ${response.status}, batch not acknowledged`);
  }
}

/** Write the batch as one immutable-ish object in the export bucket. */
async function deliverR2(bucket: R2Bucket | null, body: string, ref: SiemBatchRef): Promise<void> {
  if (bucket === null) {
    throw new SiemDeliveryError(
      "no SIEM_EXPORTS R2 bucket is bound; an r2 sink cannot deliver on this deployment",
    );
  }
  await bucket.put(siemObjectKey(ref), body, {
    httpMetadata: { contentType: "application/x-ndjson; charset=utf-8" },
    customMetadata: {
      // Enough for a customer to reconcile an object against this platform's
      // own cursor without opening it. No credential, no request content.
      sink: ref.sink.id,
      stream: ref.stream,
      tenant: ref.sink.tenant,
      batch_id: siemBatchId(ref),
    },
  });
}

/**
 * Deliver one batch. Returns on acknowledgement, throws otherwise.
 *
 * `credential` is passed in rather than resolved here so that the pump resolves
 * it ONCE per stream instead of once per batch, and so that the value's
 * lifetime is visible at exactly one call site.
 */
export async function deliverSiemBatch(
  sink: SiemSink,
  ref: SiemBatchRef,
  documents: readonly unknown[],
  context: { readonly credential: string | null; readonly bucket: R2Bucket | null },
): Promise<void> {
  const body = encodeNdjson(documents);
  if (sink.destination.kind === "r2") {
    await deliverR2(context.bucket, body, ref);
    return;
  }
  await deliverHttp(
    sink.destination.endpoint,
    sink.destination.auth,
    context.credential,
    body,
    ref,
  );
}
