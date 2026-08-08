/**
 * Provider-NATIVE batch passthrough (#698, slice 3) — the ~50% discount leg.
 *
 * ```
 *   executor tick
 *     ├── nativeBatchFamilyFor(route)  → null ⇒ run the lines ourselves
 *     └── submit()  POST  {baseUrl}/batches            (openai family)
 *                   POST  {baseUrl}/messages/batches   (anthropic family)
 *         poll()    GET   …/{provider_batch_id}
 *         collect() GET   the provider's own results file / results stream
 * ```
 *
 * ## Why this is NOT a new `InferenceOperation` member
 *
 * The obvious place to put "build a batch request for this provider" is the
 * adapter registry, beside `chat.completions`. It was rejected. Adding a member
 * to the `InferenceOperation` union breaks SEVEN exhaustive switches in
 * `inference/adapters.ts` (the label map plus one per family), the
 * `ModelCapability` table in `@ferrogate/providers`, and the family-totality
 * test — for a capability exactly TWO of the nine families have. Every other
 * family would gain a `case "batches": return unsupported` arm whose only
 * purpose is to keep a switch total.
 *
 * So the knowledge lives here, keyed off `PhysicalRoute.providerKind`, and a
 * family that is not in {@link NATIVE_BATCH_FAMILIES} simply falls through to
 * the local executor. Adding a third family is one entry in one table.
 *
 * ## Governance is NOT weaker on this path — it is applied EARLIER
 *
 * This is the leg where it would be easiest to get the issue wrong. Handing a
 * whole JSONL file to OpenAI means the gateway never sees the individual calls,
 * so there is no per-line seam to gate. The answer is that the SAME gates run,
 * just at submission rather than per line:
 *
 *  - the residency gate (`admitRoute`) runs against the resolved route BEFORE
 *    a single byte of the tenant's prompts leaves for the provider — which is
 *    strictly stronger than the local path, where it also runs but per line;
 *  - the budget/wallet gate (`admitSpend`) runs before submission, and again on
 *    every poll tick, so a job whose tenant runs out of budget mid-flight is
 *    CANCELLED at the provider rather than allowed to finish;
 *  - metering is per line as usual, from the usage the provider reports on each
 *    result, with {@link NATIVE_BATCH_COST_MULTIPLIER} applied — the discount is
 *    passed through to the tenant's ledger instead of being pocketed.
 *
 * What IS weaker, stated plainly: per-line residency cannot be re-evaluated
 * once a job is with the provider, and a policy change mid-flight is honoured
 * only at the next poll (by cancelling), not retroactively.
 */
import type { PhysicalRoute } from "../inference/ports.js";

/**
 * The provider families that expose a batch endpoint of their own.
 *
 * Keyed on `PhysicalRoute.providerKind`, the same string
 * `defaultAdapterRegistry.adapterFor` dispatches on. `azure-openai` is
 * deliberately ABSENT even though Azure hosts OpenAI models: its batch surface
 * is deployment-scoped and versioned by `api-version`, so submitting to it with
 * the OpenAI shape would 404 at deploy time rather than fail a test.
 */
export const NATIVE_BATCH_FAMILIES = {
  "openai-compatible": "openai",
  anthropic: "anthropic",
} as const satisfies Record<string, NativeBatchFamily>;

export type NativeBatchFamily = "openai" | "anthropic";

/**
 * The fraction of the synchronous price a native batch is billed at.
 *
 * Both vendors advertise 50% off the equivalent synchronous call. It is applied
 * to the SETTLED cost rather than to the reported token counts: halving tokens
 * would corrupt every usage rollup and every quota that reads them, and the
 * tenant's dashboard would under-report what its models actually consumed.
 */
export const NATIVE_BATCH_COST_MULTIPLIER = 0.5;

/** The family this route can run natively, or `null` for the local path. */
export function nativeBatchFamilyFor(route: PhysicalRoute): NativeBatchFamily | null {
  const family = (NATIVE_BATCH_FAMILIES as Record<string, NativeBatchFamily | undefined>)[
    route.providerKind
  ];
  if (family === undefined) return null;
  // Anthropic's message-batches endpoint takes `/v1/messages` bodies only, and
  // this gateway's batch surface accepts chat/embeddings shapes. A route with
  // no credential cannot be dialled at all.
  if (route.apiKey === undefined || route.apiKey === "") return null;
  return family;
}

/** Is this batch endpoint expressible on that family's native surface? */
export function nativeBatchSupportsEndpoint(family: NativeBatchFamily, endpoint: string): boolean {
  if (family === "openai") {
    return endpoint === "/v1/chat/completions" || endpoint === "/v1/embeddings";
  }
  // Anthropic's batch API is `/v1/messages` only. `/v1/embeddings` has no
  // Anthropic equivalent at all, and a chat body would need the full
  // OpenAI→Anthropic translation applied per line before submission, which is
  // #886's surface and not wired through here. Falling back to the local
  // executor is correct and loses only the discount.
  return false;
}

// ---------------------------------------------------------------------------
// The wire calls
// ---------------------------------------------------------------------------

/** What a native submission needs, independent of transport. */
export interface NativeBatchSubmission {
  readonly family: NativeBatchFamily;
  readonly route: PhysicalRoute;
  /** The batch's endpoint, e.g. `/v1/chat/completions`. */
  readonly endpoint: string;
  /** The provider-side file id holding the input JSONL. */
  readonly inputFileId: string;
  readonly completionWindow: string;
}

export type NativeBatchOutcome =
  | { readonly ok: true; readonly providerBatchId: string }
  | { readonly ok: false; readonly code: string; readonly message: string };

/** Provider batch state, normalized onto our own vocabulary. */
export type NativeBatchState = "in_progress" | "completed" | "failed" | "cancelled";

export interface NativeBatchStatus {
  readonly state: NativeBatchState;
  /** The provider's own output file id, when it has published one. */
  readonly outputFileId?: string | undefined;
  readonly errorFileId?: string | undefined;
  readonly detail?: string | undefined;
}

/** The HTTP seam. Tests replace it; production hands it `fetch`. */
export type NativeBatchFetch = (input: string, init: RequestInit) => Promise<Response>;

function authHeaders(family: NativeBatchFamily, route: PhysicalRoute): Record<string, string> {
  const apiKey = route.apiKey ?? "";
  if (family === "anthropic") {
    return {
      "content-type": "application/json",
      "x-api-key": apiKey,
      "anthropic-version": "2023-06-01",
    };
  }
  return { "content-type": "application/json", authorization: `Bearer ${apiKey}` };
}

function batchesUrl(family: NativeBatchFamily, route: PhysicalRoute, suffix = ""): string {
  const base = route.baseUrl.replace(/\/+$/, "");
  const path = family === "anthropic" ? "/messages/batches" : "/batches";
  return `${base}${path}${suffix}`;
}

/** Normalize a provider status payload onto {@link NativeBatchStatus}. */
export function nativeBatchStatusFrom(
  family: NativeBatchFamily,
  payload: unknown,
): NativeBatchStatus | undefined {
  if (typeof payload !== "object" || payload === null) return undefined;
  const source = payload as Record<string, unknown>;
  if (family === "anthropic") {
    const processing = source.processing_status;
    if (processing === "in_progress") return { state: "in_progress" };
    if (processing === "canceling") return { state: "in_progress" };
    if (processing === "ended") {
      const results = source.results_url;
      return {
        state: "completed",
        outputFileId: typeof results === "string" ? results : undefined,
      };
    }
    return undefined;
  }
  const status = source.status;
  if (typeof status !== "string") return undefined;
  const outputFileId =
    typeof source.output_file_id === "string" ? source.output_file_id : undefined;
  const errorFileId = typeof source.error_file_id === "string" ? source.error_file_id : undefined;
  switch (status) {
    case "validating":
    case "in_progress":
    case "finalizing":
      return { state: "in_progress" };
    case "completed":
      return { state: "completed", outputFileId, errorFileId };
    case "cancelled":
    case "cancelling":
      return { state: "cancelled" };
    default:
      // `failed`, `expired`, and anything a vendor adds later. Treating an
      // UNKNOWN status as failed rather than as in_progress is deliberate: an
      // unrecognised terminal state that we poll forever is a job that never
      // finishes and a lease that never frees.
      return { state: "failed", errorFileId, detail: status };
  }
}

/**
 * Stage the input JSONL on the PROVIDER's Files API and return its file id.
 *
 * The tenant's input file lives in our asset store, which OpenAI cannot read,
 * so a native submission is a two-step: upload, then submit the upload's id.
 * The bytes are the tenant's own input verbatim — nothing is rewritten — which
 * is what makes the discount available without changing what was asked for.
 */
export async function uploadNativeBatchInput(
  family: NativeBatchFamily,
  route: PhysicalRoute,
  bytes: Uint8Array,
  http: NativeBatchFetch,
  timeoutMs: number,
): Promise<{ ok: true; fileId: string } | { ok: false; code: string; message: string }> {
  if (family !== "openai") {
    return { ok: false, code: "unsupported", message: `${family} has no batch input upload` };
  }
  const form = new FormData();
  form.set("purpose", "batch");
  form.set("file", new Blob([bytes], { type: "application/jsonl" }), "batch_input.jsonl");
  const base = route.baseUrl.replace(/\/+$/, "");
  let response: Response;
  try {
    response = await http(`${base}/files`, {
      method: "POST",
      // No `content-type`: `fetch` sets the multipart boundary itself, and
      // setting it by hand produces a body the provider cannot parse.
      headers: { authorization: `Bearer ${route.apiKey ?? ""}` },
      body: form,
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (error) {
    return {
      ok: false,
      code: "provider_unavailable",
      message: `native batch input upload failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    };
  }
  if (response.status < 200 || response.status >= 300) {
    await response.body?.cancel();
    return {
      ok: false,
      code: "provider_error",
      message: `native batch input upload refused with status ${response.status}`,
    };
  }
  let payload: unknown;
  try {
    payload = (await response.json()) as unknown;
  } catch {
    return { ok: false, code: "provider_error", message: "input upload returned no JSON" };
  }
  const id = (payload as { id?: unknown } | null)?.id;
  if (typeof id !== "string" || id === "") {
    return { ok: false, code: "provider_error", message: "input upload returned no file id" };
  }
  return { ok: true, fileId: id };
}

/**
 * Read a finished job's output back from the provider.
 *
 * `undefined` rather than a throw on failure, for the same reason
 * {@link pollNativeBatch} returns `undefined`: the provider still holds the
 * results, so the right response to an unreadable download is to try again on
 * the next tick, not to fail a job that succeeded upstream.
 */
export async function downloadNativeBatchOutput(
  family: NativeBatchFamily,
  route: PhysicalRoute,
  reference: string,
  http: NativeBatchFetch,
  timeoutMs: number,
  maxBytes: number,
): Promise<string | undefined> {
  const base = route.baseUrl.replace(/\/+$/, "");
  // Anthropic hands back an absolute `results_url`; OpenAI hands back a file id
  // that has to be turned into a Files-API content path.
  const url = reference.startsWith("http")
    ? reference
    : `${base}/files/${encodeURIComponent(reference)}/content`;
  let response: Response;
  try {
    response = await http(url, {
      method: "GET",
      headers: authHeaders(family, route),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    return undefined;
  }
  if (response.status < 200 || response.status >= 300) {
    await response.body?.cancel();
    return undefined;
  }
  const text = await response.text();
  // BOUNDED, because the provider decides this length and a Worker has a fixed
  // memory ceiling. A truncated read is refused outright rather than parsed:
  // half a JSONL file would publish a partial output as if it were complete.
  return text.length > maxBytes ? undefined : text;
}

/** Submit the job to the provider's own batch endpoint. */
export async function submitNativeBatch(
  submission: NativeBatchSubmission,
  http: NativeBatchFetch,
  timeoutMs: number,
): Promise<NativeBatchOutcome> {
  const { family, route } = submission;
  if (family !== "openai") {
    // REFUSED, not "submitted empty". The anthropic arm used to build
    // `{ requests: [] }`, and the only thing keeping that unreachable was
    // `nativeBatchSupportsEndpoint` returning false — which the docblock above
    // invites a future slice to flip ("adding a third family is one entry in
    // one table"). Flipping it would have POSTed an empty batch to Anthropic,
    // taken back a real batch id, persisted it and later reported `completed`
    // for a job whose input was never sent. A family with no submission body is
    // a refusal, which the executor treats as retryable and the Cron surfaces
    // rather than silently completing.
    return {
      ok: false,
      code: "unsupported",
      message: `${family} has no native batch submission; run the job on the local executor`,
    };
  }
  const body = {
    input_file_id: submission.inputFileId,
    endpoint: submission.endpoint,
    completion_window: submission.completionWindow,
  };
  let response: Response;
  try {
    response = await http(batchesUrl(family, route), {
      method: "POST",
      headers: authHeaders(family, route),
      body: JSON.stringify(body),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (error) {
    return {
      ok: false,
      code: "provider_unavailable",
      message: `native batch submission failed: ${
        error instanceof Error ? error.message : String(error)
      }`,
    };
  }
  if (response.status < 200 || response.status >= 300) {
    await response.body?.cancel();
    return {
      ok: false,
      code: "provider_error",
      message: `native batch submission refused with status ${response.status}`,
    };
  }
  let payload: unknown;
  try {
    payload = (await response.json()) as unknown;
  } catch (error) {
    return {
      ok: false,
      code: "provider_error",
      message: `native batch submission returned an unreadable body: ${
        error instanceof Error ? error.message : String(error)
      }`,
    };
  }
  const id = (payload as { id?: unknown } | null)?.id;
  if (typeof id !== "string" || id === "") {
    return { ok: false, code: "provider_error", message: "native batch response carried no id" };
  }
  return { ok: true, providerBatchId: id };
}

/** Poll a submitted job. `undefined` = the reading failed; try again later. */
export async function pollNativeBatch(
  family: NativeBatchFamily,
  route: PhysicalRoute,
  providerBatchId: string,
  http: NativeBatchFetch,
  timeoutMs: number,
): Promise<NativeBatchStatus | undefined> {
  let response: Response;
  try {
    response = await http(batchesUrl(family, route, `/${encodeURIComponent(providerBatchId)}`), {
      method: "GET",
      headers: authHeaders(family, route),
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch {
    // A transport failure is NOT a job failure. The lease expires, the next
    // tick polls again, and the provider is still holding the work.
    return undefined;
  }
  if (response.status < 200 || response.status >= 300) {
    await response.body?.cancel();
    return undefined;
  }
  let payload: unknown;
  try {
    payload = (await response.json()) as unknown;
  } catch {
    return undefined;
  }
  return nativeBatchStatusFrom(family, payload);
}

/** Ask the provider to cancel a job we are no longer allowed to run. */
export async function cancelNativeBatch(
  family: NativeBatchFamily,
  route: PhysicalRoute,
  providerBatchId: string,
  http: NativeBatchFetch,
  timeoutMs: number,
): Promise<void> {
  try {
    const response = await http(
      batchesUrl(family, route, `/${encodeURIComponent(providerBatchId)}/cancel`),
      {
        method: "POST",
        headers: authHeaders(family, route),
        signal: AbortSignal.timeout(timeoutMs),
      },
    );
    await response.body?.cancel();
  } catch {
    // Best effort by construction: the local row is already terminal, and a
    // provider that will not accept the cancellation will finish the job and
    // bill for it either way. Throwing here would only fail the tick that has
    // already recorded the right local state.
  }
}
