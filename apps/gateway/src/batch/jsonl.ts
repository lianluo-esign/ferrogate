/**
 * The JSONL wire format on both ends of a batch job (#698, slice 2).
 *
 * Input lines are the caller's; output lines are ours. Both are OpenAI's
 * shapes, and both are handled HERE rather than inside the executor so the
 * executor is about lifecycle and the parsing rules are testable without a
 * provider, a queue or a clock.
 *
 * ## Every parse failure is a LINE, not an exception
 *
 * A batch of 50,000 requests in which line 37 is malformed must still run the
 * other 49,999. OpenAI's own semantics are per-line: a bad line becomes an
 * entry in the error file and the job still completes. So {@link
 * parseBatchInputLine} returns a discriminated result and the executor turns a
 * refusal straight into an error output line. The ONLY thing that fails a whole
 * job is an input file that cannot be read at all.
 */

/** One usable input line. */
export interface BatchInputLine {
  /** Zero-based position in the file — the results table's key. */
  readonly lineIndex: number;
  /** The caller's correlation id, echoed on the output line. `""` if absent. */
  readonly customId: string;
  readonly method: string;
  readonly url: string;
  readonly body: Record<string, unknown>;
}

export type BatchInputLineResult =
  | { readonly ok: true; readonly line: BatchInputLine }
  | {
      readonly ok: false;
      readonly customId: string;
      readonly code: string;
      readonly message: string;
    };

/** The per-line error object written into the error JSONL. */
export interface BatchLineError {
  readonly code: string;
  readonly message: string;
}

function stringField(source: Record<string, unknown>, field: string): string | undefined {
  const value = source[field];
  return typeof value === "string" && value !== "" ? value : undefined;
}

/**
 * Parse one physical line.
 *
 * `endpoint` is the batch's declared endpoint. A line whose `url` names a
 * DIFFERENT endpoint is refused rather than executed: the batch's endpoint is
 * what `createBatch` validated and what the executor resolved an operation for,
 * so honouring a per-line override would let a caller smuggle an unserved (or
 * more expensive) operation past creation-time validation.
 */
export function parseBatchInputLine(
  raw: string,
  lineIndex: number,
  endpoint: string,
): BatchInputLineResult {
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw) as unknown;
  } catch (error) {
    return {
      ok: false,
      customId: "",
      code: "invalid_request",
      message: `line ${lineIndex + 1} is not valid JSON: ${
        error instanceof Error ? error.message : String(error)
      }`,
    };
  }
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    return {
      ok: false,
      customId: "",
      code: "invalid_request",
      message: `line ${lineIndex + 1} is not a JSON object`,
    };
  }
  const source = parsed as Record<string, unknown>;
  const customId = stringField(source, "custom_id") ?? "";
  const method = stringField(source, "method") ?? "POST";
  const url = stringField(source, "url") ?? endpoint;
  if (url !== endpoint) {
    return {
      ok: false,
      customId,
      code: "invalid_request",
      message: `url must be ${endpoint}, the endpoint this batch was created for`,
    };
  }
  if (method.toUpperCase() !== "POST") {
    return { ok: false, customId, code: "invalid_request", message: "method must be POST" };
  }
  const body = source.body;
  if (typeof body !== "object" || body === null || Array.isArray(body)) {
    return { ok: false, customId, code: "invalid_request", message: "body must be a JSON object" };
  }
  const model = stringField(body as Record<string, unknown>, "model");
  if (model === undefined) {
    return { ok: false, customId, code: "invalid_request", message: "body.model is required" };
  }
  return {
    ok: true,
    line: { lineIndex, customId, method, url, body: body as Record<string, unknown> },
  };
}

/**
 * Split a JSONL payload into non-empty physical lines, keeping each line's
 * ORIGINAL index.
 *
 * The index survives the filter on purpose: it is the results table's key and
 * therefore the resume cursor, so renumbering after dropping blank lines would
 * make a resumed tick re-execute paid work under a different key.
 */
export function jsonlLines(text: string): readonly { index: number; raw: string }[] {
  const out: { index: number; raw: string }[] = [];
  const physical = text.split("\n");
  for (const [index, value] of physical.entries()) {
    const raw = value.trim();
    if (raw === "") continue;
    out.push({ index, raw });
  }
  return out;
}

/** `{id, custom_id, response, error}` — one output-file line. */
export function batchOutputLine(
  batchId: string,
  lineIndex: number,
  customId: string,
  statusCode: number,
  body: unknown,
): Record<string, unknown> {
  return {
    id: `${batchId}_req_${lineIndex}`,
    custom_id: customId,
    response: { status_code: statusCode, request_id: `${batchId}_req_${lineIndex}`, body },
    error: null,
  };
}

/** `{id, custom_id, response: null, error}` — one error-file line. */
export function batchErrorLine(
  batchId: string,
  lineIndex: number,
  customId: string,
  error: BatchLineError,
): Record<string, unknown> {
  return {
    id: `${batchId}_req_${lineIndex}`,
    custom_id: customId,
    response: null,
    error: { code: error.code, message: error.message },
  };
}

/** Render output lines back to a JSONL payload, newline-terminated. */
export function renderJsonl(lines: readonly unknown[]): string {
  return lines.length === 0 ? "" : `${lines.map((line) => JSON.stringify(line)).join("\n")}\n`;
}
