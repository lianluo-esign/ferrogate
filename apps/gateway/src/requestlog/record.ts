/**
 * The durable per-decision evidence record, and the wire form it travels in.
 *
 * ## What a request log is FOR, and why that shapes this type
 *
 * `GET /admin/v1/request-logs` answered `200 []` on every deployment because
 * nothing in `apps/<app>/src` ever wrote a row (#664). Two different people are
 * hurt by that and they want the same record: an operator debugging one bad
 * response, and an auditor asking what the system did — EU AI Act Art. 12/72
 * record-keeping for high-risk systems is per DECISION, not per report.
 *
 * So the record is one row per REQUEST, not per provider call and not per
 * metering event, and it exists for a request that was refused before it ever
 * reached a provider. A trail that only records successful inference is a trail
 * in which every interesting failure is invisible.
 *
 * ## Every field is either always known, or explicitly absent
 *
 * There is no field here that the gateway fabricates. `tenantId` is the
 * AUTHENTICATED tenant off the credential, never a client-declared header;
 * `logicalModel` is the model the router resolved, not the string in the body;
 * an absent token count means the provider reported none, which is the honest
 * answer for a request that was blocked, cached or errored. A column filled
 * with a plausible default is worse than a null: it is evidence of something
 * that did not happen.
 */

/**
 * What guardrail screening decided about this request.
 *
 * Three values, and the third is the one that matters. `not_screened` is NOT a
 * synonym for `allowed`: it means no guardrail policy was evaluated at all
 * (the operation is not guardrail-bound, or the body could not be parsed and
 * the downstream reader owns the 400/413). An auditor reading `allowed` on a
 * request that was never screened would conclude a control ran when it did
 * not, which is the exact defect shape this codebase keeps finding.
 */
export type GuardrailVerdict = "allowed" | "blocked" | "not_screened";

/** One durable request-log row, in the gateway's own vocabulary. */
export interface RequestLogRecord {
  /** The id the CLIENT was told (`x-request-id`), so a report can be joined. */
  readonly requestId: string;
  /** The W3C trace id, adopted from a valid inbound `traceparent` when present. */
  readonly traceId?: string | undefined;
  /** `#305/#522` — the agent run this request belongs to. */
  readonly agentRunId?: string | undefined;
  /**
   * `#691` — the whole VERIFIED delegation chain
   * (`user:u_1>agent:planner>agent:writer`), and its root principal split out
   * as its own field.
   *
   * Both, rather than one: an auditor asks "who was involved" and wants the
   * path, finance asks "whose spend is this" and wants an equality predicate.
   * Answering the second by prefix-matching the first would be a scan, and
   * would answer wrongly for any principal that is a prefix of another.
   *
   * Absent for an undelegated request, which is most of them — and absent, not
   * blank: "nobody delegated" and "we did not look" must stay distinguishable.
   */
  readonly delegationChain?: string | undefined;
  readonly delegationRoot?: string | undefined;
  readonly tenantId?: string | undefined;
  readonly projectId?: string | undefined;
  readonly workspaceId?: string | undefined;
  /** The credential that made the call, for per-key attribution and revocation. */
  readonly apiKeyId?: string | undefined;
  /** The contract `operation_id` (`createChatCompletion`, `pushAsset`, …). */
  readonly operationId?: string | undefined;
  readonly method: string;
  /** The CANONICAL path, so two spellings of one operation are one series. */
  readonly path: string;
  /** The provider route label (`openai.chat.completions`), when one was chosen. */
  readonly route?: string | undefined;
  readonly provider?: string | undefined;
  /** The model the CALLER named, after resolution. */
  readonly logicalModel?: string | undefined;
  /** The model the PROVIDER was actually asked for — the two differ, and both matter. */
  readonly providerModel?: string | undefined;
  readonly statusCode: number;
  /** The FerroGate error `code` for a refusal, when the body carried one. */
  readonly errorCode?: string | undefined;
  /** `x-ferrogate-cache` (`hit` / `miss` / `bypass` / …), verbatim. */
  readonly cacheStatus?: string | undefined;
  readonly startedAtUnix: number;
  readonly completedAtUnix: number;
  readonly latencyMs: number;
  readonly promptTokens?: number | undefined;
  readonly completionTokens?: number | undefined;
  readonly totalTokens?: number | undefined;
  readonly guardrailVerdict: GuardrailVerdict;
  /** The rule id of the policy that blocked, for `blocked` verdicts. */
  readonly guardrailPolicyId?: string | undefined;
  readonly streamed: boolean;
  /** Rust `ProviderAttempt.index` (#135) — which dispatch attempt served this. */
  readonly providerAttemptIndex?: number | undefined;
}

/**
 * The Queue message body / D1 `request_json` document — snake_case, JSON-safe.
 *
 * Deliberately a FLAT record of primitives. A Queue body is structured-clone
 * encoded and a D1 column is text, so anything that is not a string, number,
 * boolean or null has to be decided about at both ends; keeping the wire flat
 * means a consumer written against this shape cannot be surprised by a nested
 * object appearing in one deployment and not another.
 *
 * Absent optional fields are OMITTED rather than sent as `null`, so the
 * document half of the row stays small (a request log is written on every
 * request, at gateway volume) and so "the writer did not know" and "the writer
 * knew it was nothing" stay distinguishable.
 */
export type RequestLogWire = Record<string, string | number | boolean>;

/** `object` on the wire and in the stored document, matching the admin reader. */
export const REQUEST_LOG_OBJECT = "request_log";

function put(out: RequestLogWire, key: string, value: string | number | boolean | undefined): void {
  if (value === undefined) return;
  // A blank string is the same "nothing" a missing field is, and storing it
  // would make `WHERE provider IS NOT NULL` lie.
  if (typeof value === "string" && value === "") return;
  out[key] = value;
}

/** Encode a record for the Queue and for `request_logs.request_json`. */
export function requestLogToWire(record: RequestLogRecord): RequestLogWire {
  const wire: RequestLogWire = {
    object: REQUEST_LOG_OBJECT,
    request_id: record.requestId,
    method: record.method,
    path: record.path,
    status_code: record.statusCode,
    started_at_unix: record.startedAtUnix,
    completed_at_unix: record.completedAtUnix,
    latency_ms: record.latencyMs,
    guardrail_verdict: record.guardrailVerdict,
    streamed: record.streamed,
  };
  put(wire, "trace_id", record.traceId);
  put(wire, "agent_run_id", record.agentRunId);
  put(wire, "delegation_chain", record.delegationChain);
  put(wire, "delegation_root", record.delegationRoot);
  put(wire, "tenant_id", record.tenantId);
  put(wire, "project_id", record.projectId);
  put(wire, "workspace_id", record.workspaceId);
  put(wire, "api_key_id", record.apiKeyId);
  put(wire, "operation_id", record.operationId);
  put(wire, "route", record.route);
  put(wire, "provider", record.provider);
  put(wire, "logical_model", record.logicalModel);
  put(wire, "provider_model", record.providerModel);
  put(wire, "error_code", record.errorCode);
  put(wire, "cache_status", record.cacheStatus);
  put(wire, "prompt_tokens", record.promptTokens);
  put(wire, "completion_tokens", record.completionTokens);
  put(wire, "total_tokens", record.totalTokens);
  put(wire, "guardrail_policy_id", record.guardrailPolicyId);
  put(wire, "provider_attempt_index", record.providerAttemptIndex);
  return wire;
}

function str(wire: RequestLogWire, key: string): string | undefined {
  const value = wire[key];
  return typeof value === "string" && value !== "" ? value : undefined;
}

function num(wire: RequestLogWire, key: string): number | undefined {
  const value = wire[key];
  return typeof value === "number" && Number.isFinite(value) ? value : undefined;
}

function verdictOf(wire: RequestLogWire): GuardrailVerdict {
  const value = wire["guardrail_verdict"];
  return value === "allowed" || value === "blocked" ? value : "not_screened";
}

/**
 * Decode a wire body back into a record — the Queue CONSUMER's entry point.
 *
 * Total, never throwing: a Queue delivers at least once and a malformed body
 * would otherwise poison a whole batch of good evidence. A message missing the
 * fields that make a row addressable (`request_id`, the timestamps) is rejected
 * by returning `undefined`, because a row keyed on `""` would collide every
 * such message onto one another under the primary key — silently collapsing
 * many decisions into one, which is worse than dropping them visibly.
 *
 * An unrecognised `guardrail_verdict` degrades to `not_screened`, never to
 * `allowed`: an unreadable verdict must not be recorded as a control having
 * passed.
 */
export function requestLogFromWire(body: unknown): RequestLogRecord | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const wire = body as RequestLogWire;
  const requestId = str(wire, "request_id");
  const startedAtUnix = num(wire, "started_at_unix");
  if (requestId === undefined || startedAtUnix === undefined) return undefined;
  const completedAtUnix = num(wire, "completed_at_unix") ?? startedAtUnix;
  return {
    requestId,
    method: str(wire, "method") ?? "",
    path: str(wire, "path") ?? "",
    statusCode: num(wire, "status_code") ?? 0,
    startedAtUnix,
    completedAtUnix,
    latencyMs: num(wire, "latency_ms") ?? Math.max((completedAtUnix - startedAtUnix) * 1000, 0),
    guardrailVerdict: verdictOf(wire),
    streamed: wire["streamed"] === true,
    traceId: str(wire, "trace_id"),
    agentRunId: str(wire, "agent_run_id"),
    delegationChain: str(wire, "delegation_chain"),
    delegationRoot: str(wire, "delegation_root"),
    tenantId: str(wire, "tenant_id"),
    projectId: str(wire, "project_id"),
    workspaceId: str(wire, "workspace_id"),
    apiKeyId: str(wire, "api_key_id"),
    operationId: str(wire, "operation_id"),
    route: str(wire, "route"),
    provider: str(wire, "provider"),
    logicalModel: str(wire, "logical_model"),
    providerModel: str(wire, "provider_model"),
    errorCode: str(wire, "error_code"),
    cacheStatus: str(wire, "cache_status"),
    promptTokens: num(wire, "prompt_tokens"),
    completionTokens: num(wire, "completion_tokens"),
    totalTokens: num(wire, "total_tokens"),
    guardrailPolicyId: str(wire, "guardrail_policy_id"),
    providerAttemptIndex: num(wire, "provider_attempt_index"),
  };
}
