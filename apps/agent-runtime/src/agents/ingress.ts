/**
 * The A2A agent ingress: `POST /v1/agents/{name}`,
 * `POST /v1/agents/{name}/message:send`, `POST /v1/agents/{name}/message:stream`.
 *
 * Clean-room port of
 * `crates/ferrogate-gateway/src/server/local.rs::handle_agent_ingress` and
 * `server/a2a.rs` (issue #278: "A2A ingress deep governance"). The point of
 * #278 was that the upstream forward is NOT a bare proxy — it goes through the
 * same auth → governance → dispatch → evidence chokepoint the inference
 * ingresses use. That structure is preserved here:
 *
 *  1. auth (contract middleware, scope `agents.invoke`);
 *  2. upstream lookup + **visibility** — an upstream this API key cannot see is
 *     403 `agent_not_visible`, distinct from 404 `agent_not_found`, because a
 *     configured-but-invisible upstream is a real, attributable denial;
 *  3. declared correlation identity (#305 `x-ferrogate-agent-run-id`, #307
 *     `x-ferrogate-parent-action-fingerprint`) — malformed is 400, absent stays
 *     NULL, never fabricated;
 *  4. the REQUEST-stage guardrail over the flattened A2A text
 *     (Rust `a2a_input_envelope`), before any forward;
 *  5. the capability/egress gate — the upstream host must be inside the
 *     governed allowlist, so an A2A forward cannot become an unsupervised
 *     egress channel;
 *  6. forward, preserving SSE framing byte for byte on `message:stream`;
 *  7. the RESPONSE-stage guardrail over the reply (Rust `a2a_output_envelope`);
 *  8. record the exchange on the declared run's timeline when there is one.
 *
 * ## The response stage on a STREAMED reply
 *
 * Rust buffers the whole A2A reply and evaluates the response-stage envelope
 * before writing a byte, so a match can BLOCK. Buffering is not available here:
 * `docs/rewrite/ROUTE-MAP.md` requires `message:stream` to preserve upstream SSE
 * framing byte for byte AND incrementally, which holding the reply destroys.
 *
 * The answer is neither of the two obvious ones. The streamed leg screens the
 * body **frame by frame** (`./stream-screen.ts`): only the frame currently
 * being assembled is held, each complete frame is evaluated BEFORE any of its
 * bytes are handed on, a frame that passes is enqueued unmodified, and a frame
 * a policy refuses is never delivered — the stream is cut with one terminal
 * `event: ferrogate.guardrail_blocked` frame carrying the operator's own code,
 * and the upstream connection is cancelled. `stream-screen.ts` documents that
 * caller-visible shape in full, including the fact that the HTTP status was
 * already committed as 200 and cannot be retracted.
 *
 * This is a STRENGTHENING of the previous behaviour, which `tee()`d the body,
 * buffered the whole teed branch, and could only RECORD a match after every
 * byte had already reached the caller. The unary leg is unchanged and blocks
 * exactly as Rust does.
 */
import { Hono } from "hono";
import type { Context } from "hono";
import { depsOrThrow, requireAuth, tenantIdOf } from "../middleware/auth.js";
import { HttpError } from "../middleware/errors.js";
import type { AgentRuntimeDeps, AgentRuntimeEnv, AgentUpstream, AuthContext } from "../ports.js";
import { runStateStub } from "../runs/addressing.js";
import { SSE_HEADERS } from "../runs/events.js";
import { declaredAgentRunId, declaredParentActionFingerprint } from "../runs/governance.js";
import { type StreamBlock, screenSseStream } from "./stream-screen.js";

/** Rust `A2A_ROUTE`. */
export const A2A_ROUTE = "a2a.message";

export const agentRoutes = new Hono<AgentRuntimeEnv>();

/**
 * Rust `collect_a2a_text`: recursively collect the `text` of every A2A text
 * part. A2A carries parts in several envelope shapes (`message.parts[]`,
 * `messages[].parts[]`, top-level `parts[]`, task status messages, artifacts),
 * so the walk keys off the presence of a string `text` field rather than any
 * one shape — the same fail-safe "scan all inbound content" posture the chat
 * ingress applies.
 */
export function collectA2aText(value: unknown, out: string[] = []): string[] {
  if (Array.isArray(value)) {
    for (const item of value) collectA2aText(item, out);
    return out;
  }
  if (typeof value === "object" && value !== null) {
    const record = value as Record<string, unknown>;
    const text = record.text;
    if (typeof text === "string" && text !== "") out.push(text);
    for (const [key, child] of Object.entries(record)) {
      // `text` is already captured; recurse into everything else to reach
      // nested parts/artifacts.
      if (key !== "text") collectA2aText(child, out);
    }
  }
  return out;
}

/**
 * Rust `a2a_message_count`: the metered message unit. A body with no
 * recognizable parts still counts as one exchange, so a shape the parser does
 * not know is never metered as zero.
 */
export function a2aMessageCount(body: unknown): number {
  return Math.max(collectA2aText(body).length, 1);
}

/**
 * Rust `sse_data_values`: the JSON value carried by each `data:` frame of an
 * SSE reply. Unparseable frames are skipped rather than aborting the walk, so
 * one malformed frame cannot blind the detector to the rest of the stream.
 */
export function sseDataValues(body: string): unknown[] {
  const values: unknown[] = [];
  for (const line of body.split("\n")) {
    const trimmed = line.trimStart();
    if (!trimmed.startsWith("data:")) continue;
    const payload = trimmed.slice("data:".length).trim();
    if (payload === "" || payload === "[DONE]") continue;
    try {
      values.push(JSON.parse(payload));
    } catch {
      // Not JSON: nothing to walk, but the raw text is still covered by the
      // fail-safe fallback in `a2aReplyText`.
    }
  }
  return values;
}

/**
 * Rust `a2a_output_envelope`'s text extraction, for both reply shapes.
 *
 * The FALLBACK matters as much as the parse: a reply whose shape the parser
 * does not recognise falls back to the raw bytes so it is still scanned rather
 * than silently skipped. A detector that quietly sees an empty string on an
 * unfamiliar payload is worse than no detector, because it looks like a pass.
 */
export function a2aReplyText(body: string, stream = false): string {
  const collected: string[] = [];
  if (stream) {
    for (const value of sseDataValues(body)) collectA2aText(value, collected);
  } else {
    try {
      collectA2aText(JSON.parse(body), collected);
    } catch {
      // Fall through to the raw-body fallback below.
    }
  }
  return collected.length === 0 ? body : collected.join("\n");
}

/**
 * Record a mid-stream guardrail block on the declared run's timeline.
 *
 * `enforced: true`, and that is a factual change rather than a cosmetic one:
 * under the previous buffering shape the bytes were already gone when the match
 * was found, so the row honestly said `enforced: false`. Frame-by-frame
 * screening means the offending frame was never delivered, so an investigator
 * reading this row is being told the truth about what the caller received.
 *
 * Errors are swallowed deliberately: this runs after the response has been
 * committed, so throwing could only produce an unhandled rejection, never a
 * refusal the caller would see. The BLOCK itself does not depend on this
 * succeeding — the stream is already cut by the time it runs.
 */
async function recordStreamBlock(
  block: StreamBlock,
  context: {
    readonly tenantId: string;
    readonly agentId: string;
    readonly runStateStub: ReturnType<typeof runStateStub> | null;
    readonly agentRunId: string | null;
    readonly parentActionFingerprint: string | null;
    readonly requestId: string;
    readonly nowUnix: number;
  },
): Promise<void> {
  if (context.runStateStub === null || context.agentRunId === null) return;
  try {
    await context.runStateStub.appendEvent(context.tenantId, {
      kind: "guardrail_match",
      body: {
        route: A2A_ROUTE,
        agent_id: context.agentId,
        stage: block.stage,
        detector: block.code,
        enforced: true,
        message: block.message,
      },
      nowUnix: context.nowUnix,
      source: "control_plane",
      requestId: context.requestId,
      traceId: null,
      agentRunId: context.agentRunId,
      parentActionFingerprint: context.parentActionFingerprint,
    });
  } catch {
    // See the doc comment: nothing useful can be surfaced from here.
  }
}

/** Rust `agent_upstream_visible_to_auth`. */
export function upstreamVisibleTo(upstream: AgentUpstream, auth: AuthContext): boolean {
  if (auth.platformOperator) return true;
  if (upstream.operatorOnly) return false;
  if (upstream.visibleToTenantIds.length === 0) return true;
  return upstream.visibleToTenantIds.includes(auth.tenancy.tenantId ?? "");
}

/** `POST /v1/agents/{name}` and the two `message:*` verbs share one handler. */
async function handleAgentIngress(
  c: Context<AgentRuntimeEnv>,
  mode: "invoke" | "send" | "stream",
): Promise<Response> {
  const deps = depsOrThrow(c);
  const config = deps.config.agentRuntime();
  if (!config.enabled) {
    throw new HttpError(
      403,
      "agent_runtime_disabled",
      "agent runtime is disabled by operator config",
    );
  }

  const auth = requireAuth(c);
  const tenantId = tenantIdOf(auth);
  const agentId = c.req.param("name") ?? "";
  if (agentId === "") {
    throw new HttpError(404, "agent_not_found", "agent endpoint not found");
  }

  // THE REACH SET, resolved per dispatch and fenced to this caller. With
  // `CONTROL_DB` bound this is the durable `agent-upstreams` table
  // (`./registry.ts`), so an upstream withdrawn through
  // `DELETE /admin/v1/agent-upstreams/{id}` is unreachable on the very next
  // request — no redeploy, no cache to flush.
  const resolved = await deps.upstreams.lookup(agentId, {
    tenantId: auth.platformOperator ? null : tenantId,
  });
  // FAIL CLOSED, and distinguishably. A registry this Worker cannot read must
  // REFUSE the forward: admitting on a lookup failure would re-open every
  // withdrawn upstream the moment the control database blinked, which is the
  // wave-16 bypass in a new form. 503 rather than 404 so an outage is never
  // reported as a successful withdrawal — the posture
  // `apps/gateway/src/ratelimit/quota.ts` argues for the admission ladder.
  if (resolved.outcome === "unavailable") {
    throw new HttpError(
      503,
      "agent_upstream_unavailable",
      `agent upstream registry is unavailable: ${resolved.detail}`,
    );
  }
  const upstream = resolved.outcome === "found" ? resolved.upstream : undefined;
  if (upstream === undefined || !upstream.enabled) {
    throw new HttpError(404, "agent_not_found", `agent upstream ${agentId} was not found`);
  }
  // 403, not 404: a configured upstream the caller may not reach is an
  // attributable denial, and Rust reports it as one.
  if (!upstreamVisibleTo(upstream, auth)) {
    throw new HttpError(
      403,
      "agent_not_visible",
      `agent upstream ${agentId} is not visible to this API key`,
    );
  }

  const raw = await c.req.text();
  if (new TextEncoder().encode(raw).length > config.agentIngressBodyMaxBytes) {
    throw new HttpError(
      413,
      "payload_too_large",
      `request body exceeds maximum size of ${config.agentIngressBodyMaxBytes} bytes`,
    );
  }
  let payload: unknown;
  try {
    payload = JSON.parse(raw);
  } catch (error) {
    throw new HttpError(400, "invalid_json", `invalid agent request JSON: ${String(error)}`);
  }

  // #305/#307: declared correlation identity. Every governance row this handler
  // records joins on these; absent stays NULL rather than fabricated.
  const agentRunId = declaredAgentRunId(c.req.raw.headers);
  const parentActionFingerprint = declaredParentActionFingerprint(c.req.raw.headers);
  const requestId = c.get("requestId") ?? "";
  const stream = mode === "stream";

  // #278: the REQUEST-stage guardrail, over every text part the body carries,
  // BEFORE the forward — a body that must not leave the gateway must not reach
  // the upstream either, so this cannot be moved after the dispatch.
  const requestVerdict = await deps.guardrails.evaluate({
    stage: "request",
    tenantId,
    agentId,
    streaming: stream,
    text: collectA2aText(payload).join("\n"),
  });
  if (requestVerdict.outcome === "deny") {
    // The OPERATOR's own code when a DURABLE activated revision matched, and
    // the route's historical `guardrail_blocked` otherwise. That is what makes
    // ONE activation refuse with the SAME code on every Worker that enforces it
    // (`docs/rewrite/FLEET-CONSISTENCY.md` FC-3) rather than each Worker
    // inventing a private one.
    throw new HttpError(
      403,
      requestVerdict.denial.code ?? "guardrail_blocked",
      requestVerdict.denial.message,
    );
  }

  // The egress gate: an A2A forward must not become an unsupervised egress
  // channel, so the upstream host is checked against the SAME governed
  // allowlist a sandbox workload is held to (#471, sealed by default).
  const upstreamHost = new URL(upstream.url).hostname.toLowerCase();
  const decision = await deps.governance.authorize({
    tenantId,
    workspaceId: auth.tenancy.workspaceId ?? "default",
    frameworkAdapter: config.defaultFrameworkAdapter,
    requiredCapabilities: ["network.egress"],
    egressAllowlist: [upstreamHost],
    parentActionFingerprint,
  });
  if (decision.outcome === "deny") {
    throw new HttpError(decision.denial.status, decision.denial.code, decision.denial.message);
  }

  const messageCount = a2aMessageCount(payload);

  // Record the exchange on the declared run's timeline BEFORE the forward, so
  // an upstream that never answers still leaves evidence that the call was
  // made and authorized.
  if (agentRunId !== null) {
    await runStateStub(c.env, tenantId, agentRunId).appendEvent(tenantId, {
      kind: "a2a_exchange",
      body: {
        route: A2A_ROUTE,
        agent_id: agentId,
        upstream: upstream.url,
        stream,
        message_count: messageCount,
      },
      nowUnix: deps.clock.nowUnix(),
      source: "control_plane",
      requestId,
      traceId: c.get("traceId") ?? null,
      agentRunId,
      parentActionFingerprint,
    });
  }

  const forwarded = await fetch(upstream.url, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      accept: stream ? "text/event-stream" : "application/json",
      // The correlation identity rides the forward so the upstream stamps the
      // same keys the control plane persisted.
      "x-ferrogate-request-id": requestId,
      ...(agentRunId === null ? {} : { "x-ferrogate-agent-run-id": agentRunId }),
      ...(parentActionFingerprint === null
        ? {}
        : { "x-ferrogate-parent-action-fingerprint": parentActionFingerprint }),
    },
    body: raw,
  });

  if (stream) {
    if (forwarded.body === null) {
      throw new HttpError(502, "upstream_error", "agent upstream returned no stream");
    }
    // INCREMENTAL response-stage screening. Each complete SSE frame is
    // evaluated before any of its bytes are handed on, and a frame that passes
    // is enqueued unmodified — so the upstream framing survives byte for byte
    // exactly as `ROUTE-MAP.md` requires, while content an activated policy
    // forbids never leaves this Worker. See `./stream-screen.ts` for what a
    // mid-stream block looks like to the caller.
    const evidence = {
      tenantId,
      agentId,
      runStateStub: agentRunId === null ? null : runStateStub(c.env, tenantId, agentRunId),
      agentRunId,
      parentActionFingerprint,
      requestId,
      nowUnix: deps.clock.nowUnix(),
    };
    const screened = screenSseStream(forwarded.body, {
      textOf: (frame) => a2aReplyText(frame, true),
      screen: (text) =>
        deps.guardrails.evaluate({
          stage: "response",
          tenantId,
          agentId,
          streaming: true,
          text,
        }),
      onBlock: (block) => {
        c.executionCtx.waitUntil(recordStreamBlock(block, evidence));
      },
    });
    return new Response(screened, {
      status: forwarded.status,
      headers: { ...SSE_HEADERS },
    });
  }

  const body = await forwarded.text();

  // #278: the RESPONSE-stage guardrail. The unary reply is already fully in
  // hand, so a match BLOCKS here exactly as it does in Rust — the upstream's
  // bytes are never handed to the caller.
  const responseVerdict = await deps.guardrails.evaluate({
    stage: "response",
    tenantId,
    agentId,
    streaming: false,
    text: a2aReplyText(body),
  });
  if (responseVerdict.outcome === "deny") {
    throw new HttpError(
      403,
      responseVerdict.denial.code ?? "guardrail_blocked",
      responseVerdict.denial.message,
    );
  }

  return new Response(body, {
    status: forwarded.status,
    headers: {
      "content-type": forwarded.headers.get("content-type") ?? "application/json",
      "x-ferrogate-a2a-message-count": String(messageCount),
    },
  });
}

/** `POST /v1/agents/{name}` — `invokeAgent`, scope `agents.invoke`. */
agentRoutes.post("/v1/agents/:name", (c) => handleAgentIngress(c, "invoke"));

/**
 * `message:send` / `message:stream`.
 *
 * Registered as a `:verb` parameter rather than as two literal patterns because
 * the A2A verb separator is a COLON, which is also Hono's parameter sigil —
 * `"/v1/agents/:name/message:stream"` would be parsed as a parameter named
 * `stream`. Matching the segment and comparing it here is unambiguous. The
 * contract middleware has already refused any other verb, so the fallthrough
 * is belt-and-braces.
 */
agentRoutes.post("/v1/agents/:name/:verb", (c) => {
  const verb = c.req.param("verb");
  if (verb === "message:send") return handleAgentIngress(c, "send");
  if (verb === "message:stream") return handleAgentIngress(c, "stream");
  throw new HttpError(404, "not_found", "agent endpoint not found");
});
