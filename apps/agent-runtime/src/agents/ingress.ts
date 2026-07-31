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
 *  4. the capability/egress gate — the upstream host must be inside the
 *     governed allowlist, so an A2A forward cannot become an unsupervised
 *     egress channel;
 *  5. forward, preserving SSE framing byte for byte on `message:stream`;
 *  6. record the exchange on the declared run's timeline when there is one.
 *
 * // PORT-TODO(inventory-edge-control §agent-worker): the request- and
 * // response-stage GUARDRAIL evaluation (`a2a_input_envelope` /
 * // `a2a_output_envelope`, which flatten every A2A text part and hand it to
 * // the detector stack) belongs to `@ferrogate/guardrails`, a wave-2 package
 * // still being written. The text-flattening walk this Worker needs is
 * // implemented below as {@link collectA2aText} so the envelope is ready to
 * // hand over; only the detector call is deferred, and the metering unit
 * // (`a2a_message_count`) already rides on it.
 */
import { Hono } from "hono";
import type { Context } from "hono";
import { depsOrThrow, requireAuth, tenantIdOf } from "../middleware/auth.js";
import { HttpError } from "../middleware/errors.js";
import type { AgentRuntimeEnv, AgentUpstream, AuthContext } from "../ports.js";
import { runStateStub } from "../runs/addressing.js";
import { SSE_HEADERS } from "../runs/events.js";
import { declaredAgentRunId, declaredParentActionFingerprint } from "../runs/governance.js";

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

  const upstream = await deps.upstreams.lookup(agentId);
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
    // Byte-for-byte passthrough: the body is never re-encoded, so the upstream
    // SSE framing survives exactly as `ROUTE-MAP.md` requires.
    return new Response(forwarded.body, {
      status: forwarded.status,
      headers: { ...SSE_HEADERS },
    });
  }

  const body = await forwarded.text();
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
