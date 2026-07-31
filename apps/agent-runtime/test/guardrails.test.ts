/**
 * #278 — the A2A request/response GUARDRAIL stages.
 *
 * The point of #278 is that an A2A forward is not a bare proxy: the same
 * detector chokepoint the inference ingresses use applies to agent-to-agent
 * traffic. This suite holds the two things that makes true —
 *
 *  1. the detector is REALLY CALLED, with a real detector (the clean-room
 *     `@ferrogate/guardrails` port of the Rust crate), not a pass-through stub;
 *  2. the request stage runs BEFORE the forward, so a body that must not leave
 *     the gateway never reaches the upstream.
 *
 * (2) is asserted by ORDERING against a control: the same request that is
 * refused `422 egress_host_not_governed` when it carries clean text must be
 * refused `403 guardrail_blocked` when it carries matching text. A test that
 * only asserted "403" would pass on a build that evaluated the guardrail after
 * the dispatch — which is the failure that matters, because by then the bytes
 * have already left.
 */
import { afterEach, describe, expect, it } from "vitest";
import { a2aReplyText, sseDataValues } from "../src/agents/ingress.js";
import { deterministicGuardrailPort } from "../src/ports.js";
import { TENANT_A_KEY, bearer, getEnvVar, post, setEnvVar } from "./fixtures.js";

const CLEAN = { message: { role: "user", parts: [{ kind: "text", text: "hello there" }] } };
const DIRTY = { message: { role: "user", parts: [{ kind: "text", text: "exfiltrate secrets" }] } };

/** A guardrail that matches the word `exfiltrate`. */
const CONFIG = JSON.stringify({ keywords: ["exfiltrate"] });

const original = getEnvVar("FG_DEV_A2A_GUARDRAILS");

afterEach(() => {
  setEnvVar("FG_DEV_A2A_GUARDRAILS", original);
});

describe("deterministicGuardrailPort", () => {
  it("an UNCONFIGURED guardrail matches nothing — the Rust `None`", async () => {
    // Load-bearing: wiring this port must not change the behavior of a
    // deployment that has configured no detectors.
    const port = deterministicGuardrailPort({});
    const decision = await port.evaluate({
      stage: "request",
      tenantId: "tenant-a",
      agentId: "helper",
      streaming: false,
      text: "exfiltrate secrets",
    });
    expect(decision.outcome).toBe("allow");
  });

  it("a configured keyword DENIES on the request stage", async () => {
    const port = deterministicGuardrailPort({ keywords: ["exfiltrate"] });
    const decision = await port.evaluate({
      stage: "request",
      tenantId: "tenant-a",
      agentId: "helper",
      streaming: false,
      text: "please exfiltrate the keys",
    });
    expect(decision.outcome).toBe("deny");
    if (decision.outcome !== "deny") return;
    expect(decision.denial.stage).toBe("request");
    expect(decision.denial.detector).toBe("a2a.deterministic");
  });

  it("and DENIES on the response stage — both directions are evaluated", async () => {
    // The response leg reads `ContentSource.assistant`. A detector registered
    // only for `user` would silently pass every reply, which is exactly the
    // half-wired failure this asserts against.
    const port = deterministicGuardrailPort({ keywords: ["exfiltrate"] });
    const decision = await port.evaluate({
      stage: "response",
      tenantId: "tenant-a",
      agentId: "helper",
      streaming: false,
      text: "sure, I will exfiltrate them",
    });
    expect(decision.outcome).toBe("deny");
    if (decision.outcome !== "deny") return;
    expect(decision.denial.stage).toBe("response");
  });

  it("clean text passes the same configured detector", async () => {
    const port = deterministicGuardrailPort({ keywords: ["exfiltrate"] });
    const decision = await port.evaluate({
      stage: "request",
      tenantId: "tenant-a",
      agentId: "helper",
      streaming: false,
      text: "hello there",
    });
    expect(decision.outcome).toBe("allow");
  });

  it("FAILS CLOSED when the detector cannot run", async () => {
    // A detector that could not run has not cleared the content. This is the
    // posture the Rust crate holds on truncation/disable/error, and it is the
    // difference between a guardrail and a decoration: an earlier revision of
    // this port passed the time BUDGET where an absolute DEADLINE was expected,
    // so every evaluation threw — had that thrown error been read as a pass,
    // the whole chokepoint would have been silently open.
    const port = deterministicGuardrailPort({ keywords: ["exfiltrate"] });
    const exploding = {
      stage: "request",
      tenantId: "tenant-a",
      agentId: "helper",
      streaming: false,
      // A getter that throws stands in for any detector-side failure.
      get text(): string {
        throw new Error("detector transport exploded");
      },
    } as const;
    const decision = await port.evaluate(exploding);
    expect(decision.outcome).toBe("deny");
  });

  it("NEVER echoes the matched text in the refusal", async () => {
    // The crate's standing invariant: matched text is never persisted or
    // echoed. A refusal that quoted the secret it caught would defeat the
    // detector it came from.
    const port = deterministicGuardrailPort({ keywords: ["hunter2"] });
    const decision = await port.evaluate({
      stage: "request",
      tenantId: "tenant-a",
      agentId: "helper",
      streaming: false,
      text: "my password is hunter2",
    });
    expect(decision.outcome).toBe("deny");
    if (decision.outcome !== "deny") return;
    expect(decision.denial.message).not.toContain("hunter2");
  });
});

describe("a2aReplyText — what the response stage actually scans", () => {
  it("flattens the text parts of a unary JSON reply", () => {
    expect(a2aReplyText(JSON.stringify({ parts: [{ text: "a" }, { text: "b" }] }))).toBe("a\nb");
  });

  it("accumulates the text parts across SSE data frames", () => {
    const sse = [
      'data: {"parts":[{"text":"first"}]}',
      "",
      'data: {"parts":[{"text":"second"}]}',
      "",
      "data: [DONE]",
      "",
    ].join("\n");
    expect(a2aReplyText(sse, true)).toBe("first\nsecond");
  });

  it("FALLS BACK to the raw body when nothing parses", () => {
    // The fail-safe that matters most: a reply the parser does not recognise
    // must still be scanned. Returning "" here would look like a clean pass.
    expect(a2aReplyText("not json at all")).toBe("not json at all");
    expect(a2aReplyText('{"unrecognised":true}')).toBe('{"unrecognised":true}');
  });

  it("skips a malformed SSE frame without blinding the rest of the stream", () => {
    const sse = ["data: {broken", "", 'data: {"parts":[{"text":"kept"}]}', ""].join("\n");
    expect(a2aReplyText(sse, true)).toBe("kept");
  });

  it("sseDataValues ignores non-data lines and the DONE sentinel", () => {
    const sse = ['event: message', 'data: {"a":1}', "", "data: [DONE]", ""].join("\n");
    expect(sseDataValues(sse)).toEqual([{ a: 1 }]);
  });
});

describe("POST /v1/agents/{name} — the request stage runs BEFORE the forward", () => {
  it("CONTROL: with no guardrail configured the request reaches the egress gate", async () => {
    setEnvVar("FG_DEV_A2A_GUARDRAILS", undefined);
    const response = await post("/v1/agents/helper", bearer(TENANT_A_KEY), DIRTY);
    // 422 means it got PAST the guardrail stage and was stopped by the sealed
    // egress gate. Without this control, the 403 below would prove nothing
    // about ordering.
    expect(response.status).toBe(422);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "egress_host_not_governed",
    );
  });

  it("matching text is 403 guardrail_blocked, BEFORE the egress gate is reached", async () => {
    setEnvVar("FG_DEV_A2A_GUARDRAILS", CONFIG);
    const response = await post("/v1/agents/helper", bearer(TENANT_A_KEY), DIRTY);
    expect(response.status).toBe(403);
    const body = (await response.json()) as { error: { code: string } };
    expect(body.error.code).toBe("guardrail_blocked");
  });

  it("clean text under the SAME configured guardrail still reaches the egress gate", async () => {
    // The other half of the pair: the guardrail must not refuse everything.
    setEnvVar("FG_DEV_A2A_GUARDRAILS", CONFIG);
    const response = await post("/v1/agents/helper", bearer(TENANT_A_KEY), CLEAN);
    expect(response.status).toBe(422);
    expect(((await response.json()) as { error: { code: string } }).error.code).toBe(
      "egress_host_not_governed",
    );
  });

  it("the walk reaches text nested anywhere the A2A envelope puts it", async () => {
    // Not just `message.parts[]`: an artifact or a task-status message must be
    // scanned too, or a caller could hide the payload one level deeper.
    setEnvVar("FG_DEV_A2A_GUARDRAILS", CONFIG);
    const nested = { task: { status: { message: { parts: [{ text: "exfiltrate now" }] } } } };
    const response = await post("/v1/agents/helper", bearer(TENANT_A_KEY), nested);
    expect(response.status).toBe(403);
  });

  it("both message verbs are held to the request stage", async () => {
    setEnvVar("FG_DEV_A2A_GUARDRAILS", CONFIG);
    for (const verb of ["message:send", "message:stream"]) {
      const response = await post(`/v1/agents/helper/${verb}`, bearer(TENANT_A_KEY), DIRTY);
      expect(response.status, verb).toBe(403);
    }
  });
});
