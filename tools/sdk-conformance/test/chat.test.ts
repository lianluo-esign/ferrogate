/**
 * Non-streaming `client.chat.completions.create()` through the official
 * `openai` client.
 *
 * This is the base case of the adoption claim: an existing OpenAI codebase sets
 * `baseURL` to a FerroGate deployment and its very first call keeps working.
 */
import { describe, expect, it } from "vitest";
import { interceptUpstream, openaiClient, upstreamJson } from "./harness.js";

const COMPLETION = {
  id: "chatcmpl-conformance",
  object: "chat.completion",
  created: 1_700_000_000,
  model: "gpt-4o-mini-2024-07-18",
  choices: [
    {
      index: 0,
      message: { role: "assistant", content: "hello from the upstream" },
      finish_reason: "stop",
    },
  ],
  usage: { prompt_tokens: 11, completion_tokens: 4, total_tokens: 15 },
};

describe("openai SDK — chat.completions.create", () => {
  it("round-trips a completion the SDK typed and parsed itself", async () => {
    const upstream = interceptUpstream(() => upstreamJson(COMPLETION));
    try {
      const completion = await openaiClient().chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi" }],
      });

      // Read through the SDK's own types — if the envelope were reshaped the
      // client would surface `undefined` here, not throw.
      expect(completion.choices[0]?.message.content).toBe("hello from the upstream");
      expect(completion.choices[0]?.finish_reason).toBe("stop");
      expect(completion.usage?.total_tokens).toBe(15);
      expect(completion.model).toBe("gpt-4o-mini-2024-07-18");
    } finally {
      upstream.restore();
    }
  });

  it("presents the credential as a bearer token the gateway accepts", async () => {
    const upstream = interceptUpstream(() => upstreamJson(COMPLETION));
    try {
      await openaiClient().chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "hi" }],
      });

      // The gateway resolved the LOGICAL model to the physical one and used its
      // OWN provider credential upstream — the caller's key never leaves.
      const call = upstream.last();
      expect(call.url).toBe("https://api.openai.conformance.test/v1/chat/completions");
      expect((call.body as { model: string }).model).toBe("gpt-4o-mini-2024-07-18");
      expect(call.headers["authorization"]).toBe(
        "Bearer upstream-key-placeholder-not-a-credential",
      );
    } finally {
      upstream.restore();
    }
  });

  it("exposes the gateway request id the SDK read off the response", async () => {
    const upstream = interceptUpstream(() => upstreamJson(COMPLETION));
    try {
      const { data, response } = await openaiClient()
        .chat.completions.create({
          model: "gpt-4o-mini",
          messages: [{ role: "user", content: "hi" }],
        })
        .withResponse();

      expect(data.id).toBe("chatcmpl-conformance");
      // `x-request-id` is what the SDK surfaces as `_request_id` and what an
      // operator correlates a support ticket with. FerroGate writes its own.
      expect(response.headers.get("x-request-id")).toMatch(/^fg-/);
    } finally {
      upstream.restore();
    }
  });

  it("lists models through the SDK's pagination wrapper", async () => {
    // No upstream call at all: `/v1/models` is served from the gateway's own
    // registry, and the SDK insists on `{object:"list",data:[...]}`.
    const models = await openaiClient().models.list();
    const ids = models.data.map((model) => model.id).sort();
    expect(ids).toContain("gpt-4o-mini");
  });
});
