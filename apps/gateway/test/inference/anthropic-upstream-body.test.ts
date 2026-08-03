/**
 * What actually reaches an ANTHROPIC upstream (issue #725).
 *
 * The Anthropic adapter is the one family that does not forward the caller's
 * body: Anthropic rejects unknown top-level members, so the adapter REBUILT a
 * native body from an allowlist — `model`, `messages`, `max_tokens`, `stream`,
 * plus `system` only when the translated body already had one. Everything else
 * the caller sent was dropped on the floor while the request answered 200.
 *
 * That is the worst shape a gateway defect can take. A caller that sends
 * `tools` gets a well-formed completion back in which the model simply never
 * calls a tool; nothing errors, nothing is logged, and the caller debugs its
 * prompt. #690's governing rule is that what a family cannot express is
 * REFUSED, never silently degraded — and every field pinned below is one this
 * family CAN express, which makes dropping it strictly worse than the case
 * that rule was written for.
 *
 * Every assertion here is a SEPARATE test per field on purpose: one test
 * asserting "the body matches" would stay green with any subset of the fields
 * restored, and this file's whole job is to make each field individually
 * load-bearing.
 *
 * Only the outbound provider `fetch` is stubbed; the request travels the real
 * ingress → translation → plan → adapter → dispatch path.
 */
import { describe, expect, it } from "vitest";

import { ANTHROPIC_ROUTE, OPENAI_ROUTE, errorBody, harness } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

const ANTHROPIC_MESSAGE = {
  id: "msg_725",
  type: "message",
  role: "assistant",
  model: "claude-3-5-sonnet-20241022",
  content: [{ type: "text", text: "hello" }],
  stop_reason: "end_turn",
  stop_sequence: null,
  usage: { input_tokens: 7, output_tokens: 2 },
};

const ROUTES = [ANTHROPIC_ROUTE, OPENAI_ROUTE];

const WEATHER_TOOL = {
  name: "get_weather",
  description: "Look up the weather",
  input_schema: {
    type: "object",
    properties: { city: { type: "string" } },
    required: ["city"],
  },
};

/** The OpenAI spelling of {@link WEATHER_TOOL}, as a chat caller sends it. */
const WEATHER_TOOL_OPENAI = {
  type: "function",
  function: {
    name: "get_weather",
    description: "Look up the weather",
    parameters: WEATHER_TOOL.input_schema,
  },
};

interface Sent {
  readonly status: number;
  readonly calls: number;
  /** The body the Anthropic upstream actually received. */
  readonly body: Record<string, any>;
  readonly code: string | undefined;
  readonly message: string | undefined;
}

/** Drive one request to the Anthropic-backed route and report what went out. */
async function sent(path: string, request: unknown): Promise<Sent> {
  const provider = interceptProviderFetch(() => providerJson(ANTHROPIC_MESSAGE));
  try {
    const res = await harness({}, ROUTES).post(path, request);
    const failure =
      res.status >= 400 ? (await errorBody(res)).error : { code: undefined, message: undefined };
    return {
      status: res.status,
      calls: provider.requests.length,
      body: (provider.requests[0]?.body ?? {}) as Record<string, any>,
      code: failure.code,
      message: failure.message,
    };
  } finally {
    provider.restore();
  }
}

/** The Anthropic-native request that carries every field the issue names. */
function messagesRequest(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    model: "claude-logical",
    max_tokens: 64,
    system: "be brief",
    temperature: 0.3,
    stop_sequences: ["STOP"],
    tool_choice: { type: "auto" },
    tools: [WEATHER_TOOL],
    messages: [{ role: "user", content: "weather?" }],
    ...extra,
  };
}

/** The OpenAI-native request that carries the same intent. */
function chatRequest(extra: Record<string, unknown> = {}): Record<string, unknown> {
  return {
    model: "claude-logical",
    max_tokens: 64,
    messages: [
      { role: "system", content: "be brief" },
      { role: "user", content: "weather?" },
    ],
    ...extra,
  };
}

describe("/v1/messages on an anthropic upstream forwards what the caller sent", () => {
  it("forwards tools, in the Anthropic spelling", async () => {
    const out = await sent("/v1/messages", messagesRequest());
    expect(out.status).toBe(200);
    // Not merely "present": the ingress translated the caller's tools into the
    // OpenAI grammar on the way in, so forwarding the translated shape verbatim
    // would be a 400 from Anthropic. The round trip has to land back on
    // `input_schema`.
    expect(out.body["tools"]).toEqual([WEATHER_TOOL]);
  });

  it("forwards tool_choice", async () => {
    const out = await sent("/v1/messages", messagesRequest());
    expect(out.status).toBe(200);
    expect(out.body["tool_choice"]).toEqual({ type: "auto" });
  });

  it("forwards a forced tool choice by name", async () => {
    const out = await sent(
      "/v1/messages",
      messagesRequest({ tool_choice: { type: "tool", name: "get_weather" } }),
    );
    expect(out.status).toBe(200);
    expect(out.body["tool_choice"]).toEqual({ type: "tool", name: "get_weather" });
  });

  it("forwards temperature", async () => {
    const out = await sent("/v1/messages", messagesRequest());
    expect(out.status).toBe(200);
    expect(out.body["temperature"]).toBe(0.3);
  });

  it("forwards stop_sequences", async () => {
    const out = await sent("/v1/messages", messagesRequest());
    expect(out.status).toBe(200);
    expect(out.body["stop_sequences"]).toEqual(["STOP"]);
  });

  it("forwards top_p", async () => {
    const out = await sent("/v1/messages", messagesRequest({ top_p: 0.9 }));
    expect(out.status).toBe(200);
    expect(out.body["top_p"]).toBe(0.9);
  });

  it("passes system as the top-level parameter, not as a role inside messages", async () => {
    const out = await sent("/v1/messages", messagesRequest());
    expect(out.status).toBe(200);
    expect(out.body["system"]).toBe("be brief");
    // The Messages API accepts only `user` and `assistant` turns, so a
    // `role: "system"` entry here is a body the upstream would reject outright
    // — the request only "worked" because no real Anthropic endpoint saw it.
    expect(out.body["messages"]).toEqual([{ role: "user", content: "weather?" }]);
  });

  it("carries a tool_use / tool_result turn back in the Anthropic grammar", async () => {
    // The second turn of an agent loop. The caller replays what it received —
    // an assistant `tool_use` and a user `tool_result` — and the ingress folds
    // both into OpenAI's `tool_calls` / `role: "tool"` spelling. Handing those
    // to Anthropic unchanged is a 400, which would make the tool fix above
    // useless in the only workflow that needs it.
    const out = await sent(
      "/v1/messages",
      messagesRequest({
        messages: [
          { role: "user", content: "weather?" },
          {
            role: "assistant",
            content: [{ type: "tool_use", id: "toolu_1", name: "get_weather", input: { city: "SF" } }],
          },
          {
            role: "user",
            content: [{ type: "tool_result", tool_use_id: "toolu_1", content: "18C" }],
          },
        ],
      }),
    );
    expect(out.status).toBe(200);
    expect(out.body["messages"]).toEqual([
      { role: "user", content: "weather?" },
      {
        role: "assistant",
        content: [{ type: "tool_use", id: "toolu_1", name: "get_weather", input: { city: "SF" } }],
      },
      {
        role: "user",
        content: [{ type: "tool_result", tool_use_id: "toolu_1", content: "18C" }],
      },
    ]);
    expect(JSON.stringify(out.body)).not.toContain("tool_calls");
  });

  it("maps the Anthropic metadata.user_id through the OpenAI grammar and back", async () => {
    const out = await sent("/v1/messages", messagesRequest({ metadata: { user_id: "u-42" } }));
    expect(out.status).toBe(200);
    expect(out.body["metadata"]).toEqual({ user_id: "u-42" });
  });
});

describe("/v1/chat/completions on an anthropic upstream forwards what the caller sent", () => {
  it("translates OpenAI tools into Anthropic tools", async () => {
    const out = await sent("/v1/chat/completions", chatRequest({ tools: [WEATHER_TOOL_OPENAI] }));
    expect(out.status).toBe(200);
    expect(out.body["tools"]).toEqual([WEATHER_TOOL]);
  });

  it('translates tool_choice "required" into Anthropic\'s "any"', async () => {
    const out = await sent(
      "/v1/chat/completions",
      chatRequest({ tools: [WEATHER_TOOL_OPENAI], tool_choice: "required" }),
    );
    expect(out.status).toBe(200);
    expect(out.body["tool_choice"]).toEqual({ type: "any" });
  });

  it("translates a single `stop` string into a stop_sequences array", async () => {
    const out = await sent("/v1/chat/completions", chatRequest({ stop: "STOP" }));
    expect(out.status).toBe(200);
    expect(out.body["stop_sequences"]).toEqual(["STOP"]);
  });

  it("lifts the system-role message to the top-level system parameter", async () => {
    const out = await sent("/v1/chat/completions", chatRequest());
    expect(out.status).toBe(200);
    expect(out.body["system"]).toBe("be brief");
    expect(out.body["messages"]).toEqual([{ role: "user", content: "weather?" }]);
  });

  it("translates the OpenAI `user` field into Anthropic's metadata.user_id", async () => {
    const out = await sent("/v1/chat/completions", chatRequest({ user: "u-42" }));
    expect(out.status).toBe(200);
    expect(out.body["metadata"]).toEqual({ user_id: "u-42" });
  });

  it("expresses parallel_tool_calls: false as disable_parallel_tool_use", async () => {
    const out = await sent(
      "/v1/chat/completions",
      chatRequest({ tools: [WEATHER_TOOL_OPENAI], parallel_tool_calls: false }),
    );
    expect(out.status).toBe(200);
    expect(out.body["tool_choice"]).toEqual({ type: "auto", disable_parallel_tool_use: true });
  });

  it("translates an assistant tool_calls turn and a tool-role result", async () => {
    const out = await sent(
      "/v1/chat/completions",
      chatRequest({
        tools: [WEATHER_TOOL_OPENAI],
        messages: [
          { role: "user", content: "weather?" },
          {
            role: "assistant",
            content: null,
            tool_calls: [
              {
                id: "call_1",
                type: "function",
                function: { name: "get_weather", arguments: '{"city":"SF"}' },
              },
            ],
          },
          { role: "tool", tool_call_id: "call_1", content: "18C" },
        ],
      }),
    );
    expect(out.status).toBe(200);
    expect(out.body["messages"]).toEqual([
      { role: "user", content: "weather?" },
      {
        role: "assistant",
        content: [{ type: "tool_use", id: "call_1", name: "get_weather", input: { city: "SF" } }],
      },
      {
        role: "user",
        content: [{ type: "tool_result", tool_use_id: "call_1", content: "18C" }],
      },
    ]);
  });
});

describe("what Anthropic cannot express is refused, not dropped", () => {
  /**
   * Each of these members changes the answer the caller expects. Dropping one
   * and answering 200 is the silent degrade #690 forbids; refusing takes THIS
   * candidate off the failover ladder, so a deployment that also lists an
   * OpenAI route under the same logical model is served there instead of being
   * quietly answered under different rules.
   */
  const inexpressible: ReadonlyArray<readonly [string, Record<string, unknown>]> = [
    ["n", { n: 2 }],
    ["frequency_penalty", { frequency_penalty: 0.5 }],
    ["presence_penalty", { presence_penalty: 0.5 }],
    ["logit_bias", { logit_bias: { "1234": -100 } }],
    ["logprobs", { logprobs: true }],
    ["top_logprobs", { top_logprobs: 3 }],
    ["seed", { seed: 7 }],
    ["reasoning_effort", { reasoning_effort: "high" }],
  ];

  for (const [name, extra] of inexpressible) {
    it(`refuses \`${name}\` rather than answering without it`, async () => {
      const out = await sent("/v1/chat/completions", chatRequest(extra));
      expect(out.status).toBe(400);
      expect(out.code).toBe("model_capability_unsupported");
      // The message names the member, because "unsupported" without a subject
      // sends the caller back to bisecting its own request body.
      expect(out.message).toContain(name);
      // And nothing was dispatched: a refusal that still spends the tokens is
      // not a refusal.
      expect(out.calls).toBe(0);
    });
  }

  it("tolerates the no-op spellings SDKs send by default", async () => {
    // `n: 1`, a zero penalty and `logprobs: false` ask for nothing, so refusing
    // them would break working traffic to make a point.
    const out = await sent(
      "/v1/chat/completions",
      chatRequest({ n: 1, frequency_penalty: 0, presence_penalty: 0, logprobs: false }),
    );
    expect(out.status).toBe(200);
    expect(out.calls).toBe(1);
  });
});

describe("the members FerroGate owns never reach the wire", () => {
  it("strips its own request metadata, the caching directive and OpenAI transport knobs", async () => {
    const out = await sent(
      "/v1/chat/completions",
      chatRequest({
        metadata: { cost_center: "acme" },
        prompt_cache: { mode: "auto" },
        stream_options: { include_usage: true },
        store: false,
      }),
    );
    expect(out.status).toBe(200);
    // FerroGate's billing metadata is not Anthropic's `{user_id}` metadata;
    // forwarding it is a 400 upstream.
    expect(out.body["metadata"]).toBeUndefined();
    const wire = JSON.stringify(out.body);
    expect(wire).not.toContain("prompt_cache");
    expect(wire).not.toContain("stream_options");
    expect(wire).not.toContain("cost_center");
    expect(wire).not.toContain('"store"');
  });

  it("keeps response_format off the wire, having coerced it into a tool", async () => {
    const out = await sent(
      "/v1/chat/completions",
      chatRequest({
        response_format: {
          type: "json_schema",
          json_schema: {
            name: "answer",
            schema: { type: "object", properties: { a: { type: "string" } } },
          },
        },
      }),
    );
    expect(out.status).toBe(200);
    expect(JSON.stringify(out.body)).not.toContain("response_format");
    // #674's coercion still holds through the new translation.
    expect(out.body["tool_choice"]).toMatchObject({ type: "tool" });
  });
});

describe("a member no one has classified is forwarded, never dropped", () => {
  /**
   * The INBOUND half of the same mechanism claim (issue #725).
   *
   * `/v1/messages` is translated into the OpenAI grammar before it is routed,
   * and that translation was an allowlist too — `model`, `max_tokens`,
   * `temperature`, `top_p`, `stream`, which #690 had already had to widen once
   * for `prompt_cache`. So a member Anthropic has and OpenAI does not was lost
   * at the DOOR, before the adapter this file mostly tests ever saw it: a
   * `/v1/messages` caller could not reach `top_k` or `thinking` on an Anthropic
   * upstream through its own protocol.
   *
   * These four are asserted together because they share one code path — there
   * is no per-member code to forward, which is the point — but each is checked
   * on its own so a partial fix cannot pass.
   */
  it("carries the Messages parameters that have no OpenAI name at all", async () => {
    const out = await sent(
      "/v1/messages",
      messagesRequest({
        top_k: 5,
        thinking: { type: "enabled", budget_tokens: 1024 },
        service_tier: "auto",
        container: "container_725",
      }),
    );
    expect(out.status).toBe(200);
    expect(out.body["top_k"]).toBe(5);
    expect(out.body["thinking"]).toEqual({ type: "enabled", budget_tokens: 1024 });
    expect(out.body["service_tier"]).toBe("auto");
    expect(out.body["container"]).toBe("container_725");
  });

  it("carries an Anthropic-native member the OpenAI grammar has no name for", async () => {
    // This is the mechanism claim, not a feature request. The old code was an
    // ALLOWLIST, so the next field Anthropic adds was lost by default and
    // someone had to notice. Forwarding the remainder inverts that: an
    // unclassified member either works (it is Anthropic's) or draws a 400 from
    // the upstream naming it. Neither outcome is silent.
    const out = await sent("/v1/chat/completions", chatRequest({ top_k: 5 }));
    expect(out.status).toBe(200);
    expect(out.body["top_k"]).toBe(5);
  });
});
