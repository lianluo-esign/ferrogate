/**
 * Structured outputs — `response_format`, and the SDK's `.parse()` path.
 *
 * `client.chat.completions.parse()` does two things a plain `.create()` does
 * not, and both are gateway-visible:
 *
 *  1. it AUTO-PARSES `choices[].message.content` into `message.parsed` using the
 *     schema it sent, so a mangled `content` surfaces as a parse throw rather
 *     than a wrong string;
 *  2. it refuses to run at all unless the request it built survived the round
 *     trip — the `json_schema` block with `strict: true` must reach the
 *     provider, since that flag is what makes the output well-formed in the
 *     first place. A gateway that dropped it would leave every structured-output
 *     caller silently on best-effort JSON.
 *
 * `zodResponseFormat` is used rather than a hand-written schema because it is
 * what the SDK's own documentation tells users to write, and it is the shape
 * whose serialization a gateway is most likely to mangle.
 */
import { zodResponseFormat } from "openai/helpers/zod";
import { describe, expect, it } from "vitest";
import { z } from "zod";
import { interceptUpstream, openaiClient, upstreamJson } from "./harness.js";

const Weather = z.object({
  city: z.string(),
  temperature_c: z.number(),
  conditions: z.enum(["sunny", "rain", "cloud"]),
});

const PARSED_CONTENT = { city: "Shanghai", temperature_c: 31, conditions: "sunny" };

const STRUCTURED_COMPLETION = {
  id: "chatcmpl-structured",
  object: "chat.completion",
  created: 1_700_000_000,
  model: "gpt-4o-mini-2024-07-18",
  choices: [
    {
      index: 0,
      message: { role: "assistant", content: JSON.stringify(PARSED_CONTENT), refusal: null },
      finish_reason: "stop",
    },
  ],
  usage: { prompt_tokens: 30, completion_tokens: 20, total_tokens: 50 },
};

describe("openai SDK — structured outputs", () => {
  it("parses the response into the caller's schema", async () => {
    const upstream = interceptUpstream(() => upstreamJson(STRUCTURED_COMPLETION));
    try {
      const completion = await openaiClient().chat.completions.parse({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "weather in Shanghai" }],
        response_format: zodResponseFormat(Weather, "weather"),
      });

      const parsed = completion.choices[0]?.message.parsed;
      expect(parsed).toEqual(PARSED_CONTENT);
      // Typed, not `unknown` — the SDK's generic survived the gateway.
      expect(parsed?.conditions).toBe("sunny");
    } finally {
      upstream.restore();
    }
  });

  it("delivers the json_schema block to the provider with `strict` intact", async () => {
    const upstream = interceptUpstream(() => upstreamJson(STRUCTURED_COMPLETION));
    try {
      await openaiClient().chat.completions.parse({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "weather in Shanghai" }],
        response_format: zodResponseFormat(Weather, "weather"),
      });

      const body = upstream.last().body as {
        response_format?: {
          type?: string;
          json_schema?: { name?: string; strict?: boolean; schema?: Record<string, unknown> };
        };
      };
      expect(body.response_format?.type).toBe("json_schema");
      expect(body.response_format?.json_schema?.name).toBe("weather");
      expect(body.response_format?.json_schema?.strict).toBe(true);
      // The schema itself, nested objects and all — this is the member most
      // likely to be lost to a shallow re-serialization.
      expect(body.response_format?.json_schema?.schema).toMatchObject({
        type: "object",
        properties: {
          city: { type: "string" },
          temperature_c: { type: "number" },
          conditions: { enum: ["sunny", "rain", "cloud"] },
        },
      });
    } finally {
      upstream.restore();
    }
  });

  it("surfaces a model refusal as the SDK's refusal field, not as parsed data", async () => {
    const refusal = {
      ...STRUCTURED_COMPLETION,
      choices: [
        {
          index: 0,
          message: { role: "assistant", content: null, refusal: "I can't help with that." },
          finish_reason: "stop",
        },
      ],
    };
    const upstream = interceptUpstream(() => upstreamJson(refusal));
    try {
      const completion = await openaiClient().chat.completions.parse({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "something refused" }],
        response_format: zodResponseFormat(Weather, "weather"),
      });

      expect(completion.choices[0]?.message.refusal).toBe("I can't help with that.");
      expect(completion.choices[0]?.message.parsed).toBeNull();
    } finally {
      upstream.restore();
    }
  });

  it("supports the older json_object mode too", async () => {
    const upstream = interceptUpstream(() => upstreamJson(STRUCTURED_COMPLETION));
    try {
      const completion = await openaiClient().chat.completions.create({
        model: "gpt-4o-mini",
        messages: [{ role: "user", content: "reply in json" }],
        response_format: { type: "json_object" },
      });

      expect(JSON.parse(completion.choices[0]?.message.content ?? "")).toEqual(PARSED_CONTENT);
      expect((upstream.last().body as { response_format?: unknown }).response_format).toEqual({
        type: "json_object",
      });
    } finally {
      upstream.restore();
    }
  });
});
