/**
 * Structured outputs must survive a cross-family failover (issue #674).
 *
 * The defect these tests pin: `response_format: {"type":"json_schema"}` reached
 * an OpenAI-family upstream only because `prepareChatCompletions` there copies
 * the caller's body wholesale. Anthropic, Gemini, Vertex and Bedrock rebuild the
 * upstream body field-by-field, so the field was silently dropped and the
 * caller — who asked for a schema — got free text back. A gateway whose failover
 * changes the output contract is not a failover.
 *
 * Each family therefore has to carry the SAME canonical requirement in its own
 * dialect (`response_format` / tool-call coercion / `responseSchema` /
 * `toolConfig`), and every requirement a family genuinely cannot express has to
 * REFUSE, never degrade to unconstrained text.
 */
import { describe, expect, test } from "vitest";

import {
  AdapterError,
  AnthropicAdapter,
  BedrockAdapter,
  GeminiAdapter,
  OpenAiCompatibleAdapter,
  SecretValue,
  VertexAiAdapter,
  structuredOutputFromChatBody,
  structuredOutputFromResponsesBody,
} from "../src/index.js";
import type { ProviderConfig } from "../src/index.js";

// --- fixtures --------------------------------------------------------------

/** One schema, reused everywhere, so the per-family output is comparable. */
const INVOICE_SCHEMA = {
  type: "object",
  properties: { total: { type: "number" }, currency: { type: "string" } },
  required: ["total", "currency"],
  additionalProperties: false,
};

const RESPONSE_FORMAT = {
  type: "json_schema",
  json_schema: {
    name: "invoice",
    description: "a parsed invoice",
    strict: true,
    schema: INVOICE_SCHEMA,
  },
};

const chatBody = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  model: "logical",
  messages: [{ role: "user", content: "parse this invoice" }],
  response_format: RESPONSE_FORMAT,
  ...extra,
});

/** The `/v1/responses` spelling of the same requirement (`text.format`). */
const responsesBody = (extra: Record<string, unknown> = {}): Record<string, unknown> => ({
  model: "logical",
  input: "parse this invoice",
  text: {
    format: {
      type: "json_schema",
      name: "invoice",
      strict: true,
      schema: INVOICE_SCHEMA,
    },
  },
  ...extra,
});

const openaiProvider: ProviderConfig = {
  name: "openai",
  kind: "openai",
  baseUrl: "https://api.openai.example/v1/",
};
const anthropicProvider: ProviderConfig = {
  name: "anthropic",
  kind: "anthropic",
  baseUrl: "https://api.anthropic.example/v1/",
};
const geminiProvider: ProviderConfig = {
  name: "google",
  kind: "gemini",
  baseUrl: "https://generativelanguage.googleapis.example/v1beta/",
};
const vertexProvider: ProviderConfig = {
  name: "vertex",
  kind: "vertex",
  baseUrl: "https://us-central1-aiplatform.googleapis.example",
  gcpCredentials: {
    accessToken: new SecretValue("ya29.EXAMPLE"),
    projectId: "my-gcp-project",
    location: "us-central1",
  },
};
const bedrockProvider: ProviderConfig = {
  name: "bedrock",
  kind: "bedrock",
  baseUrl: "https://bedrock-runtime.us-east-1.amazonaws.example",
  awsCredentials: {
    accessKeyId: "AKIDEXAMPLE",
    secretAccessKey: new SecretValue("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"),
    region: "us-east-1",
  },
};

const chatPlan = (body: Record<string, unknown>) => ({
  logicalModel: "logical",
  providerModel: "physical",
  stream: false,
  body: body as never,
});

// --- canonical parsing -----------------------------------------------------

describe("canonical structured-output parsing", () => {
  test("reads the chat `response_format` and the Responses `text.format` alike", () => {
    const fromChat = structuredOutputFromChatBody(chatBody() as never);
    const fromResponses = structuredOutputFromResponsesBody(responsesBody() as never);
    expect(fromChat).toMatchObject({ kind: "json_schema", name: "invoice", strict: true });
    // Both ingress spellings collapse to the SAME canonical requirement, which
    // is what makes a chat→responses (or responses→chat) route comparable.
    expect(fromResponses).toMatchObject({ kind: "json_schema", name: "invoice", strict: true });
    expect((fromChat as { schema: unknown }).schema).toEqual(INVOICE_SCHEMA);
    expect((fromResponses as { schema: unknown }).schema).toEqual(INVOICE_SCHEMA);
  });

  test("a plain-text request carries no requirement at all", () => {
    expect(structuredOutputFromChatBody({ response_format: { type: "text" } } as never)).toBeUndefined();
    expect(structuredOutputFromChatBody({ messages: [] } as never)).toBeUndefined();
  });

  test("a json_schema with no schema is a caller error, not a silent no-op", () => {
    expect(() =>
      structuredOutputFromChatBody({
        response_format: { type: "json_schema", json_schema: { name: "x" } },
      } as never),
    ).toThrowError(/json_schema.*schema/i);
  });
});

// --- per-family translation ------------------------------------------------

describe("chat completions carry the schema into every family's dialect", () => {
  test("openai-compatible keeps the native response_format", () => {
    const prepared = new OpenAiCompatibleAdapter().prepareChatCompletions(
      openaiProvider,
      chatPlan(chatBody()),
    );
    expect((prepared.body as Record<string, unknown>)["response_format"]).toEqual(RESPONSE_FORMAT);
  });

  test("anthropic coerces the schema into a forced tool call", () => {
    const prepared = new AnthropicAdapter().prepareChatCompletions(
      anthropicProvider,
      chatPlan(chatBody()),
    );
    const body = prepared.body as Record<string, any>;
    expect(body["tools"]).toEqual([
      {
        name: "invoice",
        description: "a parsed invoice",
        input_schema: INVOICE_SCHEMA,
      },
    ]);
    // Forced, not merely offered: an `auto` choice would let the model answer
    // in prose and break the contract exactly as dropping the field did.
    expect(body["tool_choice"]).toEqual({ type: "tool", name: "invoice" });
  });

  test("gemini sends responseSchema + a JSON response mime type", () => {
    const prepared = new GeminiAdapter().prepareChatCompletions(
      geminiProvider,
      chatPlan(chatBody({ temperature: 0.2 })),
    );
    const config = (prepared.body as Record<string, any>)["generationConfig"];
    expect(config["responseMimeType"]).toBe("application/json");
    expect(config["responseSchema"]).toMatchObject({
      type: "object",
      required: ["total", "currency"],
    });
    // Sampling params still ride along — the structured requirement is merged
    // into the generationConfig, not substituted for it.
    expect(config["temperature"]).toBe(0.2);
  });

  test("vertex (gemini on vertex) carries the same responseSchema", () => {
    const prepared = new VertexAiAdapter().prepareChatCompletions(
      vertexProvider,
      chatPlan(chatBody()),
    );
    const config = (prepared.body as Record<string, any>)["generationConfig"];
    expect(config["responseMimeType"]).toBe("application/json");
    expect(config["responseSchema"]).toMatchObject({ type: "object" });
  });

  test("bedrock converse coerces the schema into a forced toolConfig", () => {
    const prepared = new BedrockAdapter().prepareChatCompletions(
      bedrockProvider,
      chatPlan(chatBody()),
    );
    const toolConfig = (prepared.body as Record<string, any>)["toolConfig"];
    expect(toolConfig["tools"]).toEqual([
      {
        toolSpec: {
          name: "invoice",
          description: "a parsed invoice",
          inputSchema: { json: INVOICE_SCHEMA },
        },
      },
    ]);
    expect(toolConfig["toolChoice"]).toEqual({ tool: { name: "invoice" } });
  });

  test("no family drops the requirement — the failover keeps the contract", () => {
    const body = chatBody();
    const carriers = [
      JSON.stringify(
        new OpenAiCompatibleAdapter().prepareChatCompletions(openaiProvider, chatPlan(body)).body,
      ),
      JSON.stringify(
        new AnthropicAdapter().prepareChatCompletions(anthropicProvider, chatPlan(body)).body,
      ),
      JSON.stringify(
        new GeminiAdapter().prepareChatCompletions(geminiProvider, chatPlan(body)).body,
      ),
      JSON.stringify(
        new VertexAiAdapter().prepareChatCompletions(vertexProvider, chatPlan(body)).body,
      ),
      JSON.stringify(
        new BedrockAdapter().prepareChatCompletions(bedrockProvider, chatPlan(body)).body,
      ),
    ];
    // The schema's own field names are the family-independent evidence that the
    // requirement reached the wire in SOME dialect.
    for (const carrier of carriers) {
      expect(carrier).toContain("currency");
    }
  });
});

describe("/v1/responses carries the schema into every family's dialect", () => {
  test("anthropic responses coerce `text.format` into a forced tool call", () => {
    const prepared = new AnthropicAdapter().prepareResponses(
      anthropicProvider,
      chatPlan(responsesBody()),
    );
    const body = prepared.body as Record<string, any>;
    expect(body["tools"]).toEqual([{ name: "invoice", input_schema: INVOICE_SCHEMA }]);
    expect(body["tool_choice"]).toEqual({ type: "tool", name: "invoice" });
  });

  test("gemini responses carry `text.format` as responseSchema", () => {
    const prepared = new GeminiAdapter().prepareResponses(
      geminiProvider,
      chatPlan(responsesBody({ max_output_tokens: 512 })),
    );
    const config = (prepared.body as Record<string, any>)["generationConfig"];
    expect(config["responseMimeType"]).toBe("application/json");
    expect(config["responseSchema"]).toMatchObject({ type: "object" });
    expect(config["maxOutputTokens"]).toBe(512);
  });
});

// --- refusals: what a family cannot honour ---------------------------------

describe("a family that cannot honour the requirement refuses instead of degrading", () => {
  test("anthropic refuses bare json_object mode (no schema to coerce with)", () => {
    expect.assertions(3);
    try {
      new AnthropicAdapter().prepareChatCompletions(
        anthropicProvider,
        chatPlan(chatBody({ response_format: { type: "json_object" } })),
      );
    } catch (error) {
      expect(error).toBeInstanceOf(AdapterError);
      expect((error as AdapterError).kind).toBe("UnsupportedCapability");
      expect((error as AdapterError).message).toMatch(/json_object/);
    }
  });

  test("gemini CAN honour json_object — it is a mime type there, so no refusal", () => {
    const prepared = new GeminiAdapter().prepareChatCompletions(
      geminiProvider,
      chatPlan(chatBody({ response_format: { type: "json_object" } })),
    );
    const config = (prepared.body as Record<string, any>)["generationConfig"];
    expect(config["responseMimeType"]).toBe("application/json");
    expect(config["responseSchema"]).toBeUndefined();
  });

  test("gemini refuses a $ref/$defs schema its responseSchema subset cannot express", () => {
    const refSchema = {
      type: "object",
      properties: { line: { $ref: "#/$defs/line" } },
      $defs: { line: { type: "string" } },
    };
    expect.assertions(2);
    try {
      new GeminiAdapter().prepareChatCompletions(
        geminiProvider,
        chatPlan(
          chatBody({
            response_format: {
              type: "json_schema",
              json_schema: { name: "invoice", schema: refSchema },
            },
          }),
        ),
      );
    } catch (error) {
      expect((error as AdapterError).kind).toBe("UnsupportedCapability");
      expect((error as AdapterError).message).toMatch(/\$ref/);
    }
  });

  test("a response_format shape the gateway does not model is refused, not dropped", () => {
    expect(() =>
      new AnthropicAdapter().prepareChatCompletions(
        anthropicProvider,
        chatPlan(chatBody({ response_format: { type: "json_lines" } })),
      ),
    ).toThrowError(/json_lines/);
    expect(() =>
      new GeminiAdapter().prepareChatCompletions(
        geminiProvider,
        chatPlan(chatBody({ response_format: { type: "json_lines" } })),
      ),
    ).toThrowError(/json_lines/);
  });

  test("anthropic refuses when the coercion tool would shadow a caller tool", () => {
    expect(() =>
      new AnthropicAdapter().prepareResponses(
        anthropicProvider,
        chatPlan(
          responsesBody({
            tools: [{ name: "invoice", parameters: { type: "object" } }],
          }),
        ),
      ),
    ).toThrowError(/invoice/);
  });

  test("anthropic refuses a tool_choice that contradicts the forced coercion", () => {
    expect(() =>
      new AnthropicAdapter().prepareResponses(
        anthropicProvider,
        chatPlan(
          responsesBody({
            tools: [{ name: "lookup", parameters: { type: "object" } }],
            tool_choice: { type: "function", name: "lookup" },
          }),
        ),
      ),
    ).toThrowError(/tool_choice/);
  });
});
