/**
 * `POST /v1/messages/count_tokens` — operation `countMessageTokens` (issue #671).
 *
 * ## What these tests are actually defending
 *
 * The endpoint's whole value is that the number it returns is the number the
 * caller will be billed against. A count that silently disagrees with the bill
 * is worse than no endpoint at all: it turns a budget pre-flight into a
 * confidently wrong one.
 *
 * So the arithmetic is pinned twice, in two independent ways:
 *
 *  1. **Golden table** (`INPUT_TOKEN_GOLDENS`) — hand-derived from the
 *     documented estimator arithmetic (`src/inference/estimate.ts`):
 *     `floor((unicodeScalarCount + 3) / 4)` over the TRANSLATED
 *     OpenAI-shaped `messages`, plus 4 tokens of ChatML framing per translated
 *     message. Every constant below was computed by hand, not captured from a
 *     run, so a change to the estimator that is "green because the snapshot
 *     moved with it" cannot happen here.
 *  2. **Reservation equality** — the same body is sent to `POST /v1/messages`
 *     with a spying {@link TokenGovernor} installed on the request scope, i.e.
 *     the exact seam the deployed TPM window plugs into. The metering
 *     reservation must be `input_tokens + completion reservation` for the same
 *     body. If someone sharpens the prompt leg of the estimator for one surface
 *     and not the other, this goes red even though the golden table would still
 *     pass on the endpoint alone.
 *
 * Both are run per PROVIDER FAMILY (an Anthropic-native upstream and an
 * OpenAI-family upstream), because `/v1/messages` reaches both and the issue's
 * acceptance criterion is stated per family.
 */
import { SELF } from "cloudflare:test";
import { describe, expect, it } from "vitest";
import { operationById } from "../../src/contract.js";
import {
  DEFAULT_COMPLETION_TOKEN_RESERVATION,
  setInferenceRequestScope,
} from "../../src/inference/index.js";
import type { TokenAdmissionHandle, TokenGovernor } from "../../src/inference/index.js";
import { INFERENCE_OPERATION_IDS } from "../../src/routes/index.js";
import { ALL_ROUTES, errorBody, harness, tenantCaller } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

const PATH = "/v1/messages/count_tokens";

/** A minimal upstream answer, so the `/v1/messages` leg of the cross-check completes. */
const ANTHROPIC_MESSAGE = {
  id: "msg_01",
  type: "message",
  role: "assistant",
  model: "claude-3-5-sonnet-20241022",
  content: [{ type: "text", text: "ok" }],
  stop_reason: "end_turn",
  usage: { input_tokens: 7, output_tokens: 3 },
};

// ---------------------------------------------------------------------------
// The golden table
// ---------------------------------------------------------------------------

interface Golden {
  readonly name: string;
  /** The Anthropic-native request body, minus `model`. */
  readonly body: Record<string, unknown>;
  /** Hand-derived expected `input_tokens`. */
  readonly inputTokens: number;
  /** The hand-derivation, so a future reader can re-check it without running anything. */
  readonly derivation: string;
}

const INPUT_TOKEN_GOLDENS: readonly Golden[] = [
  {
    name: "one plain user turn",
    body: { messages: [{ role: "user", content: "hi" }] },
    inputTokens: 6,
    // translated messages: [{role:"user",content:"hi"}]
    // scalars: "user"(4) + "hi"(2) = 6 -> floor((6+3)/4) = 2; overhead 1*4 = 4.
    derivation: "2 + 4",
  },
  {
    name: "top-level system prompt is COUNTED, not dropped",
    body: { system: "be concise", messages: [{ role: "user", content: "hi" }] },
    inputTokens: 14,
    // `to_chat_completions` folds `system` into messages[0] as a system-role
    // turn, so it is counted AND it adds a second message's framing. Counting
    // the untranslated body would return 6 here and under-report the bill.
    // scalars: "system"(6)+"be concise"(10)+"user"(4)+"hi"(2) = 22
    //          -> floor((22+3)/4) = 6; overhead 2*4 = 8.
    derivation: "6 + 8",
  },
  {
    name: "content blocks: the `type` discriminator is structure, not prompt",
    body: {
      messages: [{ role: "user", content: [{ type: "text", text: "hello world" }] }],
    },
    inputTokens: 8,
    // A lone text block collapses to a plain string in translation.
    // scalars: "user"(4) + "hello world"(11) = 15 -> floor((15+3)/4) = 4;
    // overhead 1*4 = 4.
    derivation: "4 + 4",
  },
  {
    name: "three turns",
    body: {
      messages: [
        { role: "user", content: "hi" },
        { role: "assistant", content: "hello" },
        { role: "user", content: "again" },
      ],
    },
    inputTokens: 20,
    // scalars: 4+2 + 9+5 + 4+5 = 29 -> floor((29+3)/4) = 8; overhead 3*4 = 12.
    derivation: "8 + 12",
  },
  {
    name: "astral characters count as Unicode SCALARS, not UTF-16 code units",
    body: { messages: [{ role: "user", content: "😀😀😀😀😀" }] },
    inputTokens: 7,
    // Five astral scalars. Rust counts 5; JS `String.length` would count 10.
    // scalars: "user"(4) + 5 = 9 -> floor((9+3)/4) = 3; overhead 4.
    // With `.length` it would be 4 + 10 = 14 -> floor(17/4) = 4, i.e. 8 — so
    // this row is the one that fails if the scalar count is ever regressed.
    derivation: "3 + 4",
  },
];

/** The two provider families `/v1/messages` can be served by. */
const FAMILIES = [
  { family: "anthropic", model: "claude-logical" },
  { family: "openai", model: "gpt-4o-mini" },
] as const;

async function countTokens(model: string, body: Record<string, unknown>): Promise<Response> {
  return await harness().post(PATH, { model, ...body });
}

describe("POST /v1/messages/count_tokens — golden arithmetic", () => {
  for (const { family, model } of FAMILIES) {
    for (const golden of INPUT_TOKEN_GOLDENS) {
      it(`${family}: ${golden.name} => ${golden.inputTokens} (${golden.derivation})`, async () => {
        const res = await countTokens(model, golden.body);
        expect(res.status).toBe(200);
        expect(await res.json()).toEqual({ input_tokens: golden.inputTokens });
      });
    }
  }

  for (const { family, model } of FAMILIES) {
    it(`${family}: empty messages are refused with 400 (issue #727)`, async () => {
      const res = await countTokens(model, { messages: [] });
      expect(res.status).toBe(400);
    });
  }

  it("returns the Anthropic-native shape and nothing else", async () => {
    const res = await countTokens("claude-logical", {
      messages: [{ role: "user", content: "hi" }],
    });
    expect(res.headers.get("content-type")).toContain("application/json");
    expect(Object.keys((await res.json()) as object)).toEqual(["input_tokens"]);
  });

  it("carries the gateway response envelope headers", async () => {
    const res = await countTokens("claude-logical", {
      messages: [{ role: "user", content: "hi" }],
    });
    expect(res.headers.get("x-request-id")).toBe("fg-000000000000002a");
  });

  it("never touches a provider", async () => {
    const provider = interceptProviderFetch(() => providerJson(ANTHROPIC_MESSAGE));
    try {
      await countTokens("claude-logical", { messages: [{ role: "user", content: "hi" }] });
      expect(provider.requests).toHaveLength(0);
    } finally {
      provider.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// The count IS the reservation
// ---------------------------------------------------------------------------

/** Records every TPM admission the inference path asks for. */
function spyGovernor(): { readonly admitted: number[]; readonly governor: TokenGovernor } {
  const admitted: number[] = [];
  return {
    admitted,
    governor: {
      admit: async (estimatedTokens: number): Promise<TokenAdmissionHandle | null> => {
        admitted.push(estimatedTokens);
        return null;
      },
      settle: async (): Promise<void> => {},
    },
  };
}

/**
 * Drive `POST /v1/messages` through the inner router with a spying TPM
 * governor published on the request scope — the same seam
 * `inference/route-module.ts` uses in the deployed Worker.
 */
async function reservationFor(
  model: string,
  body: Record<string, unknown>,
): Promise<number | undefined> {
  const spy = spyGovernor();
  const h = harness();
  const request = new Request("https://gw.test/v1/messages", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify({ model, ...body }),
  });
  setInferenceRequestScope(request, { tokens: spy.governor });
  const provider = interceptProviderFetch(() => providerJson(ANTHROPIC_MESSAGE));
  try {
    const res = await h.router.fetch(request);
    expect(res.status).toBe(200);
  } finally {
    provider.restore();
  }
  return spy.admitted[0];
}

describe("the count agrees with the metering reservation", () => {
  for (const { family, model } of FAMILIES) {
    it(`${family}: reservation === input_tokens + max_tokens`, async () => {
      const body = {
        max_tokens: 256,
        system: "be concise",
        messages: [{ role: "user", content: "hi" }],
      };
      const counted = (await (await countTokens(model, body)).json()) as {
        input_tokens: number;
      };
      expect(await reservationFor(model, body)).toBe(counted.input_tokens + 256);
    });

    it(`${family}: reservation === input_tokens + the default completion reservation`, async () => {
      const body = { messages: [{ role: "user", content: "hi" }] };
      const counted = (await (await countTokens(model, body)).json()) as {
        input_tokens: number;
      };
      expect(await reservationFor(model, body)).toBe(
        counted.input_tokens + DEFAULT_COMPLETION_TOKEN_RESERVATION,
      );
    });
  }
});

// ---------------------------------------------------------------------------
// The model gate — same ladder as every other inference operation
// ---------------------------------------------------------------------------

describe("the model gate", () => {
  it("400 model_not_found for a model that does not exist", async () => {
    const res = await countTokens("no-such-model", {
      messages: [{ role: "user", content: "hi" }],
    });
    expect(res.status).toBe(400);
    expect((await errorBody(res)).error.code).toBe("model_not_found");
  });

  it("400 model_disabled for a model that exists but is switched off", async () => {
    const res = await countTokens("retired-model", {
      messages: [{ role: "user", content: "hi" }],
    });
    expect(res.status).toBe(400);
    expect((await errorBody(res)).error.code).toBe("model_disabled");
  });

  it("400 model_not_found for another tenant's private model", async () => {
    // The count endpoint must not become the oracle that tells a tenant which
    // private logical names other tenants have registered (issue #515).
    const res = await harness({ caller: tenantCaller("globex") }, ALL_ROUTES).post(PATH, {
      model: "acme-private",
      messages: [{ role: "user", content: "hi" }],
    });
    expect(res.status).toBe(400);
    expect((await errorBody(res)).error.code).toBe("model_not_found");
  });

  it("403 model_not_allowed when the key's allowlist excludes the model", async () => {
    const res = await harness({
      caller: () => ({ scope: { kind: "platform_operator" }, allowedModels: ["gpt-4o-mini"] }),
    }).post(PATH, { model: "claude-logical", messages: [{ role: "user", content: "hi" }] });
    expect(res.status).toBe(403);
    expect((await errorBody(res)).error.code).toBe("model_not_allowed");
  });
});

// ---------------------------------------------------------------------------
// Request validation
// ---------------------------------------------------------------------------

describe("request validation", () => {
  it("400 invalid_request without a messages array", async () => {
    const res = await countTokens("claude-logical", {});
    expect(res.status).toBe(400);
    const body = await errorBody(res);
    expect(body.error.code).toBe("invalid_request");
    expect(body.error.message).toContain('must include a "messages" array');
  });

  it("400 invalid_json for a body that is not JSON", async () => {
    const res = await harness().post(PATH, "not json");
    expect(res.status).toBe(400);
    expect((await errorBody(res)).error.code).toBe("invalid_json");
  });
});

// ---------------------------------------------------------------------------
// The contract, and the deployed Worker's auth ladder
// ---------------------------------------------------------------------------

describe("contract classification", () => {
  it("is a bearer operation on the messages scope", () => {
    const operation = operationById("countMessageTokens");
    expect(operation?.method).toBe("POST");
    expect(operation?.path).toBe(PATH);
    expect(operation?.visibility).toBe("public");
    expect(operation?.auth.kind).toBe("bearer");
    // Reusing `messages.create` rather than minting a new scope is deliberate:
    // a new scope would 403 every key already provisioned for `/v1/messages`,
    // and a caller able to send a Messages request is by construction able to
    // pre-count one.
    expect(operation?.auth.scope).toBe("messages.create");
  });

  it("is owned by the gateway inference module", () => {
    expect([...INFERENCE_OPERATION_IDS]).toContain("countMessageTokens");
  });
});

describe("the deployed Worker guards it like every other /v1 operation", () => {
  const BASE = "https://ferrogate.test";

  async function post(headers: Record<string, string>): Promise<Response> {
    return await SELF.fetch(`${BASE}${PATH}`, {
      method: "POST",
      headers: { ...headers, "content-type": "application/json" },
      body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "hi" }] }),
    });
  }

  it("401 missing_api_key with no credential — no free counting oracle", async () => {
    const res = await post({});
    expect(res.status).toBe(401);
    expect((await errorBody(res)).error.code).toBe("missing_api_key");
  });

  it("401 invalid_api_key for an unknown credential", async () => {
    const res = await post({ authorization: "Bearer fg_not_a_key" });
    expect(res.status).toBe(401);
    expect((await errorBody(res)).error.code).toBe("invalid_api_key");
  });

  it("403 scope_denied for a credential without messages.create", async () => {
    const res = await post({ authorization: "Bearer fg_tenant_readonly" });
    expect(res.status).toBe(403);
    expect((await errorBody(res)).error.code).toBe("scope_denied");
  });

  it("is MOUNTED — a scoped credential reaches the handler, not a 404", async () => {
    // `fg_root` is the operator static key (every scope). The registry is empty
    // in this suite, so the handler's own `model_not_found` is the mount proof:
    // a guarded-but-unmounted contract path answers 404 `not_found`.
    const res = await post({ authorization: "Bearer fg_root" });
    expect(res.status).toBe(400);
    expect((await errorBody(res)).error.code).toBe("model_not_found");
  });
});
