/**
 * THE STORED TURN IS SCREENED CONTENT — `/v1/responses` conversation state may
 * not become a guardrail bypass (issue #689, audit blocker 1).
 *
 * ## The defect this file exists to catch
 *
 * The turn is decided and served INSIDE the inner inference router
 * (`src/inference/handlers.ts`), and the guardrail RESPONSE stage runs one layer
 * OUT, in `src/guardrails/middleware.ts`, on the way back. Persisting from the
 * inner router therefore filed the PRE-SCREENING bytes: the copy the operator's
 * policy had not yet redacted, and — worse — the copy it was about to refuse
 * outright. `GET /v1/responses/{id}` then handed that copy back, and a
 * continuation replayed it upstream as `input`.
 *
 * Measured before the fix, with these exact two policies:
 *
 *  - a REDACT policy: the caller received `[REDACTED:CREDIT_CARD]`, and the GET
 *    returned the card number;
 *  - a DENY policy: the caller received `403 guardrail_blocked` and never saw
 *    the answer at all, while the full answer sat in `responses_conversations`.
 *
 * That is every guardrail investment on the response stage (#680's PII
 * redaction, #688's injection defence, #703's transcript screening) bypassable
 * by storing a turn and reading it back.
 *
 * ## Why these requests go through `SELF.fetch`
 *
 * The bug is a MOUNT-ORDER bug: which layer holds the bytes when the write
 * happens. A test that drives `createInferenceRouter` by hand cannot see it,
 * because the guardrail middleware is not in that picture at all — which is
 * exactly why the whole conversation suite was green while the bypass was open.
 * So every request below goes `SELF.fetch` → `src/worker.ts` → `src/index.ts`
 * → `GATEWAY_MIDDLEWARE` → `createGatewayApp`, against the committed
 * `wrangler.toml`, with the real `D1ConversationStore` on the real `env.DB`.
 * Only the outbound provider `fetch` is a stand-in.
 *
 * ## What each assertion states
 *
 * Never "the card is gone" alone — that is also true of a store that dropped the
 * turn on the floor. Every leg states the SURVIVING text as well, so a fix that
 * empties the row cannot pass.
 */

import { SELF, env } from "cloudflare:test";
import { PROBE_SECRET } from "@ferrogate/guardrails";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { FINGERPRINT_SECRET_REF, secretScanPolicy } from "../guardrails/fixtures.js";

const BASE = "https://gw.test";
const PROVIDER_HOST = "api.responses-guardrail-probe.example";

/** A synthetic card number, from the same test-data family `#680` uses. */
const CARD = "4111111111111111";

/**
 * The two policies, both RESPONSE-stage and both in `enforce` mode.
 *
 * They are orthogonal by construction so one env can carry both: the PII
 * detector reads card numbers and never matches an AWS key, the deterministic
 * secret scanner reads `aws_access_key_id` and never matches a card. A clean
 * answer passes both, which is what the third leg below needs.
 */
const REDACT_POLICY = secretScanPolicy({
  policyId: "responses-pii-redact",
  stage: "response",
  detector: {
    kind: "pii",
    entities: ["credit_card"],
    redaction: "mask",
    fingerprint_secret_ref: FINGERPRINT_SECRET_REF,
  } as never,
  onFail: [{ kind: "redact", code: "guardrail_redacted", message: "pii redacted" }],
});

const DENY_POLICY = secretScanPolicy({
  policyId: "responses-secret-deny",
  stage: "response",
});

const PROVIDERS = JSON.stringify([
  { name: "probe", kind: "openai", base_url: `https://${PROVIDER_HOST}/v1` },
]);

const MODELS = JSON.stringify([
  { name: "guard-probe", provider: "probe", provider_model: "guard-probe-physical" },
]);

// Tenant-scoped, empty scope set => every data-plane scope and no admin one.
// Tenant-scoped is load-bearing: `conversationOwner` refuses to file state for a
// credential that is not confined to a tenant.
const KEYS = JSON.stringify([
  { key: "fg_conv_guard", id: "key_conv_guard", tenant_id: "tenant_a", scopes: [] },
]);

const OVERRIDES: Record<string, string> = {
  GATEWAY_PROVIDERS: PROVIDERS,
  GATEWAY_MODELS: MODELS,
  GATEWAY_NATIVE_API_KEYS: KEYS,
  // The policies must be on `env` before the FIRST request in this file:
  // `guardrails()` memoizes the compiled engine per `env` object.
  GATEWAY_GUARDRAIL_POLICIES: JSON.stringify([REDACT_POLICY, DENY_POLICY]),
  [FINGERPRINT_SECRET_REF]: "test-fingerprint-key",
};

const ORIGINAL: Record<string, unknown> = {};
const mutable = env as unknown as Record<string, unknown>;
const DB = (env as unknown as { DB: D1Database }).DB;

beforeAll(() => {
  for (const [name, value] of Object.entries(OVERRIDES)) {
    ORIGINAL[name] = mutable[name];
    mutable[name] = value;
  }
});

afterAll(() => {
  for (const [name, value] of Object.entries(ORIGINAL)) {
    mutable[name] = value;
  }
});

beforeEach(async () => {
  await DB.prepare("DELETE FROM responses_conversations").run();
});

/** A `/v1/responses` answer whose single assistant message says `text`. */
function providerAnswer(text: string): Record<string, unknown> {
  return {
    id: "resp_upstream_probe",
    object: "response",
    model: "guard-probe-physical",
    output: [
      {
        type: "message",
        role: "assistant",
        status: "completed",
        content: [{ type: "output_text", text }],
      },
    ],
    usage: { input_tokens: 3, output_tokens: 4, total_tokens: 7 },
  };
}

interface Upstream {
  readonly calls: () => number;
  restore(): void;
}

/** Answer the probe provider with `body`; anything else falls through. */
function stubUpstream(body: Record<string, unknown>): Upstream {
  const original = globalThis.fetch;
  let calls = 0;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (new URL(url).hostname !== PROVIDER_HOST) {
      return await original(input as RequestInfo, init);
    }
    calls += 1;
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  return {
    calls: () => calls,
    restore: () => {
      globalThis.fetch = original;
    },
  };
}

let upstream: Upstream | undefined;

afterEach(() => {
  upstream?.restore();
  upstream = undefined;
});

function createResponse(body: unknown): Promise<Response> {
  return SELF.fetch(`${BASE}/v1/responses`, {
    method: "POST",
    headers: { authorization: "Bearer fg_conv_guard", "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

function getResponse(responseId: string): Promise<Response> {
  return SELF.fetch(`${BASE}/v1/responses/${responseId}`, {
    headers: { authorization: "Bearer fg_conv_guard" },
  });
}

/** Every `response_json` this tenant currently has filed. */
async function storedBodies(): Promise<string[]> {
  const rows = await DB.prepare(
    "SELECT response_id, response_json FROM responses_conversations ORDER BY response_id",
  ).all<{ response_id: string; response_json: string }>();
  return (rows.results ?? []).map((row) => row.response_json);
}

async function storedIds(): Promise<string[]> {
  const rows = await DB.prepare(
    "SELECT response_id FROM responses_conversations ORDER BY response_id",
  ).all<{ response_id: string }>();
  return (rows.results ?? []).map((row) => row.response_id);
}

/** The concatenated `output_text` of a Responses document. */
function outputText(body: unknown): string {
  const output = (body as { output?: unknown }).output;
  if (!Array.isArray(output)) return "";
  let out = "";
  for (const item of output) {
    const content = (item as { content?: unknown }).content;
    if (!Array.isArray(content)) continue;
    for (const part of content) {
      const text = (part as { text?: unknown }).text;
      if (typeof text === "string") out += text;
    }
  }
  return out;
}

describe("a REDACTED turn is stored redacted (#689)", () => {
  it("GET /v1/responses/{id} returns what the caller got, not the un-redacted answer", async () => {
    upstream = stubUpstream(providerAnswer(`your card ${CARD} was charged`));

    const created = await createResponse({
      model: "guard-probe",
      input: "what did you charge",
      store: true,
    });
    expect(created.status).toBe(200);
    const createdBody = (await created.json()) as Record<string, unknown>;
    const responseId = String(createdBody.id);
    expect(responseId).toMatch(/^resp_[0-9a-f]{32}$/);

    // What the caller was served: the card is gone AND the sentence survives.
    expect(outputText(createdBody)).toBe("your card [REDACTED:CREDIT_CARD] was charged");
    expect(JSON.stringify(createdBody)).not.toContain(CARD);
    expect(created.headers.get("x-ferrogate-response-stored")).toBe("true");

    // THE ASSERTION. Before the fix the row held the pre-screening body and this
    // GET handed the card straight back to the same credential the policy had
    // just protected.
    const read = await getResponse(responseId);
    expect(read.status).toBe(200);
    const readBody = await read.json();
    expect(JSON.stringify(readBody)).not.toContain(CARD);
    expect(outputText(readBody)).toBe("your card [REDACTED:CREDIT_CARD] was charged");

    // And at rest: the bytes on disk are the redacted ones, so the leak is not
    // merely filtered on the way out of the GET.
    const stored = await storedBodies();
    expect(stored).toHaveLength(1);
    expect(stored[0]).not.toContain(CARD);
    expect(stored[0]).toContain("[REDACTED:CREDIT_CARD]");
  });

  it("replays the REDACTED transcript upstream on the next turn", async () => {
    upstream = stubUpstream(providerAnswer(`your card ${CARD} was charged`));
    const created = await createResponse({
      model: "guard-probe",
      input: "what did you charge",
      store: true,
    });
    const responseId = String(((await created.json()) as Record<string, unknown>).id);
    upstream.restore();

    // Turn two replays turn one as `input`. Before the fix the un-redacted card
    // went back out to the provider — the precise egress a redact policy exists
    // to stop, performed by the gateway itself.
    let replayed: Record<string, unknown> | undefined;
    const original = globalThis.fetch;
    globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
      if (new URL(url).hostname !== PROVIDER_HOST) {
        return await original(input as RequestInfo, init);
      }
      replayed = JSON.parse(String(init?.body)) as Record<string, unknown>;
      return new Response(JSON.stringify(providerAnswer("noted")), {
        status: 200,
        headers: { "content-type": "application/json" },
      });
    }) as typeof fetch;
    upstream = {
      calls: () => 1,
      restore: () => {
        globalThis.fetch = original;
      },
    };

    const second = await createResponse({
      model: "guard-probe",
      input: "and the one before",
      previous_response_id: responseId,
    });
    expect(second.status).toBe(200);
    expect(JSON.stringify(replayed)).not.toContain(CARD);
    expect(JSON.stringify(replayed)).toContain("[REDACTED:CREDIT_CARD]");
  });
});

describe("a DENIED turn is not stored at all (#689)", () => {
  it("files nothing the caller was refused", async () => {
    upstream = stubUpstream(providerAnswer(`the key is ${PROBE_SECRET}, keep it safe`));

    const created = await createResponse({
      model: "guard-probe",
      input: "what is the key",
      store: true,
    });
    // The caller never saw the answer.
    expect(created.status).toBe(403);
    const refusal = (await created.json()) as { error: { code: string } };
    expect(refusal.error.code).toBe("guardrail_blocked");

    // THE ASSERTION. Before the fix the answer the operator's policy REFUSED was
    // filed verbatim, retained for the whole retention window, and readable by
    // `GET /v1/responses/{id}` — a copy of content that was never delivered.
    expect(await storedIds()).toEqual([]);

    // And the reachability it implies, stated as something that ACTUALLY RUNS.
    // This used to be a loop over `storedIds()` — the list the line above has
    // just proved empty — so the body never executed and it read as coverage it
    // was not. Filing a CLEAN turn afterwards makes the same statement
    // reachable: the store is non-empty, every id in it is readable, and none of
    // them answers with the text the operator refused.
    upstream?.restore();
    upstream = stubUpstream(providerAnswer("nothing to report"));
    const clean = await createResponse({
      model: "guard-probe",
      input: "anything else",
      store: true,
    });
    expect(clean.status).toBe(200);

    const ids = await storedIds();
    expect(ids).toHaveLength(1);
    for (const id of ids) {
      const read = await getResponse(id);
      expect(read.status).toBe(200);
      expect(await read.text()).not.toContain(PROBE_SECRET);
    }
  });
});

describe("a CLEAN turn is unaffected (#689)", () => {
  it("stores and returns the answer verbatim", async () => {
    upstream = stubUpstream(providerAnswer("nothing was charged"));

    const created = await createResponse({
      model: "guard-probe",
      input: "what did you charge",
      store: true,
    });
    expect(created.status).toBe(200);
    const createdBody = (await created.json()) as Record<string, unknown>;
    expect(created.headers.get("x-ferrogate-response-stored")).toBe("true");

    const read = await getResponse(String(createdBody.id));
    expect(read.status).toBe(200);
    expect(outputText(await read.json())).toBe("nothing was charged");
  });
});
