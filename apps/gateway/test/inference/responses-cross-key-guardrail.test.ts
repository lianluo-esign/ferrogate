/**
 * THE CONVERSATION FENCE IS WIDER THAN THE POLICY FENCE — `GET /v1/responses/{id}`
 * across two credentials of one tenant (issue #689, re-audit blocker).
 *
 * ## The defect this file exists to catch
 *
 * Persisting the turn ABOVE the guardrail response stage
 * (`src/inference/conversation-commit.ts`) makes the stored bytes byte-for-byte
 * the bytes the WRITER received. That closed the original bypass, and the
 * justification for leaving `getResponse` unscreened was written on top of it:
 * every byte the operation can serve is one "the response stage approved and
 * this credential already holds".
 *
 * The second half of that sentence is false, and the two fences are why:
 *
 *  - conversation state is fenced on `(tenantId, projectId)` —
 *    `src/inference/conversation.ts::conversationOwner`;
 *  - guardrail policy scope is fenced per KEY — `api_key_ids` in
 *    `packages/guardrails/src/policy.ts`, selected from `auth.subject` and
 *    ranked MOST SPECIFIC of all the administrative scopes.
 *
 * So two credentials of one project share one conversation store while sitting
 * under DIFFERENT policies. The response stage approved the stored bytes *for
 * the writer*. The reader does not already hold them.
 *
 * Measured before the fix, with the exact fixture below — one redact policy
 * scoped to `key_conv_b` alone:
 *
 *  - key B creates a turn: the card is redacted (B's policy is live);
 *  - key A creates a turn: no policy binds A, so it is stored verbatim, which
 *    is correct;
 *  - **key B `GET /v1/responses/{A's id}` answered 200 with the card** — a byte
 *    B's own live policy would have redacted, handed to B by a route that was
 *    marked "already screened".
 *
 * The fix is to bind `getResponse` at the RESPONSE stage in
 * `GUARDRAIL_OPERATIONS`. It is a complement to the write-side fix, not a
 * substitute for it: the write-side fix is what keeps a DENIED turn off disk and
 * what keeps a same-key continuation from replaying un-redacted text upstream,
 * and it is O(1)-per-turn; this binding is one screening pass over one stored
 * document on a read that would otherwise be free.
 *
 * ## The residual this file does NOT close, stated so it is not mistaken for covered
 *
 * A continuation — key B posting `previous_response_id` addressing A's turn —
 * replays A's stored text UPSTREAM as `input`, and binding `getResponse` does
 * nothing about that. It cannot: the chain is assembled INSIDE the inner
 * inference router, after `guardrails()` has already run its request stage on
 * the client's own body, so the assembled document is not visible to the
 * screener at any point before it is dispatched. Closing it means screening at
 * the point of assembly, which is a change inside the router and a different
 * cost argument (O(foreign turns) rather than O(1)). Tracked as #779, which
 * carries the measured upstream body; see also the note in
 * `src/guardrails/middleware.ts` on the `getResponse` binding.
 *
 * ## Why these requests go through `SELF.fetch`
 *
 * Same reason as `responses-guardrail-bypass.test.ts`: the property under test
 * is a WIRING property — which operations the composed Worker screens — and a
 * test that drives the inference router by hand cannot see the middleware at
 * all. Every request below goes `SELF.fetch` → `src/worker.ts` → `src/index.ts`
 * → `GATEWAY_MIDDLEWARE` → `createGatewayApp`, against the committed
 * `wrangler.toml`, with the real `D1ConversationStore` on the real `env.DB`.
 * Only the outbound provider `fetch` is a stand-in.
 */
import { SELF, env } from "cloudflare:test";
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { FINGERPRINT_SECRET_REF, secretScanPolicy } from "../guardrails/fixtures.js";

const BASE = "https://gw.test";
const PROVIDER_HOST = "api.responses-crosskey-probe.example";

/** A synthetic card number, from the same test-data family `#680` uses. */
const CARD = "4111111111111111";

const KEY_A = "fg_conv_key_a";
const KEY_B = "fg_conv_key_b";

/**
 * ONE policy, RESPONSE stage, redact, scoped to key B and nothing else.
 *
 * `api_key_ids` is the narrowest administrative scope the selector has, so this
 * is the sharpest possible statement of "B is governed and A is not" — which is
 * exactly the operator posture the unscreened-`getResponse` exception assumed
 * could not exist.
 */
const REDACT_FOR_B_ONLY = secretScanPolicy({
  policyId: "responses-crosskey-redact",
  stage: "response",
  scope: { api_key_ids: ["key_conv_b"] },
  detector: {
    kind: "pii",
    entities: ["credit_card"],
    redaction: "mask",
    fingerprint_secret_ref: FINGERPRINT_SECRET_REF,
  } as never,
  onFail: [{ kind: "redact", code: "guardrail_redacted", message: "pii redacted" }],
});

const PROVIDERS = JSON.stringify([
  { name: "probe", kind: "openai", base_url: `https://${PROVIDER_HOST}/v1` },
]);

const MODELS = JSON.stringify([
  { name: "crosskey-probe", provider: "probe", provider_model: "crosskey-probe-physical" },
]);

/**
 * TWO keys, ONE tenant, no project on either — so `conversationOwner` resolves
 * the SAME `(tenant_a, "")` owner for both and they genuinely share one store.
 * That shared fence is the premise; if a future change narrows it, the "key B
 * reads A's turn" legs below stop being reachable and go red rather than silent.
 */
const KEYS = JSON.stringify([
  { key: KEY_A, id: "key_conv_a", tenant_id: "tenant_a", scopes: [] },
  { key: KEY_B, id: "key_conv_b", tenant_id: "tenant_a", scopes: [] },
]);

const OVERRIDES: Record<string, string> = {
  GATEWAY_PROVIDERS: PROVIDERS,
  GATEWAY_MODELS: MODELS,
  GATEWAY_NATIVE_API_KEYS: KEYS,
  // Must be on `env` before the FIRST request in this file: `guardrails()`
  // memoizes the compiled engine per `env` object.
  GATEWAY_GUARDRAIL_POLICIES: JSON.stringify([REDACT_FOR_B_ONLY]),
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
    id: "resp_upstream_crosskey",
    object: "response",
    model: "crosskey-probe-physical",
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
  restore(): void;
}

/** Answer the probe provider with `body`; anything else falls through. */
function stubUpstream(body: Record<string, unknown>): Upstream {
  const original = globalThis.fetch;
  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = typeof input === "string" ? input : input instanceof URL ? input.href : input.url;
    if (new URL(url).hostname !== PROVIDER_HOST) {
      return await original(input as RequestInfo, init);
    }
    return new Response(JSON.stringify(body), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  }) as typeof fetch;
  return { restore: () => void (globalThis.fetch = original) };
}

let upstream: Upstream | undefined;

afterEach(() => {
  upstream?.restore();
  upstream = undefined;
});

function createResponse(key: string, body: unknown): Promise<Response> {
  return SELF.fetch(`${BASE}/v1/responses`, {
    method: "POST",
    headers: { authorization: `Bearer ${key}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
}

function readResponse(key: string, responseId: string): Promise<Response> {
  return SELF.fetch(`${BASE}/v1/responses/${responseId}`, {
    headers: { authorization: `Bearer ${key}` },
  });
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

/** Key A files one turn carrying the card, and it is stored VERBATIM. */
async function storeVerbatimTurnAsKeyA(): Promise<string> {
  upstream = stubUpstream(providerAnswer(`your card ${CARD} was charged`));
  const created = await createResponse(KEY_A, {
    model: "crosskey-probe",
    input: "what did you charge",
    store: true,
  });
  expect(created.status).toBe(200);
  const body = (await created.json()) as Record<string, unknown>;
  // A is UNGOVERNED: the policy names key B only, so A both receives and files
  // the card. That is the correct behaviour for A, and it is the premise of
  // every assertion below rather than a defect — a fix that redacted here would
  // be enforcing B's policy on A's traffic.
  expect(outputText(body)).toBe(`your card ${CARD} was charged`);
  expect(created.headers.get("x-ferrogate-response-stored")).toBe("true");

  const rows = await DB.prepare(
    "SELECT response_json FROM responses_conversations WHERE response_id = ?",
  )
    .bind(String(body["id"]))
    .all<{ response_json: string }>();
  expect(rows.results ?? []).toHaveLength(1);
  expect((rows.results ?? [])[0]?.response_json).toContain(CARD);

  upstream.restore();
  upstream = undefined;
  return String(body["id"]);
}

describe("the redact policy really is scoped to key B (#689)", () => {
  it("redacts what B creates and leaves what A creates alone", async () => {
    // The control leg, and it is not decoration: without it "B's GET came back
    // redacted" is also satisfied by a policy that matches nobody and a GET that
    // returns nothing, and "A's turn is verbatim" is also satisfied by a policy
    // whose detector never fires. Both directions are stated here so the
    // cross-key assertion below can only pass for the right reason.
    upstream = stubUpstream(providerAnswer(`your card ${CARD} was charged`));
    const asB = await createResponse(KEY_B, {
      model: "crosskey-probe",
      input: "what did you charge",
      store: true,
    });
    expect(asB.status).toBe(200);
    const bBody = (await asB.json()) as Record<string, unknown>;
    expect(outputText(bBody)).toBe("your card [REDACTED:CREDIT_CARD] was charged");
    expect(JSON.stringify(bBody)).not.toContain(CARD);
    upstream.restore();
    upstream = undefined;

    // And the other direction, which is what makes the policy SCOPED rather
    // than global.
    const aId = await storeVerbatimTurnAsKeyA();
    expect(aId).toMatch(/^resp_[0-9a-f]{32}$/);
  });
});

describe("GET /v1/responses/{id} is screened under the READER's policy (#689)", () => {
  it("does not hand key B a card key B's own policy redacts", async () => {
    const aId = await storeVerbatimTurnAsKeyA();

    // THE ASSERTION. The conversation fence is `(tenant_a, "")`, which both keys
    // share, so B addresses A's row and the store is right to serve it. What was
    // wrong was serving it UNSCREENED: `getResponse` was on the unscreened list
    // on the argument that its bytes were already approved for this credential,
    // and they were approved for A.
    const read = await readResponse(KEY_B, aId);
    expect(read.status).toBe(200);
    const readBody = (await read.json()) as Record<string, unknown>;
    expect(JSON.stringify(readBody)).not.toContain(CARD);
    // Never "the card is gone" alone — that is also true of a route that
    // started answering with an empty document. The sentence has to survive.
    expect(outputText(readBody)).toBe("your card [REDACTED:CREDIT_CARD] was charged");
  });

  it("still serves key A its own turn verbatim", async () => {
    const aId = await storeVerbatimTurnAsKeyA();

    // The anti-blanket leg. A fix that screened the read under a policy set
    // resolved from anything other than the READER — or that redacted every
    // stored turn on the way out — would pass the assertion above and be wrong:
    // no policy binds A, so A must still see A's own bytes. Screening a read is
    // only correct if it selects policies exactly the way every other stage
    // does, from `auth.subject`.
    const read = await readResponse(KEY_A, aId);
    expect(read.status).toBe(200);
    expect(outputText(await read.json())).toBe(`your card ${CARD} was charged`);
  });

  it("leaves the row on disk untouched — the read is screened, not rewritten", async () => {
    const aId = await storeVerbatimTurnAsKeyA();
    await readResponse(KEY_B, aId);

    // Screening the READ must not mutate what was stored. If it did, A's next
    // continuation would silently inherit B's policy, and a shared store would
    // become order-dependent: whichever credential read the turn first would
    // decide what every other credential sees.
    const rows = await DB.prepare(
      "SELECT response_json FROM responses_conversations WHERE response_id = ?",
    )
      .bind(aId)
      .all<{ response_json: string }>();
    expect((rows.results ?? [])[0]?.response_json).toContain(CARD);
  });

  it("does not screen a 404 into a 200", async () => {
    // The response stage returns early for `status >= 400`, and that early
    // return is what keeps the refusal envelope intact. Worth a leg because a
    // redaction pass over an error body would rewrite the code the caller is
    // told, and because the 404 here is the tenant-fence answer.
    const missing = await readResponse(KEY_B, "resp_00000000000000000000000000000000");
    expect(missing.status).toBe(404);
    const body = (await missing.json()) as { error: { code: string } };
    expect(body.error.code).toBe("previous_response_not_found");
  });
});
