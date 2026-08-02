/**
 * WHY A REQUEST WAS NOT SAMPLED (#692) — the diagnostics an empty score table is
 * read with.
 *
 * `test/evals/enforcement.test.ts` proves the OUTCOME ("nothing was queued")
 * through the deployed chain, which is the property that matters to a customer.
 * This file proves the REASON, which is the property that matters to whoever has
 * to answer "why are there no scores?" — and the two are not the same claim: a
 * pipeline that skipped everything for one wrong reason would satisfy the first
 * and be useless.
 *
 * It drives the same middleware with a LOCAL sink, because the deployed sink is
 * module scope in `src/index.ts` and its counters are (correctly) not exported.
 *
 * ## MUTATION LOG
 *
 * | mutation (in `src/`)                                       | red |
 * |--------------------------------------------------------------|-----|
 * | `middleware.ts`: drop the `evaluableResponse` guard           | `names a streamed response as never having been a candidate` (the reason became `content_not_extractable`) |
 * | `policy.ts`: both ZDR arms deleted                            | `names the ZDR exclusion, so an operator can tell it from an empty sample` |
 * | `middleware.ts`: `peek` replaced by a synchronous default     | `names a cold isolate rather than blaming the policy` |
 */
import { afterEach, describe, expect, it } from "vitest";

import {
  type OnlineEvalPolicySource,
  createOnlineEvalSink,
  onlineEvalPolicySourceFromVars,
  onlineEvaluation,
} from "../../src/evals/index.js";
import { GATEWAY_MIDDLEWARE } from "../../src/index.js";
import { InMemoryModelResolver, inferenceRouteModule } from "../../src/inference/index.js";
import { createGatewayApp } from "../../src/routes/index.js";
import { OPENAI_ROUTE } from "../inference/fixtures.js";
import {
  type ProviderInterceptor,
  interceptProviderFetch,
  providerJson,
  providerSse,
} from "../inference/provider-mock.js";

const CRITERIA = [{ id: "grounded", definition: "Is it supported by the context?" }];

const POLICY = {
  tenant_id: "tenant_a",
  enabled: true,
  sample_rate: 1,
  judge_model: "judge-model",
  criteria: CRITERIA,
};

let provider: ProviderInterceptor | undefined;

afterEach(() => {
  provider?.restore();
  provider = undefined;
});

function answers(text = "Paris."): void {
  provider = interceptProviderFetch(() =>
    providerJson({
      id: "chatcmpl-1",
      object: "chat.completion",
      choices: [{ index: 0, message: { role: "assistant", content: text } }],
    }),
  );
}

function streams(): void {
  provider = interceptProviderFetch(() =>
    providerSse([
      'data: {"id":"1","object":"chat.completion.chunk","choices":[{"delta":{"content":"Paris."}}]}',
      "data: [DONE]",
    ]),
  );
}

/**
 * The deployed chain PLUS one more `onlineEvaluation`, wired to a sink this
 * test can read.
 *
 * The second mount is harmless — each instance decides independently and both
 * write to their own sink — and it is what lets the reason be observed without
 * exporting the deployed sink's counters, which would be a production API added
 * for a test.
 */
async function skipsFor(
  body: unknown,
  options: {
    readonly policies?: readonly Record<string, unknown>[];
    readonly residency?: readonly Record<string, unknown>[];
    readonly source?: OnlineEvalPolicySource;
  } = {},
): Promise<Record<string, number>> {
  const sink = createOnlineEvalSink();
  const env = {
    GATEWAY_NATIVE_API_KEYS: JSON.stringify([{ key: "fg_a", id: "key_a", tenant_id: "tenant_a" }]),
    GATEWAY_ONLINE_EVAL_POLICIES: JSON.stringify(options.policies ?? [POLICY]),
    ...(options.residency === undefined
      ? {}
      : { GATEWAY_RESIDENCY_POLICIES: JSON.stringify(options.residency) }),
    ONLINE_EVAL: { async send(): Promise<void> {}, async sendBatch(): Promise<void> {} },
  };
  const { app } = createGatewayApp({
    modules: [
      inferenceRouteModule({
        models: new InMemoryModelResolver([{ ...OPENAI_ROUTE, zeroDataRetention: true }]),
      }),
    ],
    middleware: [
      ...GATEWAY_MIDDLEWARE,
      onlineEvaluation(sink, options.source === undefined ? {} : { policies: options.source }),
    ],
  });

  const response = await app.request(
    "https://gw.test/v1/chat/completions",
    {
      method: "POST",
      headers: { authorization: "Bearer fg_a", "content-type": "application/json" },
      body: JSON.stringify(body),
    },
    env,
  );
  await response.text();
  await new Promise((resolve) => setTimeout(resolve, 25));
  return sink.stats.skipped as Record<string, number>;
}

const CHAT = { model: "gpt-4o-mini", messages: [{ role: "user", content: "capital of France?" }] };

describe("every non-sample says WHY", () => {
  it("names the tenant that never opted in", async () => {
    answers();
    expect(await skipsFor(CHAT, { policies: [] })).toEqual({ not_opted_in: 1 });
  });

  it("names the ZDR exclusion, so an operator can tell it from an empty sample", async () => {
    // The distinction this holds: `zero_data_retention` is a DELIBERATE
    // exclusion, `not_in_sample` is the sampler working. Collapsing them would
    // make a compliance decision look like arithmetic.
    answers();
    expect(
      await skipsFor(CHAT, {
        residency: [{ tenant_id: "tenant_a", require_zero_data_retention: true }],
      }),
    ).toEqual({ zero_data_retention: 1 });
  });

  it("names a streamed response as never having been a candidate", async () => {
    // NOT `content_not_extractable`: a streamed response is a deployment
    // property (this gateway does not evaluate SSE), while an unreadable body
    // is a gap in the extractor. On a deployment that streams everything, one
    // shared counter would hide the second inside the first forever.
    streams();
    expect(await skipsFor({ ...CHAT, stream: true })).toEqual({ response_not_evaluable: 1 });
  });

  it("names a cold isolate rather than blaming the policy", async () => {
    // The request path takes NO I/O, so a memo that has not been warmed yet
    // yields `policy_not_warm` — which is the honest answer, and a different
    // one from "this tenant did not opt in".
    answers();
    const cold: OnlineEvalPolicySource = {
      async policyFor() {
        return { ok: true, policy: null };
      },
      peek() {
        return undefined;
      },
    };
    expect(await skipsFor(CHAT, { source: cold })).toEqual({ policy_not_warm: 1 });
  });

  it("names an unreadable policy as a bug, not as an opt-out", async () => {
    const broken: OnlineEvalPolicySource = {
      async policyFor() {
        return { ok: false, detail: "D1_ERROR: network" };
      },
      peek() {
        return { ok: false, detail: "D1_ERROR: network" };
      },
    };
    answers();
    expect(await skipsFor(CHAT, { source: broken })).toEqual({ policy_unreadable: 1 });
  });

  it("counts nothing at all when the request IS sampled", async () => {
    // The control: without it, a sampler that skipped everything for one wrong
    // reason would satisfy every case above.
    answers();
    expect(
      await skipsFor(CHAT, {
        source: onlineEvalPolicySourceFromVars({
          GATEWAY_ONLINE_EVAL_POLICIES: JSON.stringify([POLICY]),
        }),
      }),
    ).toEqual({});
  });
});
