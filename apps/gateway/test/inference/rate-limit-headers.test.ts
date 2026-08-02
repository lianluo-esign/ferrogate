/**
 * THE PACING CONTRACT (#726) — the response headers a throttled client backs
 * off on, on the way OUT of the gateway.
 *
 * A client that cannot see it is being throttled cannot back off, so it retries
 * into the wall and makes the throttling worse. Both official SDKs read
 * `retry-after` / `retry-after-ms` to time their backoff and fall back to a
 * blind exponential schedule without them, and OpenAI documents the
 * `x-ratelimit-*` family as the way a client paces itself BEFORE it is refused.
 *
 * Every assertion below names the header EXACTLY and asserts its VALUE. That is
 * not pedantry: `x-ratelimit-remaining-tokens` is a wire contract, and a test
 * that only asks "was a header set" passes against a relay that emits the wrong
 * name (every SDK's built-in backoff silently does nothing) or the right name
 * carrying a constant zero (every client backs off forever).
 *
 * The suite drives the REAL inference router with only the OUTBOUND provider
 * `fetch` intercepted, so it goes red if the relay is removed from
 * `errors.ts`/`handlers.ts` — not merely if a helper is renamed.
 */
import { describe, expect, it } from "vitest";
import type { PhysicalRoute } from "../../src/inference/index.js";
import { harness } from "./fixtures.js";
import {
  OPENAI_CHAT_STREAM_FRAMES,
  interceptProviderFetch,
  providerSse,
  readBody,
} from "./provider-mock.js";

const MODEL = "relay-model";
const CHAT_BODY = { model: MODEL, messages: [{ role: "user", content: "hi" }] };

const CHAT_OK = {
  id: "chatcmpl-relay",
  object: "chat.completion",
  model: "gpt-4o-mini",
  choices: [{ index: 0, message: { role: "assistant", content: "ok" }, finish_reason: "stop" }],
  usage: { prompt_tokens: 3, completion_tokens: 1, total_tokens: 4 },
};

function route(overrides: Partial<PhysicalRoute> & { provider: string }): PhysicalRoute {
  return {
    logicalModel: MODEL,
    providerModel: "gpt-4o-mini",
    providerKind: "openai",
    baseUrl: `https://${overrides.provider}.test/v1`,
    apiKey: "sk-test",
    enabled: true,
    ...overrides,
  };
}

function providerOf(url: string): string {
  return new URL(url).hostname.replace(/\.test$/, "");
}

/**
 * The exact header set an OpenAI-family provider puts on a 429, values chosen
 * so no two are equal and none is `0` by accident.
 */
const OPENAI_THROTTLE_HEADERS: Record<string, string> = {
  "content-type": "application/json",
  "retry-after": "7",
  "retry-after-ms": "6500",
  "x-ratelimit-limit-requests": "500",
  "x-ratelimit-remaining-requests": "0",
  "x-ratelimit-reset-requests": "7s",
  "x-ratelimit-limit-tokens": "30000",
  "x-ratelimit-remaining-tokens": "12",
  "x-ratelimit-reset-tokens": "1.5s",
};

function throttled(): Response {
  return new Response(JSON.stringify({ error: { message: "slow down", type: "rate_limit_error" } }), {
    status: 429,
    headers: OPENAI_THROTTLE_HEADERS,
  });
}

// ---------------------------------------------------------------------------
// 1. Relayed from the upstream that the caller was actually routed to
// ---------------------------------------------------------------------------

describe("a provider 429 reaches the client with its pacing headers intact", () => {
  it("relays retry-after and every x-ratelimit-* member, by exact name and value", async () => {
    const provider = interceptProviderFetch(() => throttled());
    try {
      const app = harness({}, [route({ provider: "primary" })]);
      const res = await app.post("/v1/chat/completions", CHAT_BODY);

      expect(res.status).toBe(429);
      // Names are asserted one by one rather than as a set: a relay that
      // lower-cased, hyphenated or pluralised one of them differently would
      // still produce "some headers", and every SDK's backoff would go quiet.
      expect(res.headers.get("retry-after")).toBe("7");
      expect(res.headers.get("retry-after-ms")).toBe("6500");
      expect(res.headers.get("x-ratelimit-limit-requests")).toBe("500");
      expect(res.headers.get("x-ratelimit-remaining-requests")).toBe("0");
      expect(res.headers.get("x-ratelimit-reset-requests")).toBe("7s");
      expect(res.headers.get("x-ratelimit-limit-tokens")).toBe("30000");
      // The value the mutation proof turns into a constant: `12`, not `0`.
      expect(res.headers.get("x-ratelimit-remaining-tokens")).toBe("12");
      expect(res.headers.get("x-ratelimit-reset-tokens")).toBe("1.5s");
      // The provider's own error body still survives untouched.
      expect(((await res.json()) as { error: { message: string } }).error.message).toBe(
        "slow down",
      );
    } finally {
      provider.restore();
    }
  });

  it("relays the family on a SUCCESSFUL response too — pacing happens before the 429", async () => {
    const provider = interceptProviderFetch(
      () =>
        new Response(JSON.stringify(CHAT_OK), {
          status: 200,
          headers: {
            "content-type": "application/json",
            "x-ratelimit-limit-requests": "500",
            "x-ratelimit-remaining-requests": "499",
            "x-ratelimit-remaining-tokens": "29873",
          },
        }),
    );
    try {
      const app = harness({}, [route({ provider: "primary" })]);
      const res = await app.post("/v1/chat/completions", CHAT_BODY);

      expect(res.status).toBe(200);
      expect(res.headers.get("x-ratelimit-remaining-requests")).toBe("499");
      expect(res.headers.get("x-ratelimit-remaining-tokens")).toBe("29873");
    } finally {
      provider.restore();
    }
  });

  it("relays the anthropic-ratelimit-* family through the translated /v1/messages body", async () => {
    // `/v1/messages` answers with the gateway's OWN serialization of a
    // translated Message, not the upstream bytes — so the relay has to be on
    // the response builder, not on the "pass the body through" branch alone.
    const provider = interceptProviderFetch(
      () =>
        new Response(
          JSON.stringify({
            id: "msg_relay",
            type: "message",
            role: "assistant",
            model: "claude-3-5-sonnet-20241022",
            content: [{ type: "text", text: "hello" }],
            stop_reason: "end_turn",
            usage: { input_tokens: 7, output_tokens: 3 },
          }),
          {
            status: 200,
            headers: {
              "content-type": "application/json",
              "anthropic-ratelimit-requests-limit": "1000",
              "anthropic-ratelimit-requests-remaining": "998",
              "anthropic-ratelimit-tokens-remaining": "39500",
              "anthropic-ratelimit-requests-reset": "2026-08-02T12:00:00Z",
            },
          },
        ),
    );
    try {
      const res = await harness().post("/v1/messages", {
        model: "claude-logical",
        max_tokens: 64,
        messages: [{ role: "user", content: "hi" }],
      });

      expect(res.status).toBe(200);
      expect(res.headers.get("anthropic-ratelimit-requests-limit")).toBe("1000");
      expect(res.headers.get("anthropic-ratelimit-requests-remaining")).toBe("998");
      expect(res.headers.get("anthropic-ratelimit-tokens-remaining")).toBe("39500");
      expect(res.headers.get("anthropic-ratelimit-requests-reset")).toBe(
        "2026-08-02T12:00:00Z",
      );
    } finally {
      provider.restore();
    }
  });

  it("relays onto a STREAMING response, whose headers are written before the body", async () => {
    const provider = interceptProviderFetch(() => {
      const sse = providerSse(OPENAI_CHAT_STREAM_FRAMES);
      const headers = new Headers(sse.headers);
      headers.set("x-ratelimit-remaining-requests", "17");
      headers.set("retry-after", "3");
      return new Response(sse.body, { status: 200, headers });
    });
    try {
      const app = harness({}, [route({ provider: "primary" })]);
      const res = await app.post("/v1/chat/completions", { ...CHAT_BODY, stream: true });

      expect(res.headers.get("content-type")).toContain("text/event-stream");
      expect(res.headers.get("x-ratelimit-remaining-requests")).toBe("17");
      expect(res.headers.get("retry-after")).toBe("3");
      // The stream itself is untouched by the relay.
      expect(await readBody(res)).toContain("chatcmpl-test");
    } finally {
      provider.restore();
    }
  });

  it("relays ONLY the rate-limit families, and never overwrites a gateway header", async () => {
    // A blanket header copy is the wrong fix: it would hand the caller the
    // upstream's correlation id (breaking `x-request-id` ⇄ body agreement) and
    // whatever else the provider felt like setting.
    const provider = interceptProviderFetch(
      () =>
        new Response(JSON.stringify(CHAT_OK), {
          status: 200,
          headers: {
            "content-type": "application/json",
            "x-ratelimit-remaining-requests": "4",
            "x-request-id": "upstream-req-id",
            "openai-organization": "org-secret",
            "set-cookie": "session=abc",
          },
        }),
    );
    try {
      const app = harness({}, [route({ provider: "primary" })]);
      const res = await app.post("/v1/chat/completions", CHAT_BODY);

      expect(res.headers.get("x-ratelimit-remaining-requests")).toBe("4");
      expect(res.headers.get("openai-organization")).toBeNull();
      expect(res.headers.get("set-cookie")).toBeNull();
      // The gateway's own correlation id wins; it is the one in the body and in
      // the logs, and the upstream's is meaningless to this caller.
      expect(res.headers.get("x-request-id")).toBe("fg-000000000000002a");
    } finally {
      provider.restore();
    }
  });
});

// ---------------------------------------------------------------------------
// 2. After a FAILOVER the numbers describe a route the caller never asked for
// ---------------------------------------------------------------------------

describe("a failover suppresses the upstream numbers instead of misreporting them", () => {
  it("drops the relayed family and says why, when a fallback answered", async () => {
    // The caller asked for `relay-model`. `primary` broke, so `backup`
    // answered — and `backup`'s window is not the window the caller will be
    // measured against next time (the ladder may route them anywhere). Passing
    // `x-ratelimit-remaining-requests: 0` through here would make an SDK back
    // off from a limit it is not actually on.
    const provider = interceptProviderFetch((request) =>
      providerOf(request.url) === "primary"
        ? new Response(JSON.stringify({ error: "overloaded" }), {
            status: 503,
            headers: { "content-type": "application/json" },
          })
        : new Response(JSON.stringify(CHAT_OK), {
            status: 200,
            headers: {
              "content-type": "application/json",
              "x-ratelimit-remaining-requests": "0",
              "x-ratelimit-remaining-tokens": "0",
              "retry-after": "600",
            },
          }),
    );
    try {
      const app = harness({}, [
        route({ provider: "primary", priority: 0 }),
        route({ provider: "backup", priority: 1 }),
      ]);
      const res = await app.post("/v1/chat/completions", CHAT_BODY);

      expect(res.status).toBe(200);
      expect(provider.requests.map((request) => providerOf(request.url))).toEqual([
        "primary",
        "backup",
      ]);
      // NOTHING from the fallback's window reaches the client…
      expect(res.headers.get("retry-after")).toBeNull();
      expect(res.headers.get("x-ratelimit-remaining-requests")).toBeNull();
      expect(res.headers.get("x-ratelimit-remaining-tokens")).toBeNull();
      // …and the omission is stated rather than silent, so an operator reading
      // a client's "no pacing headers" report can tell this apart from a relay
      // that is broken.
      expect(res.headers.get("x-ferrogate-ratelimit-relay")).toBe("suppressed-after-failover");
    } finally {
      provider.restore();
    }
  });

  it("still relays when the FIRST candidate answered, even with a ladder configured", async () => {
    // The suppression must key on "did we fail over", not on "is there more
    // than one candidate" — otherwise every multi-route model loses pacing on
    // every request, which is the defect this issue closes, one layer over.
    //
    // The served response is a 200 rather than a 429 on purpose: a provider 429
    // IS a retryable status, so the ladder would walk past it to `backup` and
    // the answer would legitimately be a failed-over one. Pacing headers on a
    // success are what a client uses to avoid the 429 in the first place.
    const provider = interceptProviderFetch(
      () =>
        new Response(JSON.stringify(CHAT_OK), {
          status: 200,
          headers: {
            "content-type": "application/json",
            "x-ratelimit-limit-requests": "500",
            "x-ratelimit-remaining-requests": "23",
            "x-ratelimit-remaining-tokens": "12",
          },
        }),
    );
    try {
      const app = harness({}, [
        route({ provider: "primary", priority: 0 }),
        route({ provider: "backup", priority: 1 }),
      ]);
      const res = await app.post("/v1/chat/completions", CHAT_BODY);

      expect(res.status).toBe(200);
      expect(provider.requests.map((request) => providerOf(request.url))).toEqual(["primary"]);
      expect(res.headers.get("x-ratelimit-remaining-requests")).toBe("23");
      expect(res.headers.get("x-ratelimit-remaining-tokens")).toBe("12");
      expect(res.headers.get("x-ferrogate-ratelimit-relay")).toBeNull();
    } finally {
      provider.restore();
    }
  });

  it("treats a same-provider RETRY as no failover — it is the caller's own route", async () => {
    // A retry re-dials the SAME provider, so the window the second attempt
    // reports IS the one the caller is on. Only a route change invalidates it.
    let attempts = 0;
    const provider = interceptProviderFetch(() => {
      attempts += 1;
      return attempts === 1
        ? new Response(JSON.stringify({ error: "overloaded" }), {
            status: 503,
            headers: { "content-type": "application/json" },
          })
        : throttled();
    });
    try {
      const app = harness({ reliability: { maxDispatchRetries: 1 } }, [
        route({ provider: "solo" }),
      ]);
      const res = await app.post("/v1/chat/completions", CHAT_BODY);

      expect(attempts).toBe(2);
      expect(provider.requests.map((request) => providerOf(request.url))).toEqual([
        "solo",
        "solo",
      ]);
      expect(res.headers.get("retry-after")).toBe("7");
      expect(res.headers.get("x-ferrogate-ratelimit-relay")).toBeNull();
    } finally {
      provider.restore();
    }
  });
});
