/**
 * `server/dispatch.rs` semantics, driven through the real handler pipeline.
 *
 * Everything asserted here was **declared-but-unread configuration** before this
 * slice: `limits.dispatchTimeoutMs` and `limits.providerResponseMaxBytes` sat on
 * `InferenceLimits`, were defaulted in `defaults.ts`, and no code path read
 * either of them. A gateway that never times a provider out and buffers an
 * unbounded provider body is not a faithful port of a Rust tree that does both
 * — so these tests exist to keep the values load-bearing, not decorative.
 *
 * Only the outbound provider `fetch` is stubbed; the route, the auth-free
 * inference router, the adapter, `dispatchUpstream` and the error envelope are
 * all real.
 */
import { describe, expect, it } from "vitest";
import type { PhysicalRoute } from "../../src/inference/index.js";
import { ALL_ROUTES, errorBody, harness } from "./fixtures.js";
import { interceptProviderFetch, providerJson } from "./provider-mock.js";

const CHAT = {
  model: "gpt-4o-mini",
  messages: [{ role: "user", content: "hi" }],
};

/** A provider `fetch` that never answers until its signal aborts. */
function hangingFetch(onSignal?: (signal: AbortSignal | null | undefined) => void): {
  install(): void;
  restore(): void;
} {
  let original: typeof globalThis.fetch;
  return {
    install(): void {
      original = globalThis.fetch;
      globalThis.fetch = (async (_input: unknown, init?: RequestInit) => {
        const signal = init?.signal;
        onSignal?.(signal);
        return await new Promise<Response>((_resolve, rejectPromise) => {
          if (signal === null || signal === undefined) {
            return;
          }
          if (signal.aborted) {
            rejectPromise(signal.reason);
            return;
          }
          signal.addEventListener(
            "abort",
            () => {
              rejectPromise(signal.reason);
            },
            { once: true },
          );
        });
      }) as typeof globalThis.fetch;
    },
    restore(): void {
      globalThis.fetch = original;
    },
  };
}

/** A body of `size` bytes delivered in `chunkSize` pieces with NO content-length. */
function chunkedBody(size: number, chunkSize: number): ReadableStream<Uint8Array> {
  let sent = 0;
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      if (sent >= size) {
        controller.close();
        return;
      }
      const next = Math.min(chunkSize, size - sent);
      controller.enqueue(new Uint8Array(next).fill(0x61));
      sent += next;
    },
  });
}

describe("provider dispatch deadline (`limits.dispatchTimeoutMs`)", () => {
  it("refuses a provider that does not answer inside the deadline", async () => {
    const provider = hangingFetch();
    provider.install();
    try {
      const h = harness({ limits: { dispatchTimeoutMs: 25 } });
      const res = await h.post("/v1/chat/completions", CHAT);

      expect(res.status).toBe(502);
      const body = await errorBody(res);
      expect(body.error.code).toBe("provider_dispatch_error");
      // `provider_transport_error("provider request failed", err)` renders the
      // class in the message (issue #384) so a refused connection and an
      // elapsed deadline stop collapsing into one indistinct string.
      expect(body.error.message).toBe(
        "provider dispatch failed: provider request failed (timeout)",
      );
    } finally {
      provider.restore();
    }
  });

  it("uses the STREAMING label when the upstream request was a stream", async () => {
    const provider = hangingFetch();
    provider.install();
    try {
      const h = harness({ limits: { dispatchTimeoutMs: 25 } });
      const res = await h.post("/v1/chat/completions", { ...CHAT, stream: true });

      expect(res.status).toBe(502);
      expect((await errorBody(res)).error.message).toBe(
        "provider dispatch failed: provider streaming request failed (timeout)",
      );
    } finally {
      provider.restore();
    }
  });

  it("does not call it a timeout when the CLIENT aborted", async () => {
    const client = new AbortController();
    const provider = hangingFetch(() => {
      // Hang up as soon as the provider call is in flight; the deadline below is
      // long enough that it cannot be what fires.
      client.abort(new DOMException("client hung up", "AbortError"));
    });
    provider.install();
    try {
      const h = harness({ limits: { dispatchTimeoutMs: 60_000 } });
      const res = await h.post("/v1/chat/completions", CHAT, { signal: client.signal });

      expect(res.status).toBe(502);
      expect((await errorBody(res)).error.message).toBe(
        "provider dispatch failed: provider request failed (request)",
      );
    } finally {
      provider.restore();
    }
  });

  it("names the `connect` class for a connection failure", async () => {
    const original = globalThis.fetch;
    globalThis.fetch = (async () => {
      throw new TypeError("Network connection lost.");
    }) as typeof globalThis.fetch;
    try {
      const h = harness();
      const res = await h.post("/v1/chat/completions", CHAT);

      expect(res.status).toBe(502);
      expect((await errorBody(res)).error.message).toBe(
        "provider dispatch failed: provider request failed (connect)",
      );
    } finally {
      globalThis.fetch = original;
    }
  });

  it("keeps the deadline armed AFTER the response headers arrive", async () => {
    // The Rust deadline is a reqwest REQUEST-level timeout: `ProviderBodyStream`
    // says it "keeps covering body reads exactly as before". A port that cleared
    // the timer once `fetch` resolved would let a stalled SSE body run forever.
    let seen: AbortSignal | null | undefined;
    const original = globalThis.fetch;
    globalThis.fetch = (async (_input: unknown, init?: RequestInit) => {
      seen = init?.signal;
      return providerJson({ id: "chatcmpl-1", choices: [] });
    }) as typeof globalThis.fetch;
    try {
      const h = harness({ limits: { dispatchTimeoutMs: 20 } });
      await h.post("/v1/chat/completions", CHAT);
    } finally {
      globalThis.fetch = original;
    }

    expect(seen).toBeInstanceOf(AbortSignal);
    expect(seen?.aborted).toBe(false);
    await new Promise((resolve) => setTimeout(resolve, 60));
    // Still the same signal object, and it fired on its own after the response
    // was already in hand — which is what reaches an in-flight body stream.
    expect(seen?.aborted).toBe(true);
  });
});

describe("provider endpoint scheme (`parse_provider_endpoint`)", () => {
  const FTP_ROUTE: PhysicalRoute = {
    logicalModel: "ftp-model",
    provider: "weird",
    providerModel: "m",
    providerKind: "openai",
    baseUrl: "ftp://files.example/v1",
    enabled: true,
  };

  it("refuses a non-http(s) base_url before opening a socket", async () => {
    let called = false;
    const original = globalThis.fetch;
    globalThis.fetch = (async () => {
      called = true;
      return providerJson({});
    }) as typeof globalThis.fetch;
    try {
      const h = harness({}, [...ALL_ROUTES, FTP_ROUTE]);
      const res = await h.post("/v1/chat/completions", { ...CHAT, model: "ftp-model" });

      expect(res.status).toBe(502);
      expect((await errorBody(res)).error.message).toBe(
        "provider dispatch failed: provider dispatch supports http and https endpoints only, got ftp",
      );
      // `build_provider_request` parses BEFORE it sends; nothing goes out.
      expect(called).toBe(false);
    } finally {
      globalThis.fetch = original;
    }
  });
});

describe("bounded provider response body (`limits.providerResponseMaxBytes`)", () => {
  it("refuses on a DECLARED oversized Content-Length even when the body is small", async () => {
    // The `Content-Length` pre-check is a separate guard from the accumulating
    // one and has to be pinned separately, or deleting it would stay green (the
    // accumulating check would catch a genuinely-oversized body anyway). The
    // only body that isolates it is one that DECLARES too much and delivers
    // little — which Rust refuses on the header alone, before reading a byte.
    const provider = interceptProviderFetch(
      () =>
        new Response("{}", {
          headers: { "content-type": "application/json", "content-length": "4096" },
        }),
    );
    try {
      const h = harness({ limits: { providerResponseMaxBytes: 1024 } });
      const res = await h.post("/v1/chat/completions", CHAT);

      expect(res.status).toBe(502);
      const body = await errorBody(res);
      expect(body.error.code).toBe("provider_dispatch_error");
      expect(body.error.message).toBe(
        "provider dispatch failed: provider_response_body_too_large: provider response body exceeds 1024 bytes",
      );
    } finally {
      provider.restore();
    }
  });

  it("refuses a CHUNKED body that never declares its length", async () => {
    // This is the case the Rust comment says the post-read length check did NOT
    // protect against: no `Content-Length`, so only the accumulating check can
    // stop unbounded buffering.
    const provider = interceptProviderFetch(
      () =>
        new Response(chunkedBody(8192, 256), {
          headers: { "content-type": "application/json" },
        }),
    );
    try {
      const h = harness({ limits: { providerResponseMaxBytes: 1024 } });
      const res = await h.post("/v1/chat/completions", CHAT);

      expect(res.status).toBe(502);
      expect((await errorBody(res)).error.message).toBe(
        "provider dispatch failed: provider_response_body_too_large: provider response body exceeds 1024 bytes",
      );
    } finally {
      provider.restore();
    }
  });

  it("refuses an oversized provider ERROR body instead of relaying it", async () => {
    // Order matters: in Rust the cap is enforced inside `dispatch_provider_request`,
    // i.e. before the status is ever inspected.
    const provider = interceptProviderFetch(
      () =>
        new Response(chunkedBody(8192, 256), {
          status: 400,
          headers: { "content-type": "application/json" },
        }),
    );
    try {
      const h = harness({ limits: { providerResponseMaxBytes: 1024 } });
      const res = await h.post("/v1/chat/completions", CHAT);

      expect(res.status).toBe(502);
      expect((await errorBody(res)).error.code).toBe("provider_dispatch_error");
    } finally {
      provider.restore();
    }
  });

  it("passes a body that fits through untouched", async () => {
    const completion = {
      id: "chatcmpl-ok",
      choices: [{ index: 0, message: { role: "assistant", content: "hi" } }],
    };
    const provider = interceptProviderFetch(() => providerJson(completion));
    try {
      const h = harness({ limits: { providerResponseMaxBytes: 1024 } });
      const res = await h.post("/v1/chat/completions", CHAT);

      expect(res.status).toBe(200);
      expect(await res.json()).toEqual(completion);
    } finally {
      provider.restore();
    }
  });

  it("applies the cap on `/v1/embeddings` too, not only on chat", async () => {
    const provider = interceptProviderFetch(
      () =>
        new Response(chunkedBody(8192, 256), {
          headers: { "content-type": "application/json" },
        }),
    );
    try {
      const h = harness({ limits: { providerResponseMaxBytes: 1024 } });
      const res = await h.post("/v1/embeddings", { model: "text-embed", input: "hi" });

      expect(res.status).toBe(502);
      expect((await errorBody(res)).error.code).toBe("provider_dispatch_error");
    } finally {
      provider.restore();
    }
  });
});
