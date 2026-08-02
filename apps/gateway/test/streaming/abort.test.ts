import { describe, expect, test } from "vitest";

import {
  CLIENT_DISCONNECT_REASON,
  abortOnCancel,
  createUpstreamAbort,
  dispatchStreamingUpstream,
  linkAbortSignal,
} from "../../src/streaming/abort.js";
import { openAiToAnthropicStream } from "../../src/streaming/anthropic.js";
import { bytes } from "./helpers.js";

/** A stream that never ends — the shape of a live provider response. */
function endlessStream(onCancel?: () => void): ReadableStream<Uint8Array> {
  return new ReadableStream<Uint8Array>({
    pull(controller) {
      controller.enqueue(bytes('data: {"choices":[{"delta":{"content":"x"}}]}\n\n'));
    },
    cancel() {
      onCancel?.();
    },
  });
}

describe("linkAbortSignal", () => {
  test("forwards an abort from the client signal to the upstream controller", () => {
    const client = new AbortController();
    const upstream = new AbortController();
    linkAbortSignal(client.signal, upstream);
    expect(upstream.signal.aborted).toBe(false);
    client.abort();
    expect(upstream.signal.aborted).toBe(true);
  });

  test("fires synchronously when the client already hung up", () => {
    const client = new AbortController();
    client.abort();
    const upstream = new AbortController();
    linkAbortSignal(client.signal, upstream);
    expect(upstream.signal.aborted).toBe(true);
  });

  test("unsubscribing stops the forwarding (no listener leak)", () => {
    const client = new AbortController();
    const upstream = new AbortController();
    linkAbortSignal(client.signal, upstream)();
    client.abort();
    expect(upstream.signal.aborted).toBe(false);
  });

  test("an absent client signal is a no-op", () => {
    const upstream = new AbortController();
    expect(() => linkAbortSignal(undefined, upstream)()).not.toThrow();
    expect(upstream.signal.aborted).toBe(false);
  });
});

describe("createUpstreamAbort", () => {
  test("the returned signal aborts when the client disconnects", () => {
    const client = new AbortController();
    const abort = createUpstreamAbort(client.signal);
    expect(abort.aborted).toBe(false);
    client.abort();
    expect(abort.aborted).toBe(true);
    expect(abort.signal.aborted).toBe(true);
  });

  test("can be aborted explicitly (guardrail veto / budget exhaustion)", () => {
    const abort = createUpstreamAbort();
    abort.abort();
    expect(abort.signal.aborted).toBe(true);
    // Idempotent.
    expect(() => abort.abort()).not.toThrow();
  });
});

describe("abortOnCancel", () => {
  test("cancelling the client-facing stream aborts the upstream fetch", async () => {
    const controller = new AbortController();
    let upstreamCancelled = false;
    const wrapped = abortOnCancel(
      endlessStream(() => {
        upstreamCancelled = true;
      }),
      controller,
    );

    const reader = wrapped.getReader();
    await reader.read();
    expect(controller.signal.aborted).toBe(false);

    await reader.cancel("client went away");

    expect(controller.signal.aborted).toBe(true);
    expect(upstreamCancelled).toBe(true);
  });

  test("normal completion does NOT abort the upstream", async () => {
    const controller = new AbortController();
    const wrapped = abortOnCancel(
      new ReadableStream<Uint8Array>({
        start(target) {
          target.enqueue(bytes("data: ok\n\n"));
          target.close();
        },
      }),
      controller,
    );
    const reader = wrapped.getReader();
    for (;;) {
      const { done } = await reader.read();
      if (done) {
        break;
      }
    }
    expect(controller.signal.aborted).toBe(false);
  });

  test("cancellation propagates through the normalization pipeline", async () => {
    const controller = new AbortController();
    let upstreamCancelled = false;
    const body = abortOnCancel(
      endlessStream(() => {
        upstreamCancelled = true;
      }),
      controller,
    ).pipeThrough(openAiToAnthropicStream({ fallbackModel: "claude-logical" }));

    const reader = body.getReader();
    await reader.read();
    await reader.cancel(CLIENT_DISCONNECT_REASON);
    // Give the pipe a turn to unwind to the source.
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(controller.signal.aborted).toBe(true);
    expect(upstreamCancelled).toBe(true);
  });

  test("an upstream error surfaces to the reader instead of hanging", async () => {
    const controller = new AbortController();
    const wrapped = abortOnCancel(
      new ReadableStream<Uint8Array>({
        pull(target) {
          target.error(new Error("upstream exploded"));
        },
      }),
      controller,
    );
    await expect(wrapped.getReader().read()).rejects.toThrow("upstream exploded");
  });
});

describe("dispatchStreamingUpstream", () => {
  test("passes a managed signal to fetch and aborts it on client cancel", async () => {
    let seen: AbortSignal | undefined;
    const upstream = await dispatchStreamingUpstream({
      url: "https://provider.test/v1/chat/completions",
      init: { method: "POST" },
      fetchImpl: (_input, init) => {
        seen = init?.signal ?? undefined;
        return Promise.resolve(new Response(endlessStream()));
      },
    });

    expect(seen).toBeDefined();
    expect(seen!.aborted).toBe(false);

    const reader = upstream.body!.getReader();
    await reader.read();
    await reader.cancel();

    expect(seen!.aborted).toBe(true);
    expect(upstream.abort.aborted).toBe(true);
  });

  test("a client that disconnects mid-flight aborts the provider fetch", async () => {
    const client = new AbortController();
    let seen: AbortSignal | undefined;
    const upstream = await dispatchStreamingUpstream({
      url: "https://provider.test/v1/messages",
      clientSignal: client.signal,
      fetchImpl: (_input, init) => {
        seen = init?.signal ?? undefined;
        return Promise.resolve(new Response(endlessStream()));
      },
    });
    expect(upstream.response.ok).toBe(true);

    client.abort();

    expect(seen!.aborted).toBe(true);
    expect(upstream.abort.aborted).toBe(true);
  });

  test("a body-less provider response yields a null body, not a throw", async () => {
    const upstream = await dispatchStreamingUpstream({
      url: "https://provider.test/v1/models",
      fetchImpl: () => Promise.resolve(new Response(null, { status: 204 })),
    });
    expect(upstream.body).toBeNull();
  });

  test("a fetch rejection cleans up the client-signal listener", async () => {
    const client = new AbortController();
    await expect(
      dispatchStreamingUpstream({
        url: "https://provider.test/v1/chat/completions",
        clientSignal: client.signal,
        fetchImpl: () => Promise.reject(new Error("connect failed")),
      }),
    ).rejects.toThrow("connect failed");
  });
});
