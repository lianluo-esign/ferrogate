/**
 * The unified client session's Durable Object and its resume cursor (#687).
 *
 * `test/unified-session-wire.test.ts` holds the ingress contract over the real
 * Worker. This file holds the two things that file cannot reach:
 *
 *  1. **The cursor's parsing rules**, which are strict on purpose. Every
 *     lenient reading of a resume cursor ends with a client resuming from a
 *     point it did not ask for and believing it has the whole history.
 *  2. **The retention boundary**, exercised by actually overflowing the log.
 *     This is the case that separates a real replay from a plausible one: once
 *     the frames after a cursor have been pruned, the only honest answers are
 *     "refuse" and "hand back a history with a hole in it", and a client cannot
 *     tell the second one from a complete answer.
 *
 * The Durable Object is driven through the REAL `env.MCP_CLIENT_SESSION`
 * namespace booted by `@cloudflare/vitest-pool-workers` in workerd — the same
 * implementation `wrangler dev --local` runs. No fake store.
 */
import { env } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import { MULTIPLEX_DEGRADED_META } from "../src/multiplex.js";
import {
  type DispatchContext,
  type McpPorts,
  type McpServerConfig,
  inMemoryPorts,
  resetInMemoryPorts,
} from "../src/ports.js";
import { MCP_PROTOCOL_VERSION } from "../src/protocol.js";
import { toolsList } from "../src/tools.js";
import { HttpMcpUpstreams } from "../src/transport.js";
import { attributionSink } from "../src/unified-ingress.js";
import {
  MAX_RETAINED_FRAMES,
  UnifiedSessionStore,
  clientSessionKey,
  mintSessionId,
  parseUnifiedCursor,
  unifiedCursorToken,
} from "../src/unified.js";
import { tenantAuth } from "./fixtures.js";

const NAMESPACE = env.MCP_CLIENT_SESSION as NonNullable<typeof env.MCP_CLIENT_SESSION>;

/** A store for one tenant. Two with the same tenant model two isolates. */
function store(tenantId: string): UnifiedSessionStore {
  return new UnifiedSessionStore(NAMESPACE, tenantId);
}

// ---------------------------------------------------------------------------
// The cursor
// ---------------------------------------------------------------------------

describe("the resume cursor parses strictly or not at all", () => {
  it("round-trips a well-formed cursor", () => {
    const token = unifiedCursorToken("sess-1", 42);
    expect(token).toBe("42:sess-1");
    expect(parseUnifiedCursor(token)).toEqual({ seq: 42, sessionId: "sess-1" });
  });

  it("keeps a session id containing colons intact", () => {
    // Only the FIRST colon separates, so a session id is never truncated into a
    // different session's id — which would be a silent cross-session resume.
    expect(parseUnifiedCursor("7:a:b:c")).toEqual({ seq: 7, sessionId: "a:b:c" });
  });

  it("refuses every near-miss a lenient parser would accept", () => {
    for (const raw of [
      "12abc:s", // `Number.parseInt` would read 12
      "1e3:s", // ...and 1
      "0x10:s", // ...and 0
      "-1:s", // a sequence is unsigned
      "1.5:s",
      ":s", // no sequence at all
      "1:", // no session
      "nocolon",
      "",
    ]) {
      expect(
        parseUnifiedCursor(raw),
        `expected ${JSON.stringify(raw)} to be refused`,
      ).toBeUndefined();
    }
  });
});

describe("the Durable Object address carries the tenant", () => {
  it("gives two tenants holding the same session id two different objects", async () => {
    const sessionId = mintSessionId();
    await store("t-a").open(sessionId, ["alpha"], 1_700);
    // Same id, different tenant: the object was never opened, so there is
    // nothing to describe. This is a property of the ADDRESS, not of a check
    // inside the object that a later author could delete.
    expect(await store("t-b").describe(sessionId)).toBeUndefined();
    expect(await store("t-a").describe(sessionId)).toBeDefined();
    expect(clientSessionKey("t-a", sessionId)).not.toBe(clientSessionKey("t-b", sessionId));
  });

  it("separates the fields with an escape, never a literal NUL byte", () => {
    // A raw NUL in a source file makes it BINARY to git and grep, so the file
    // emits no diff hunk and becomes invisible to review. Written as `\0`.
    expect(clientSessionKey("a", "b")).toBe(`a${String.fromCharCode(0)}b`);
  });
});

// ---------------------------------------------------------------------------
// The session record
// ---------------------------------------------------------------------------

describe("FerroGateMcpUnifiedSession", () => {
  it("does not reset an already-open session, which would void every cursor", async () => {
    const id = mintSessionId();
    const s = store("t-open");
    await s.open(id, ["alpha"], 1_700);
    const seq = await s.append(id, "{}", ["alpha"]);
    expect(seq).toBe(1);

    // A second `initialize`-shaped open on the same id must be a no-op.
    const reopened = await s.open(id, ["alpha", "beta"], 1_800);
    expect(reopened.nextSeq).toBe(2);
    expect(reopened.openedAtUnix).toBe(1_700);
  });

  it("allocates one monotonic sequence across frames from different upstreams", async () => {
    const id = mintSessionId();
    const s = store("t-seq");
    await s.open(id, ["alpha", "beta"], 1_700);
    expect(await s.append(id, '{"n":1}', ["alpha"])).toBe(1);
    expect(await s.append(id, '{"n":2}', ["beta"])).toBe(2);
    expect(await s.append(id, '{"n":3}', ["alpha", "beta"])).toBe(3);

    const replayed = await s.replay(id, 1);
    expect(replayed.kind).toBe("replay");
    if (replayed.kind !== "replay") throw new Error("unreachable");
    expect(replayed.frames.map((frame) => frame.seq)).toEqual([2, 3]);
    // The attribution survives the round trip, so an operator reading a replay
    // can see which leg of the fan-out each frame came from.
    expect(replayed.frames[1]?.servers).toEqual(["alpha", "beta"]);
  });

  it("appending to a session that was never opened returns nothing", async () => {
    expect(await store("t-void").append(mintSessionId(), "{}", [])).toBeUndefined();
  });

  it("REFUSES a cursor ahead of the last sequence it emitted", async () => {
    const id = mintSessionId();
    const s = store("t-ahead");
    await s.open(id, ["alpha"], 1_700);
    await s.append(id, "{}", ["alpha"]);
    // The control: the honest cursor works.
    expect((await s.replay(id, 1)).kind).toBe("replay");

    const refused = await s.replay(id, 2);
    expect(refused.kind).toBe("refused");
    if (refused.kind !== "refused") throw new Error("unreachable");
    expect(refused.reason).toContain("ahead of the last event");
  });

  it("REFUSES a cursor whose successors have been pruned", async () => {
    const id = mintSessionId();
    const s = store("t-prune");
    await s.open(id, ["alpha"], 1_700);
    for (let i = 0; i < MAX_RETAINED_FRAMES + 5; i += 1) {
      await s.append(id, `{"n":${i}}`, ["alpha"]);
    }

    // Cursor 1 means "I have seen frame 1"; frames 2..6 are gone, so replaying
    // from what IS retained would hand back a history with a hole in it that
    // the client would read as complete.
    const refused = await s.replay(id, 1);
    expect(refused.kind).toBe("refused");
    if (refused.kind !== "refused") throw new Error("unreachable");
    expect(refused.reason).toContain("predates this session's retained history");

    // The control: a cursor inside the retained window still replays, and
    // replays EXACTLY, so the refusal above is about the boundary and not about
    // replay being broken.
    const state = await s.describe(id);
    const oldest = state?.oldestRetainedSeq as number;
    const ok = await s.replay(id, oldest - 1);
    expect(ok.kind).toBe("replay");
    if (ok.kind !== "replay") throw new Error("unreachable");
    expect(ok.frames).toHaveLength(MAX_RETAINED_FRAMES);
    expect(ok.frames[0]?.seq).toBe(oldest);
    // Generous, and deliberately not a smaller retention bound to make it fast:
    // this test's whole point is overflowing the REAL bound against the REAL
    // Durable Object, which is 261 sequential storage round trips in workerd.
  }, 30_000);

  it("records an upstream that dropped mid-conversation without closing the session", async () => {
    const id = mintSessionId();
    const s = store("t-drop");
    await s.open(id, ["alpha", "beta"], 1_700);

    const dropped = await s.recordUpstreamHealth(id, [
      { server: "beta", message: "connect refused" },
    ]);
    expect(dropped?.upstreams).toEqual([
      { server: "alpha", state: "bound" },
      { server: "beta", state: "dropped", lastError: "connect refused" },
    ]);
    // The session is still usable — one leg of the fan-out falling over must
    // not take the client's whole conversation with it.
    expect(await s.append(id, "{}", ["alpha"])).toBe(1);

    // ...and a recovered upstream stops being reported without a new session.
    const recovered = await s.recordUpstreamHealth(id, []);
    expect(recovered?.upstreams.every((entry) => entry.state === "bound")).toBe(true);
  });

  it("reconciles the bound set against the catalogue and reports the delta", async () => {
    const id = mintSessionId();
    const s = store("t-reconcile");
    await s.open(id, ["alpha", "beta"], 1_700);

    const delta = await s.reconcile(id, ["alpha", "gamma"]);
    expect(delta?.added).toEqual(["gamma"]);
    expect(delta?.removed).toEqual(["beta"]);
    expect(delta?.state.upstreams.map((entry) => entry.server)).toEqual(["alpha", "gamma"]);

    // A reconcile that changes nothing reports nothing, so a client is not told
    // its fan-out moved on every single request.
    const stable = await s.reconcile(id, ["alpha", "gamma"]);
    expect(stable?.added).toEqual([]);
    expect(stable?.removed).toEqual([]);
  });

  it("reconciling an unopened session answers nothing rather than opening one", async () => {
    expect(await store("t-none").reconcile(mintSessionId(), ["alpha"])).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// The seam between the fan-in and the session
// ---------------------------------------------------------------------------

describe("an upstream that drops mid-conversation reaches the session", () => {
  beforeEach(() => {
    resetInMemoryPorts();
  });

  function fleet(): McpPorts {
    const ports = inMemoryPorts();
    const configs: McpServerConfig[] = ["alpha", "offline"].map((name) => ({
      name,
      transport: "streamable_http" as const,
      url: `https://${name}.upstream.test/mcp`,
      authType: "none" as const,
      toolsToExecute: ["ping"],
      toolsToAutoExecute: ["ping"],
      timeoutMs: 5_000,
    }));
    const fetchImpl = (async (input: RequestInfo | URL) => {
      const target = String(typeof input === "string" || input instanceof URL ? input : input.url);
      if (target.includes("offline")) throw new Error("connection refused");
      const body = { jsonrpc: "2.0", id: 1, result: {} } as Record<string, unknown>;
      const url = new URL(target);
      void url;
      return new Response(
        JSON.stringify({
          ...body,
          result: {
            resultType: "complete",
            capabilities: {},
            supportedVersions: [MCP_PROTOCOL_VERSION],
            tools: [{ name: "ping", inputSchema: { type: "object" } }],
          },
        }),
        { status: 200, headers: { "content-type": "application/json" } },
      );
    }) as unknown as typeof fetch;
    return { ...ports, upstreams: new HttpMcpUpstreams(configs, fetchImpl) };
  }

  it("reports the dead upstream through the dispatch context's attribution sink", async () => {
    const sink = attributionSink();
    const context: DispatchContext = {
      requestId: "req-drop",
      auth: tenantAuth(),
      upstreams: sink,
    };
    const ports = fleet();
    const response = await toolsList(ports, context, 1);

    // The listing itself already reported the degradation (the leg PR #754
    // landed); what is new is that the SESSION now learns about it too.
    const result = response.result as Record<string, unknown>;
    const meta = result["_meta"] as Record<string, unknown>;
    expect(meta[MULTIPLEX_DEGRADED_META]).toBeDefined();

    expect(sink.servers).toEqual(["alpha"]);
    expect(sink.failures.map((failure) => failure.server)).toEqual(["offline"]);

    // ...and that fact, written to a live session, survives for the client to
    // discover after it reconnects.
    const id = mintSessionId();
    const s = store("t-sink");
    await s.open(id, ["alpha", "offline"], 1_700);
    const state = await s.recordUpstreamHealth(id, sink.failures);
    expect(state?.upstreams.find((entry) => entry.server === "offline")?.state).toBe("dropped");
    expect(state?.upstreams.find((entry) => entry.server === "alpha")?.state).toBe("bound");
  });
});
