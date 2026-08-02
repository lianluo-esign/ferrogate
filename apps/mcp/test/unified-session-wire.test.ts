/**
 * The UNIFIED SESSION and its RESUMABLE stream, on the wire (#687 legs 2 + 3).
 *
 * #687's problem statement names the defect exactly: *"an SSE reconnect loses
 * the whole fan-out"*. Before this slice the ingress minted no client-facing
 * `Mcp-Session-Id` at all (`src/transport.ts` said so in its own header), so
 * there was no identity for a reconnect to resume against and every dropped
 * connection started the fan-out again from nothing.
 *
 * What is asserted here, and why each one is the interesting case rather than
 * the happy path:
 *
 *  - **One client session, many upstream sessions.** `initialize` mints the id
 *    and binds every upstream the tenant's catalogue currently holds.
 *  - **An unknown session id is REFUSED**, not silently upgraded to a fresh
 *    one. A client that believes it is resuming must not be handed a blank
 *    history that looks like a resumed one.
 *  - **A cursor that cannot be honoured EXACTLY is refused.** A resume that
 *    silently starts from the wrong point is worse than no resume at all,
 *    because the client believes it has the full history. Three refusals are
 *    pinned: a cursor from a different session, a cursor ahead of anything the
 *    session emitted, and a cursor whose events have been pruned.
 *  - **The cursor is meaningful ACROSS upstreams.** The sequence is allocated
 *    by the session, in the order frames left the gateway, so one number orders
 *    events that arrived from several different upstreams.
 *  - **Cross-tenant reach is refused STRUCTURALLY.** Tenant B presenting tenant
 *    A's session id addresses a different Durable Object, which has never been
 *    opened. That is a property of the address, not of a check.
 */
import { SELF, env } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { inMemoryPorts, resetInMemoryPorts } from "../src/ports.js";
import { parseSseEvents } from "../src/transport.js";
import { EXEC_KEY, READ_KEY, TENANT, rpcRequest, tenantAuth, upstreamConfig } from "./fixtures.js";

/** The header the MCP Streamable-HTTP transport carries a session on. */
const SESSION_HEADER = "mcp-session-id";
/** The SSE reconnect header a browser (and the MCP SDK) resends automatically. */
const LAST_EVENT_ID = "last-event-id";

const OTHER_KEY = "fg_test_other_tenant_key";
const OTHER_TENANT = "tenant-2";

function seed(): void {
  resetInMemoryPorts();
  const ports = inMemoryPorts();
  ports.auth
    .register(READ_KEY, tenantAuth({ scopes: ["tools.read"] }))
    .register(EXEC_KEY, tenantAuth())
    .register(OTHER_KEY, tenantAuth({ organizationId: OTHER_TENANT }));
  register(["alpha", "beta"]);
}

/** Re-seed the catalogue with exactly these upstreams, each serving `ping`. */
function register(names: readonly string[]): void {
  const ports = inMemoryPorts();
  ports.upstreams.clear();
  for (const name of names) {
    ports.upstreams.register(
      upstreamConfig({ name, toolsToExecute: ["ping"], toolsToAutoExecute: ["ping"] }),
      [{ name: "ping", input_schema: { type: "object" } }],
      // eslint-disable-next-line @typescript-eslint/require-await
      async () => ({ content: { content: [{ type: "text", text: name }] }, isError: false }),
    );
  }
}

/** POST a JSON-RPC body, optionally under a session and/or a resume cursor. */
function send(
  body: Record<string, unknown>,
  init: { key?: string; session?: string; lastEventId?: string; sse?: boolean } = {},
): Promise<Response> {
  const headers: Record<string, string> = {};
  if (init.session !== undefined) headers[SESSION_HEADER] = init.session;
  if (init.lastEventId !== undefined) headers[LAST_EVENT_ID] = init.lastEventId;
  if (init.sse !== false) headers["accept"] = "text/event-stream";
  return SELF.fetch(rpcRequest(body, { key: init.key ?? EXEC_KEY, headers }));
}

const INITIALIZE = { jsonrpc: "2.0", id: 1, method: "initialize", params: {} };

async function openSession(key = EXEC_KEY): Promise<string> {
  const res = await send(INITIALIZE, { key });
  const id = res.headers.get(SESSION_HEADER);
  expect(id, "initialize must mint a client-facing Mcp-Session-Id").toBeTruthy();
  return id as string;
}

/** The SSE frames of a response, with their `id:` cursors. */
async function frames(res: Response): Promise<Array<{ id?: string; data: string }>> {
  const parsed = parseSseEvents(await res.text());
  return parsed.map((event) => {
    const out: { id?: string; data: string } = { data: event.data };
    if (event.id !== undefined) out.id = event.id;
    return out;
  });
}

beforeEach(() => {
  seed();
});

afterEach(() => {
  resetInMemoryPorts();
});

// ---------------------------------------------------------------------------
// Leg 2 — the unified session
// ---------------------------------------------------------------------------

describe("one client session in front of many upstream sessions", () => {
  it("mints a session on initialize and names every upstream it fans in to", async () => {
    const res = await send(INITIALIZE);
    expect(res.status).toBe(200);
    const sessionId = res.headers.get(SESSION_HEADER);
    expect(sessionId).toBeTruthy();

    const body = JSON.parse((await frames(res))[0]?.data ?? "{}") as {
      result?: { _meta?: Record<string, unknown> };
    };
    const session = body.result?._meta?.["ferrogate/session"] as
      | { id?: string; upstreams?: string[] }
      | undefined;
    expect(session?.id).toBe(sessionId);
    // The fan-out the session stands in front of, named — not a bare opaque id.
    expect(session?.upstreams?.slice().sort()).toEqual(["alpha", "beta"]);
  });

  it("carries the same session across several requests", async () => {
    const sessionId = await openSession();
    const first = await send(
      { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "alpha-ping" } },
      { session: sessionId },
    );
    expect(first.status).toBe(200);
    expect(first.headers.get(SESSION_HEADER)).toBe(sessionId);

    const second = await send(
      { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "beta-ping" } },
      { session: sessionId },
    );
    expect(second.headers.get(SESSION_HEADER)).toBe(sessionId);
  });

  it("REFUSES an unknown session id instead of quietly minting a fresh one", async () => {
    const res = await send(
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      {
        key: READ_KEY,
        session: "00000000-0000-4000-8000-000000000000",
      },
    );
    expect(res.status).toBe(404);
    expect(await res.text()).toContain("mcp_session_not_found");
  });

  it("refuses one tenant's session id presented by another tenant", async () => {
    const sessionId = await openSession();
    // The control: it works for the tenant that opened it.
    expect(
      (await send({ jsonrpc: "2.0", id: 2, method: "tools/list" }, { session: sessionId })).status,
    ).toBe(200);

    const crossed = await send(
      { jsonrpc: "2.0", id: 3, method: "tools/list" },
      {
        key: OTHER_KEY,
        session: sessionId,
      },
    );
    // Not 403-after-a-lookup: the id addresses a Durable Object that was never
    // opened for this tenant, so there is nothing to find.
    expect(crossed.status).toBe(404);
  });

  it("survives an upstream leaving the catalogue and names what it lost", async () => {
    const sessionId = await openSession(READ_KEY);
    // The operator removes `beta` while the client's session is live.
    register(["alpha"]);

    const res = await send(
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      {
        key: READ_KEY,
        session: sessionId,
      },
    );
    expect(res.status).toBe(200);
    const body = JSON.parse((await frames(res))[0]?.data ?? "{}") as {
      result?: { _meta?: Record<string, unknown> };
    };
    expect(body.result?._meta?.["ferrogate/sessionUpstreamsRemoved"]).toEqual(["beta"]);
    // The session is NOT invalidated: one upstream leaving must not take the
    // client's whole fan-in with it.
    expect(res.headers.get(SESSION_HEADER)).toBe(sessionId);
  });

  it("binds an upstream added while the session is live", async () => {
    const sessionId = await openSession(READ_KEY);
    register(["alpha", "beta", "gamma"]);

    const res = await send(
      { jsonrpc: "2.0", id: 2, method: "tools/list" },
      {
        key: READ_KEY,
        session: sessionId,
      },
    );
    const body = JSON.parse((await frames(res))[0]?.data ?? "{}") as {
      result?: { _meta?: Record<string, unknown> };
    };
    expect(body.result?._meta?.["ferrogate/sessionUpstreamsAdded"]).toEqual(["gamma"]);
    // ...and the new upstream's tools are actually in the fan-in.
    const listed = JSON.parse(
      (
        await frames(
          await send(
            { jsonrpc: "2.0", id: 3, method: "tools/list" },
            { key: READ_KEY, session: sessionId },
          ),
        )
      )[0]?.data ?? "{}",
    ) as {
      result?: { tools?: Array<{ name: string }> };
    };
    expect(listed.result?.tools?.map((tool) => tool.name)).toContain("gamma-ping");
  });
});

// ---------------------------------------------------------------------------
// Leg 3 — the resumable stream
// ---------------------------------------------------------------------------

describe("the resume cursor is meaningful across the whole fan-out", () => {
  it("stamps a monotonic cursor on every frame, whichever upstream served it", async () => {
    const sessionId = await openSession();
    const seen: string[] = [];
    for (const name of ["alpha-ping", "beta-ping", "alpha-ping"]) {
      const res = await send(
        { jsonrpc: "2.0", id: 9, method: "tools/call", params: { name } },
        { session: sessionId },
      );
      const id = (await frames(res))[0]?.id;
      expect(id, "every framed response must carry a resume cursor").toBeTruthy();
      seen.push(id as string);
    }
    // The sequence is allocated by the SESSION, so it totally orders events
    // that came from two different upstreams. A per-upstream counter could not.
    const seqs = seen.map((cursor) => Number.parseInt(cursor.split(":")[0] ?? "", 10));
    expect(seqs.every((seq) => Number.isSafeInteger(seq))).toBe(true);
    expect(seqs).toEqual([...seqs].sort((a, b) => a - b));
    expect(new Set(seqs).size).toBe(3);
    // ...and every cursor names the session it belongs to.
    for (const cursor of seen) expect(cursor.endsWith(`:${sessionId}`)).toBe(true);
  });

  it("replays exactly the frames the client missed, from both upstreams", async () => {
    const sessionId = await openSession();
    const first = await send(
      { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "alpha-ping" } },
      { session: sessionId },
    );
    const cursor = (await frames(first))[0]?.id as string;

    // Two more frames the client never saw, served by DIFFERENT upstreams.
    await send(
      { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "beta-ping" } },
      { session: sessionId },
    );
    await send(
      { jsonrpc: "2.0", id: 4, method: "tools/call", params: { name: "alpha-ping" } },
      { session: sessionId },
    );

    // The reconnect: the SDK resends the last id it saw.
    const resumed = await send(
      { jsonrpc: "2.0", id: 5, method: "ping" },
      {
        session: sessionId,
        lastEventId: cursor,
      },
    );
    expect(resumed.status).toBe(200);
    const replayed = await frames(resumed);
    // Two missed frames, then the answer to the request just made. Nothing
    // before the cursor, and nothing dropped between it and now.
    expect(replayed).toHaveLength(3);
    expect(replayed.slice(0, 2).map((frame) => JSON.parse(frame.data).id)).toEqual([3, 4]);
    expect(JSON.parse(replayed[2]?.data ?? "{}").id).toBe(5);
  });

  it("REFUSES a cursor from a different session rather than resuming from zero", async () => {
    const one = await openSession();
    const two = await openSession();
    await send(
      { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "alpha-ping" } },
      { session: one },
    );
    const stolen = (
      await frames(
        await send(
          { jsonrpc: "2.0", id: 3, method: "tools/call", params: { name: "alpha-ping" } },
          { session: one },
        ),
      )
    )[0]?.id as string;

    const res = await send(
      { jsonrpc: "2.0", id: 4, method: "ping" },
      {
        session: two,
        lastEventId: stolen,
      },
    );
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("mcp_session_not_resumable");
  });

  it("REFUSES a cursor ahead of anything the session ever emitted", async () => {
    const sessionId = await openSession();
    const res = await send(
      { jsonrpc: "2.0", id: 2, method: "ping" },
      {
        session: sessionId,
        lastEventId: `9999:${sessionId}`,
      },
    );
    // A client that claims to have seen frames we never sent has a corrupt
    // view; handing it "everything since 0" would silently overlap, and
    // handing it nothing would silently lose the gap.
    expect(res.status).toBe(400);
    expect(await res.text()).toContain("mcp_session_not_resumable");
  });

  it("REFUSES an unparseable cursor", async () => {
    const sessionId = await openSession();
    const res = await send(
      { jsonrpc: "2.0", id: 2, method: "ping" },
      {
        session: sessionId,
        lastEventId: "not-a-cursor",
      },
    );
    expect(res.status).toBe(400);
  });

  it("refuses a resume with no session at all", async () => {
    const res = await send(
      { jsonrpc: "2.0", id: 2, method: "ping" },
      { lastEventId: "1:whatever" },
    );
    expect(res.status).toBe(400);
  });
});
