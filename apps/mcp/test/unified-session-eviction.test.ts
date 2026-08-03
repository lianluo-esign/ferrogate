/**
 * IDLE EVICTION of the unified client session (#765).
 *
 * #687 gave the session a `close()` and a `DELETE`-shaped contract, and then
 * nothing ever called it. Every `initialize` minted a Durable Object that lived
 * forever: unbounded state growth driven by CALLERS rather than by operators,
 * and — because a DO that merely exists is attributable to no request — a cost
 * surface #677's per-request cost view cannot see. An agent that reconnects on
 * every run minted a fresh one each time.
 *
 * ## What this file holds, and why each one is the interesting case
 *
 *  - **The MOUNT.** Not "`close()` behaves correctly when called" — #687
 *    already had that, and it is exactly the thing that was never invoked. The
 *    assertions here are client-visible: a session goes quiet, the idle alarm
 *    it armed fires, and the client's next request is answered differently.
 *    Deleting the arming, or the `close()` inside `alarm()`, or the ingress's
 *    eviction-aware refusal each turns a different assertion red. See the
 *    per-test notes.
 *  - **The refusal.** A client that reconnects with a cursor into an evicted
 *    session must be REFUSED with a message naming the eviction — never served
 *    a 200 whose replay is silently empty, which the client would read as "I am
 *    up to date". This is #687's fourth cursor refusal in the SAME shape as its
 *    three others (`mcp_session_not_resumable` + a reason), not a new mechanism.
 *  - **The policy.** {@link SESSION_IDLE_TTL_SECS} is asserted as an interval,
 *    on the armed alarm, so the number in the source is the number in the
 *    deployment rather than a comment nobody checked.
 *  - **Renewal.** Eviction is on IDLENESS, not on age: a session that keeps
 *    talking pushes its deadline forward. Pinned with the DO's `clock` seam, so
 *    the assertion is exact rather than "the second number was bigger".
 *  - **The tombstone is bounded too.** An eviction that left a permanent record
 *    behind would be the same unbounded-growth defect one order of magnitude
 *    smaller.
 *
 * Time is not faked: `runDurableObjectAlarm` runs the armed alarm now, which is
 * indistinguishable — from the handler's side — from the deadline arriving,
 * because the handler is unconditional and the DEADLINE is where the policy
 * lives. See `src/unified.ts`.
 */
import { SELF, env, runDurableObjectAlarm, runInDurableObject } from "cloudflare:test";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { inMemoryPorts, resetInMemoryPorts } from "../src/ports.js";
import { parseSseEvents } from "../src/transport.js";
import {
  type FerroGateMcpUnifiedSession,
  SESSION_IDLE_TTL_SECS,
  SESSION_TOMBSTONE_TTL_SECS,
  UnifiedSessionStore,
  clientSessionKey,
} from "../src/unified.js";
import { EXEC_KEY, TENANT, rpcRequest, tenantAuth, upstreamConfig } from "./fixtures.js";

const SESSION_HEADER = "mcp-session-id";
const LAST_EVENT_ID = "last-event-id";

const NAMESPACE = env.MCP_CLIENT_SESSION as NonNullable<typeof env.MCP_CLIENT_SESSION>;

function seed(): void {
  resetInMemoryPorts();
  const ports = inMemoryPorts();
  ports.auth.register(EXEC_KEY, tenantAuth());
  ports.upstreams.register(
    upstreamConfig({ name: "alpha", toolsToExecute: ["ping"], toolsToAutoExecute: ["ping"] }),
    [{ name: "ping", input_schema: { type: "object" } }],
    // eslint-disable-next-line @typescript-eslint/require-await
    async () => ({ content: { content: [{ type: "text", text: "alpha" }] }, isError: false }),
  );
}

function send(
  body: Record<string, unknown>,
  init: { session?: string; lastEventId?: string } = {},
): Promise<Response> {
  const headers: Record<string, string> = { accept: "text/event-stream" };
  if (init.session !== undefined) headers[SESSION_HEADER] = init.session;
  if (init.lastEventId !== undefined) headers[LAST_EVENT_ID] = init.lastEventId;
  return SELF.fetch(rpcRequest(body, { key: EXEC_KEY, headers }));
}

const INITIALIZE = { jsonrpc: "2.0", id: 1, method: "initialize", params: {} };
const PING = { jsonrpc: "2.0", id: 9, method: "ping" };

async function openSession(): Promise<string> {
  const res = await send(INITIALIZE);
  const id = res.headers.get(SESSION_HEADER);
  expect(id, "initialize must mint a client-facing Mcp-Session-Id").toBeTruthy();
  return id as string;
}

/** The Durable Object behind one client session id, for this tenant. */
function stubFor(sessionId: string): DurableObjectStub<FerroGateMcpUnifiedSession> {
  return NAMESPACE.get(NAMESPACE.idFromName(clientSessionKey(TENANT, sessionId)));
}

/** The wall-clock instant the session's alarm is armed for, or `null`. */
function armedAt(sessionId: string): Promise<number | null> {
  return runInDurableObject(stubFor(sessionId), (_instance, state) => state.storage.getAlarm());
}

/** Run the armed alarm now — the deadline arriving, without waiting for it. */
function fireAlarm(sessionId: string): Promise<boolean> {
  return runDurableObjectAlarm(stubFor(sessionId));
}

/** The `id:` cursor of a framed response. */
async function cursorOf(res: Response): Promise<string> {
  const id = parseSseEvents(await res.text())[0]?.id;
  expect(id, "a framed response in a session must carry a resume cursor").toBeTruthy();
  return id as string;
}

beforeEach(() => {
  seed();
});

afterEach(() => {
  resetInMemoryPorts();
});

// ---------------------------------------------------------------------------
// The mount
// ---------------------------------------------------------------------------

describe("a session that goes quiet is evicted", () => {
  /**
   * THE MOUNT PIN, stated as the client-visible consequence rather than as the
   * call site — pinning `close()`'s call site would repeat #764's mistake one
   * level up.
   *
   * Measured, not asserted — each of these was applied and the RED observed:
   *
   *  - neutralise the five `#arm` calls ⇒ **7 RED of 7**, every one of them at
   *    `fireAlarm` returning `false`: no alarm is ever scheduled, which is
   *    exactly the pre-#765 tree;
   *  - delete the `close()` inside `alarm()` ⇒ **5 RED**, this test at
   *    `expected 200 to be 400` — the alarm runs, the session survives, and the
   *    resume is served as if nothing had happened;
   *  - delete the ingress's eviction branch ⇒ **1 RED**, the bare-reconnect test
   *    below at `expected 200 to be 404`. This test stays GREEN, because the
   *    refusal is TWO layers: the ingress answers off `status`, and the object's
   *    own `replay` refuses a cursor with the same reason. Removing BOTH ⇒
   *    **2 RED**, this one at `expected … to contain 'evicted'`. The lower layer
   *    has its own gate below, so neither layer is load-free.
   */
  it("evicts it and REFUSES a cursor into it, naming the eviction", async () => {
    const sessionId = await openSession();
    const cursor = await cursorOf(
      await send(
        { jsonrpc: "2.0", id: 2, method: "tools/call", params: { name: "alpha-ping" } },
        { session: sessionId },
      ),
    );

    // The control that makes the refusal below mean something: while the
    // session is live, THIS cursor resumes.
    const live = await send(PING, { session: sessionId, lastEventId: cursor });
    expect(live.status, "the cursor must be honourable before the eviction").toBe(200);

    // The client stops talking for the idle interval; the deadline arrives.
    expect(
      await fireAlarm(sessionId),
      "a live session must ARM an idle alarm — without one nothing ever evicts",
    ).toBe(true);

    const resumed = await send(PING, { session: sessionId, lastEventId: cursor });
    // NOT a 200 with an empty replay: a client handed that believes it holds
    // the whole history and will never ask for the gap again.
    expect(resumed.status).toBe(400);
    const body = await resumed.text();
    expect(body).toContain("mcp_session_not_resumable");
    expect(body).toContain("evicted");
    expect(body).toContain(String(SESSION_IDLE_TTL_SECS));
    expect(body, "the refusal must not carry a replayed frame").not.toContain("jsonrpc");
  });

  it("answers a bare reconnect with 404 whose message names the eviction", async () => {
    const sessionId = await openSession();
    expect(await fireAlarm(sessionId)).toBe(true);

    // No cursor: the session is simply not open any more, so the code stays the
    // one #687 already defined for that — but the MESSAGE distinguishes "it was
    // evicted for idleness" from "this id was never a session", which is the
    // whole difference between an answerable support call and "it vanished".
    const res = await send(PING, { session: sessionId });
    expect(res.status).toBe(404);
    const body = await res.text();
    expect(body).toContain("mcp_session_not_found");
    expect(body).toContain("evicted");
  });

  /**
   * The LOWER layer of the same refusal, gated on its own.
   *
   * The ingress answers an evicted session off `status` and never reaches
   * `replay`, so deleting `replay`'s tombstone branch alone left all seven wire
   * tests green — an ungated seam, which by this tree's rules is either a gate
   * to write or a defect to report. It is the first: the store is a public seam
   * and a caller that reaches it directly must get the same named refusal, not
   * the generic "session is not open" that reads like a client mistake.
   */
  it("refuses a replay off the store itself with the SAME named reason", async () => {
    const store = new UnifiedSessionStore(NAMESPACE, TENANT);
    const sessionId = await openSession();
    expect(await fireAlarm(sessionId)).toBe(true);

    const answer = await store.replay(sessionId, 1);
    expect(answer.kind).toBe("refused");
    const reason = answer.kind === "refused" ? answer.reason : "";
    expect(reason).toContain("evicted");
    expect(reason).toContain(String(SESSION_IDLE_TTL_SECS));
  });

  it("does not resurrect on the next request — eviction really deleted the state", async () => {
    const sessionId = await openSession();
    expect(await fireAlarm(sessionId)).toBe(true);
    await send(PING, { session: sessionId });

    // A refused request must not re-open the object it refused. If it did, the
    // eviction would be a no-op against an agent that reconnects in a loop —
    // the exact caller this issue is about.
    const state = await new UnifiedSessionStore(NAMESPACE, TENANT).describe(sessionId);
    expect(state).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// The policy
// ---------------------------------------------------------------------------

describe("the idle interval is a stated policy", () => {
  /**
   * The LITERAL numbers, deliberately.
   *
   * Every other assertion in this file compares the armed alarm against the
   * imported constant, which means changing the constant moves both sides and
   * proves nothing — measured: setting the interval to five minutes left all
   * eight tests green. A policy is only stated if changing it forces someone to
   * come here and change the stated reasoning too, so the numbers are written
   * out once, next to the sentence that justifies them.
   */
  it("is thirty minutes idle, with a twenty-four-hour tombstone", () => {
    expect(
      SESSION_IDLE_TTL_SECS,
      "30 minutes: longer than any live client's reconnect, shorter than the interval over which an abandoned session stops being noticed (src/unified.ts)",
    ).toBe(30 * 60);
    expect(
      SESSION_TOMBSTONE_TTL_SECS,
      "24 hours: long enough that the support call an eviction causes gets an answer, short enough that the record is not itself unbounded growth",
    ).toBe(24 * 60 * 60);
  });

  it("arms the alarm exactly one idle interval out", async () => {
    const before = Date.now();
    const sessionId = await openSession();
    const armed = await armedAt(sessionId);
    expect(armed, "opening a session must arm its idle alarm").not.toBeNull();
    const delayMs = (armed as number) - before;
    // A minute of slack either way, because the test's `Date.now()` and the
    // isolate's are only approximately the same clock. It is still an exact
    // enough pin for the policy: any other plausible interval — five minutes,
    // an hour, a day — misses this window by a wide margin, so changing the
    // constant without changing the stated policy fails here.
    expect(Math.abs(delayMs - SESSION_IDLE_TTL_SECS * 1000)).toBeLessThan(60_000);
  });

  it("RENEWS the deadline on every request — it evicts idleness, not age", async () => {
    const sessionId = await openSession();
    const stub = stubFor(sessionId);

    // Pin the DO's clock the way `RateLimiterDurableObject`'s tests pin theirs,
    // so this asserts an exact deadline instead of "the second number was
    // bigger" — which passes even if the renewal is off by a millisecond of
    // wall clock and proves nothing.
    const t0 = 1_800_000_000_000;
    await runInDurableObject(stub, (instance) => {
      instance.clock = () => t0;
    });
    await send(PING, { session: sessionId });
    expect(await armedAt(sessionId)).toBe(t0 + SESSION_IDLE_TTL_SECS * 1000);

    const t1 = t0 + 5 * 60 * 1000;
    await runInDurableObject(stub, (instance) => {
      instance.clock = () => t1;
    });
    await send(PING, { session: sessionId });
    expect(await armedAt(sessionId)).toBe(t1 + SESSION_IDLE_TTL_SECS * 1000);
  });
});

// ---------------------------------------------------------------------------
// The tombstone
// ---------------------------------------------------------------------------

describe("the eviction record is itself bounded", () => {
  it("keeps a tombstone for the stated grace, then removes the object entirely", async () => {
    const sessionId = await openSession();
    expect(await fireAlarm(sessionId)).toBe(true);

    // Phase one left a tombstone AND armed its expiry: an eviction record that
    // outlived the session forever would be this same defect, smaller.
    const tombstoneAlarm = await armedAt(sessionId);
    expect(tombstoneAlarm, "the tombstone must arm its own expiry").not.toBeNull();
    expect((tombstoneAlarm as number) - Date.now()).toBeGreaterThan(
      SESSION_TOMBSTONE_TTL_SECS * 1000 - 60_000,
    );

    // Phase two: the grace elapses and the object holds nothing at all.
    expect(await fireAlarm(sessionId)).toBe(true);
    const left = await runInDurableObject(stubFor(sessionId), async (_instance, state) =>
      [...(await state.storage.list()).keys()].sort(),
    );
    expect(left).toEqual([]);

    // ...and the client's answer degrades to the plain unknown-session refusal,
    // because there is no longer anything that remembers the eviction.
    const res = await send(PING, { session: sessionId });
    expect(res.status).toBe(404);
    const body = await res.text();
    expect(body).toContain("mcp_session_not_found");
    expect(body).not.toContain("evicted");
  });

  it("does not let a tombstone shadow a session opened at the same address", async () => {
    // Not reachable through the ingress (ids are freshly minted UUIDs), but the
    // store is a public seam and a stale tombstone next to a live session would
    // make `status` lie about which one is true.
    const store = new UnifiedSessionStore(NAMESPACE, TENANT);
    const sessionId = "reused-address";
    await store.open(sessionId, ["alpha"], 1_800_000_000);
    expect(await fireAlarm(sessionId)).toBe(true);
    expect((await store.status(sessionId)).kind).toBe("evicted");

    await store.open(sessionId, ["alpha"], 1_800_000_100);
    expect((await store.status(sessionId)).kind).toBe("open");
  });
});
