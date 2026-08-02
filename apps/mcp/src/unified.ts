/**
 * The UNIFIED CLIENT SESSION (#687 legs 2 and 3): one `Mcp-Session-Id` in front
 * of many upstream MCP sessions, with a replay log the fan-out can be resumed
 * from.
 *
 * ## What this closes
 *
 * `src/transport.ts` carried the note in its own header: the server-side
 * ingress minted no `Mcp-Session-Id` and kept no `Last-Event-ID` replay log, so
 * — in #687's own words — *"an SSE reconnect loses the whole fan-out"*. There
 * was no identity for a reconnect to resume against, and a client that dropped
 * mid-conversation had to start the whole multiplexed conversation again.
 *
 * This is distinct from {@link module:session}'s `FerroGateMcpSession`, and the
 * distinction is the substance of the issue:
 *
 * | | `FerroGateMcpSession` | `FerroGateMcpUnifiedSession` (here) |
 * |---|---|---|
 * | one instance per | `(tenant, UPSTREAM)` | `(tenant, CLIENT session)` |
 * | holds | the negotiated protocol + tool list of ONE upstream | the client's view of ALL of them |
 * | lifetime | as long as the upstream is configured | one client conversation |
 *
 * A client session maps to MANY upstream sessions. The interesting cases are
 * the failures, and each one has a rule here:
 *
 *  - an upstream DROPS its session mid-conversation → the client session
 *    survives and records the drop ({@link UnifiedSessionState.upstreams} moves
 *    that entry to `dropped`). Invalidating the client's whole fan-in because
 *    one of several upstreams fell over would destroy exactly the multiplexing
 *    the session exists to provide.
 *  - an upstream is ADDED or REMOVED while the session is live → the session is
 *    RECONCILED against the tenant's current catalogue on every request, and
 *    the delta is REPORTED to the client. Silently changing the fan-out under a
 *    live conversation is how an agent ends up reasoning about a tool that
 *    stopped existing three requests ago.
 *
 * ## The replay cursor, and why it refuses more than it resumes
 *
 * The cursor shape deliberately mirrors `apps/agent-runtime/src/runs/events.ts`
 * (`eventCursorToken` / `resolveEventCursor`) rather than inventing a second
 * replay vocabulary in the same tree: a COMPOSITE `"<position>:<id>"` token
 * that resolves WITHOUT a lookup, so it keeps working after the event it names
 * has been pruned. `Last-Event-ID` — the header a browser and the MCP SDK
 * resend automatically — is what carries it, exactly as it does there.
 *
 * What is DIFFERENT, because a multiplexed stream is not a single run's
 * timeline: the position is a sequence number allocated BY THIS SESSION, in the
 * order frames left the gateway. Events arrive from several upstreams; a
 * per-upstream counter, or an upstream's own event id, could not order them
 * against each other, so a cursor built from one would resume at a point that
 * is only meaningful for one leg of the fan-out. One monotonic sequence over
 * the merged stream is what makes the cursor mean the same thing for all of
 * them.
 *
 * And the rule that matters most: **a cursor that cannot be honoured EXACTLY is
 * REFUSED.** A resume that silently starts from the wrong point is worse than
 * no resume at all, because the client believes it now holds the full history
 * and will never ask again. So all four of these refuse rather than approximate:
 *
 *  - a cursor naming a DIFFERENT session (the id half does not match);
 *  - a cursor AHEAD of the highest sequence this session emitted — the client
 *    claims to have seen frames that were never sent;
 *  - a cursor whose successors have been PRUNED by the retention bound, so the
 *    replay would have a hole in it;
 *  - a cursor into a session that has been EVICTED for idleness (#765), whose
 *    whole log is gone rather than partly pruned;
 *  - anything that does not parse.
 *
 * ## Idle eviction, and why the object does not simply vanish (#765)
 *
 * A Durable Object has no TTL. #687 wrote {@link
 * FerroGateMcpUnifiedSession.close} and never called it, so every `initialize`
 * minted an object that outlived its conversation forever — growth driven by
 * CALLERS rather than by operators, and a cost line attributable to no request.
 * The reaper is an ALARM, the same primitive `./oauth-flow.ts` uses for an
 * abandoned OAuth flow, armed one {@link SESSION_IDLE_TTL_SECS} out and pushed
 * forward by every touch, so what it collects is IDLENESS rather than age.
 *
 * Eviction happens in TWO phases, and the second one is the part that matters
 * for the client:
 *
 *  1. at the idle deadline the session and its frames are deleted and a small
 *     {@link UnifiedSessionTombstone} is written in their place;
 *  2. one {@link SESSION_TOMBSTONE_TTL_SECS} later the tombstone goes too, and
 *     the object holds nothing at all — which is how a Durable Object ceases to
 *     cost anything.
 *
 * The tombstone exists because "your session silently vanished" is the worst
 * possible answer to the support call that follows an eviction. While it is
 * there, a reconnect is told what happened and when, in the SAME refusal shape
 * the three older cursor refusals use. After it expires the answer degrades to
 * the ordinary unknown-session refusal — a bounded record is the price of a
 * bounded object, and this is where that trade is made explicit.
 *
 * ## Cross-tenant isolation is the ADDRESS, not a check
 *
 * The Durable Object is addressed by `idFromName(clientSessionKey(tenantId,
 * sessionId))`. A second tenant presenting the first tenant's session id
 * therefore addresses a DIFFERENT object, which was never opened, and is
 * refused as unknown. There is no `if (state.tenantId !== auth.tenant)` for a
 * later author to forget — the same property `sessionKey` gives the per-upstream
 * session, applied one level up.
 */
import { DurableObject } from "cloudflare:workers";

/** The MCP Streamable-HTTP session header, lowercased for `Headers.get`. */
export const MCP_SESSION_ID_HEADER = "mcp-session-id";

/** The SSE reconnect header. Sent automatically by browsers and the MCP SDK. */
export const LAST_EVENT_ID_HEADER = "last-event-id";

/** `_meta` key carrying the session descriptor on `initialize`. */
export const UNIFIED_SESSION_META = "ferrogate/session";

/** `_meta` key listing upstreams bound to the session since the last request. */
export const UNIFIED_ADDED_META = "ferrogate/sessionUpstreamsAdded";

/** `_meta` key listing upstreams that left the catalogue under a live session. */
export const UNIFIED_REMOVED_META = "ferrogate/sessionUpstreamsRemoved";

/** `_meta` key listing upstreams whose own session dropped mid-conversation. */
export const UNIFIED_DROPPED_META = "ferrogate/sessionUpstreamsDropped";

/**
 * How many emitted frames one session keeps for replay.
 *
 * Bounded because a Durable Object's storage is not free and a long-lived agent
 * conversation is unbounded. The bound is SAFE precisely because exceeding it
 * makes a resume REFUSE rather than silently return a truncated history — see
 * {@link UnifiedSessionState.oldestRetainedSeq}.
 */
export const MAX_RETAINED_FRAMES = 256;

/**
 * How long a client session may go QUIET before it is evicted (#765).
 *
 * Thirty minutes, and the number is a policy rather than a round figure:
 *
 *  - it must be far longer than any reconnect a live client makes. The MCP
 *    Streamable-HTTP SDK and every browser `EventSource` retry an SSE drop in
 *    seconds, and an agent's gap between turns is seconds to minutes; evicting
 *    inside that window would take sessions away from clients that are still
 *    using them, which is much worse than keeping a dead one.
 *  - it must be shorter than the interval over which an abandoned session's
 *    cost becomes invisible. Up to {@link MAX_RETAINED_FRAMES} rendered frames
 *    sit in each object; a day-long or unbounded lifetime turns "an agent that
 *    reconnects on every run" into permanent storage nobody ordered.
 *  - it must exceed the longest single request that could hold a session open
 *    without touching it. Nothing in this ingress runs for thirty minutes —
 *    Workers cap a request far below that — so no in-flight request can be
 *    outlived by its own session.
 *
 * It is a CONSTANT, not an operator `[vars]` value, deliberately: a per-
 * deployment eviction window is a per-deployment client contract, and the
 * refusal message a client reads would then mean something different in each
 * environment. Change it here, in one place, with this reasoning to update.
 */
export const SESSION_IDLE_TTL_SECS = 30 * 60;

/**
 * How long the eviction TOMBSTONE outlives the session it replaced (#765).
 *
 * Twenty-four hours: long enough that "my agent says the session vanished"
 * reaches an operator within the same working day and is answered with what
 * actually happened, short enough that the record is not itself the unbounded
 * growth this issue is about. The tombstone is a few dozen bytes against a log
 * of up to {@link MAX_RETAINED_FRAMES} rendered responses, so the object is
 * already ~all of the way to free at phase one; phase two takes the rest.
 */
export const SESSION_TOMBSTONE_TTL_SECS = 24 * 60 * 60;

/** The address of one client session's Durable Object. */
export function clientSessionKey(tenantId: string, sessionId: string): string {
  // `\0` cannot occur in either field, so no pair of (tenant, session) values
  // can collide by concatenation. Written as an ESCAPE, never as a literal NUL
  // byte: a raw NUL makes the source file binary to git and grep, and a binary
  // file emits no diff hunk for a reviewer to read.
  return `${tenantId}\0${sessionId}`;
}

/** One upstream, as this client session sees it. */
export interface UnifiedSessionUpstream {
  readonly server: string;
  /** `bound` = fanned in; `dropped` = its own session failed mid-conversation. */
  readonly state: "bound" | "dropped";
  readonly lastError?: string;
}

/** The client session record. */
export interface UnifiedSessionState {
  readonly sessionId: string;
  readonly openedAtUnix: number;
  readonly upstreams: readonly UnifiedSessionUpstream[];
  /** The sequence the NEXT emitted frame will take. Frames are numbered from 1. */
  readonly nextSeq: number;
  /** The lowest sequence still replayable. Frames below it have been pruned. */
  readonly oldestRetainedSeq: number;
  /**
   * When this session was last touched, in unix seconds (#765).
   *
   * The idle alarm is the authority on eviction; this field is what makes the
   * eviction EXPLICABLE afterwards — it is copied into the tombstone, so the
   * refusal a reconnecting client reads can say when the session last spoke
   * rather than only that it is gone.
   */
  readonly lastSeenUnix: number;
}

/**
 * What is left where an evicted session used to be (#765).
 *
 * Deliberately small and deliberately NOT the session: nothing here can be
 * resumed from, and `status` reports it as `evicted` rather than as an open
 * session with an empty log — which is the shape that would let a client
 * silently resume from zero.
 */
export interface UnifiedSessionTombstone {
  readonly sessionId: string;
  /** Unix seconds at which the idle alarm collected the session. */
  readonly evictedAtUnix: number;
  /** The last request the session served, in unix seconds. */
  readonly lastSeenUnix: number;
  /** The policy that evicted it, carried so the message can name the number. */
  readonly idleTtlSecs: number;
  /** The highest sequence the session ever emitted, for the operator's view. */
  readonly highestSeq: number;
  /** How many retained frames the eviction discarded. */
  readonly framesDiscarded: number;
}

/**
 * What this address currently holds.
 *
 * Three outcomes rather than `state | undefined`, because "evicted" and "never
 * opened" are the same absence to storage and a completely different answer to
 * a client: one of them has a cause the operator can be told.
 */
export type UnifiedSessionStatus =
  | { readonly kind: "open"; readonly state: UnifiedSessionState }
  | { readonly kind: "evicted"; readonly tombstone: UnifiedSessionTombstone }
  | { readonly kind: "unknown" };

/** One frame this session emitted to the client. */
export interface UnifiedFrame {
  readonly seq: number;
  /** The rendered JSON-RPC response, verbatim, as it went onto the wire. */
  readonly payload: string;
  /** The upstreams that contributed to it, for the operator's view of a replay. */
  readonly servers: readonly string[];
}

/** What a reconcile against the current catalogue changed. */
export interface UnifiedReconcile {
  readonly added: readonly string[];
  readonly removed: readonly string[];
  readonly dropped: readonly string[];
  readonly state: UnifiedSessionState;
}

/** The answer to a `Last-Event-ID`. A refusal is a first-class outcome. */
export type UnifiedReplay =
  | { readonly kind: "replay"; readonly frames: readonly UnifiedFrame[] }
  | { readonly kind: "refused"; readonly reason: string };

/** Render the resume cursor an SSE `id:` field carries. */
export function unifiedCursorToken(sessionId: string, seq: number): string {
  return `${seq}:${sessionId}`;
}

/**
 * Parse a resume cursor.
 *
 * Deliberately STRICT — the sequence must be all digits and the session half
 * must be non-empty — because every lenient reading of a cursor ends in a
 * resume from a point the client did not ask for. `Number.parseInt` would have
 * read `"12abc"` as 12 and `"1e3"` as 1, so the digits-only guard is the same
 * one `parseEventLimit` uses in `apps/agent-runtime` and for the same reason.
 */
export function parseUnifiedCursor(
  raw: string,
): { readonly seq: number; readonly sessionId: string } | undefined {
  const separator = raw.indexOf(":");
  if (separator <= 0) return undefined;
  const head = raw.slice(0, separator);
  if (!/^\d+$/.test(head)) return undefined;
  const seq = Number.parseInt(head, 10);
  if (!Number.isSafeInteger(seq)) return undefined;
  const sessionId = raw.slice(separator + 1);
  if (sessionId === "") return undefined;
  return { seq, sessionId };
}

/** A fresh session id. `crypto.randomUUID` is available in workerd. */
export function mintSessionId(): string {
  return crypto.randomUUID();
}

const STATE_KEY = "unified";
const FRAMES_KEY = "frames";
/** Written by the idle alarm in place of the session it evicted (#765). */
const TOMBSTONE_KEY = "evicted";

/**
 * ONE client session, addressed by `idFromName(clientSessionKey(tenant, id))`.
 *
 * Storage is the DO's own embedded SQLite (`new_sqlite_classes`). Two records:
 * the session state and the bounded replay log. Every mutation runs inside
 * `blockConcurrencyWhile` so two concurrent requests on the same session cannot
 * interleave a read and a write and hand out the same sequence number twice —
 * which would make two different frames share a cursor, and a resume from that
 * cursor ambiguous.
 */
export class FerroGateMcpUnifiedSession extends DurableObject {
  /**
   * Unix-MILLISECONDS clock, kept as a plain field rather than an RPC method so
   * `cloudflare:test`'s `runInDurableObject` can pin it exactly the way
   * `RateLimiterDurableObject.clock` and `ProviderCircuitDurableObject.clock`
   * are pinned. Nothing reachable over the DO binding can rewrite it, so this
   * is a test seam and not an input.
   *
   * It exists because the idle deadline (#765) is the whole policy: a test that
   * could only observe "the second alarm was scheduled later than the first"
   * would pass against a renewal that is off by an arbitrary amount.
   */
  clock: () => number = () => Date.now();

  /** The session, or `undefined` when this address is not holding one. */
  async describe(): Promise<UnifiedSessionState | undefined> {
    return await this.ctx.storage.get<UnifiedSessionState>(STATE_KEY);
  }

  /**
   * What this address holds: an open session, an eviction tombstone, or
   * nothing (#765).
   *
   * The ingress asks THIS rather than {@link describe}, because `undefined`
   * cannot distinguish "evicted twenty minutes ago" from "never a session", and
   * telling a client the second when the first is true is how an eviction
   * becomes "it silently vanished".
   */
  async status(): Promise<UnifiedSessionStatus> {
    const state = await this.ctx.storage.get<UnifiedSessionState>(STATE_KEY);
    if (state !== undefined) return { kind: "open", state };
    const tombstone = await this.ctx.storage.get<UnifiedSessionTombstone>(TOMBSTONE_KEY);
    if (tombstone !== undefined) return { kind: "evicted", tombstone };
    return { kind: "unknown" };
  }

  /**
   * Push the idle deadline out by one {@link SESSION_IDLE_TTL_SECS} (#765).
   *
   * Called by every mutator, INSIDE its `blockConcurrencyWhile`, so what the
   * alarm eventually collects is a session nothing has touched for the whole
   * interval. `setAlarm` replaces the pending alarm rather than adding one, so
   * a busy session costs one overwrite per request and never accumulates
   * timers.
   *
   * The consequence worth stating: because the deadline moves on every touch,
   * the alarm HANDLER needs no idleness check — if it runs, by construction no
   * touch happened within the interval. That keeps the policy in exactly one
   * place instead of split between a deadline and a second comparison that
   * could disagree with it.
   */
  async #arm(nowMs: number): Promise<void> {
    await this.ctx.storage.setAlarm(nowMs + SESSION_IDLE_TTL_SECS * 1000);
  }

  /**
   * Open the session. Idempotent: re-opening an existing session returns it
   * unchanged rather than resetting its sequence, because a reset would
   * invalidate every cursor the client already holds.
   */
  async open(sessionId: string, servers: string[], nowUnix: number): Promise<UnifiedSessionState> {
    return await this.ctx.blockConcurrencyWhile(async () => {
      const existing = await this.ctx.storage.get<UnifiedSessionState>(STATE_KEY);
      if (existing !== undefined) return existing;
      const state: UnifiedSessionState = {
        sessionId,
        openedAtUnix: nowUnix,
        upstreams: servers.map((server) => ({ server, state: "bound" as const })),
        nextSeq: 1,
        oldestRetainedSeq: 1,
        lastSeenUnix: nowUnix,
      };
      await this.ctx.storage.put(STATE_KEY, state);
      // A tombstone at an address being opened again describes a DIFFERENT,
      // finished session. Leaving it would make `status` report an open session
      // and an eviction at once, and whichever the reader trusts is a coin
      // flip. Not reachable through the ingress — session ids are freshly
      // minted UUIDs — but the store is a public seam.
      await this.ctx.storage.delete(TOMBSTONE_KEY);
      await this.#arm(this.clock());
      return state;
    });
  }

  /**
   * Reconcile the session's bound upstream set against the tenant's CURRENT
   * catalogue, and report the delta.
   *
   * A removed upstream is dropped from the session rather than left behind as a
   * ghost the client could still name; an added one is bound. The session
   * itself is never invalidated by either — that is the whole point of a
   * session that stands in front of many upstreams instead of one.
   */
  async reconcile(servers: string[]): Promise<UnifiedReconcile | undefined> {
    return await this.ctx.blockConcurrencyWhile(async () => {
      const state = await this.ctx.storage.get<UnifiedSessionState>(STATE_KEY);
      if (state === undefined) return undefined;
      const nowMs = this.clock();
      const current = new Set(servers);
      const known = new Map(state.upstreams.map((entry) => [entry.server, entry]));
      const added = servers.filter((server) => !known.has(server)).sort();
      const removed = [...known.keys()].filter((server) => !current.has(server)).sort();
      const dropped = state.upstreams
        .filter((entry) => entry.state === "dropped" && current.has(entry.server))
        .map((entry) => entry.server)
        .sort();
      // Reconciling is a TOUCH even when the catalogue has not moved: a client
      // whose whole traffic is notifications appends no frame, and a session
      // evicted while it was talking would be an eviction of a live client.
      if (added.length === 0 && removed.length === 0) {
        const touched = { ...state, lastSeenUnix: Math.floor(nowMs / 1000) };
        await this.ctx.storage.put(STATE_KEY, touched);
        await this.#arm(nowMs);
        return { added, removed, dropped, state: touched };
      }
      const upstreams: UnifiedSessionUpstream[] = servers.map(
        (server) => known.get(server) ?? { server, state: "bound" as const },
      );
      const next: UnifiedSessionState = {
        ...state,
        upstreams,
        lastSeenUnix: Math.floor(nowMs / 1000),
      };
      await this.ctx.storage.put(STATE_KEY, next);
      await this.#arm(nowMs);
      return { added, removed, dropped, state: next };
    });
  }

  /**
   * Record that an upstream's own session failed under this client session.
   *
   * The client session stays OPEN. `messages` is keyed by server name; a server
   * absent from it and currently `dropped` is restored to `bound`, so a
   * recovered upstream stops being reported as broken without needing a new
   * client session.
   */
  async recordUpstreamHealth(
    failures: Array<{ server: string; message: string }>,
  ): Promise<UnifiedSessionState | undefined> {
    return await this.ctx.blockConcurrencyWhile(async () => {
      const state = await this.ctx.storage.get<UnifiedSessionState>(STATE_KEY);
      if (state === undefined) return undefined;
      const nowMs = this.clock();
      const failed = new Map(failures.map((failure) => [failure.server, failure.message]));
      const upstreams = state.upstreams.map((entry) => {
        const message = failed.get(entry.server);
        if (message !== undefined) {
          return { server: entry.server, state: "dropped" as const, lastError: message };
        }
        return { server: entry.server, state: "bound" as const };
      });
      const next: UnifiedSessionState = {
        ...state,
        upstreams,
        lastSeenUnix: Math.floor(nowMs / 1000),
      };
      await this.ctx.storage.put(STATE_KEY, next);
      await this.#arm(nowMs);
      return next;
    });
  }

  /**
   * Append one emitted frame and return its cursor sequence.
   *
   * The sequence is allocated HERE, by the single-threaded actor, which is what
   * makes it a total order over a stream fed by several upstreams — and what
   * stops two concurrent requests from sharing a number.
   */
  async append(payload: string, servers: string[]): Promise<number | undefined> {
    return await this.ctx.blockConcurrencyWhile(async () => {
      const state = await this.ctx.storage.get<UnifiedSessionState>(STATE_KEY);
      if (state === undefined) return undefined;
      const nowMs = this.clock();
      const frames = (await this.ctx.storage.get<UnifiedFrame[]>(FRAMES_KEY)) ?? [];
      const seq = state.nextSeq;
      frames.push({ seq, payload, servers });
      // Prune the oldest, and RAISE the retention floor as we do. A cursor
      // below the floor is refused rather than partially honoured — the floor
      // is the only thing that makes that refusal possible.
      while (frames.length > MAX_RETAINED_FRAMES) frames.shift();
      const oldestRetainedSeq = frames[0]?.seq ?? seq;
      const next: UnifiedSessionState = {
        ...state,
        nextSeq: seq + 1,
        oldestRetainedSeq,
        lastSeenUnix: Math.floor(nowMs / 1000),
      };
      await this.ctx.storage.put(FRAMES_KEY, frames);
      await this.ctx.storage.put(STATE_KEY, next);
      await this.#arm(nowMs);
      return seq;
    });
  }

  /**
   * Everything emitted strictly AFTER `afterSeq`, or a refusal.
   *
   * See the module header for why each refusal is a refusal rather than a
   * best-effort replay. The one thing this must never do is return a history
   * with a hole in it: the client would treat it as complete.
   */
  async replay(afterSeq: number): Promise<UnifiedReplay> {
    const state = await this.ctx.storage.get<UnifiedSessionState>(STATE_KEY);
    if (state === undefined) {
      // The FOURTH refusal (#765), in the same shape as the other three rather
      // than a new mechanism: an evicted session's log is gone entirely, so the
      // only alternative to refusing is replaying nothing and calling it a
      // resume. The ingress normally answers this one before it gets here — it
      // asks `status` first — but a refusal that names its cause belongs at the
      // object that knows the cause, not only at the caller that formats it.
      const tombstone = await this.ctx.storage.get<UnifiedSessionTombstone>(TOMBSTONE_KEY);
      if (tombstone !== undefined) return { kind: "refused", reason: evictionReason(tombstone) };
      return { kind: "refused", reason: "session is not open" };
    }
    const highest = state.nextSeq - 1;
    if (afterSeq > highest) {
      return {
        kind: "refused",
        reason: `resume cursor ${afterSeq} is ahead of the last event this session emitted (${highest})`,
      };
    }
    // `afterSeq + 1` is the first frame the client still needs. If retention
    // has already passed it, the replay would silently skip the gap.
    if (afterSeq + 1 < state.oldestRetainedSeq) {
      return {
        kind: "refused",
        reason: `resume cursor ${afterSeq} predates this session's retained history (oldest is ${state.oldestRetainedSeq}); reconnect with a new session`,
      };
    }
    const frames = (await this.ctx.storage.get<UnifiedFrame[]>(FRAMES_KEY)) ?? [];
    return { kind: "replay", frames: frames.filter((frame) => frame.seq > afterSeq) };
  }

  /** Explicit close — the `DELETE` half of the Streamable-HTTP session contract. */
  async close(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }

  /**
   * THE REAPER (#765) — the caller `close()` never had.
   *
   * Runs in two phases, distinguished by what is in storage rather than by a
   * flag, so a redeploy mid-grace cannot lose track of which phase an object is
   * in:
   *
   *  - a session is present ⇒ this is the IDLE deadline. Nothing touched the
   *    session for {@link SESSION_IDLE_TTL_SECS} (every touch pushes the alarm
   *    forward, so the alarm firing IS the idleness proof — there is no second
   *    comparison here that could disagree with the deadline). The session and
   *    its frames go through `close()`, a tombstone takes their place, and the
   *    tombstone's own expiry is armed.
   *  - no session is present ⇒ this is the tombstone's expiry. Everything goes,
   *    and a Durable Object holding nothing costs nothing.
   *
   * The order — `close()` first, tombstone second — matters: `deleteAll()`
   * would otherwise remove the tombstone this same handler just wrote.
   *
   * An in-flight request racing the eviction cannot resurrect a half-session:
   * `reconcile`, `recordUpstreamHealth` and `append` all return `undefined`
   * when the state is absent, and each runs under the same input gate as this
   * handler, so the worst case is a request that finds its session gone — which
   * is precisely the answer it should get.
   */
  override async alarm(): Promise<void> {
    await this.ctx.blockConcurrencyWhile(async () => {
      const state = await this.ctx.storage.get<UnifiedSessionState>(STATE_KEY);
      if (state === undefined) {
        await this.close();
        return;
      }
      const nowMs = this.clock();
      const frames = (await this.ctx.storage.get<UnifiedFrame[]>(FRAMES_KEY)) ?? [];
      const tombstone: UnifiedSessionTombstone = {
        sessionId: state.sessionId,
        evictedAtUnix: Math.floor(nowMs / 1000),
        lastSeenUnix: state.lastSeenUnix,
        idleTtlSecs: SESSION_IDLE_TTL_SECS,
        highestSeq: state.nextSeq - 1,
        framesDiscarded: frames.length,
      };
      await this.close();
      await this.ctx.storage.put(TOMBSTONE_KEY, tombstone);
      await this.ctx.storage.setAlarm(nowMs + SESSION_TOMBSTONE_TTL_SECS * 1000);
      // The operator's half of the answer. The client gets the refusal; a
      // `wrangler tail` gets this, which is the only place an eviction is
      // visible BEFORE somebody reconnects and complains. Deliberately one
      // line per eviction: a session evicted while its agent believed it was
      // live is worth a log entry, and there is at most one per session.
      console.warn(
        "mcp: unified client session evicted for idleness",
        JSON.stringify({
          session: tombstone.sessionId,
          idleTtlSecs: tombstone.idleTtlSecs,
          lastSeenUnix: tombstone.lastSeenUnix,
          framesDiscarded: tombstone.framesDiscarded,
        }),
      );
    });
  }
}

/**
 * The one sentence a client is told about an eviction (#765).
 *
 * Written once and shared by the object's own refusal and the ingress's, so the
 * two cannot drift into describing the same event differently. It names the
 * CAUSE (idleness), the POLICY (the interval), and the REMEDY (open a new
 * session) — "not found" alone is what turns an eviction into a support call
 * with no answer.
 */
export function evictionReason(tombstone: UnifiedSessionTombstone): string {
  const when = `last seen at unix ${tombstone.lastSeenUnix}, evicted at unix ${tombstone.evictedAtUnix}`;
  return `MCP session ${tombstone.sessionId} was evicted after ${tombstone.idleTtlSecs}s idle (${when}); its replay log is gone — send initialize to open a new session`;
}

/**
 * The RPC surface {@link UnifiedSessionStore} invokes on a stub.
 *
 * Hand-written for the same compiler reason `McpSessionRpc` is (see
 * `src/session.ts`): reading a stub's methods off the class through
 * `Rpc.Provider` is what makes `tsc` give up with TS2589 on this app. Every
 * payload here is deliberately a string, a number or a flat record — nothing
 * recursive crosses the boundary.
 */
interface UnifiedSessionRpc {
  describe(): Promise<UnifiedSessionState | undefined>;
  status(): Promise<UnifiedSessionStatus>;
  open(sessionId: string, servers: string[], nowUnix: number): Promise<UnifiedSessionState>;
  reconcile(servers: string[]): Promise<UnifiedReconcile | undefined>;
  recordUpstreamHealth(
    failures: Array<{ server: string; message: string }>,
  ): Promise<UnifiedSessionState | undefined>;
  append(payload: string, servers: string[]): Promise<number | undefined>;
  replay(afterSeq: number): Promise<UnifiedReplay>;
  close(): Promise<void>;
}

/**
 * Compile-time proof that {@link UnifiedSessionRpc} still mirrors the DO class.
 * The `T extends U` CONSTRAINT does the work; a conditional type would compile
 * to its false branch and prove nothing.
 */
type Implements<T extends U, U> = T;
export type FerroGateMcpUnifiedSessionImplementsRpc = Implements<
  FerroGateMcpUnifiedSession,
  UnifiedSessionRpc
>;

/**
 * The seam the request path talks to.
 *
 * Constructed with the AUTHENTICATED tenant id, which becomes half the DO name.
 * A caller cannot supply it and cannot widen it: the only session ids this
 * store can ever reach are the ones opened under the same tenant.
 */
export class UnifiedSessionStore {
  readonly #namespace: DurableObjectNamespace<FerroGateMcpUnifiedSession>;
  readonly #tenantId: string;

  constructor(namespace: DurableObjectNamespace<FerroGateMcpUnifiedSession>, tenantId: string) {
    this.#namespace = namespace;
    this.#tenantId = tenantId;
  }

  #stub(sessionId: string): UnifiedSessionRpc {
    const name = clientSessionKey(this.#tenantId, sessionId);
    const stub = this.#namespace.get(this.#namespace.idFromName(name));
    return stub as unknown as UnifiedSessionRpc;
  }

  describe(sessionId: string): Promise<UnifiedSessionState | undefined> {
    return this.#stub(sessionId).describe();
  }

  /** Open, evicted, or never opened — the distinction the ingress needs (#765). */
  status(sessionId: string): Promise<UnifiedSessionStatus> {
    return this.#stub(sessionId).status();
  }

  open(sessionId: string, servers: string[], nowUnix: number): Promise<UnifiedSessionState> {
    return this.#stub(sessionId).open(sessionId, servers, nowUnix);
  }

  reconcile(sessionId: string, servers: string[]): Promise<UnifiedReconcile | undefined> {
    return this.#stub(sessionId).reconcile(servers);
  }

  recordUpstreamHealth(
    sessionId: string,
    failures: Array<{ server: string; message: string }>,
  ): Promise<UnifiedSessionState | undefined> {
    return this.#stub(sessionId).recordUpstreamHealth(failures);
  }

  append(sessionId: string, payload: string, servers: string[]): Promise<number | undefined> {
    return this.#stub(sessionId).append(payload, servers);
  }

  replay(sessionId: string, afterSeq: number): Promise<UnifiedReplay> {
    return this.#stub(sessionId).replay(afterSeq);
  }

  close(sessionId: string): Promise<void> {
    return this.#stub(sessionId).close();
  }
}
