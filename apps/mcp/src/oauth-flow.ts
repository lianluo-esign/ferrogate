/**
 * The ATOMIC single-use claim for an in-flight MCP OAuth authorization.
 *
 * ## Why this file exists
 *
 * The anonymous `GET /v1/mcp/identity/callback` carries NO FerroGate
 * credential. Its entire authorization is the flow record being (a) time
 * bounded and (b) **single use**. Rust gets (b) from one SQL statement:
 *
 * ```sql
 * UPDATE mcp_oauth_flows SET consumed_at = now
 *  WHERE id = ? AND consumed_at IS NULL RETURNING *
 * ```
 *
 * — an indivisible claim, so of two callbacks racing on the same `state`
 * exactly one is served.
 *
 * Workers KV cannot express that: it has no compare-and-swap and no
 * conditional write, so `get()` + `delete()` is two operations with a window
 * between them ({@link KvOauthFlowStore} documents the residual). A **Durable
 * Object** can, and that is what this module is: one DO instance per state
 * digest, so every claim for a given `state` is serialized through a
 * single-threaded actor.
 *
 * ## Why the claim is really atomic here, and what actually carries it
 *
 * The load-bearing mechanism is `idFromName(stateId)` plus the Durable Object
 * INPUT GATE. `idFromName` maps a state digest to exactly ONE object instance
 * globally, so two racing callbacks reach the same actor rather than two
 * isolates; the input gate then refuses to deliver a second event to that
 * actor while the first one's storage operations are in flight, so no request
 * is interleaved between the read and the delete.
 *
 * `ctx.blockConcurrencyWhile` below is DEFENCE IN DEPTH, not the mechanism —
 * measured, not assumed. Replacing it with a bare `get`/`delete` pair (even
 * with an explicit timer yield between the two) leaves the race test green,
 * because the input gate is already closed; the gate is what does the work.
 * It is kept because it states the requirement explicitly at the call site and
 * survives a future refactor that moves the read off `ctx.storage`.
 *
 * The close is genuine and is measured against the primitive it replaces: the
 * suite races four concurrent claims on one state through BOTH stores, and
 * `KvOauthFlowStore` serves all FOUR while this class serves exactly ONE (see
 * `test/oauth-flow-claim.test.ts`). The loser of the race observes
 * `undefined`, the same thing a replay observes.
 *
 * ## Cost, stated honestly
 *
 * A DO round trip is more expensive than a KV read and is a single point of
 * serialization per `state`. That is the correct trade for an authorization
 * primitive and it is bounded per state digest — flows are short-lived and each
 * digest is used at most once by construction.
 */
import { DurableObject } from "cloudflare:workers";

import { decodeFlow, encodeFlow } from "./durable.js";
import type { StoredMcpOauthFlow } from "./ports.js";

/** The one storage key each instance holds. */
const FLOW_KEY = "flow";

/**
 * Grace period (seconds) added to the flow lifetime before the DO alarm reaps
 * an unconsumed record.
 *
 * KV had `expirationTtl` do this; a DO has no TTL, so an abandoned flow would
 * otherwise keep its instance's storage forever. The alarm is the replacement.
 * `expiresAtUnix` remains AUTHORITATIVE and is still checked on read — the
 * alarm is only the garbage collector, exactly as the KV TTL was, so a late
 * alarm can never turn an expired record back into a usable one, and an early
 * one can only lose a record that was already unusable.
 */
export const FLOW_REAP_GRACE_SECS = 60;

/**
 * One in-flight OAuth flow, addressed by `idFromName(<sha256 of state>)`.
 *
 * Deliberately holds ONE record, not a table. Sharding by state digest is what
 * makes the claim contention-free across unrelated flows: a busy tenant's
 * callbacks never queue behind another tenant's.
 */
export class McpOauthFlowClaim extends DurableObject {
  /**
   * Store (or replace) the flow record and arm the reaper.
   *
   * `lifetimeSecs` is a RELATIVE duration, deliberately — the same shape KV's
   * `expirationTtl` took. Scheduling the alarm off the flow's absolute
   * `expiresAtUnix` instead would mean trusting the CALLER's clock to agree
   * with wall-clock time; where it does not, the alarm resolves to a moment
   * already past and reaps the record the instant it is written. The
   * authoritative expiry check stays on `expiresAtUnix` at read time, so the
   * relative alarm is only ever the garbage collector.
   */
  async begin(encoded: string, lifetimeSecs: number): Promise<void> {
    await this.ctx.storage.put(FLOW_KEY, encoded);
    const delayMs = (Math.max(lifetimeSecs, 0) + FLOW_REAP_GRACE_SECS) * 1000;
    await this.ctx.storage.setAlarm(Date.now() + delayMs);
  }

  /**
   * Atomically claim the record: read it, delete it, and return it — or return
   * `undefined` when there is nothing to claim.
   *
   * No other request to this object is delivered between the read and the
   * delete — the DO input gate holds it, with `blockConcurrencyWhile` stating
   * the requirement explicitly. That is the property KV cannot provide and the
   * reason this class exists.
   */
  async claim(nowUnix: number): Promise<string | undefined> {
    const raw = await this.ctx.blockConcurrencyWhile(async () => {
      const stored = await this.ctx.storage.get<string>(FLOW_KEY);
      if (stored === undefined) return undefined;
      // Delete INSIDE the gate and BEFORE any validation, so an expired or
      // undecodable record is also consumed rather than left as a poison key
      // that fails every later callback.
      await this.ctx.storage.delete(FLOW_KEY);
      await this.ctx.storage.deleteAlarm();
      return stored;
    });
    if (raw === undefined) return undefined;
    // Expiry is checked AFTER the claim: an expired record is still consumed
    // (it is spent either way) but is never returned as an authorization.
    let flow: StoredMcpOauthFlow;
    try {
      flow = decodeFlow(raw);
    } catch {
      return undefined;
    }
    if (flow.expiresAtUnix <= nowUnix) return undefined;
    return raw;
  }

  /** The reaper: an unconsumed flow does not outlive its expiry. */
  override async alarm(): Promise<void> {
    await this.ctx.storage.deleteAll();
  }
}

/**
 * The flow half of {@link McpCredentialStorePort}, backed by
 * {@link McpOauthFlowClaim}.
 *
 * Shares `encodeFlow`/`decodeFlow` with the KV store on purpose: the wire
 * format is one definition, so a field added to `StoredMcpOauthFlow` cannot be
 * persisted by one store and dropped by the other.
 */
export class DurableOauthFlowStore {
  readonly #namespace: DurableObjectNamespace<McpOauthFlowClaim>;

  constructor(namespace: DurableObjectNamespace<McpOauthFlowClaim>) {
    this.#namespace = namespace;
  }

  #stub(stateId: string): DurableObjectStub<McpOauthFlowClaim> {
    // `idFromName`, NOT `newUniqueId`: the state digest must map to a stable
    // instance or two racers would reach two different actors and the claim
    // would not be a claim at all.
    return this.#namespace.get(this.#namespace.idFromName(stateId));
  }

  async begin(flow: StoredMcpOauthFlow): Promise<void> {
    // The same lifetime `KvOauthFlowStore` hands KV as `expirationTtl`, so the
    // two stores reap on the same schedule.
    await this.#stub(flow.id).begin(encodeFlow(flow), flow.expiresAtUnix - flow.createdAtUnix);
  }

  async consume(stateId: string, nowUnix: number): Promise<StoredMcpOauthFlow | undefined> {
    const raw = await this.#stub(stateId).claim(nowUnix);
    if (raw === undefined) return undefined;
    return decodeFlow(raw);
  }
}
