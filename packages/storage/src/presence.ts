/**
 * Durable, coalesced observed-agent presence (ports
 * `ferrogate-storage::observed_agent_presence`, issue #357).
 *
 * Monotonic-upsert correctness proof (inventory §1.5.6): one conditional upsert
 * per `(tenant, api_key)` keeps `lastSeen` maximal and `firstSeen` minimal
 * (`GREATEST`/`LEAST` on Postgres, `max`/`min` on SQLite), folding
 * `requestCount + 1` in the same write — so a delayed/out-of-order touch never
 * regresses the row and a burst never grows the table.
 */
import { observedAgentPresenceKey } from "./ids.js";
import { saturatingAdd } from "./ids.js";

export interface StoredObservedAgentPresence {
  tenantId: string;
  apiKeyId: string;
  firstSeenAtUnix: number;
  lastSeenAtUnix: number;
  requestCount: number;
  updatedAtUnix: number;
}

/** One coalesced presence touch (fire-and-forget off the request hot path). */
export interface ObservedAgentPresenceTouch {
  tenantId: string;
  apiKeyId: string;
  seenAtUnix: number;
}

export class MemoryPresenceStore {
  private readonly rows = new Map<string, StoredObservedAgentPresence>();

  /** Coalesced upsert: max last-seen, min first-seen, +1 count. Never regresses. */
  touchObservedAgentPresence(touch: ObservedAgentPresenceTouch): void {
    const key = observedAgentPresenceKey(touch.tenantId, touch.apiKeyId);
    const existing = this.rows.get(key);
    if (existing) {
      existing.lastSeenAtUnix = Math.max(existing.lastSeenAtUnix, touch.seenAtUnix);
      existing.firstSeenAtUnix = Math.min(existing.firstSeenAtUnix, touch.seenAtUnix);
      existing.requestCount = saturatingAdd(existing.requestCount, 1);
      existing.updatedAtUnix = Math.max(existing.updatedAtUnix, touch.seenAtUnix);
    } else {
      this.rows.set(key, {
        tenantId: touch.tenantId,
        apiKeyId: touch.apiKeyId,
        firstSeenAtUnix: touch.seenAtUnix,
        lastSeenAtUnix: touch.seenAtUnix,
        requestCount: 1,
        updatedAtUnix: touch.seenAtUnix,
      });
    }
  }

  /**
   * Presence rows whose most recent touch is at/after `sinceUnix`, newest first.
   * `tenantScope` restricts to one tenant (the isolation boundary); `undefined`
   * is the platform-operator cross-tenant view.
   */
  listObservedAgentPresenceSince(
    tenantScope: string | undefined,
    sinceUnix: number,
  ): StoredObservedAgentPresence[] {
    const out = [...this.rows.values()]
      .filter((r) => r.lastSeenAtUnix >= sinceUnix)
      .filter((r) => tenantScope === undefined || r.tenantId === tenantScope)
      .map((r) => ({ ...r }));
    out.sort(
      (a, b) =>
        b.lastSeenAtUnix - a.lastSeenAtUnix ||
        a.tenantId.localeCompare(b.tenantId) ||
        a.apiKeyId.localeCompare(b.apiKeyId),
    );
    return out;
  }
}
