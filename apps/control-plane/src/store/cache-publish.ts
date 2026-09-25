/** Timestamp-only changes do not invalidate content caches. Freshness leases may
 * still require a bounded refresh (quota plans must expire within 60 seconds). */
export async function publishSnapshotIfChanged(
  kv: KVNamespace,
  key: string,
  snapshot: Record<string, unknown>,
  timestamp: "published_at_unix" | "published_at_ms" = "published_at_unix",
  refreshAfter?: number,
): Promise<boolean> {
  const content = ({ [timestamp]: _time, ...body }: Record<string, unknown>) =>
    JSON.stringify(body);
  if (typeof kv.get === "function") {
    try {
      const prior: unknown = await kv.get(key, "json");
      if (prior !== null && typeof prior === "object" && !Array.isArray(prior)) {
        const previous = prior as Record<string, unknown>;
        const age = Number(snapshot[timestamp]) - Number(previous[timestamp]);
        if (
          content(previous) === content(snapshot) &&
          age >= 0 &&
          (refreshAfter === undefined || age < refreshAfter)
        )
          return false;
      }
    } catch {
      // A malformed/missing cache must be repaired from the authority.
    }
  }
  await kv.put(key, JSON.stringify(snapshot));
  return true;
}
