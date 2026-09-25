import { describe, expect, test, vi } from "vitest";
import { publishSnapshotIfChanged } from "../src/store/cache-publish.js";

function cache() {
  let value: string | null = null;
  const get = vi.fn(async () => (value === null ? null : JSON.parse(value)));
  const put = vi.fn(async (_key: string, next: string) => {
    value = next;
  });
  return { get, put, kv: { get, put } as unknown as KVNamespace };
}

describe("platform snapshot write suppression", () => {
  test("unchanged content does not rewrite KV, but edits publish immediately", async () => {
    const { kv, put } = cache();
    expect(
      await publishSnapshotIfChanged(kv, "catalog", { published_at_unix: 100, models: ["a"] }),
    ).toBe(true);
    expect(
      await publishSnapshotIfChanged(kv, "catalog", { published_at_unix: 160, models: ["a"] }),
    ).toBe(false);
    expect(put).toHaveBeenCalledTimes(1);
    expect(
      await publishSnapshotIfChanged(kv, "catalog", { published_at_unix: 161, models: ["b"] }),
    ).toBe(true);
    expect(put).toHaveBeenCalledTimes(2);
  });

  test("quota plans renew their freshness lease even when content is unchanged", async () => {
    const { kv, put } = cache();
    const publish = (time: number) =>
      publishSnapshotIfChanged(
        kv,
        "plans",
        { published_at_ms: time, plans: [] },
        "published_at_ms",
        30_000,
      );
    expect(await publish(100_000)).toBe(true);
    expect(await publish(129_999)).toBe(false);
    expect(await publish(130_000)).toBe(true);
    expect(put).toHaveBeenCalledTimes(2);
  });

  test("a failed KV read repairs the cache, and a failed write is not acknowledged", async () => {
    const { kv, get, put } = cache();
    get.mockRejectedValueOnce(new Error("unavailable"));
    expect(await publishSnapshotIfChanged(kv, "catalog", { published_at_unix: 100 })).toBe(true);
    put.mockRejectedValueOnce(new Error("write failed"));
    await expect(
      publishSnapshotIfChanged(kv, "catalog", { published_at_unix: 101, changed: true }),
    ).rejects.toThrow("write failed");
  });
});
