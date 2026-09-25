import { describe, expect, test, vi } from "vitest";
import { D1SiteDomainDirectory, type SiteDomainDatabase } from "../../src/sites/domains.js";

function harness() {
  const values = new Map<string, string>();
  const get = vi.fn(async (key: string) => JSON.parse(values.get(key) ?? "null"));
  const put = vi.fn(async (key: string, value: string) => {
    values.set(key, value);
  });
  const kv = { get, put } as unknown as KVNamespace;
  const first = vi.fn(
    async (): Promise<unknown> => ({
      hostname: "docs.test",
      tenant_id: "tenant-a",
      site: "docs",
      state: "verified",
      token_expires_at_unix: 1000,
      verification_expires_at_unix: 130,
    }),
  );
  const db = { prepare: () => ({ bind: () => ({ first }) }) } as SiteDomainDatabase;
  const directory = () => new D1SiteDomainDirectory(db, 60, kv);
  return { first, put, get, values, directory };
}

describe("shared custom-domain route cache", () => {
  test("a second worker reuses KV without extending cache or proof deadlines", async () => {
    const h = harness();
    expect((await h.directory().resolve("docs.test", 100)).kind).toBe("route");
    const second = h.directory();
    expect((await second.resolve("docs.test", 120)).kind).toBe("route");
    expect(await second.resolve("docs.test", 130)).toMatchObject({
      kind: "inactive",
      reason: "expired",
    });
    expect(h.first).toHaveBeenCalledTimes(1);
    await second.resolve("docs.test", 160);
    expect(h.first).toHaveBeenCalledTimes(2);
  });

  test("concurrent cold requests share the authority read", async () => {
    const h = harness();
    const directory = h.directory();
    const results = await Promise.all(
      Array.from({ length: 20 }, () => directory.resolve("docs.test", 100)),
    );
    expect(results.every((result) => result.kind === "route")).toBe(true);
    expect(h.first).toHaveBeenCalledTimes(1);
    expect(h.put).toHaveBeenCalledTimes(1);
  });

  test("unknown hostnames do not create KV entries", async () => {
    const h = harness();
    h.first.mockResolvedValue(null);
    expect(await h.directory().resolve("unknown.test", 100)).toEqual({ kind: "unbound" });
    expect(h.put).not.toHaveBeenCalled();
  });

  test("KV failure falls back to the authority", async () => {
    const h = harness();
    h.get.mockRejectedValue(new Error("offline"));
    h.put.mockRejectedValue(new Error("offline"));
    expect((await h.directory().resolve("docs.test", 100)).kind).toBe("route");
    expect(h.first).toHaveBeenCalledTimes(1);
  });
});
