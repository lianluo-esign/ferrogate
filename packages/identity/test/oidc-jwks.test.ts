/**
 * JWKS fetching, caching, and KEY ROTATION.
 *
 * The rotation property is the one that decides whether a cache is a
 * correctness feature or an outage: a cache that never refetches serves a
 * rotated-away key forever (every login fails after the IdP rotates), and a
 * cache that refetches on every unknown `kid` is an unauthenticated remote
 * fetch amplifier. Both failure modes are pinned below.
 */
import { describe, expect, test } from "vitest";
import { JWKS_CACHE_TTL_SECONDS, JwksCache } from "../src/oidc/jwks.js";
import { generateRs256Key, jwksDocument } from "./jwt-fixtures.js";
import { FakeClock } from "./memory-store.js";

function jwksFetcher(documents: () => unknown, counter: { calls: number }) {
  return async (): Promise<Response> => {
    counter.calls += 1;
    return new Response(JSON.stringify(documents()), {
      status: 200,
      headers: { "content-type": "application/json" },
    });
  };
}

describe("JwksCache", () => {
  test("fetches once and serves the cached key for repeated lookups", async () => {
    const key = await generateRs256Key("k1");
    const counter = { calls: 0 };
    const clock = new FakeClock(1_000);
    const cache = new JwksCache({
      fetch: jwksFetcher(() => jwksDocument([key]), counter),
      clock,
    });
    expect(await cache.findKey("https://idp.test/jwks", "k1")).toMatchObject({ kid: "k1" });
    expect(await cache.findKey("https://idp.test/jwks", "k1")).toMatchObject({ kid: "k1" });
    expect(counter.calls).toBe(1);
  });

  test("does NOT serve a rotated-away key past the TTL", async () => {
    const oldKey = await generateRs256Key("old");
    const newKey = await generateRs256Key("new");
    let published = jwksDocument([oldKey]);
    const counter = { calls: 0 };
    const clock = new FakeClock(1_000);
    const cache = new JwksCache({ fetch: jwksFetcher(() => published, counter), clock });

    expect(await cache.findKey("https://idp.test/jwks", "old")).toMatchObject({ kid: "old" });
    // The IdP rotates: `old` is withdrawn from the published document.
    published = jwksDocument([newKey]);
    // Still inside the TTL — the stale entry is intentionally served.
    clock.advance(JWKS_CACHE_TTL_SECONDS - 1);
    expect(await cache.findKey("https://idp.test/jwks", "old")).toMatchObject({ kid: "old" });
    // Past the TTL the cache MUST refetch and the withdrawn key MUST be gone.
    clock.advance(2);
    expect(await cache.findKey("https://idp.test/jwks", "old")).toBeNull();
    expect(counter.calls).toBe(2);
  });

  test("refetches immediately for an unknown kid so a fresh rotation is picked up", async () => {
    const oldKey = await generateRs256Key("old");
    const newKey = await generateRs256Key("new");
    let published = jwksDocument([oldKey]);
    const counter = { calls: 0 };
    const clock = new FakeClock(1_000);
    const cache = new JwksCache({ fetch: jwksFetcher(() => published, counter), clock });

    expect(await cache.findKey("https://idp.test/jwks", "old")).toMatchObject({ kid: "old" });
    published = jwksDocument([oldKey, newKey]);
    // `new` is not in the cached document; the cache must go and look rather
    // than fail the login until the TTL lapses.
    expect(await cache.findKey("https://idp.test/jwks", "new")).toMatchObject({ kid: "new" });
    expect(counter.calls).toBe(2);
  });

  test("rate-limits the unknown-kid refetch so a bogus kid cannot amplify", async () => {
    const key = await generateRs256Key("k1");
    const counter = { calls: 0 };
    const clock = new FakeClock(1_000);
    const cache = new JwksCache({ fetch: jwksFetcher(() => jwksDocument([key]), counter), clock });

    await cache.findKey("https://idp.test/jwks", "k1");
    expect(counter.calls).toBe(1);
    for (let i = 0; i < 25; i += 1) {
      expect(await cache.findKey("https://idp.test/jwks", `forged-${i}`)).toBeNull();
    }
    // Exactly ONE forced refresh, not 25.
    expect(counter.calls).toBe(2);
  });

  test("caches per jwks_uri, never across issuers", async () => {
    const a = await generateRs256Key("shared-kid");
    const b = await generateRs256Key("shared-kid");
    const counter = { calls: 0 };
    const clock = new FakeClock(1_000);
    const cache = new JwksCache({
      fetch: async (url: string) => {
        counter.calls += 1;
        const document = url.includes("idp-a") ? jwksDocument([a]) : jwksDocument([b]);
        return new Response(JSON.stringify(document), { status: 200 });
      },
      clock,
    });
    const fromA = await cache.findKey("https://idp-a.test/jwks", "shared-kid");
    const fromB = await cache.findKey("https://idp-b.test/jwks", "shared-kid");
    expect(fromA).not.toBeNull();
    expect(fromB).not.toBeNull();
    // Two DIFFERENT keys share a kid across two issuers; a cache keyed only by
    // kid would hand issuer B's login issuer A's key.
    expect((fromA as JsonWebKey).n).not.toBe((fromB as JsonWebKey).n);
    expect(counter.calls).toBe(2);
  });

  test("fails closed (null, no throw) when the JWKS endpoint errors", async () => {
    const clock = new FakeClock(1_000);
    const cache = new JwksCache({
      fetch: async () => new Response("nope", { status: 503 }),
      clock,
    });
    expect(await cache.findKey("https://idp.test/jwks", "k1")).toBeNull();
  });

  test("fails closed when the JWKS body is not a JWKS", async () => {
    const clock = new FakeClock(1_000);
    const cache = new JwksCache({
      fetch: async () => new Response('{"not":"a jwks"}', { status: 200 }),
      clock,
    });
    expect(await cache.findKey("https://idp.test/jwks", "k1")).toBeNull();
  });

  test("fails closed when the transport rejects", async () => {
    const clock = new FakeClock(1_000);
    const cache = new JwksCache({
      fetch: async () => {
        throw new Error("connect ECONNREFUSED");
      },
      clock,
    });
    expect(await cache.findKey("https://idp.test/jwks", "k1")).toBeNull();
  });

  test("ignores JWKS entries whose use is not signature verification", async () => {
    const key = await generateRs256Key("enc-only");
    const counter = { calls: 0 };
    const clock = new FakeClock(1_000);
    const encryptionOnly = { keys: [{ ...key.jwk, use: "enc" }] };
    const cache = new JwksCache({ fetch: jwksFetcher(() => encryptionOnly, counter), clock });
    expect(await cache.findKey("https://idp.test/jwks", "enc-only")).toBeNull();
  });
});
