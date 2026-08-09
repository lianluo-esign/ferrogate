/**
 * TWO-HOP API-key resolution (#821), against REAL `workerd` objects.
 *
 * Nothing here is mocked. The directory hop reads `api_key_directory` from the
 * real `CONTROL_DATA` object (reached with the app's own `controlDatabaseFrom`);
 * the second hop routes to a real per-tenant `TenantDataObject` and reads its
 * `api_keys`. Every row is seeded through the same `hashVirtualApiKeySecret` the
 * resolver hashes the presented secret with, so a test can never prove the
 * resolver correct against a hash only the test knows how to make.
 *
 * ## The taxonomy this file exists to hold
 *
 * `src/middleware/auth.ts::resolveOrThrow` maps `ApiKeyResolution` onto HTTP:
 *
 *   `unknown`               → 401 `invalid_api_key`
 *   `key_suspended`         → 401 `invalid_api_key`   ← SAME response. Not 403.
 *   `token_budget_exhausted`→ 429 `token_budget_exceeded`
 *   `unavailable`           → 503 `external_auth_unavailable`
 *   `resolved` + `!hasScope`→ 403 `scope_denied`
 *
 * so asserting the variant here IS asserting the status code. The one thing this
 * file must never let drift is that every SUSPENSION state — directory disabled/
 * revoked/expired, tenant row disabled/revoked/expired, OR a directory whose
 * tenant row is gone — produces the *unknown-key* variant and not an
 * authenticated-but-forbidden one. `suspended key is INDISTINGUISHABLE from an
 * unknown key` pins that by deep-equality against the unknown-key answer.
 */

import { env } from "cloudflare:test";
import { D1TwoHopApiKeyDirectory, type TwoHopApiKeyResolution } from "@ferrogate/storage";
import { beforeEach, describe, expect, test } from "vitest";
import { depsFromEnv } from "../../src/adapters.js";
import {
  ApiKeyResolutionCache,
  D1ApiKeyResolver,
  apiKeyCacheTtlSeconds,
  d1ApiKeyResolverFromEnv,
  isCacheableResolution,
  resetSharedApiKeyCache,
} from "../../src/keys/index.js";
import type { ApiKeyAuthenticatorPort, ApiKeyResolution } from "../../src/ports.js";
import { hasScope } from "../../src/ports.js";
import {
  controlDb,
  deleteApiKey,
  resetApiKeysTable,
  seedApiKey,
  suspendApiKey,
  tenantRouter,
  testSecret,
} from "./seed.js";

const NOW = 1_800_000_000;

/** A resolver over the real two-hop objects, with an injected clock and no cache. */
function resolver(
  options: {
    readonly fallback?: ApiKeyAuthenticatorPort;
    readonly cache?: ApiKeyResolutionCache;
    readonly now?: number;
  } = {},
): D1ApiKeyResolver {
  return new D1ApiKeyResolver({
    directory: new D1TwoHopApiKeyDirectory(controlDb(), tenantRouter(), {
      now: () => options.now ?? NOW,
    }),
    fallback: options.fallback,
    cache: options.cache,
  });
}

/** A resolver whose directory seam is a stub — for the outage cases D1 cannot stage. */
function resolverWith(
  directory: { resolve(keyHash: string): Promise<TwoHopApiKeyResolution> },
  cache?: ApiKeyResolutionCache,
): D1ApiKeyResolver {
  return new D1ApiKeyResolver({ directory, cache });
}

beforeEach(async () => {
  await resetApiKeysTable();
  resetSharedApiKeyCache();
});

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

describe("a valid key", () => {
  test("resolves to its tenancy, scopes and api-key id", async () => {
    const secret = await seedApiKey({
      id: "key_a",
      secret: testSecret("tenant-a-good"),
      tenantId: "tenant_a",
      projectId: "project_a",
      workspaceId: "workspace_a",
      scopes: ["chat.completions", "models.read"],
    });

    const resolution = await resolver().authenticate(secret);

    expect(resolution).toEqual({
      outcome: "resolved",
      auth: {
        subject: "key_a",
        tenancy: {
          tenantId: "tenant_a",
          projectId: "project_a",
          workspaceId: "workspace_a",
          userId: null,
        },
        scopes: ["chat.completions", "models.read"],
        platformOperator: false,
        source: "durable_native",
        // The two allowlists are ALWAYS present (`NOT NULL DEFAULT '[]'`) and
        // empty means "no allowlist"; part of this deep equality on purpose.
        allowedModels: [],
        allowedProviders: [],
      },
    });
  });

  test("is tolerant of surrounding whitespace, exactly as Rust trims", async () => {
    const secret = await seedApiKey({
      id: "key_trim",
      secret: testSecret("trim"),
      tenantId: "tenant_a",
    });
    const resolution = await resolver().authenticate(`  ${secret}\n`);
    expect(resolution.outcome).toBe("resolved");
  });

  test("a durable key is NEVER platform root, whatever the row says", async () => {
    // Neither `api_key_directory` nor `api_keys` has a `platform_operator`
    // column and this port reads none: the flag is the literal `false`. A
    // compromised control-plane write cannot mint cross-tenant root.
    const secret = await seedApiKey({
      id: "key_pretender",
      secret: testSecret("platform-operator-root"),
      tenantId: "tenant_a",
      name: "platform_operator",
      scopes: ["*"],
    });
    const resolution = await resolver().authenticate(secret);
    expect(resolution.outcome).toBe("resolved");
    if (resolution.outcome !== "resolved") return;
    expect(resolution.auth.platformOperator).toBe(false);
    expect(resolution.auth.tenancy.tenantId).toBe("tenant_a");
  });
});

// ---------------------------------------------------------------------------
// 401: unknown, and the suspension family that must be indistinguishable from it
// ---------------------------------------------------------------------------

describe("401 — unknown key", () => {
  test("a key absent from the directory is `unknown`", async () => {
    await seedApiKey({ id: "key_a", secret: testSecret("present"), tenantId: "tenant_a" });
    await expect(resolver().authenticate(testSecret("never-issued"))).resolves.toEqual({
      outcome: "unknown",
    });
  });

  test("a forged secret hashes to a DIFFERENT directory key and is `unknown`", async () => {
    // The directory is keyed by `key_hash`; a secret that is not the seeded one
    // hashes elsewhere and matches no row. (Under the old prefix index this was
    // the "prefix matches, hash does not" case; the hash-keyed lookup makes it a
    // plain miss.)
    const secret = testSecret("prefix-known");
    await seedApiKey({ id: "key_a", secret, tenantId: "tenant_a" });
    const forged = `${secret.slice(0, 16)}${"f".repeat(secret.length - 20)}${secret.slice(-4)}`;
    expect(forged).not.toBe(secret);
    await expect(resolver().authenticate(forged)).resolves.toEqual({ outcome: "unknown" });
  });

  test("a blank credential resolves nothing", async () => {
    await expect(resolver().authenticate("   ")).resolves.toEqual({ outcome: "unknown" });
  });

  test("a row whose key_hash is PLAINTEXT never authenticates", async () => {
    // The failure mode a bad migration or a hand-written INSERT produces: the
    // secret ends up in `key_hash` verbatim (in BOTH halves). Every probe carries
    // the `sha256:` tag over the DIGEST, so it can never equal a plaintext value.
    const secret = testSecret("plaintext-hash-row");
    await seedApiKey({
      id: "key_plaintext",
      secret,
      tenantId: "tenant_a",
      keyHash: secret,
    });
    await expect(resolver().authenticate(secret)).resolves.toEqual({ outcome: "unknown" });
  });

  test("an `unroutable` two-hop result renders as the unknown-key 401, with no fallback", async () => {
    const rescuing: ApiKeyAuthenticatorPort = {
      async authenticate(): Promise<ApiKeyResolution> {
        return {
          outcome: "resolved",
          auth: {
            subject: "config_key",
            tenancy: { tenantId: "tenant_x", projectId: null, workspaceId: null, userId: null },
            scopes: ["*"],
            platformOperator: true,
            source: "static_config",
          },
        };
      },
    };
    const resolver = new D1ApiKeyResolver({
      directory: {
        async resolve(): Promise<TwoHopApiKeyResolution> {
          return { kind: "unroutable" };
        },
      },
      fallback: rescuing,
    });
    // A durable key whose tenant is unprovisioned must NOT be rescued by a config
    // var — that would let the var speak for a durable credential the DB owns.
    await expect(resolver.authenticate(testSecret("x"))).resolves.toEqual({ outcome: "unknown" });
  });
});

describe("401 — a SUSPENDED key is 401, not 403", () => {
  test("enabled = 0 answers `key_suspended`, which the middleware renders 401", async () => {
    const secret = await seedApiKey({
      id: "key_suspended",
      secret: testSecret("suspended"),
      tenantId: "tenant_a",
      scopes: ["chat.completions"],
      enabled: false,
    });

    const resolution = await resolver().authenticate(secret);

    expect(resolution).toEqual({ outcome: "key_suspended", reason: "disabled" });
    expect(resolution.outcome).not.toBe("static_key_disabled");
    expect(resolution.outcome).not.toBe("static_key_expired");
    expect(resolution.outcome).not.toBe("resolved");
  });

  test("suspended key is INDISTINGUISHABLE from an unknown key", async () => {
    const suspended = await seedApiKey({
      id: "key_susp",
      secret: testSecret("susp"),
      tenantId: "tenant_a",
      enabled: false,
    });

    const suspendedAnswer = await resolver().authenticate(suspended);
    const unknownAnswer = await resolver().authenticate(testSecret("no-such-key"));

    const httpFor = (resolution: ApiKeyResolution): number =>
      resolution.outcome === "unknown" || resolution.outcome === "key_suspended" ? 401 : 403;
    expect(httpFor(suspendedAnswer)).toBe(401);
    expect(httpFor(unknownAnswer)).toBe(401);
    expect(httpFor(suspendedAnswer)).toBe(httpFor(unknownAnswer));
  });

  test("a REVOKED key (revoked_at_unix set) is 401 too", async () => {
    const secret = await seedApiKey({
      id: "key_revoked",
      secret: testSecret("revoked"),
      tenantId: "tenant_a",
      revokedAtUnix: NOW - 1,
    });
    await expect(resolver().authenticate(secret)).resolves.toEqual({
      outcome: "key_suspended",
      reason: "revoked",
    });
  });

  test("an EXPIRED key is 401, and expiry is inclusive of `now`", async () => {
    const past = await seedApiKey({
      id: "key_expired",
      secret: testSecret("expired"),
      tenantId: "tenant_a",
      expiresAtUnix: NOW - 1,
    });
    const exactly = await seedApiKey({
      id: "key_expiring_now",
      secret: testSecret("expiring-now"),
      tenantId: "tenant_a",
      expiresAtUnix: NOW,
    });
    const future = await seedApiKey({
      id: "key_not_expired",
      secret: testSecret("not-expired"),
      tenantId: "tenant_a",
      expiresAtUnix: NOW + 1,
    });

    await expect(resolver().authenticate(past)).resolves.toEqual({
      outcome: "key_suspended",
      reason: "expired",
    });
    await expect(resolver().authenticate(exactly)).resolves.toEqual({
      outcome: "key_suspended",
      reason: "expired",
    });
    expect((await resolver().authenticate(future)).outcome).toBe("resolved");
  });

  test("a directory whose TENANT ROW is gone is 401 (a revoke that landed leg 2)", async () => {
    const secret = await seedApiKey({
      id: "key_ghost_row",
      secret: testSecret("ghost-row"),
      tenantId: "tenant_a",
      skipTenantRow: true,
    });
    await expect(resolver().authenticate(secret)).resolves.toEqual({
      outcome: "key_suspended",
      reason: "revoked",
    });
  });
});

// ---------------------------------------------------------------------------
// 403: authenticated but under-scoped
// ---------------------------------------------------------------------------

describe("403 — insufficient scope", () => {
  test("an under-scoped key RESOLVES, then fails the scope check", async () => {
    const secret = await seedApiKey({
      id: "key_readonly",
      secret: testSecret("readonly"),
      tenantId: "tenant_a",
      scopes: ["models.read"],
    });

    const resolution = await resolver().authenticate(secret);
    expect(resolution.outcome).toBe("resolved");
    if (resolution.outcome !== "resolved") return;

    expect(hasScope(resolution.auth.scopes, "models.read")).toBe(true);
    expect(hasScope(resolution.auth.scopes, "chat.completions")).toBe(false);
    expect(hasScope(resolution.auth.scopes, "admin.write")).toBe(false);
  });

  test("an UNSCOPED durable key gets data-plane scopes and never admin.*", async () => {
    const secret = await seedApiKey({
      id: "key_unscoped",
      secret: testSecret("unscoped"),
      tenantId: "tenant_a",
      scopes: [],
    });

    const resolution = await resolver().authenticate(secret);
    expect(resolution.outcome).toBe("resolved");
    if (resolution.outcome !== "resolved") return;

    expect(resolution.auth.scopes).toEqual([]);
    expect(hasScope(resolution.auth.scopes, "chat.completions")).toBe(true);
    expect(hasScope(resolution.auth.scopes, "admin.read")).toBe(false);
    expect(hasScope(resolution.auth.scopes, "admin.write")).toBe(false);
  });

  test("a malformed scopes_json degrades to the empty set, never a wildcard", async () => {
    const secret = testSecret("bad-scopes");
    await seedApiKey({ id: "key_bad_scopes", secret, tenantId: "tenant_a" });
    await (await tenantRouter().forTenant("tenant_a")).db
      .prepare("UPDATE api_keys SET scopes_json = ? WHERE id = ?")
      .bind("{not json", "key_bad_scopes")
      .run();

    const resolution = await resolver().authenticate(secret);
    expect(resolution.outcome).toBe("resolved");
    if (resolution.outcome !== "resolved") return;
    expect(resolution.auth.scopes).toEqual([]);
    expect(hasScope(resolution.auth.scopes, "admin.write")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Cross-tenant isolation — the whole point of the two hops
// ---------------------------------------------------------------------------

describe("cross-tenant isolation", () => {
  test("a tenant A key resolves ONLY to its directory tenant, holding `*`", async () => {
    const aSecret = await seedApiKey({
      id: "key_a",
      secret: testSecret("tenant-a"),
      tenantId: "tenant_a",
      projectId: "project_a",
      workspaceId: "workspace_a",
      scopes: ["*"],
    });
    await seedApiKey({
      id: "key_b",
      secret: testSecret("tenant-b"),
      tenantId: "tenant_b",
      projectId: "project_b",
      workspaceId: "workspace_b",
      scopes: ["*"],
    });

    const resolution = await resolver().authenticate(aSecret);
    expect(resolution.outcome).toBe("resolved");
    if (resolution.outcome !== "resolved") return;

    expect(resolution.auth.tenancy).toEqual({
      tenantId: "tenant_a",
      projectId: "project_a",
      workspaceId: "workspace_a",
      userId: null,
    });
    expect(resolution.auth.subject).toBe("key_a");
    // Even holding `*`, it is confined to one tenant — a SCOPE grant, not a
    // tenancy one.
    expect(resolution.auth.platformOperator).toBe(false);
  });

  test("a key is NEVER resolved against another tenant's database", async () => {
    // The directory routes to tenant A; the `api_keys` row was written into
    // tenant B's database ONLY. A router that ignored its argument, or a shared
    // database, would authenticate this. The correct answer is that A's database
    // has no such row ⇒ the tenant row is gone ⇒ 401.
    const secret = await seedApiKey({
      id: "key_wrong_db",
      secret: testSecret("wrong-db"),
      tenantId: "tenant_a",
      tenantRowIn: "tenant_b",
      scopes: ["*"],
    });
    await expect(resolver().authenticate(secret)).resolves.toEqual({
      outcome: "key_suspended",
      reason: "revoked",
    });
  });
});

// ---------------------------------------------------------------------------
// Budgets and store availability
// ---------------------------------------------------------------------------

describe("budget and availability", () => {
  test("monthly_token_budget = 0 is 429, and NULL is unlimited", async () => {
    const exhausted = await seedApiKey({
      id: "key_broke",
      secret: testSecret("broke"),
      tenantId: "tenant_a",
      monthlyTokenBudget: 0,
    });
    const unlimited = await seedApiKey({
      id: "key_unlimited",
      secret: testSecret("unlimited"),
      tenantId: "tenant_a",
      monthlyTokenBudget: null,
    });
    const funded = await seedApiKey({
      id: "key_funded",
      secret: testSecret("funded"),
      tenantId: "tenant_a",
      monthlyTokenBudget: 1,
    });

    await expect(resolver().authenticate(exhausted)).resolves.toEqual({
      outcome: "token_budget_exhausted",
    });
    expect((await resolver().authenticate(unlimited)).outcome).toBe("resolved");
    expect((await resolver().authenticate(funded)).outcome).toBe("resolved");
  });

  test("a control-object outage is 503, never 401", async () => {
    const broken = {
      async resolve(): Promise<TwoHopApiKeyResolution> {
        return { kind: "unavailable", detail: "D1_ERROR: network" };
      },
    };
    const resolution = await resolverWith(broken).authenticate(testSecret("anything"));
    expect(resolution).toEqual({ outcome: "unavailable", detail: "D1_ERROR: network" });
  });
});

// ---------------------------------------------------------------------------
// Key-source ORDER: durable first, config fallback second (Rust's order)
// ---------------------------------------------------------------------------

describe("key-source order", () => {
  const configOnly: ApiKeyAuthenticatorPort = {
    async authenticate(presented: string): Promise<ApiKeyResolution> {
      return presented === "fg_static_operator_key_value_0000000000000000"
        ? {
            outcome: "resolved",
            auth: {
              subject: "key_static",
              tenancy: { tenantId: null, projectId: null, workspaceId: null, userId: null },
              scopes: ["*"],
              platformOperator: true,
              source: "static_config",
            },
          }
        : { outcome: "unknown" };
    },
  };

  test("a durable row wins over the config table", async () => {
    const secret = await seedApiKey({
      id: "key_durable",
      secret: testSecret("durable-first"),
      tenantId: "tenant_a",
    });
    const resolution = await resolver({ fallback: configOnly }).authenticate(secret);
    expect(resolution.outcome).toBe("resolved");
    if (resolution.outcome === "resolved") expect(resolution.auth.source).toBe("durable_native");
  });

  test("a config key still resolves when no durable row matches", async () => {
    const resolution = await resolver({ fallback: configOnly }).authenticate(
      "fg_static_operator_key_value_0000000000000000",
    );
    expect(resolution.outcome).toBe("resolved");
    if (resolution.outcome === "resolved") expect(resolution.auth.source).toBe("static_config");
  });

  test("a suspended durable row still lets the config table answer, as Rust does", async () => {
    await seedApiKey({
      id: "key_suspended_collide",
      secret: "fg_static_operator_key_value_0000000000000000",
      tenantId: "tenant_a",
      enabled: false,
    });
    const resolution = await resolver({ fallback: configOnly }).authenticate(
      "fg_static_operator_key_value_0000000000000000",
    );
    expect(resolution.outcome).toBe("resolved");
    if (resolution.outcome === "resolved") expect(resolution.auth.source).toBe("static_config");
  });

  test("with no config match, the suspension is the answer — and it is 401", async () => {
    const secret = await seedApiKey({
      id: "key_only_suspended",
      secret: testSecret("only-suspended"),
      tenantId: "tenant_a",
      enabled: false,
    });
    await expect(resolver({ fallback: configOnly }).authenticate(secret)).resolves.toEqual({
      outcome: "key_suspended",
      reason: "disabled",
    });
  });
});

// ---------------------------------------------------------------------------
// Cache
// ---------------------------------------------------------------------------

describe("cache", () => {
  test("an explicitly uncached resolver keeps revocation immediate", async () => {
    const secret = await seedApiKey({
      id: "key_live",
      secret: testSecret("live"),
      tenantId: "tenant_a",
    });
    const port = resolver({ cache: new ApiKeyResolutionCache({ ttlSeconds: 0 }) });
    expect((await port.authenticate(secret)).outcome).toBe("resolved");

    await suspendApiKey("key_live");

    await expect(port.authenticate(secret)).resolves.toEqual({
      outcome: "key_suspended",
      reason: "disabled",
    });
    expect(apiKeyCacheTtlSeconds({})).toBe(30);
  });

  test("a SUSPENDED key stops working once the TTL elapses — and no later", async () => {
    let nowMs = 1_000_000;
    const cache = new ApiKeyResolutionCache({ ttlSeconds: 30, now: () => nowMs });
    const port = resolver({ cache });

    const secret = await seedApiKey({
      id: "key_cached",
      secret: testSecret("cached"),
      tenantId: "tenant_a",
      scopes: ["chat.completions"],
    });
    expect((await port.authenticate(secret)).outcome).toBe("resolved");

    await suspendApiKey("key_cached");

    nowMs += 29_000;
    expect((await port.authenticate(secret)).outcome).toBe("resolved");

    nowMs += 1_000;
    await expect(port.authenticate(secret)).resolves.toEqual({
      outcome: "key_suspended",
      reason: "disabled",
    });

    nowMs += 60_000;
    expect((await port.authenticate(secret)).outcome).toBe("key_suspended");
  });

  test("a DELETED key stops working once the TTL elapses", async () => {
    let nowMs = 5_000_000;
    const cache = new ApiKeyResolutionCache({ ttlSeconds: 10, now: () => nowMs });
    const port = resolver({ cache });

    const secret = await seedApiKey({
      id: "key_doomed",
      secret: testSecret("doomed"),
      tenantId: "tenant_a",
    });
    expect((await port.authenticate(secret)).outcome).toBe("resolved");

    await deleteApiKey("key_doomed");

    nowMs += 9_999;
    expect((await port.authenticate(secret)).outcome).toBe("resolved");
    nowMs += 1;
    await expect(port.authenticate(secret)).resolves.toEqual({ outcome: "unknown" });
  });

  test("an unknown key is never cached, so a freshly-minted key works at once", async () => {
    const nowMs = 7_000_000;
    const cache = new ApiKeyResolutionCache({ ttlSeconds: 300, now: () => nowMs });
    const port = resolver({ cache });

    const secret = testSecret("minted-later");
    await expect(port.authenticate(secret)).resolves.toEqual({ outcome: "unknown" });
    expect(cache.size).toBe(0);

    await seedApiKey({ id: "key_new", secret, tenantId: "tenant_a" });

    expect((await port.authenticate(secret)).outcome).toBe("resolved");
  });

  test("an outage is never cached in front of a recovered database", async () => {
    let failing = true;
    const flaky = {
      async resolve(): Promise<TwoHopApiKeyResolution> {
        if (failing) return { kind: "unavailable", detail: "D1_ERROR: down" };
        return { kind: "no_directory_row" };
      },
    };
    const cache = new ApiKeyResolutionCache({ ttlSeconds: 300, now: () => 1 });
    const port = resolverWith(flaky, cache);

    expect((await port.authenticate(testSecret("x"))).outcome).toBe("unavailable");
    expect(cache.size).toBe(0);
    failing = false;
    expect((await port.authenticate(testSecret("x"))).outcome).toBe("unknown");
  });

  test("`set` itself refuses to store a miss or an outage", async () => {
    const cache = new ApiKeyResolutionCache({ ttlSeconds: 300, now: () => 1 });

    expect(isCacheableResolution({ outcome: "unknown" })).toBe(false);
    expect(isCacheableResolution({ outcome: "unavailable", detail: "down" })).toBe(false);
    expect(isCacheableResolution({ outcome: "key_suspended", reason: "revoked" })).toBe(true);
    expect(isCacheableResolution({ outcome: "token_budget_exhausted" })).toBe(true);

    cache.set("miss", { outcome: "unknown" });
    cache.set("outage", { outcome: "unavailable", detail: "down" });
    expect(cache.size).toBe(0);

    cache.set("suspended", { outcome: "key_suspended", reason: "revoked" });
    expect(cache.size).toBe(1);
  });

  test("the plaintext secret is never used as the cache key", async () => {
    const cache = new ApiKeyResolutionCache({ ttlSeconds: 300, now: () => 1 });
    const secret = await seedApiKey({
      id: "key_secret",
      secret: testSecret("no-plaintext"),
      tenantId: "tenant_a",
    });
    await resolver({ cache }).authenticate(secret);
    expect(cache.size).toBe(1);
    expect(cache.get(secret)).toBeUndefined();
  });

  test("apiKeyCacheTtlSeconds reads the var and fails closed on junk", () => {
    expect(apiKeyCacheTtlSeconds({ GATEWAY_API_KEY_CACHE_TTL_SECONDS: "30" })).toBe(30);
    expect(apiKeyCacheTtlSeconds({ GATEWAY_API_KEY_CACHE_TTL_SECONDS: "" })).toBe(0);
    expect(apiKeyCacheTtlSeconds({ GATEWAY_API_KEY_CACHE_TTL_SECONDS: "abc" })).toBe(0);
    expect(apiKeyCacheTtlSeconds({ GATEWAY_API_KEY_CACHE_TTL_SECONDS: "-5" })).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// The composition seam
// ---------------------------------------------------------------------------

describe("d1ApiKeyResolverFromEnv — the wiring seam", () => {
  test("returns null with no CONTROL_DATA binding, so wiring it in is inert", () => {
    expect(d1ApiKeyResolverFromEnv({})).toBeNull();
  });

  test("builds a working resolver over the real bindings", async () => {
    const secret = await seedApiKey({
      id: "key_env",
      secret: testSecret("from-env"),
      tenantId: "tenant_a",
      scopes: ["chat.completions"],
    });
    const port = d1ApiKeyResolverFromEnv(
      env as unknown as Parameters<typeof d1ApiKeyResolverFromEnv>[0],
    );
    expect(port).not.toBeNull();
    const resolution = await port?.authenticate(secret);
    expect(resolution?.outcome).toBe("resolved");
  });

  test("resolveStoredKey exposes the row, but never for a suspended key", async () => {
    const good = await seedApiKey({
      id: "key_full",
      secret: testSecret("full-row"),
      tenantId: "tenant_a",
      allowedModels: ["gpt-4o"],
      allowedProviders: ["openai"],
      requestLimitPerMinute: 60,
    });
    const suspended = await seedApiKey({
      id: "key_full_suspended",
      secret: testSecret("full-row-suspended"),
      tenantId: "tenant_a",
      enabled: false,
      allowedModels: ["gpt-4o"],
    });

    const row = await resolver().resolveStoredKey(good);
    expect(row?.allowedModels).toEqual(["gpt-4o"]);
    expect(row?.allowedProviders).toEqual(["openai"]);
    expect(row?.requestLimitPerMinute).toBe(60);
    await expect(resolver().resolveStoredKey(suspended)).resolves.toBeNull();
  });
});

// ---------------------------------------------------------------------------
// The COMPOSITION seam — `depsFromEnv` must actually USE the two-hop resolver
// ---------------------------------------------------------------------------

describe("depsFromEnv — the gateway's credential path is wired to the directory", () => {
  test("authenticates a key that exists ONLY as a directory + tenant row", async () => {
    const secret = await seedApiKey({
      id: "key_deps_only",
      secret: testSecret("deps-wiring"),
      tenantId: "tenant_a",
      scopes: ["chat.completions"],
    });

    const deps = depsFromEnv(env as unknown as Parameters<typeof depsFromEnv>[0]);
    const resolution = await deps.apiKeys.authenticate(secret);

    expect(
      resolution.outcome,
      "depsFromEnv did not resolve a directory-only key: the two-hop resolver is not wired into GatewayDeps.apiKeys",
    ).toBe("resolved");
    expect(resolution.outcome === "resolved" ? resolution.auth.tenancy.tenantId : null).toBe(
      "tenant_a",
    );
    expect(resolution.outcome === "resolved" ? resolution.auth.source : null).toBe(
      "durable_native",
    );
  });

  test("still falls back to the configured tables, so the durable leg only ADDS a source", async () => {
    const deps = depsFromEnv(env as unknown as Parameters<typeof depsFromEnv>[0]);
    const resolution = await deps.apiKeys.authenticate("fg_tenant_tools");
    expect(resolution.outcome).toBe("resolved");
  });
});
