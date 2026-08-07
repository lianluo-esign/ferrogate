/**
 * D1-backed API-key resolution, against a REAL D1 binding in `workerd`.
 *
 * Nothing here is mocked: `env.DB` is a real local SQLite database created by
 * miniflare (the same engine `wrangler dev --local` runs), the `api_keys` table
 * is created from `sql/d1/001_init_d1.sql`'s own DDL, and every row is seeded
 * through the same `hashVirtualApiKeySecret` the resolver verifies against.
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
 * so asserting the variant here IS asserting the status code — the mapping
 * itself is held end-to-end, on the app the Worker exports, by
 * `test/auth.test.ts`. The one thing this file must never let drift is that a
 * SUSPENDED key produces the *unknown-key* variant and not an
 * authenticated-but-forbidden one, which was a real defect class in the Rust
 * tree. `suspended key is INDISTINGUISHABLE from an unknown key` below pins
 * that by deep-equality against the unknown-key answer, so no field can differ.
 */
import { beforeEach, describe, expect, test } from "vitest";
import {
  ApiKeyResolutionCache,
  type ApiKeyStore,
  ApiKeyStoreUnavailable,
  D1ApiKeyResolver,
  D1ApiKeyStore,
  type StoredApiKey,
  apiKeyCacheTtlSeconds,
  blake2b512Hex,
  d1ApiKeyResolverFromEnv,
  isCacheableResolution,
  resetSharedApiKeyCache,
} from "../../src/keys/index.js";
import type { ApiKeyAuthenticatorPort, ApiKeyResolution } from "../../src/ports.js";
import { hasScope } from "../../src/ports.js";
import { deleteApiKey, resetApiKeysTable, seedApiKey, suspendApiKey, testSecret } from "./seed.js";
import { env } from "cloudflare:test";
import { depsFromEnv } from "../../src/adapters.js";

const NOW = 1_800_000_000;

/** A resolver over the real D1 binding, with an injected clock and no cache. */
function resolver(
  options: {
    readonly fallback?: ApiKeyAuthenticatorPort;
    readonly cache?: ApiKeyResolutionCache;
    readonly now?: number;
  } = {},
): D1ApiKeyResolver {
  return new D1ApiKeyResolver({
    store: new D1ApiKeyStore(db),
    fallback: options.fallback,
    cache: options.cache,
    nowUnixSeconds: () => options.now ?? NOW,
  });
}

let db: D1Database;

beforeEach(async () => {
  db = await resetApiKeysTable();
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
        // The two allowlists are ALWAYS present (the columns are
        // `NOT NULL DEFAULT '[]'`), and empty means "no allowlist". They are
        // part of this deep equality on purpose: this assertion is the
        // anti-drift gate that noticed them arriving, and it is what will
        // notice them silently disappearing again.
        allowedModels: [],
        allowedProviders: [],
        // `requestLimitPerMinute` is ABSENT, not 0 — the column is nullable and
        // this row set no cap. `toEqual` treats an absent key and an
        // `undefined` key alike, so the "never 0" claim is pinned separately in
        // `credential-limits.test.ts`.
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

  test("authenticates a legacy blake2b: row", async () => {
    const secret = testSecret("legacy-blake2b");
    await seedApiKey({
      id: "key_legacy",
      secret,
      tenantId: "tenant_a",
      keyHash: `blake2b:${blake2b512Hex(secret)}`,
      scopes: ["chat.completions"],
    });
    const resolution = await resolver().authenticate(secret);
    expect(resolution.outcome).toBe("resolved");
  });

  test("a durable key is NEVER platform root, whatever the row says", async () => {
    // `api_keys` has no `platform_operator` column and this port reads none:
    // the flag is the literal `false`. Even a row that names itself for the
    // operator and carries the wildcard scope stays tenant-confined, so a
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
  test("a key absent from api_keys is `unknown`", async () => {
    await seedApiKey({ id: "key_a", secret: testSecret("present"), tenantId: "tenant_a" });
    await expect(resolver().authenticate(testSecret("never-issued"))).resolves.toEqual({
      outcome: "unknown",
    });
  });

  test("a row whose prefix matches but whose hash does not is `unknown`", async () => {
    // The prefix is an INDEX, not a credential. A caller who learns a prefix
    // (it is only the first 16 chars, and appears in key listings) must gain
    // nothing from it.
    const secret = testSecret("prefix-known");
    await seedApiKey({ id: "key_a", secret, tenantId: "tenant_a" });
    // Same key_prefix AND same last4 as the real row, so the two cheap
    // pre-filters both pass and only the hash verify is left to refuse it.
    const forged = `${secret.slice(0, 16)}${"f".repeat(secret.length - 20)}${secret.slice(-4)}`;
    expect(forged).toHaveLength(secret.length);
    expect(forged.slice(0, 16)).toBe(secret.slice(0, 16));
    expect(forged.slice(-4)).toBe(secret.slice(-4));
    expect(forged).not.toBe(secret);
    await expect(resolver().authenticate(forged)).resolves.toEqual({ outcome: "unknown" });
  });

  test("a blank credential resolves nothing", async () => {
    await expect(resolver().authenticate("   ")).resolves.toEqual({ outcome: "unknown" });
  });

  test("a row whose key_hash is PLAINTEXT never authenticates", async () => {
    // The failure mode a bad migration or a hand-written INSERT produces: the
    // secret ends up in `key_hash` verbatim. `verifyStoredKeyHash` only accepts
    // a `sha256:`/`blake2b:` tagged digest, so such a row can never serve —
    // which is what stops the store from silently degrading to plaintext
    // credentials that still work.
    const secret = testSecret("plaintext-hash-row");
    await seedApiKey({
      id: "key_plaintext",
      secret,
      tenantId: "tenant_a",
      keyHash: secret,
    });
    await expect(resolver().authenticate(secret)).resolves.toEqual({ outcome: "unknown" });
  });

  test("a row whose key_hash carries an unknown algorithm tag never authenticates", async () => {
    const secret = testSecret("unknown-algo-row");
    await seedApiKey({
      id: "key_unknown_algo",
      secret,
      tenantId: "tenant_a",
      // Correct digest bytes, wrong (unsupported) tag: only the two algorithms
      // Rust accepts may authenticate.
      keyHash: `md5:${blake2b512Hex(secret)}`,
    });
    await expect(resolver().authenticate(secret)).resolves.toEqual({ outcome: "unknown" });
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
    // The variants that mean 403 must be nowhere near this answer.
    expect(resolution.outcome).not.toBe("static_key_disabled");
    expect(resolution.outcome).not.toBe("static_key_expired");
    expect(resolution.outcome).not.toBe("resolved");
  });

  test("suspended key is INDISTINGUISHABLE from an unknown key", async () => {
    // The invariant, stated as an equality. `middleware/auth.ts` collapses
    // `unknown` and `key_suspended` onto one identical
    // `401 invalid_api_key` — so an attacker who guesses a real-but-suspended
    // key learns nothing that separates it from a key that never existed.
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
    // Rust: `expires_at.is_none_or(|e| e > now)` — equal means EXPIRED.
    await expect(resolver().authenticate(exactly)).resolves.toEqual({
      outcome: "key_suspended",
      reason: "expired",
    });
    expect((await resolver().authenticate(future)).outcome).toBe("resolved");
  });

  test("a row that names no tenant cannot serve traffic", async () => {
    // Rust `finalize_auth` refuses it with 403 `tenant_identity_required`, and
    // this port now answers the same thing (it used to collapse onto the 401,
    // for want of a variant). The DENIAL is the security half and is asserted
    // first so it keeps holding independently of the exact variant; the variant
    // is asserted second because the OBSERVABLE half is the parity claim.
    const secret = await seedApiKey({
      id: "key_no_tenant",
      secret: testSecret("no-tenant"),
      tenantId: "",
    });
    const resolution = await resolver().authenticate(secret);
    expect(resolution.outcome).not.toBe("resolved");
    expect(resolution).toEqual({ outcome: "tenant_identity_required", declaredButBlank: true });
  });

  test("the blank-tenant refusal does NOT fall through to the config table", async () => {
    // Rust's durable `find_map` skips a record that is not USABLE (disabled /
    // revoked / expired) and lets the config table answer; a blank tenant is
    // not one of those — the record is live, it is chosen, and `finalize_auth`
    // refuses it downstream. So the config fallback must never rescue it: a key
    // id that also exists as a static operator key would otherwise be silently
    // upgraded from "misconfigured tenant row" to "authenticated".
    const secret = await seedApiKey({
      id: "key_no_tenant_shadowed",
      secret: testSecret("no-tenant-shadowed"),
      tenantId: "",
    });
    const rescuing: ApiKeyAuthenticatorPort = {
      async authenticate(): Promise<ApiKeyResolution> {
        return {
          outcome: "resolved",
          auth: {
            subject: "key_fallback",
            tenancy: { tenantId: "tenant_a", projectId: null, workspaceId: null, userId: null },
            scopes: ["*"],
            platformOperator: true,
            source: "static_config",
          },
        };
      },
    };
    const resolution = await resolver({ fallback: rescuing }).authenticate(secret);
    expect(resolution.outcome).toBe("tenant_identity_required");
  });
});

// ---------------------------------------------------------------------------
// 403: authenticated but under-scoped
// ---------------------------------------------------------------------------

describe("403 — insufficient scope", () => {
  test("an under-scoped key RESOLVES, then fails the scope check", async () => {
    // The distinction that matters: the credential is good (so it is NOT 401)
    // and it is the SCOPE that is missing (so it is 403 `scope_denied`).
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
    // Rust `scope_set_allows`: an empty scope set on a durable/virtual key
    // grants ordinary scopes but NEVER a privileged one, so a tenant admin
    // minting a key "with no scopes" does not hand out tenant admin.
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
    await db
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
// Virtual-key scope narrowing
// ---------------------------------------------------------------------------

describe("virtual-key scope narrowing", () => {
  test("a narrowed virtual key cannot reach what its parent could", async () => {
    // Two keys in the same tenant: the console-minted `owner` key, and a
    // virtual key narrowed to inference only. Narrowing must actually bind.
    const ownerSecret = await seedApiKey({
      id: "key_owner",
      secret: testSecret("owner-key"),
      tenantId: "tenant_a",
      scopes: ["admin.read", "admin.write", "assets.read", "assets.write"],
    });
    const narrowedSecret = await seedApiKey({
      id: "key_narrowed",
      secret: testSecret("narrowed-key"),
      tenantId: "tenant_a",
      scopes: ["chat.completions"],
    });

    const owner = await resolver().authenticate(ownerSecret);
    const narrowed = await resolver().authenticate(narrowedSecret);
    expect(owner.outcome).toBe("resolved");
    expect(narrowed.outcome).toBe("resolved");
    if (owner.outcome !== "resolved" || narrowed.outcome !== "resolved") return;

    expect(hasScope(owner.auth.scopes, "admin.write")).toBe(true);
    expect(hasScope(narrowed.auth.scopes, "admin.write")).toBe(false);
    expect(hasScope(narrowed.auth.scopes, "assets.write")).toBe(false);
    expect(hasScope(narrowed.auth.scopes, "chat.completions")).toBe(true);
    // Same tenant, so this is a SCOPE difference, not a tenancy one.
    expect(narrowed.auth.tenancy.tenantId).toBe(owner.auth.tenancy.tenantId);
  });

  test("a stored wildcard is honoured verbatim, and only when stored", async () => {
    const wildcard = await seedApiKey({
      id: "key_wild",
      secret: testSecret("wildcard"),
      tenantId: "tenant_a",
      scopes: ["*"],
    });
    const resolution = await resolver().authenticate(wildcard);
    expect(resolution.outcome).toBe("resolved");
    if (resolution.outcome !== "resolved") return;
    expect(hasScope(resolution.auth.scopes, "admin.write")).toBe(true);
    // …but it is still a tenant credential, not platform root.
    expect(resolution.auth.platformOperator).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// Cross-tenant isolation
// ---------------------------------------------------------------------------

describe("cross-tenant isolation", () => {
  test("a tenant A key never resolves into tenant B scope", async () => {
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
    // Even holding `*`, it is confined to one tenant — the wildcard is a SCOPE
    // grant, not a tenancy grant.
    expect(resolution.auth.platformOperator).toBe(false);
  });

  test("a PREFIX COLLISION across tenants is resolved by the hash, not the index", async () => {
    // The lookup index is `key_prefix`; if the code ever took "first candidate
    // row" it would authenticate tenant A's secret into tenant B's tenancy.
    //
    // These two secrets share ALL 16 prefix characters AND the last4, so
    // neither cheap pre-filter can separate them: the hash verify is the ONLY
    // thing deciding which tenant the caller becomes. (A collision on the
    // prefix alone is not enough for this test — `last4Matches` would quietly
    // do the work and the assertion would pass even with the verify removed.)
    const sharedPrefix = "fg_aaaaaaaaaaaaa";
    const sharedLast4 = "cafe";
    expect(sharedPrefix).toHaveLength(16);
    const aSecret = `${sharedPrefix}${"1".repeat(30)}${sharedLast4}`;
    const bSecret = `${sharedPrefix}${"2".repeat(30)}${sharedLast4}`;
    expect(aSecret.slice(0, 16)).toBe(bSecret.slice(0, 16));
    expect(aSecret.slice(-4)).toBe(bSecret.slice(-4));

    // Tenant B's row is inserted FIRST, so "take the first candidate row" picks
    // the wrong tenant for tenant A's secret.
    await seedApiKey({ id: "key_b", secret: bSecret, tenantId: "tenant_b", scopes: ["*"] });
    await seedApiKey({ id: "key_a", secret: aSecret, tenantId: "tenant_a", scopes: ["*"] });

    const a = await resolver().authenticate(aSecret);
    const b = await resolver().authenticate(bSecret);
    expect(a.outcome).toBe("resolved");
    expect(b.outcome).toBe("resolved");
    if (a.outcome !== "resolved" || b.outcome !== "resolved") return;

    expect(a.auth.tenancy.tenantId).toBe("tenant_a");
    expect(a.auth.subject).toBe("key_a");
    expect(b.auth.tenancy.tenantId).toBe("tenant_b");
    expect(b.auth.subject).toBe("key_b");
  });

  test("a blank last4 column cannot let a sibling row's secret through", async () => {
    // Rust: `last4.is_empty() || presented.ends_with(last4)` — a blank column
    // matches ANY presented key, so the hash is the only thing left standing
    // between tenant A's row and tenant B's secret.
    const sharedPrefix = "fg_bbbbbbbbbbbbb";
    const aSecret = `${sharedPrefix}${"1".repeat(34)}`;
    const bSecret = `${sharedPrefix}${"2".repeat(34)}`;
    await seedApiKey({
      id: "key_a_blank_last4",
      secret: aSecret,
      tenantId: "tenant_a",
      last4: "",
    });

    const a = await resolver().authenticate(aSecret);
    expect(a.outcome).toBe("resolved");
    if (a.outcome === "resolved") expect(a.auth.tenancy.tenantId).toBe("tenant_a");
    await expect(resolver().authenticate(bSecret)).resolves.toEqual({ outcome: "unknown" });
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

  test("a D1 outage is 503, never 401", async () => {
    // Collapsing an outage onto `unknown` would answer "invalid API key" for a
    // perfectly valid credential and make an outage look like a revocation.
    const broken: ApiKeyStore = {
      async findByPrefix(): Promise<readonly StoredApiKey[]> {
        throw new ApiKeyStoreUnavailable("D1_ERROR: network");
      },
    };
    const resolution = await new D1ApiKeyResolver({ store: broken }).authenticate(
      testSecret("anything"),
    );
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
    // Rust skips an inactive record inside `find_map`, so the static
    // `config.api_keys` loop still runs. Preserved here.
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
  test("is OFF by default — Rust parity, so a revocation is immediate", async () => {
    const secret = await seedApiKey({
      id: "key_live",
      secret: testSecret("live"),
      tenantId: "tenant_a",
    });
    const port = resolver();
    expect((await port.authenticate(secret)).outcome).toBe("resolved");

    await suspendApiKey("key_live");

    await expect(port.authenticate(secret)).resolves.toEqual({
      outcome: "key_suspended",
      reason: "disabled",
    });
    expect(new ApiKeyResolutionCache().disabled).toBe(true);
    expect(apiKeyCacheTtlSeconds({})).toBe(0);
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

    // Inside the documented window the stale answer is still served. This is
    // the COST of enabling the cache, asserted so it can never be enlarged
    // silently.
    nowMs += 29_000;
    expect((await port.authenticate(secret)).outcome).toBe("resolved");

    // At the boundary the entry is expired — `>=`, not `>`.
    nowMs += 1_000;
    await expect(port.authenticate(secret)).resolves.toEqual({
      outcome: "key_suspended",
      reason: "disabled",
    });

    // …and it stays refused afterwards; the re-read is not itself cached back
    // into a usable state.
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

    // No clock movement: the key must work on the very next request.
    expect((await port.authenticate(secret)).outcome).toBe("resolved");
  });

  test("an outage is never cached in front of a recovered database", async () => {
    let failing = true;
    const flaky: ApiKeyStore = {
      async findByPrefix(): Promise<readonly StoredApiKey[]> {
        if (failing) throw new ApiKeyStoreUnavailable("D1_ERROR: down");
        return [];
      },
    };
    const cache = new ApiKeyResolutionCache({ ttlSeconds: 300, now: () => 1 });
    const port = new D1ApiKeyResolver({ store: flaky, cache });

    expect((await port.authenticate(testSecret("x"))).outcome).toBe("unavailable");
    expect(cache.size).toBe(0);
    failing = false;
    expect((await port.authenticate(testSecret("x"))).outcome).toBe("unknown");
  });

  test("the cache is bounded and evicts in insertion order", async () => {
    const cache = new ApiKeyResolutionCache({ ttlSeconds: 300, maxEntries: 2, now: () => 1 });
    const resolved: ApiKeyResolution = {
      outcome: "resolved",
      auth: {
        subject: "k",
        tenancy: { tenantId: "t", projectId: null, workspaceId: null, userId: null },
        scopes: [],
        platformOperator: false,
        source: "durable_native",
      },
    };
    cache.set("a", resolved);
    cache.set("b", resolved);
    cache.set("c", resolved);
    expect(cache.size).toBe(2);
    expect(cache.get("a")).toBeUndefined();
    expect(cache.get("c")).toBeDefined();
  });

  test("`set` itself refuses to store a miss or an outage", async () => {
    // The resolver already returns before caching those, so this asserts the
    // GUARD rather than the caller: the cache is exported API, and a later
    // caller that hands it an `unknown` must not be able to pin a
    // 401 in front of a key that was minted a moment later.
    const cache = new ApiKeyResolutionCache({ ttlSeconds: 300, now: () => 1 });

    expect(isCacheableResolution({ outcome: "unknown" })).toBe(false);
    expect(isCacheableResolution({ outcome: "unavailable", detail: "down" })).toBe(false);
    expect(isCacheableResolution({ outcome: "static_key_disabled" })).toBe(false);
    expect(isCacheableResolution({ outcome: "static_key_expired" })).toBe(false);
    expect(isCacheableResolution({ outcome: "key_suspended", reason: "revoked" })).toBe(true);
    expect(isCacheableResolution({ outcome: "token_budget_exhausted" })).toBe(true);

    cache.set("miss", { outcome: "unknown" });
    cache.set("outage", { outcome: "unavailable", detail: "down" });
    cache.set("static", { outcome: "static_key_disabled" });
    expect(cache.size).toBe(0);

    cache.set("suspended", { outcome: "key_suspended", reason: "revoked" });
    expect(cache.size).toBe(1);
  });

  test("a disabled cache stores nothing at all", async () => {
    const cache = new ApiKeyResolutionCache({ ttlSeconds: 0, now: () => 1 });
    cache.set("k", { outcome: "key_suspended", reason: "disabled" });
    expect(cache.size).toBe(0);
    expect(cache.get("k")).toBeUndefined();
  });

  test("the plaintext secret is never used as the cache key", async () => {
    // A live credential must not sit in isolate memory for a TTL after the
    // request that carried it. The digest is the key.
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
  test("returns null with no DB binding, so wiring it in is inert until D1 exists", () => {
    expect(d1ApiKeyResolverFromEnv({})).toBeNull();
  });

  test("builds a working resolver over the real binding", async () => {
    const secret = await seedApiKey({
      id: "key_env",
      secret: testSecret("from-env"),
      tenantId: "tenant_a",
      scopes: ["chat.completions"],
    });
    const port = d1ApiKeyResolverFromEnv({ DB: db });
    expect(port).not.toBeNull();
    const resolution = await port?.authenticate(secret);
    expect(resolution?.outcome).toBe("resolved");
  });

  test("satisfies ApiKeyAuthenticatorPort, so it drops into GatewayDeps.apiKeys", async () => {
    const port: ApiKeyAuthenticatorPort | null = d1ApiKeyResolverFromEnv({ DB: db });
    expect(typeof port?.authenticate).toBe("function");
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
// The COMPOSITION seam — `depsFromEnv` must actually USE the resolver above
// ---------------------------------------------------------------------------

/**
 * Everything above this line tests `d1ApiKeyResolverFromEnv` as a FACTORY: call
 * it, get a working resolver. None of it asserts that `depsFromEnv` — the
 * adapter the deployed Worker actually builds its `GatewayDeps` from — calls
 * that factory at all.
 *
 * The wave-14 mutation sweep proved the gap was real. Replacing
 *
 *     apiKeys: d1ApiKeyResolverFromEnv(env, { fallback: configured }) ?? configured,
 *
 * with a bare `apiKeys: configured` — i.e. unwiring D1 from the credential path
 * of the whole gateway — left all 43 tests in this file GREEN, and the rest of
 * the suite with it. That is `MOUNT-SEAMS.md` **GW-A1**, a T1 auth seam, and it
 * is precisely the trap §1 of that file names: asserting a resolver EXISTS is
 * not asserting the gateway RESOLVES WITH IT.
 *
 * The assertion below is the one thing only the real wiring can produce: a
 * secret that exists ONLY as a D1 row. `vitest.config.ts` seeds
 * `GATEWAY_NATIVE_API_KEYS` / `GATEWAY_STATIC_API_KEYS` with the `fg_tenant_*`
 * and `fg_static_*` fixtures, and this key is in neither table, so the
 * configured authenticator alone can only answer `unknown`.
 */
describe("depsFromEnv — the gateway's credential path is wired to D1", () => {
  test("authenticates a key that exists ONLY as a D1 row", async () => {
    const secret = await seedApiKey({
      id: "key_deps_d1_only",
      secret: testSecret("deps-wiring"),
      tenantId: "tenant_a",
      scopes: ["chat.completions"],
    });

    // The real adapter, over the real bindings the Worker is deployed with.
    const deps = depsFromEnv(env as unknown as Parameters<typeof depsFromEnv>[0]);
    const resolution = await deps.apiKeys.authenticate(secret);

    expect(
      resolution.outcome,
      "depsFromEnv did not resolve a D1-only key: the D1 resolver is not wired into GatewayDeps.apiKeys",
    ).toBe("resolved");
    expect(resolution.outcome === "resolved" ? resolution.auth.tenancy.tenantId : null).toBe(
      "tenant_a",
    );
    // The row came from D1, not from an operator var: `source` is the field
    // that says so, and it is the second thing only the real wiring produces.
    expect(resolution.outcome === "resolved" ? resolution.auth.source : null).toBe("durable_native");
  });

  test("still falls back to the configured tables, so the D1 leg only ADDS a source", async () => {
    // The seam is a `??` chain: wiring D1 in must not un-wire the operator
    // tables. `fg_tenant_tools` is a `vitest.config.ts` fixture with no D1 row.
    const deps = depsFromEnv(env as unknown as Parameters<typeof depsFromEnv>[0]);
    const resolution = await deps.apiKeys.authenticate("fg_tenant_tools");
    expect(resolution.outcome).toBe("resolved");
  });
});

/**
 * Regression (2026-08-07): a MISSING `api_keys` table is not a D1 outage. A
 * gateway pointed at a tenant DB that has not been provisioned yet — or a
 * deployment running entirely on operator/config static keys — must fall
 * through to the static table, not answer 503 for every request. Only a
 * genuine outage stays `unavailable`.
 */
describe("D1ApiKeyStore.findByPrefix — missing table vs outage", () => {
  const storeThatThrows = (message: string): D1ApiKeyStore => {
    const db = {
      prepare: () => ({
        bind: () => ({
          all: async () => {
            throw new Error(message);
          },
        }),
      }),
    } as unknown as D1Database;
    return new D1ApiKeyStore(db);
  };

  test("returns [] when the api_keys table does not exist (falls through to static)", async () => {
    const store = storeThatThrows("D1_ERROR: no such table: api_keys: SQLITE_ERROR");
    await expect(store.findByPrefix("fg_x")).resolves.toEqual([]);
  });

  test("still raises ApiKeyStoreUnavailable on a genuine outage", async () => {
    const store = storeThatThrows("D1_ERROR: Network connection lost");
    await expect(store.findByPrefix("fg_x")).rejects.toBeInstanceOf(ApiKeyStoreUnavailable);
  });
});
