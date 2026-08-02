import { describe, expect, test } from "vitest";
import { loadConfigFromObject, migrateControlPlaneAliases } from "../src/loader.js";
import {
  authRequired,
  configSchema,
  defaultConfig,
  durableApiKeyStore,
  hasCredentialSource,
} from "../src/schema/config.js";
import { apiKeySchema } from "../src/schema/entities.js";
import { DEFAULT_INFERENCE_BODY_MAX_BYTES, limits } from "../src/schema/sections.js";
import {
  apiKeysThatAuthorizeNothing,
  apiKeysWithoutTenantIdentity,
  ensureApiKeyDeclaresTenantIdentity,
  tenancyPostureWarnings,
  validateConfig,
  warnImplicitPlatformOperators,
  warnUndeclaredControlPlaneApiKeys,
} from "../src/validate.js";

describe("Config schema defaults", () => {
  test("an empty document deserializes to the Rust defaults", () => {
    const config = defaultConfig();
    expect(config.listen).toBe("127.0.0.1:8080");
    expect(config.auth.disabled).toBe(false);
    expect(config.tenancy.implicit_platform_operator).toBe(false);
    expect(config.storage.provider).toBe("memory");
    expect(config.storage.provider_order).toEqual(["supabase", "postgres"]);
    expect(config.admin_api.listen).toBe("127.0.0.1:8095");
    expect(config.reliability.tool_approval_timeout_secs).toBe(30);
    expect(config.cache.mode).toBe("exact_match");
  });

  test("nested section defaults are applied on omission (not left as {})", () => {
    const config = configSchema.parse({ tls: {} });
    expect(config.tls.acme.directory_url).toBe("https://acme-v02.api.letsencrypt.org/directory");
    expect(config.agent_runtime.managed_worker.policy_revision).toBe("config-v1");
  });

  test("limits accessors apply the per-route defaults", () => {
    expect(limits.inference(defaultConfig().limits)).toBe(DEFAULT_INFERENCE_BODY_MAX_BYTES);
    expect(limits.admin(defaultConfig().limits)).toBe(64 * 1024);
  });

  test("auth / credential-source accessors", () => {
    expect(authRequired(defaultConfig())).toBe(true);
    expect(hasCredentialSource(defaultConfig())).toBe(false);
    const withD1 = configSchema.parse({ storage: { provider: "cloudflare_d1" } });
    expect(durableApiKeyStore(withD1)).toBe("cloudflare_d1");
    expect(hasCredentialSource(withD1)).toBe(true);
    expect(durableApiKeyStore(defaultConfig())).toBeNull();
  });
});

describe("validateConfig — tenant identity (security invariant #7)", () => {
  // `key_env` is part of the minimum viable key (`validate_api_keys` requires one
  // of key_env/key/key_hash); without it the config now fails BEFORE the
  // tenant-identity gate these cases are about.
  const key = (extra: Record<string, unknown>) =>
    apiKeySchema.parse({ id: "k", name: "k", key_env: "FERROGATE_KEY", ...extra });

  test("refuses a document key that declares neither identity", () => {
    const config = configSchema.parse({ api_keys: [key({})] });
    expect(apiKeysWithoutTenantIdentity(config)).toEqual(["k"]);
    expect(() => validateConfig(config)).toThrow(/tenant_identity_required/);
  });

  test("accepts a key that declares platform_operator or organization_id", () => {
    expect(() =>
      validateConfig(configSchema.parse({ api_keys: [key({ platform_operator: true })] })),
    ).not.toThrow();
    expect(() =>
      validateConfig(configSchema.parse({ api_keys: [key({ organization_id: "org-1" })] })),
    ).not.toThrow();
  });

  test("implicit_platform_operator opt-in permits an undeclared key at load", () => {
    const config = configSchema.parse({
      api_keys: [key({})],
      tenancy: { implicit_platform_operator: true },
    });
    expect(() => validateConfig(config)).not.toThrow();
  });

  test("durable control-plane keys are reported, not refused", () => {
    const config = configSchema.parse({ api_keys: [key({})] });
    expect(() => validateConfig(config, { apiKeysAreControlPlaneDocuments: true })).not.toThrow();
    // The relaxation's compensating control names the ids it let through.
    expect(
      warnUndeclaredControlPlaneApiKeys(config, { apiKeysAreControlPlaneDocuments: true }),
    ).toEqual(["k"]);
    // ...and reports nothing for a config document (which is refused outright).
    expect(warnUndeclaredControlPlaneApiKeys(config)).toEqual([]);
  });

  test("platform_operator=false with no org authorizes nothing (warn-only)", () => {
    const config = configSchema.parse({ api_keys: [key({ platform_operator: false })] });
    expect(apiKeysThatAuthorizeNothing(config)).toEqual(["k"]);
    // Declared (not undeclared), so it loads clean.
    expect(() => validateConfig(config)).not.toThrow();
  });

  test("ensureApiKeyDeclaresTenantIdentity refuses one undeclared key", () => {
    const config = defaultConfig();
    expect(() => ensureApiKeyDeclaresTenantIdentity(config, key({}))).toThrow(
      /tenant_identity_required/,
    );
    expect(() =>
      ensureApiKeyDeclaresTenantIdentity(config, key({ organization_id: "o" })),
    ).not.toThrow();
  });
});

/**
 * The warn-only half of invariant #7.
 *
 * `validateConfig` returns `void` and a library on Workers has no logger, so
 * these two postures CANNOT be surfaced by the load-time gate — they are
 * surfaced by `tenancyPostureWarnings`, which `apps/control-plane`'s
 * `admin_config_ops` validate response and `apps/cli`'s config gate both render.
 * Untested, that function is a security warning nobody has ever read: it is the
 * only thing that tells an operator their legacy opt-in is handing
 * cross-tenant root to undeclared keys.
 */
describe("tenancy posture warnings (warn-only, security invariant #7)", () => {
  const key = (extra: Record<string, unknown>) =>
    apiKeySchema.parse({ id: "k", name: "k", key_env: "FERROGATE_KEY", ...extra });

  test("a clean config warns about nothing", () => {
    const config = configSchema.parse({ api_keys: [key({ organization_id: "org-1" })] });
    expect(tenancyPostureWarnings(config)).toEqual([]);
  });

  test("the legacy opt-in NAMES every key it is silently making a platform operator", () => {
    const config = configSchema.parse({
      api_keys: [key({}), key({ id: "k2", organization_id: "org-1" })],
      tenancy: { implicit_platform_operator: true },
    });
    const warnings = tenancyPostureWarnings(config);
    expect(warnings).toHaveLength(1);
    // The ids matter more than the prose: "some keys" is not actionable.
    expect(warnings[0]).toContain("implicit_platform_operator = true");
    expect(warnings[0]).toContain("UNRESTRICTED cross-tenant");
    expect(warnings[0]).toContain(": k.");
    expect(warnings[0]).not.toContain("k2");
  });

  test("a key that authorizes NOTHING is reported with the refusal it will hit", () => {
    const config = configSchema.parse({ api_keys: [key({ platform_operator: false })] });
    const warnings = tenancyPostureWarnings(config);
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toContain("tenant_identity_required: k.");
  });

  test("warnImplicitPlatformOperators is silent unless the opt-in is on", () => {
    // The switch is the whole trigger: an undeclared key WITHOUT the opt-in is
    // refused outright by `validateConfig`, so warning about it too would be
    // noise on a config that cannot load.
    const config = configSchema.parse({ api_keys: [key({})] });
    expect(warnImplicitPlatformOperators(config)).toEqual([]);
    expect(
      warnImplicitPlatformOperators(
        configSchema.parse({
          api_keys: [key({})],
          tenancy: { implicit_platform_operator: true },
        }),
      ),
    ).toEqual(["k"]);
  });

  test("both postures at once are reported as two separate warnings", () => {
    const config = configSchema.parse({
      api_keys: [key({}), key({ id: "k2", platform_operator: false })],
      tenancy: { implicit_platform_operator: true },
    });
    expect(tenancyPostureWarnings(config)).toHaveLength(2);
  });
});

describe("validateConfig — x402 reconciler money-safety (issue #400)", () => {
  test("rejects a hold TTL that cannot outlive the confirmation window", () => {
    const config = configSchema.parse({
      x402_reconciler: { enabled: true, hold_ttl_secs: 100 },
    });
    expect(() => validateConfig(config)).toThrow(/hold_ttl_secs/);
  });

  test("accepts a hold TTL above the floor and ignores a disabled reconciler", () => {
    expect(() =>
      validateConfig(
        configSchema.parse({ x402_reconciler: { enabled: true, hold_ttl_secs: 3600 } }),
      ),
    ).not.toThrow();
    expect(() =>
      validateConfig(configSchema.parse({ x402_reconciler: { enabled: false, hold_ttl_secs: 1 } })),
    ).not.toThrow();
  });
});

describe("validateConfig — asset bucket R2 (issue #410/#485)", () => {
  const bucket = (extra: Record<string, unknown>) => ({
    asset_bucket: {
      enabled: true,
      backend: "s3",
      bucket: "b",
      access_key_id: "AKIA",
      secret_access_key_env: "S",
      ...extra,
    },
  });

  test("rejects an R2-shaped endpoint that is not a bare account host", () => {
    const config = configSchema.parse(
      bucket({ endpoint: "https://a.b.r2.cloudflarestorage.com", region: "auto" }),
    );
    expect(() => validateConfig(config)).toThrow(/looks like a Cloudflare R2 endpoint/);
  });

  test("requires region auto for a valid R2 endpoint", () => {
    const config = configSchema.parse(
      bucket({ endpoint: "https://acct.r2.cloudflarestorage.com", region: "us-east-1" }),
    );
    expect(() => validateConfig(config)).toThrow(/requires region "auto"/);
  });

  test("accepts a well-formed R2 endpoint with region auto", () => {
    const config = configSchema.parse(
      bucket({ endpoint: "https://acct.r2.cloudflarestorage.com", region: "auto" }),
    );
    expect(() => validateConfig(config)).not.toThrow();
  });
});

describe("control-plane alias migration (issue #359)", () => {
  test("canonical control_api resolves into the effective admin_api", () => {
    const { config } = loadConfigFromObject({ control_api: { listen: "127.0.0.1:9099" } });
    expect(config.admin_api.listen).toBe("127.0.0.1:9099");
  });

  test("deprecated admin_api alias works with a warning", () => {
    const { config, warnings } = loadConfigFromObject({ admin_api: { listen: "127.0.0.1:9098" } });
    expect(config.admin_api.listen).toBe("127.0.0.1:9098");
    expect(warnings.join(" ")).toMatch(/deprecated alias/);
  });

  test("both present is a hard error", () => {
    expect(() =>
      migrateControlPlaneAliases({ control_api: { listen: "a" }, admin_api: { listen: "b" } }),
    ).toThrow(/conflicting control-plane API configuration/);
  });

  test("neither present leaves the defaults", () => {
    const { config, warnings } = loadConfigFromObject({});
    expect(config.admin_api.listen).toBe("127.0.0.1:8095");
    expect(warnings).toEqual([]);
  });
});

describe("validateConfig — listen address", () => {
  test("rejects an invalid listen address", () => {
    expect(() => validateConfig(configSchema.parse({ listen: "not-an-addr" }))).toThrow(
      /listen address/,
    );
    expect(() => validateConfig(configSchema.parse({ listen: "localhost:8080" }))).not.toThrow();
  });
});
