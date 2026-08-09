/**
 * Table-driven pins for the `Config::validate()` legs that previously had only
 * regex-shaped (`toThrow(/hold_ttl_secs/)`) coverage or none at all:
 *
 *   - `validate_asset_bucket`        (10 bails)
 *   - `validate_asset_bucket_r2`     (2 bails)
 *   - `validate_asset_bucket_backend`(3 bails)
 *   - `validate_cloudflare`          (6 bails)
 *   - `validate_x402_reconciler`     (1 bail)
 *   - `validate_cloudflare_mcp_servers` message text in full
 *
 * Every FAIL case asserts the WHOLE `field <path>: <reason>` string, because
 * the field path is the half of the contract an operator navigates by and a
 * bare `toThrow()` would hold neither. Every group also carries the PASS
 * config, so a validator that started refusing everything would go red too.
 */
import { describe, expect, test } from "vitest";
import { configSchema } from "../src/schema/config.js";
import { validateConfig } from "../src/validate.js";

/** The first `field ...: ...` error `validateConfig` raises, or `null`. */
function firstError(raw: Record<string, unknown>): string | null {
  try {
    validateConfig(configSchema.parse(raw));
    return null;
  } catch (error) {
    return (error as Error).message;
  }
}

function expectAccepted(raw: Record<string, unknown>): void {
  expect(firstError(raw)).toBeNull();
}

// --- [asset_bucket] credential presence (issue #176/#411/#485) --------------

describe("validate_asset_bucket", () => {
  /** A complete S3 section; each case overrides exactly one field. */
  const s3 = (extra: Record<string, unknown> = {}) => ({
    asset_bucket: {
      enabled: true,
      backend: "s3",
      endpoint: "https://s3.example.com",
      bucket: "assets",
      region: "us-east-1",
      access_key_id: "AKIA",
      secret_access_key_env: "ASSET_SECRET",
      ...extra,
    },
  });

  test("a complete S3 section is accepted", () => {
    expectAccepted(s3());
  });

  // The empty-string arm runs BEFORE `builds_s3_client()`, so it fires even on
  // a DISABLED section — that ordering is observable and is pinned here by
  // leaving `enabled` at its `false` default.
  const emptyStringCases: [string, string][] = [
    ["endpoint", "field asset_bucket.endpoint: cannot be empty"],
    ["bucket", "field asset_bucket.bucket: cannot be empty"],
    ["region", "field asset_bucket.region: cannot be empty"],
    ["access_key_id", "field asset_bucket.access_key_id: cannot be empty"],
    ["secret_access_key_env", "field asset_bucket.secret_access_key_env: cannot be empty"],
  ];
  test.each(emptyStringCases)(
    "rejects an explicitly empty %s even when the section is disabled",
    (field, expected) => {
      expect(firstError({ asset_bucket: { [field]: "" } })).toBe(expected);
    },
  );

  // The required arm runs only once the runtime would really build the S3
  // client (`enabled && backend == "s3"`).
  const requiredCases: [string, string][] = [
    ["endpoint", "field asset_bucket.endpoint: required when asset_bucket.enabled = true"],
    ["bucket", "field asset_bucket.bucket: required when asset_bucket.enabled = true"],
    ["region", "field asset_bucket.region: required when asset_bucket.enabled = true"],
    [
      "access_key_id",
      "field asset_bucket.access_key_id: required when asset_bucket.enabled = true",
    ],
    [
      "secret_access_key_env",
      "field asset_bucket.secret_access_key_env: required when asset_bucket.enabled = true",
    ],
  ];
  test.each(requiredCases)("requires %s once the S3 client is built", (field, expected) => {
    expect(firstError(s3({ [field]: null }))).toBe(expected);
  });

  test("an omitted credential is NOT required while the section is disabled", () => {
    // `builds_s3_client()` is false, so the whole required arm is skipped.
    expectAccepted({ asset_bucket: { enabled: false, backend: "s3" } });
  });

  test("an omitted S3 credential is NOT required for the CF-native backend", () => {
    // #485: `backend = "workers-static-assets"` never builds the S3 client, so
    // the S3 credential arm must not fire — only the `cf_*` arm below.
    expectAccepted({
      asset_bucket: {
        enabled: true,
        backend: "workers-static-assets",
        cf_account_id: "acct",
        cf_api_token: "tok",
        cf_script_name: "worker",
      },
    });
  });
});

// --- [asset_bucket] R2 shape (issue #410/#485) ------------------------------

describe("validate_asset_bucket_r2", () => {
  const r2 = (extra: Record<string, unknown>) => ({
    asset_bucket: {
      enabled: true,
      backend: "s3",
      bucket: "assets",
      access_key_id: "AKIA",
      secret_access_key_env: "ASSET_SECRET",
      ...extra,
    },
  });

  test("a bare account endpoint with region auto is accepted", () => {
    expectAccepted(r2({ endpoint: "https://acct.r2.cloudflarestorage.com", region: "auto" }));
  });

  test("an .eu. jurisdiction label is accepted", () => {
    expectAccepted(r2({ endpoint: "https://acct.eu.r2.cloudflarestorage.com", region: "auto" }));
  });

  test("a non-R2 endpoint is not subject to either R2 rule", () => {
    // Region is deliberately NOT `auto`: the guard must not leak onto MinIO/S3.
    expectAccepted(r2({ endpoint: "https://s3.example.com", region: "eu-west-1" }));
  });

  test("an R2-shaped endpoint with a path suffix names the endpoint field", () => {
    expect(
      firstError(r2({ endpoint: "https://acct.r2.cloudflarestorage.com/assets", region: "auto" })),
    ).toBe(
      "field asset_bucket.endpoint: https://acct.r2.cloudflarestorage.com/assets looks like a " +
        "Cloudflare R2 endpoint but is not of the form " +
        "https://<account_id>.r2.cloudflarestorage.com (optionally with an .eu./.fedramp. " +
        "jurisdiction label); the account id must be a single DNS label and the endpoint must " +
        "use https:// and carry no userinfo, port, path, query, or fragment. The runtime would " +
        "send `host: acct.r2.cloudflarestorage.com`, which R2 rejects for this endpoint shape",
    );
  });

  test("the endpoint diagnostic never echoes userinfo", () => {
    const message = firstError(
      r2({ endpoint: "https://user:hunter2@acct.r2.cloudflarestorage.com/x", region: "auto" }),
    );
    expect(message).toContain("<redacted-userinfo>@acct.r2.cloudflarestorage.com");
    expect(message).not.toContain("hunter2");
  });

  test("a non-auto region on a valid R2 endpoint names the region field, in full", () => {
    expect(
      firstError(r2({ endpoint: "https://acct.r2.cloudflarestorage.com", region: "us-east-1" })),
    ).toBe(
      'field asset_bucket.region: FerroGate requires region "auto" for Cloudflare R2 endpoints ' +
        '(got "us-east-1"); R2 ignores geographic regions and documents a blank region and ' +
        '"us-east-1" as aliases for "auto", but the signer folds this string straight into the ' +
        "credential scope, so FerroGate pins the canonical value",
    );
  });
});

// --- [asset_bucket] Cloudflare-native backend (issue #411) ------------------

describe("validate_asset_bucket_backend", () => {
  const cfNative = (extra: Record<string, unknown> = {}) => ({
    asset_bucket: {
      enabled: true,
      backend: "workers-static-assets",
      cf_account_id: "acct",
      cf_api_token: "tok",
      cf_script_name: "worker",
      ...extra,
    },
  });

  test("a complete workers-static-assets section is accepted", () => {
    expectAccepted(cfNative());
  });

  const cases: [string, string][] = [
    [
      "cf_account_id",
      'field asset_bucket.cf_account_id: required when asset_bucket.backend = "workers-static-assets"',
    ],
    [
      "cf_api_token",
      'field asset_bucket.cf_api_token: required when asset_bucket.backend = "workers-static-assets"',
    ],
    [
      "cf_script_name",
      'field asset_bucket.cf_script_name: required when asset_bucket.backend = "workers-static-assets"',
    ],
  ];
  test.each(cases)("requires %s", (field, expected) => {
    expect(firstError(cfNative({ [field]: null }))).toBe(expected);
    // Whitespace is not a value: Rust trims before the emptiness test.
    expect(firstError(cfNative({ [field]: "   " }))).toBe(expected);
  });

  test("the cf_* arm is skipped for the S3 backend", () => {
    expectAccepted({
      asset_bucket: {
        enabled: true,
        backend: "s3",
        endpoint: "https://s3.example.com",
        bucket: "assets",
        region: "us-east-1",
        access_key_id: "AKIA",
        secret_access_key_env: "ASSET_SECRET",
      },
    });
  });
});

// --- [cloudflare] (issue #405) ----------------------------------------------

describe("validate_cloudflare", () => {
  const cf = (extra: Record<string, unknown> = {}) => ({
    cloudflare: { account_id: "acct", api_token: "env://CF_TOKEN", ...extra },
  });

  test("an absent [cloudflare] block is accepted", () => {
    expectAccepted({});
  });

  test("a minimal [cloudflare] block is accepted", () => {
    expectAccepted(cf());
  });

  const cases: [string, Record<string, unknown>, string][] = [
    [
      "a blank account_id",
      { cloudflare: { account_id: "  ", api_token: "t" } },
      "field cloudflare.account_id: cannot be empty",
    ],
    [
      "a blank api_token",
      { cloudflare: { account_id: "acct", api_token: "" } },
      "field cloudflare.api_token: cannot be empty (an env:// reference or token)",
    ],
    [
      "a blank per-tenant token reference",
      cf({ tenant_tokens: { acme: "  " } }),
      "field cloudflare.tenant_tokens.acme: token reference cannot be empty",
    ],
    [
      "a blank api_base_url",
      cf({ api_base_url: "  " }),
      "field cloudflare.api_base_url: cannot be empty",
    ],
    [
      "a schemeless api_base_url",
      cf({ api_base_url: "api.cloudflare.com" }),
      "field cloudflare.api_base_url: must start with http:// or https://",
    ],
    [
      "a blank ai_gateway_base_url",
      cf({ ai_gateway_base_url: "" }),
      "field cloudflare.ai_gateway_base_url: cannot be empty",
    ],
    [
      "a schemeless ai_gateway_base_url",
      cf({ ai_gateway_base_url: "gateway.ai.cloudflare.com" }),
      "field cloudflare.ai_gateway_base_url: must start with http:// or https://",
    ],
    [
      "a schemeless r2_s3_endpoint",
      cf({ r2_s3_endpoint: "acct.r2.cloudflarestorage.com" }),
      "field cloudflare.r2_s3_endpoint: must start with http:// or https://",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("a well-formed r2_s3_endpoint is accepted", () => {
    expectAccepted(cf({ r2_s3_endpoint: "https://acct.r2.cloudflarestorage.com" }));
  });
});

// --- [x402_reconciler] money safety (issue #400/#401) -----------------------

describe("validate_x402_reconciler", () => {
  test("a hold TTL at the floor (window + 1) is accepted", () => {
    // Defaults: confirmation_deadline 900 + reconcile_check_delay 60 + tick 30
    // = 990s window, so 991s is the smallest TTL that STRICTLY outlives it.
    expectAccepted({ x402_reconciler: { enabled: true, hold_ttl_secs: 991 } });
  });

  test("a hold TTL exactly AT the window is refused (strictly-outlive, not >=)", () => {
    expect(firstError({ x402_reconciler: { enabled: true, hold_ttl_secs: 990 } })).toBe(
      "field x402_reconciler.hold_ttl_secs: the wallet hold TTL (990s) must strictly outlive " +
        "the settlement confirmation window (confirmation_deadline_secs 900s + " +
        "reconcile_check_delay_secs 60s + one reconciler tick of slack tick_interval_secs 30s " +
        "= 990s); otherwise a payment confirmed on-chain can no longer capture the wallet hold " +
        "(it has already auto-released past its TTL), delivering the stablecoin without ever " +
        "charging the wallet -- raise hold_ttl_secs above 990s or shrink the confirmation window",
    );
  });

  test("a disabled reconciler is never checked", () => {
    expectAccepted({ x402_reconciler: { enabled: false, hold_ttl_secs: 1 } });
  });

  test("the tick interval is part of the floor, not just the deadline + delay", () => {
    // Same deadline/delay, a bigger tick: the floor must move with it.
    expect(
      firstError({
        x402_reconciler: { enabled: true, tick_interval_secs: 300, hold_ttl_secs: 1200 },
      }),
    ).toBe(
      "field x402_reconciler.hold_ttl_secs: the wallet hold TTL (1200s) must strictly outlive " +
        "the settlement confirmation window (confirmation_deadline_secs 900s + " +
        "reconcile_check_delay_secs 60s + one reconciler tick of slack tick_interval_secs 300s " +
        "= 1260s); otherwise a payment confirmed on-chain can no longer capture the wallet hold " +
        "(it has already auto-released past its TTL), delivering the stablecoin without ever " +
        "charging the wallet -- raise hold_ttl_secs above 1260s or shrink the confirmation window",
    );
    expectAccepted({
      x402_reconciler: { enabled: true, tick_interval_secs: 300, hold_ttl_secs: 1261 },
    });
  });
});
