/**
 * The `Config` schema's vocabularies that are OWNED by a sibling package must be
 * the owner's, not a copy of it.
 *
 * This file exists because the copy had already drifted: the inlined
 * `ContentSource` list in `src/schema/enums.ts` was missing the `unknown`
 * variant that `ferrogate_guardrails::ContentSource` (and `@ferrogate/guardrails`)
 * both carry, which silently narrowed the DEFAULT `guardrails[].sources` set — an
 * unclassified content segment would not have been scanned by a
 * default-configured rule, and a rule that explicitly named `unknown` was
 * refused at config load. Nothing was red.
 *
 * So the assertions below are deliberately made at TWO levels:
 *   1. the exported vocabulary equals the owner's (catches an export-level copy);
 *   2. an actual `configSchema.parse(...)` accepts/defaults accordingly (catches
 *      the schema being wired to a stale local list while the export looks right
 *      — the "implemented but never mounted" failure this repo keeps hitting).
 */

import {
  ALL_CONTENT_SOURCES as GUARDRAILS_ALL_CONTENT_SOURCES,
  contentSourceSchema as guardrailsContentSourceSchema,
} from "@ferrogate/guardrails";
import {
  modelCapabilitySchema as providersModelCapabilitySchema,
  routingStrategySchema as providersRoutingStrategySchema,
} from "@ferrogate/providers";
import {
  DEFAULT_DURABLE_PROVIDER_ORDER as STORAGE_DEFAULT_DURABLE_PROVIDER_ORDER,
  providerIsDurable,
  providerIsImplemented,
} from "@ferrogate/storage";
import { describe, expect, test } from "vitest";
import { configSchema } from "../src/schema/config.js";
import {
  ALL_CONTENT_SOURCES,
  DEFAULT_DURABLE_PROVIDER_ORDER,
  contentSourceSchema,
  mcpAuthTypeSchema,
  mcpTransportSchema,
  modelCapabilitySchema,
  postgresTlsModeSchema,
  routingStrategySchema,
  storageProviderKindSchema,
} from "../src/schema/enums.js";
import { validateConfig } from "../src/validate.js";
const nn = <T>(v: T): NonNullable<T> => v as NonNullable<T>;

function firstError(raw: Record<string, unknown>): string | null {
  try {
    validateConfig(configSchema.parse(raw));
    return null;
  } catch (error) {
    return (error as Error).message;
  }
}

// --- @ferrogate/guardrails: ContentSource ----------------------------------

describe("ContentSource is @ferrogate/guardrails'", () => {
  test("the vocabulary is the owner's, `unknown` included", () => {
    expect(contentSourceSchema.options).toEqual(guardrailsContentSourceSchema.options);
    expect(contentSourceSchema.options).toContain("unknown");
    expect(ALL_CONTENT_SOURCES).toEqual([...GUARDRAILS_ALL_CONTENT_SOURCES]);
  });

  test("the DEFAULT guardrails[].sources set scans unclassified content", () => {
    // The regression this file was written for: a default rule must cover
    // `unknown`, or an unrecognized segment escapes the guardrail entirely.
    const config = configSchema.parse({
      guardrails: [{ id: "g", name: "g", keywords: ["secret"] }],
    });
    expect((config.guardrails[0] as NonNullable<(typeof config.guardrails)[0]>).sources).toEqual([
      ...GUARDRAILS_ALL_CONTENT_SOURCES,
    ]);
    expect((config.guardrails[0] as NonNullable<(typeof config.guardrails)[0]>).sources).toContain(
      "unknown",
    );
  });

  test("a rule may name `unknown` explicitly, and a bogus source is still refused", () => {
    expect(
      nn(
        configSchema.parse({ guardrails: [{ id: "g", name: "g", sources: ["unknown"] }] })
          .guardrails[0],
      ).sources,
    ).toEqual(["unknown"]);
    expect(() =>
      configSchema.parse({ guardrails: [{ id: "g", name: "g", sources: ["telepathy"] }] }),
    ).toThrow();
  });
});

// --- @ferrogate/providers: ModelCapability / RoutingStrategy ----------------

describe("ModelCapability / RoutingStrategy are @ferrogate/providers'", () => {
  test("both vocabularies are the owner's", () => {
    expect(modelCapabilitySchema.options).toEqual(providersModelCapabilitySchema.options);
    expect(routingStrategySchema.removeDefault().options).toEqual(
      providersRoutingStrategySchema.options,
    );
  });

  test("the Config field keeps the Rust `#[serde(default)]` = priority", () => {
    const parsed = configSchema.parse({
      models: [{ name: "m", provider: "p", provider_model: "pm" }],
    });
    expect((parsed.models[0] as NonNullable<(typeof parsed.models)[0]>).routing_strategy).toBe(
      "priority",
    );
  });

  test("the schema really uses that vocabulary", () => {
    const model = {
      name: "m",
      provider: "p",
      provider_model: "pm",
      capabilities: providersModelCapabilitySchema.options,
    };
    expect(nn(configSchema.parse({ models: [model] }).models[0]).capabilities).toEqual(
      providersModelCapabilitySchema.options,
    );
    expect(() =>
      configSchema.parse({ models: [{ ...model, capabilities: ["telepathy"] }] }),
    ).toThrow();
  });
});

// --- @ferrogate/storage: StorageProviderKind / PostgresTlsMode -------------

describe("StorageProviderKind / PostgresTlsMode are @ferrogate/storage'", () => {
  test("the durable-provider order is the owner's", () => {
    expect(DEFAULT_DURABLE_PROVIDER_ORDER).toEqual([...STORAGE_DEFAULT_DURABLE_PROVIDER_ORDER]);
    expect(configSchema.parse({}).storage.provider_order).toEqual([
      ...STORAGE_DEFAULT_DURABLE_PROVIDER_ORDER,
    ]);
  });

  test("no kind the owner implements is refused as unimplemented", () => {
    // `validate_storage`'s `provider {x} is not implemented yet` arm now reads
    // the OWNER's predicate, so a backend that gains an implementation in
    // `@ferrogate/storage` can never stay refused by this load-time gate.
    for (const kind of storageProviderKindSchema.options) {
      const error =
        firstError({
          storage: { provider: kind, supabase_dsn_env: "DSN", postgres_dsn_env: "DSN" },
          cloudflare: { account_id: "acct", api_token: "tok" },
        }) ?? "";
      if (providerIsImplemented(kind)) {
        expect(
          error,
          `implemented provider ${kind} must not be refused as unimplemented`,
        ).not.toContain(`provider ${kind} is not implemented yet`);
      } else {
        // turso_libsql / mysql: refused, by their own production-removal rule.
        expect(error, `unimplemented provider ${kind} must be refused`).not.toBe("");
      }
    }
  });

  test("`memory` is the only non-durable kind, per the owner", () => {
    const nonDurable = storageProviderKindSchema.options.filter((k) => !providerIsDurable(k));
    expect(nonDurable).toEqual(["memory"]);
  });

  test("postgres_tls_mode keeps the Rust default and the owner's vocabulary", () => {
    expect(configSchema.parse({}).storage.postgres_tls_mode).toBe("disable");
    expect(postgresTlsModeSchema.removeDefault().options).toEqual([
      "disable",
      "prefer",
      "require",
      "verify_ca",
      "verify_full",
    ]);
  });
});

// --- ferrogate-mcp: the leg that is NOT relocatable -------------------------

describe("McpTransport / McpAuthType stay inlined (no @ferrogate/mcp package)", () => {
  /**
   * PLATFORM/TOPOLOGY LIMIT, not a port gap: `ferrogate-mcp`'s TS port lives in
   * the `apps/mcp` WORKER, and `packages/config` must not depend on an app. So
   * these two vocabularies remain copies, read verbatim from
   * `crates/ferrogate-mcp/src/config.rs`, and are pinned here instead — this is
   * the assertion that goes red if the copy drifts from the Rust source.
   */
  test("McpTransport matches crates/ferrogate-mcp's variants", () => {
    expect(mcpTransportSchema.options).toEqual(["streamable_http", "sse", "stdio"]);
  });

  test("McpAuthType matches crates/ferrogate-mcp's variants, default and alias", () => {
    expect(mcpAuthTypeSchema.parse(undefined)).toBe("none");
    // `#[serde(alias = "headers")]` on `SharedHeaders`.
    expect(mcpAuthTypeSchema.parse("headers")).toBe("shared_headers");
    for (const value of [
      "none",
      "shared_headers",
      "oauth",
      "per_user_oauth",
      "per_user_headers",
      "original_bearer",
      "ferrogate_signed_jwt",
    ]) {
      expect(mcpAuthTypeSchema.parse(value)).toBe(value);
    }
    expect(() => mcpAuthTypeSchema.parse("mtls")).toThrow();
  });
});
