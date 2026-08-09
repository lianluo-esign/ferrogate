import { describe, expect, it, vi } from "vitest";
import {
  CfSecretsStoreConfig,
  CloudflareSecretResolver,
  SecretResolverRegistry,
  parseSecretRef,
} from "../src/index.js";
import { BASE, okEnvelope, readRoutes, resolverWith, secretsListingJson } from "./support.js";

describe("CloudflareSecretResolver.resolve (existence check only)", () => {
  it("surfaces a write-only value as a precise error", async () => {
    const resolver = resolverWith(readRoutes());
    const ref = parseSecretRef("cf://provider-keys/openai-api-key");
    await expect(resolver.resolve(ref)).rejects.toThrow(/write-only/);
    await expect(resolver.resolve(ref)).rejects.toThrow(/FERROGATE_CF_SECRET_OPENAI_API_KEY/);
    await expect(resolver.resolve(ref)).rejects.toThrow(/vault:\/\//);
  });

  it("accepts the store segment as a store id", async () => {
    const resolver = resolverWith(readRoutes());
    await expect(resolver.resolve(parseSecretRef("cf://store-1/openai-api-key"))).rejects.toThrow(
      /write-only/,
    );
  });

  it("returns null for a missing secret", async () => {
    const routes = readRoutes();
    routes.set(`GET ${BASE}/stores/store-1/secrets`, [200, okEnvelope("[]")]);
    const resolver = resolverWith(routes);
    expect(await resolver.resolve(parseSecretRef("cf://provider-keys/nope"))).toBeNull();
  });

  it("returns null for a missing store", async () => {
    const resolver = resolverWith(new Map([[`GET ${BASE}/stores`, [200, okEnvelope("[]")]]]));
    expect(await resolver.resolve(parseSecretRef("cf://absent/whatever"))).toBeNull();
  });

  it("rejects a non-cf reference", async () => {
    await expect(resolverWith(readRoutes()).resolve(parseSecretRef("env://X"))).rejects.toThrow(
      /non-cf/,
    );
  });
});

describe("CloudflareSecretResolver.createSecret (write plane + caps)", () => {
  it("rejects a value exceeding the beta cap before any network call", async () => {
    const resolver = resolverWith(new Map()); // no routes needed
    await expect(
      resolver.createSecret("provider-keys", "big-secret", "x".repeat(1025)),
    ).rejects.toThrow(/beta cap/);
  });

  it("writes via REST and returns the new secret id", async () => {
    const routes = new Map<string, [number, string]>([
      [`GET ${BASE}/stores`, [200, okEnvelope(`[{"id":"store-1","name":"provider-keys"}]`)]],
      [
        `GET ${BASE}/stores/store-1/secrets`,
        [200, okEnvelope(`[{"id":"sec-1","name":"openai-api-key"}]`)],
      ],
      [
        `POST ${BASE}/stores/store-1/secrets`,
        [200, okEnvelope(`[{"id":"sec-new","name":"new-key"}]`)],
      ],
    ]);
    const resolver = resolverWith(routes);
    expect(
      await resolver.createSecret("provider-keys", "new-key", "sk-value", "added by test"),
    ).toBe("sec-new");
  });

  it("rejects a NEW secret when the store is at the budget (before any POST)", async () => {
    // Deliberately NO Post route: firing a POST would surface "unscripted request".
    const routes = new Map<string, [number, string]>([
      [`GET ${BASE}/stores`, [200, okEnvelope(`[{"id":"store-1","name":"provider-keys"}]`)]],
      [`GET ${BASE}/stores/store-1/secrets`, [200, okEnvelope(secretsListingJson(100))]],
    ]);
    const resolver = resolverWith(routes);
    const err = resolver.createSecret("provider-keys", "one-too-many", "sk");
    await expect(err).rejects.toThrow(/100 secrets.*budget/);
    await expect(resolver.createSecret("provider-keys", "one-too-many", "sk")).rejects.not.toThrow(
      /unscripted request/,
    );
  });

  it("allows overwriting an existing name at the budget (logs soft warning)", async () => {
    const warn = vi.spyOn(console, "warn").mockImplementation(() => {});
    const routes = new Map<string, [number, string]>([
      [`GET ${BASE}/stores`, [200, okEnvelope(`[{"id":"store-1","name":"provider-keys"}]`)]],
      [`GET ${BASE}/stores/store-1/secrets`, [200, okEnvelope(secretsListingJson(100))]],
      [
        `POST ${BASE}/stores/store-1/secrets`,
        [200, okEnvelope(`[{"id":"sec-7","name":"bulk-7"}]`)],
      ],
    ]);
    const resolver = resolverWith(routes);
    expect(await resolver.createSecret("provider-keys", "bulk-7", "rotated")).toBe("sec-7");
    expect(warn).toHaveBeenCalled();
    warn.mockRestore();
  });

  it("refuses a non-canonical name before reaching the store", async () => {
    // Unscripted transport: a refusal after the call would surface loudly.
    const resolver = resolverWith(new Map());
    await expect(resolver.createSecret("provider-keys", "openai_api_key", "sk")).rejects.toThrow(
      /not canonical/,
    );
    await expect(
      resolver.createSecret("provider-keys", "openai_api_key", "sk"),
    ).rejects.not.toThrow(/unscripted request/);
  });

  it("rejects an empty secret name", async () => {
    const resolver = resolverWith(new Map());
    await expect(resolver.createSecret("provider-keys", "", "sk")).rejects.toThrow(
      /must not be empty/,
    );
  });

  it("errors when the target store is not found", async () => {
    const resolver = resolverWith(new Map([[`GET ${BASE}/stores`, [200, okEnvelope("[]")]]]));
    await expect(resolver.createSecret("absent", "new-key", "sk")).rejects.toThrow(/not found/);
  });
});

describe("CfSecretsStoreConfig + registry REST wiring", () => {
  it("fromEnv stores a token reference, never the token value", () => {
    const config = CfSecretsStoreConfig.fromEnv({
      CLOUDFLARE_ACCOUNT_ID: "acct-xyz",
      CLOUDFLARE_API_TOKEN: "cf-secret-token",
    });
    expect(config?.apiTokenRef).toBe("env://CLOUDFLARE_API_TOKEN");
    expect(JSON.stringify(config)).not.toContain("cf-secret-token");
  });

  it("fromEnv returns null when either required var is unset", () => {
    expect(CfSecretsStoreConfig.fromEnv({ CLOUDFLARE_ACCOUNT_ID: "a" })).toBeNull();
    expect(CfSecretsStoreConfig.fromEnv({})).toBeNull();
  });

  it("Debug redacts an inline token but keeps an env reference visible", () => {
    const inline = new CfSecretsStoreConfig({ accountId: "a", apiTokenRef: "raw-token" });
    expect(JSON.stringify(inline)).toContain("<redacted inline token>");
    expect(JSON.stringify(inline)).not.toContain("raw-token");
    const enved = new CfSecretsStoreConfig({ accountId: "a", apiTokenRef: "env://CF_TOKEN" });
    expect(JSON.stringify(enved)).toContain("env://CF_TOKEN");
  });

  it("registry routes cf:// through the configured REST resolver (missing → null)", async () => {
    const routes = readRoutes();
    routes.set(`GET ${BASE}/stores/store-1/secrets`, [200, okEnvelope("[]")]);
    const registry = SecretResolverRegistry.new({}).withCloudflare(resolverWith(routes));
    expect(await registry.resolve("cf://provider-keys/registry-rest-missing-key")).toBeNull();
  });

  it("registry prefers a binding value over the REST backend", async () => {
    // REST resolver with NO routes: a network call would return the loud
    // "unscripted request" error, so a successful resolve proves the binding won.
    const rest = resolverWith(new Map());
    const registry = SecretResolverRegistry.new({
      FERROGATE_CF_SECRET_OPENAI_API_KEY: "sk-bound-wins",
    }).withCloudflare(rest);
    expect(await registry.resolve("cf://provider-keys/openai-api-key")).toBe("sk-bound-wins");
  });

  it("CloudflareSecretResolver.create builds a client offline and holds a token ref", () => {
    const config = new CfSecretsStoreConfig({
      accountId: "acct-1",
      apiTokenRef: "env://CLOUDFLARE_API_TOKEN",
      apiBaseUrl: "https://api.test/client/v4",
    });
    const resolver = CloudflareSecretResolver.create(config, {
      CLOUDFLARE_API_TOKEN: "live",
    });
    expect(resolver.client().config().apiTokenRef).toBe("env://CLOUDFLARE_API_TOKEN");
    expect(JSON.stringify(resolver.client().config())).not.toContain("live");
  });
});
