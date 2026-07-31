import { describe, expect, it, vi } from "vitest";
import {
  EnvSecretResolver,
  SecretResolverRegistry,
  VaultConfig,
  VaultSecretResolver,
  parseSecretRef,
} from "../src/index.js";

describe("EnvSecretResolver", () => {
  it("reads a value and treats empty as unset", async () => {
    const resolver = new EnvSecretResolver({
      KEY: "s3cr3t",
      EMPTY: "",
      SPACES: "   ",
    });
    expect(await resolver.resolve(parseSecretRef("env://KEY"))).toBe("s3cr3t");
    expect(await resolver.resolve(parseSecretRef("env://EMPTY"))).toBeNull();
    expect(await resolver.resolve(parseSecretRef("env://SPACES"))).toBeNull();
    expect(await resolver.resolve(parseSecretRef("env://MISSING"))).toBeNull();
  });

  it("refuses a non-env:// reference", async () => {
    const resolver = new EnvSecretResolver({});
    await expect(
      resolver.resolve(parseSecretRef("vault://secret/data/x#f")),
    ).rejects.toThrow(/non-env/);
  });
});

/** A fetch stub that returns a canned JSON body for any request. */
function jsonFetch(status: number, body: unknown): typeof fetch {
  return vi.fn(async () =>
    new Response(JSON.stringify(body), { status }),
  ) as unknown as typeof fetch;
}

describe("VaultSecretResolver", () => {
  const ref = parseSecretRef("vault://secret/data/openai#api_key");
  const config = new VaultConfig({
    address: "https://vault.test",
    token: "test-token",
  });

  it("reads data.data.<field> from a KV v2 response", async () => {
    const fetchImpl = jsonFetch(200, { data: { data: { api_key: "sk-from-vault" } } });
    const resolver = new VaultSecretResolver(config, fetchImpl);
    expect(await resolver.resolve(ref)).toBe("sk-from-vault");
    // GET {addr}/v1/{mount}/data/{path}: KV v2 inserts /data/ between mount and
    // path, so mount=secret + path=data/openai → /v1/secret/data/data/openai.
    const call = (fetchImpl as unknown as ReturnType<typeof vi.fn>).mock.calls[0];
    // Assert the call happened before indexing it: a `?.` here would turn a
    // "never called" bug into two silently-skipped assertions.
    expect(call).toBeDefined();
    expect(call![0]).toBe("https://vault.test/v1/secret/data/data/openai");
    expect((call![1] as RequestInit).headers).toMatchObject({
      "X-Vault-Token": "test-token",
    });
  });

  it("returns null for a missing field", async () => {
    const resolver = new VaultSecretResolver(config, jsonFetch(200, { data: { data: {} } }));
    expect(await resolver.resolve(ref)).toBeNull();
  });

  it("throws when Vault reports errors", async () => {
    const resolver = new VaultSecretResolver(
      config,
      jsonFetch(200, { errors: ["permission denied"] }),
    );
    await expect(resolver.resolve(ref)).rejects.toThrow(/Vault returned errors/);
  });

  it("redacts the token in toJSON", () => {
    expect(JSON.stringify(config)).toContain("<redacted>");
    expect(JSON.stringify(config)).not.toContain("test-token");
  });

  it("VaultConfig.fromEnv returns null without required vars", () => {
    expect(VaultConfig.fromEnv({})).toBeNull();
    expect(VaultConfig.fromEnv({ VAULT_ADDR: "https://v" })).toBeNull();
    const cfg = VaultConfig.fromEnv({
      VAULT_ADDR: "https://v",
      VAULT_TOKEN: "t",
    });
    expect(cfg?.address).toBe("https://v");
  });
});

describe("SecretResolverRegistry env + vault dispatch", () => {
  it("resolves env:// without any backend configured", async () => {
    const registry = SecretResolverRegistry.new({ FOO: "value-1" });
    expect(await registry.resolve("env://FOO")).toBe("value-1");
  });

  it("errors on a vault:// reference without Vault configured", async () => {
    const registry = SecretResolverRegistry.new({});
    await expect(
      registry.resolve("vault://secret/data/openai#api_key"),
    ).rejects.toThrow(/VAULT_ADDR/);
  });
});
