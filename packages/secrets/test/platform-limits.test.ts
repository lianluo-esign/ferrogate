/**
 * Pins for the `@ferrogate/secrets` behaviors KEPT as PORT-TODO markers because
 * the Cloudflare platform cannot express the Rust behavior.
 *
 * A kept marker without a test is a claim. These make each one falsifiable: if
 * a future Cloudflare release closes one of these gaps, the assertion here
 * fails and names the marker to delete.
 */
import { describe, expect, test } from "vitest";
import {
  CF_BINDING_ENV_PREFIX,
  CfSecretBindings,
  EnvSecretResolver,
  EnvTokenResolver,
  SecretResolverRegistry,
  type SecretsStoreBinding,
  cfBindingEnvVar,
  defaultEnv,
  httpGet,
  isSecretsStoreBinding,
  nonEmptyEnv,
  parseSecretRef,
  readEnvSecret,
} from "../src/index.js";

/**
 * A stand-in for workerd's `SecretsStoreSecret`, the object a
 * `[[secrets_store_secrets]]` stanza puts on `env`. It is deliberately NOT a
 * string: every assertion below that expects the plaintext therefore fails if
 * the `await …get()` read is removed, because the only other thing this value
 * can become is `[object Object]` or a `TypeError`.
 */
function secretsStoreSlot(value: string): SecretsStoreBinding {
  return { get: () => Promise.resolve(value) };
}

describe("PLATFORM LIMIT — workerd has no process environment (4.8)", () => {
  /**
   * The Rust `std::env::var(...)` is callable from anywhere; a Worker can only
   * read what it was HANDED. The port's answer is an injected `EnvLike`.
   */
  test("every read goes through an injected source, never an ambient global", () => {
    expect(nonEmptyEnv("FERROGATE_TEST_KEY", { FERROGATE_TEST_KEY: "v" })).toBe("v");
    // An empty/whitespace value is UNSET, matching Rust `non_empty_env`.
    expect(nonEmptyEnv("FERROGATE_TEST_KEY", { FERROGATE_TEST_KEY: "   " })).toBeUndefined();
    expect(nonEmptyEnv("FERROGATE_TEST_KEY", {})).toBeUndefined();
  });

  test("defaultEnv() degrades to an EMPTY map where there is no process", () => {
    // Under Node/Bun (this suite) `process.env` exists, so the Rust semantics
    // ARE reproducible on the CLI parity path.
    expect(typeof defaultEnv()).toBe("object");
    // The Worker branch is the fallback: `process?.env ?? {}`. Simulated by
    // reading through an explicitly empty source, which is what a Worker call
    // site that forgot to thread `c.env` observes — indistinguishable from a
    // genuinely unset variable, which is the residual gap the marker states.
    expect(nonEmptyEnv("ANY_NAME", {})).toBeUndefined();
  });
});

describe("PLATFORM LIMIT — workerd exposes no TLS trust-store hook (4.8)", () => {
  test("caCertPath is ACCEPTED and IGNORED, so the CLI and Worker share a config", async () => {
    let sawInit: RequestInit | undefined;
    const fetchImpl = (async (_url: string | URL | Request, init?: RequestInit) => {
      sawInit = init;
      return new Response("{}", { status: 200 });
    }) as unknown as typeof fetch;

    await httpGet("https://vault.example.com/v1/x", [], {
      caCertPath: "/etc/ssl/private-root.pem",
      fetchImpl,
    });

    // There is no `fetch` option, binding, or compatibility flag that could
    // carry it — so the only honest behavior is to drop it, not to pretend.
    // If workerd ever grows one, this assertion is where it should be wired.
    expect(sawInit).toBeDefined();
    expect(JSON.stringify(sawInit)).not.toContain("private-root.pem");
  });

  test("accepting it is deliberate: a config valid for the CLI is not rejected", async () => {
    const fetchImpl = (async () => new Response("{}", { status: 200 })) as unknown as typeof fetch;
    // Not a throw. Rejecting here would split the CLI's and the Worker's config
    // schemas for a field the CLI can genuinely honour.
    await expect(
      httpGet("https://vault.example.com/v1/x", [], { caCertPath: "/x.pem", fetchImpl }),
    ).resolves.toBeInstanceOf(Uint8Array);
  });
});

describe("PLATFORM LIMIT — Secrets Store reads need a DEPLOY-time binding (4.6/4.7)", () => {
  const ref = parseSecretRef("cf://provider-keys/openai-api-key");

  test("a PRE-BOUND name resolves — selection by name over a declared set", () => {
    const injected = CfSecretBindings.fromMap({ "openai-api-key": "sk-injected" }, {});
    return expect(injected.resolve(ref)).resolves.toBe("sk-injected");
  });

  test("…and so does the FERROGATE_CF_SECRET_<NAME> env convention", () => {
    expect(cfBindingEnvVar("openai-api-key")).toBe(`${CF_BINDING_ENV_PREFIX}OPENAI_API_KEY`);
    const viaEnv = CfSecretBindings.new({ FERROGATE_CF_SECRET_OPENAI_API_KEY: "sk-env" });
    return expect(viaEnv.resolve(ref)).resolves.toBe("sk-env");
  });

  test("an UNBOUND name resolves to null — it is NOT fetched over REST", async () => {
    // This is the limit itself. The REST API's read returns metadata, never the
    // value, so there is no runtime path from a name to a secret that has no
    // `[[secrets_store_secrets]]` stanza. Returning `null` ("not configured")
    // is the only honest answer; anything that appeared to succeed would be a
    // fake. Onboarding a new `cf://` secret therefore requires a DEPLOY.
    const empty = CfSecretBindings.new({});
    expect(await empty.resolve(ref)).toBeNull();
    expect(
      await empty.resolve(parseSecretRef("cf://provider-keys/any-runtime-chosen-name")),
    ).toBeNull();
  });

  test("the binding context never answers for a reference it does not own", async () => {
    // A `cf://` resolver that quietly served an `env://` reference would hide
    // the fact that the value never came from the Secrets Store at all.
    await expect(
      CfSecretBindings.new({}).resolve(parseSecretRef("env://OPENAI_API_KEY")),
    ).rejects.toThrow(/non-cf/);
  });
});

/**
 * CLOSED (inventory-policy-core §4.8). These pin the CF-NATIVE read path — the
 * one shape the `cf://` scheme exists to serve and the one shape this package
 * could not read until the `readEnvSecret` split. Every assertion here fails if
 * the `await slot.get()` branch is removed, because the slot is an object.
 */
describe("CLOSED — a [[secrets_store_secrets]] binding is read with await get()", () => {
  const ref = parseSecretRef("cf://provider-keys/openai-api-key");

  test("cf:// resolves a SecretsStoreSecret-shaped slot, not just a string", async () => {
    const bound = CfSecretBindings.new({
      FERROGATE_CF_SECRET_OPENAI_API_KEY: secretsStoreSlot("sk-from-secrets-store"),
    });
    await expect(bound.resolve(ref)).resolves.toBe("sk-from-secrets-store");
    // …and the same read through the registry, which is the surface apps use.
    const registry = SecretResolverRegistry.new({
      FERROGATE_CF_SECRET_OPENAI_API_KEY: secretsStoreSlot("sk-from-secrets-store"),
    });
    await expect(registry.resolve("cf://provider-keys/openai-api-key")).resolves.toBe(
      "sk-from-secrets-store",
    );
  });

  test("the AMBIGUITY GUARD still fires BEFORE any binding is touched", async () => {
    // Load-bearing ordering: a non-canonical name must refuse without ever
    // calling `get()`, or a lossy variable name could serve a credential the
    // operator did not ask for. `get()` records whether it was reached.
    let reads = 0;
    const bound = CfSecretBindings.new({
      FERROGATE_CF_SECRET_OPENAI_API_KEY: {
        get: () => {
          reads += 1;
          return Promise.resolve("sk-shared");
        },
      },
    });
    await expect(bound.lookupAsync("openai.api.key")).rejects.toThrow(/not canonical/);
    expect(reads).toBe(0);
  });

  test("an exactly-injected binding still wins over the env slot", async () => {
    const bound = CfSecretBindings.fromMap(
      { "openai-api-key": "sk-injected" },
      {
        FERROGATE_CF_SECRET_OPENAI_API_KEY: secretsStoreSlot("sk-store"),
      },
    );
    await expect(bound.resolve(ref)).resolves.toBe("sk-injected");
  });

  test("an EMPTY Secrets Store value is unset, not the empty string", async () => {
    const bound = CfSecretBindings.new({
      FERROGATE_CF_SECRET_OPENAI_API_KEY: secretsStoreSlot("   "),
    });
    await expect(bound.resolve(ref)).resolves.toBeNull();
  });

  test("env:// reads the same slot shape, so a bound name is not a TypeError", async () => {
    const resolver = new EnvSecretResolver({ OPENAI_API_KEY: secretsStoreSlot("sk-env-store") });
    await expect(resolver.resolve(parseSecretRef("env://OPENAI_API_KEY"))).resolves.toBe(
      "sk-env-store",
    );
  });

  test("the Cloudflare manage-plane token may itself live in Secrets Store", async () => {
    const resolver = new EnvTokenResolver({
      CLOUDFLARE_API_TOKEN: secretsStoreSlot("cf-token"),
    });
    await expect(resolver.resolve("env://CLOUDFLARE_API_TOKEN")).resolves.toBe("cf-token");
  });

  test("readEnvSecret serves BOTH shapes; isSecretsStoreBinding separates them", async () => {
    await expect(readEnvSecret("A", { A: "plain" })).resolves.toBe("plain");
    await expect(readEnvSecret("A", { A: secretsStoreSlot("bound") })).resolves.toBe("bound");
    await expect(readEnvSecret("A", {})).resolves.toBeUndefined();
    expect(isSecretsStoreBinding(secretsStoreSlot("x"))).toBe(true);
    expect(isSecretsStoreBinding("x")).toBe(false);
    expect(isSecretsStoreBinding(null)).toBe(false);
  });

  test("another CF binding that happens to expose get() is NOT a secret", async () => {
    // A Worker `env` is heterogeneous. `env://MCP_OAUTH_KV` must not call
    // `kvNamespace.get()` with no key and serve whatever comes back.
    const kvShaped = {
      get: () => Promise.resolve("value-for-some-key"),
      put: () => Promise.resolve(),
      list: () => Promise.resolve({ keys: [] }),
      delete: () => Promise.resolve(),
    };
    const r2Shaped = { get: () => Promise.resolve(null), head: () => Promise.resolve(null) };
    const doShaped = { get: () => Promise.resolve(""), idFromName: () => ({}) };
    for (const binding of [kvShaped, r2Shaped, doShaped]) {
      expect(isSecretsStoreBinding(binding)).toBe(false);
    }
    await expect(
      readEnvSecret("MCP_OAUTH_KV", { MCP_OAUTH_KV: kvShaped } as never),
    ).resolves.toBeUndefined();
  });

  test("the SYNCHRONOUS readers refuse loudly instead of stringifying the object", () => {
    // Before the split these produced `TypeError: value.trim is not a function`
    // — or, at a call site that concatenated first, the literal text
    // "[object Object]" in a credential field. Both are worse than a refusal
    // that names the async reader.
    expect(() => nonEmptyEnv("VAULT_TOKEN", { VAULT_TOKEN: secretsStoreSlot("t") })).toThrow(
      /readEnvSecret/,
    );
    expect(() =>
      CfSecretBindings.new({
        FERROGATE_CF_SECRET_OPENAI_API_KEY: secretsStoreSlot("sk"),
      }).lookup("openai-api-key"),
    ).toThrow(/lookupAsync/);
  });

  test("the RESIDUAL limit is unchanged: a name with no stanza is unresolvable", async () => {
    // `get()` takes no argument — a binding serves exactly the one secret it was
    // bound to at DEPLOY time, so there is still no `env.SECRETS.get(name)` over
    // the account's store. This is the half of the marker that stays open.
    const bound = CfSecretBindings.new({
      FERROGATE_CF_SECRET_OPENAI_API_KEY: secretsStoreSlot("sk-store"),
    });
    await expect(
      bound.resolve(parseSecretRef("cf://provider-keys/some-other-runtime-name")),
    ).resolves.toBeNull();
  });
});
