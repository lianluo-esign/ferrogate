import { describe, expect, it } from "vitest";
import {
  CF_BINDING_ENV_PREFIX,
  CfSecretBindings,
  SecretResolverRegistry,
  cfBindingEnvVar,
  cfBindingNameIsUnambiguous,
  parseSecretRef,
} from "../src/index.js";

describe("cfBindingEnvVar", () => {
  it("follows the documented uppercase + non-alnum→_ convention", () => {
    expect(cfBindingEnvVar("openai-api-key")).toBe(
      `${CF_BINDING_ENV_PREFIX}OPENAI_API_KEY`,
    );
    // Every non-alphanumeric collapses to `_` — always a shell-exportable name.
    expect(cfBindingEnvVar("openai.api/key")).toBe(
      "FERROGATE_CF_SECRET_OPENAI_API_KEY",
    );
  });
});

describe("cfBindingNameIsUnambiguous", () => {
  it("is true exactly for the canonical [a-z0-9-]+ shape", () => {
    for (const ok of ["openai-api-key", "abc123", "a-b-c"]) {
      expect(cfBindingNameIsUnambiguous(ok)).toBe(true);
    }
    for (const bad of ["", "OpenAI", "openai.api.key", "openai_api_key", "a b"]) {
      expect(cfBindingNameIsUnambiguous(bad)).toBe(false);
    }
  });

  it("distinct non-canonical names alias onto one variable", () => {
    const aliases = ["openai-api-key", "openai.api.key", "openai_api_key", "OpenAI-API-Key"];
    const vars = new Set(aliases.map(cfBindingEnvVar));
    expect(vars.size).toBe(1);
  });
});

describe("CfSecretBindings.lookup", () => {
  it("resolves a value from the injected map (any name, lossless)", () => {
    const bindings = CfSecretBindings.fromMap({ "openai.api.key": "sk-injected" }, {});
    expect(bindings.lookup("openai.api.key")).toBe("sk-injected");
    expect(bindings.lookup("missing")).toBeNull();
  });

  it("an explicitly injected empty value counts as unset (short-circuits)", () => {
    const bindings = CfSecretBindings.fromMap({ "openai-api-key": "  " }, {});
    expect(bindings.lookup("openai-api-key")).toBeNull();
  });

  it("resolves a canonical name from the env convention", () => {
    const bindings = CfSecretBindings.new({
      FERROGATE_CF_SECRET_OPENAI_API_KEY: "sk-env",
    });
    expect(bindings.lookup("openai-api-key")).toBe("sk-env");
    expect(bindings.lookup("unset-key")).toBeNull();
  });

  it("refuses a non-canonical name with no exact injected binding", () => {
    const bindings = CfSecretBindings.new({
      FERROGATE_CF_SECRET_OPENAI_API_KEY: "sk-shared",
    });
    expect(() => bindings.lookup("openai.api.key")).toThrow(/not canonical/);
  });

  it("redacts values but shows names + count", () => {
    const bindings = CfSecretBindings.fromMap({ a: "secret-a", b: "secret-b" }, {});
    const json = JSON.stringify(bindings);
    expect(json).toContain("<redacted>");
    expect(json).toContain("boundSecretCount");
    expect(json).not.toContain("secret-a");
  });

  it("resolve() rejects a non-cf reference", async () => {
    await expect(
      CfSecretBindings.new({}).resolve(parseSecretRef("env://X")),
    ).rejects.toThrow(/non-cf/);
  });
});

describe("registry cf:// binding precedence", () => {
  it("resolves cf:// from an env binding with no REST backend", async () => {
    const registry = SecretResolverRegistry.new({
      FERROGATE_CF_SECRET_REGISTRY_ENV_BIND_KEY: "sk-bound",
    });
    expect(await registry.resolve("cf://provider-keys/registry-env-bind-key")).toBe(
      "sk-bound",
    );
  });

  it("refuses an ambiguous cf:// reference before the REST backend", async () => {
    // The REST resolver has no scripted routes, so reaching it would surface a
    // loud "unscripted request" error — its absence proves the binding-context
    // guard fired first.
    const registry = SecretResolverRegistry.new({});
    await expect(
      registry.resolve("cf://provider-keys/Registry_Ambiguous.Key"),
    ).rejects.toThrow(/not canonical/);
    await expect(
      registry.resolve("cf://provider-keys/Registry_Ambiguous.Key"),
    ).rejects.not.toThrow(/unscripted request/);
  });

  it("errors clearly when cf:// is unconfigured, naming the binding var", async () => {
    const registry = SecretResolverRegistry.new({});
    await expect(
      registry.resolve("cf://provider-keys/unbound-unconfigured-key"),
    ).rejects.toThrow(/FERROGATE_CF_SECRET_UNBOUND_UNCONFIGURED_KEY/);
  });
});
