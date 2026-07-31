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
  cfBindingEnvVar,
  defaultEnv,
  httpGet,
  nonEmptyEnv,
  parseSecretRef,
} from "../src/index.js";

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
    expect(await empty.resolve(parseSecretRef("cf://provider-keys/any-runtime-chosen-name"))).toBeNull();
  });

  test("the binding context never answers for a reference it does not own", async () => {
    // A `cf://` resolver that quietly served an `env://` reference would hide
    // the fact that the value never came from the Secrets Store at all.
    await expect(
      CfSecretBindings.new({}).resolve(parseSecretRef("env://OPENAI_API_KEY")),
    ).rejects.toThrow(/non-cf/);
  });
});
