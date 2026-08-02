/**
 * `ferrogate validate` / `check` / `reload` against the REAL config gate.
 *
 * These drive `main()` with `createFerrogateConfigValidator()` — the validator
 * the shipped binary wires — so they exercise `@ferrogate/config`'s actual
 * Caddyfile lexer/parser, its `validateConfig()` cross-field gate, and the #542
 * auth-posture gate ported in `src/config-gate.ts`.
 *
 * The invariant under test (#542): `check` exits non-zero for exactly the
 * configs `run` refuses to boot. A pre-flight that prints `config OK` for a
 * deployment the gateway then refuses is worse than no pre-flight.
 */
import { readFileSync } from "node:fs";
import { dirname, resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";
import { describe, expect, test } from "vitest";
import { configSummary, ensureAuthPostureIsDeclared, validateReport } from "../src/config-gate.js";
import { main } from "../src/index.js";
import { createFerrogateConfigValidator, runtimeConfigTextParsers } from "../src/ports.js";
import { createTestRuntime, ok } from "./helpers.js";

const REPO_ROOT = resolvePath(dirname(fileURLToPath(import.meta.url)), "../../..");
const REPO_CADDYFILE = readFileSync(resolvePath(REPO_ROOT, "Ferrogate/Caddyfile"), "utf8");

const configValidator = createFerrogateConfigValidator();

/** Run `validate` over one document and hand back the exit code plus streams. */
async function validate(
  name: string,
  source: string,
  argv: readonly string[] = [],
): Promise<{ code: number; stdout: string; stderr: string }> {
  const runtime = createTestRuntime({ files: { [name]: source }, configValidator });
  const code = await main(["validate", "-c", name, ...argv], runtime);
  return { code, stdout: runtime.stdout(), stderr: runtime.stderr() };
}

const OPEN_CADDYFILE = "{\n    auth off\n}\n:8080 {\n}\n";
const KEYED_CADDYFILE =
  ":8080 {\n  ai_gateway {\n    api_key k1 {\n      key s3cret\n      platform_operator on\n    }\n  }\n}\n";

function jsonConfig(config: Record<string, unknown>): string {
  return JSON.stringify(config);
}

const CLOUDFLARE_BLOCK = { account_id: "acct", api_token: "tok" };

describe("the real Caddyfile parser is what runs", () => {
  test("the repository's own Ferrogate/Caddyfile validates, with a real summary", async () => {
    const result = await validate("Caddyfile", REPO_CADDYFILE);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("status: ok");
    // Facts only a real parse can produce.
    expect(result.stdout).toContain("listen: 0.0.0.0:8080");
    expect(result.stdout).toContain("admin: localhost:2019");
    expect(result.stdout).toContain("providers: 1");
    expect(result.stdout).toContain("models: 1");
    expect(result.stdout).toContain("api_keys: 1");
    expect(result.stdout).toContain("auth_required: true");
    expect(result.stdout).toMatch(/snapshot: [0-9a-f]{16}/);
  });

  test("a Caddyfile diagnostic is reported with its line, column and directive", async () => {
    const result = await validate("Caddyfile", ":8080 {\n  frobnicate\n}\n");
    expect(result.code).toBe(5);
    expect(result.stdout).toContain("status: invalid");
    expect(result.stdout).toContain("Caddyfile:2:3");
    expect(result.stdout).toContain("frobnicate");
  });

  test("a cross-field schema failure is a validation exit, not a crash", async () => {
    // `field storage.provider: cloudflare_d1 requires a [cloudflare] block …`
    const result = await validate(
      "cfg.json",
      jsonConfig({ storage: { provider: "cloudflare_d1" }, auth: { disabled: true } }),
    );
    expect(result.code).toBe(5);
    expect(result.stdout).toContain("field storage.provider");
  });

  test("the deprecated [admin_api] alias migrates with a warning, not a failure", async () => {
    const result = await validate(
      "cfg.json",
      jsonConfig({
        admin_api: { listen: "127.0.0.1:8081" },
        api_keys: [{ id: "k1", name: "k1", key: "s", platform_operator: true }],
      }),
    );
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("warning:");
    expect(result.stdout).toContain("[admin_api] config section is a deprecated alias");
  });
});

describe("the #542 auth-posture gate", () => {
  test("REFUSES a config with authentication on and no credential source", async () => {
    const result = await validate("Caddyfile", ":8080 {\n}\n");
    expect(result.code).toBe(5);
    expect(result.stdout).toContain("refusing to start: authentication is required");
    expect(result.stdout).toContain("no [[api_keys]]");
    // The refusal names the switch that restores the pre-#542 behaviour.
    expect(result.stdout).toContain("auth off");
  });

  test("REFUSES `auth off` alongside a declared credential source", async () => {
    const result = await validate("Caddyfile", `{\n    auth off\n}\n${KEYED_CADDYFILE}`);
    expect(result.code).toBe(5);
    expect(result.stdout).toContain("would then never be consulted");
    expect(result.stdout).toContain("[[api_keys]]");
  });

  test("REFUSES `auth off` alongside an enabled [auth_service]", () => {
    const verdict = ensureAuthPostureIsDeclared({
      auth: { disabled: true },
      api_keys: [],
      auth_service: { enabled: true },
    } as never);
    expect(verdict.refusal).toContain("[auth_service] enabled = true");
  });

  test("ACCEPTS a stated open posture", async () => {
    const result = await validate("Caddyfile", OPEN_CADDYFILE);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("status: ok");
    expect(result.stdout).toContain("auth_required: false");
  });

  test("ACCEPTS a credentialed config", async () => {
    const result = await validate("Caddyfile", KEYED_CADDYFILE);
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("auth_required: true");
  });

  test("allows `auth off` over a durable D1 control plane, but says so loudly", async () => {
    const result = await validate(
      "cfg.json",
      jsonConfig({
        auth: { disabled: true },
        storage: { provider: "cloudflare_d1", cloudflare_d1_database_id: "db" },
        cloudflare: CLOUDFLARE_BLOCK,
      }),
    );
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("warning: [auth] disabled = true");
    expect(result.stdout).toContain('provider = "cloudflare_d1"');
    expect(result.stdout).toContain("every key in it is IGNORED");
  });

  test("a durable D1 store IS a credential source when auth is on", async () => {
    const result = await validate(
      "cfg.json",
      jsonConfig({
        storage: { provider: "cloudflare_d1", cloudflare_d1_database_id: "db" },
        cloudflare: CLOUDFLARE_BLOCK,
      }),
    );
    expect(result.code).toBe(0);
    expect(result.stdout).not.toContain("refusing to start");
  });

  test("auth_required reflects [auth_service], not just [[api_keys]] (the drifted predicate)", () => {
    const summary = configSummary({
      listen: "127.0.0.1:8080",
      admin: { listen: null },
      tls: { enabled: false, http2: false },
      upstreams: [],
      routes: [],
      providers: [],
      models: [],
      api_keys: [],
      auth: { disabled: false },
      auth_service: { enabled: true },
    } as never);
    expect(summary.auth_required).toBe(true);
    expect(summary.api_keys).toBe(0);
    expect(summary.admin).toBe("off");
  });
});

describe("tenancy posture warnings ride the same report (#540)", () => {
  test("implicit_platform_operator is surfaced where a human looks", async () => {
    const result = await validate(
      "cfg.json",
      jsonConfig({
        tenancy: { implicit_platform_operator: true },
        api_keys: [{ id: "k1", name: "k1", key: "s" }],
      }),
    );
    expect(result.code).toBe(0);
    expect(result.stdout).toContain("implicit_platform_operator = true grants UNRESTRICTED");
    expect(result.stdout).toContain("k1");
  });

  test("a key that authorizes nothing is named", async () => {
    const result = await validate(
      "cfg.json",
      jsonConfig({ api_keys: [{ id: "k1", name: "k1", key: "s", platform_operator: false }] }),
    );
    expect(result.stdout).toContain("tenant_identity_required: k1");
  });

  test("validateReport carries the summary alongside a refusal, not instead of it", () => {
    const report = validateReport({
      listen: "127.0.0.1:8080",
      admin: { listen: null },
      tls: { enabled: false, http2: false },
      upstreams: [],
      routes: [],
      providers: [],
      models: [],
      api_keys: [],
      auth: { disabled: false },
      auth_service: { enabled: false },
      storage: { provider: "memory" },
      tenancy: { implicit_platform_operator: false },
    } as never);
    expect(report.refusal).toContain("refusing to start");
    expect(report.summary.listen).toBe("127.0.0.1:8080");
  });
});

/**
 * The YAML fixture, and the object `Bun.YAML.parse` really produces from it.
 *
 * Recorded from a live `Bun.YAML.parse` run (Bun 1.3.14) rather than hand-
 * written, so the injected-parser tests below feed `loadConfigFromObject` the
 * bytes the shipped binary actually feeds it. The same document was driven end
 * to end through `createFerrogateConfigValidator()` under Bun and validated with
 * `providers: 1 / models: 1 / snapshot a024807c0a875142` — the summary asserted
 * here.
 */
const YAML_SOURCE = `listen: "0.0.0.0:8080"
auth:
  disabled: true
providers:
  - name: openai
    kind: openai
    base_url: "https://api.openai.com"
models:
  - name: gpt-4o
    provider: openai
    provider_model: gpt-4o
`;

const YAML_AS_BUN_PARSES_IT = {
  listen: "0.0.0.0:8080",
  auth: { disabled: true },
  providers: [{ name: "openai", kind: "openai", base_url: "https://api.openai.com" }],
  models: [{ name: "gpt-4o", provider: "openai", provider_model: "gpt-4o" }],
};

describe("format dispatch is honest about what it cannot read", () => {
  test.each([["cfg.yaml"], ["cfg.yml"]])(
    "%s validates for real when the runtime supplies a YAML parser",
    async (name) => {
      const withYaml = createFerrogateConfigValidator({
        yaml: (text) => {
          // Proves the CLI hands the *file's own bytes* to the parser rather
          // than a re-serialized guess.
          expect(text).toBe(YAML_SOURCE);
          return YAML_AS_BUN_PARSES_IT;
        },
      });
      const runtime = createTestRuntime({
        files: { [name]: YAML_SOURCE },
        configValidator: withYaml,
      });
      expect(await main(["validate", "-c", name], runtime)).toBe(0);
      // Facts only a real load can produce — a stub that returned `{}` would
      // report zero providers and zero models.
      expect(runtime.stdout()).toContain("providers: 1");
      expect(runtime.stdout()).toContain("models: 1");
      expect(runtime.stdout()).toContain("listen: 0.0.0.0:8080");
      expect(runtime.stdout()).toContain("snapshot: a024807c0a875142");
    },
  );

  test("a YAML document that fails the gate still fails through the YAML path", async () => {
    // #542: a config that declares no auth posture is refused, whatever format
    // it arrived in — the format leg must not become a way around the gate.
    const withYaml = createFerrogateConfigValidator({ yaml: () => ({ listen: "0.0.0.0:8080" }) });
    const runtime = createTestRuntime({
      files: { "cfg.yaml": "listen: 0.0.0.0:8080\n" },
      configValidator: withYaml,
    });
    expect(await main(["validate", "-c", "cfg.yaml"], runtime)).toBe(5);
    expect(runtime.stdout()).toContain("refusing to start");
  });

  test("a YAML parse error is reported as a diagnostic, not swallowed", async () => {
    const withYaml = createFerrogateConfigValidator({
      yaml: () => {
        throw new Error("YAML Parse error: Unexpected token");
      },
    });
    const runtime = createTestRuntime({
      files: { "cfg.yaml": "listen: [unclosed\n" },
      configValidator: withYaml,
    });
    expect(await main(["validate", "-c", "cfg.yaml"], runtime)).toBe(5);
    expect(runtime.stdout()).toContain("YAML Parse error");
  });

  test("YAML is refused — not silently skipped — when the runtime has no parser", async () => {
    const withoutYaml = createFerrogateConfigValidator({});
    const runtime = createTestRuntime({
      files: { "cfg.yaml": YAML_SOURCE },
      configValidator: withoutYaml,
    });
    expect(await main(["validate", "-c", "cfg.yaml"], runtime)).toBe(5);
    expect(runtime.stdout()).toContain("this runtime provides no YAML parser");
    expect(runtime.stdout()).toContain("uses Bun.YAML");
  });

  test("an unrecognised extension is refused, not treated as a Caddyfile", async () => {
    const result = await validate("cfg.ini", "[x]\n");
    expect(result.code).toBe(5);
    expect(result.stdout).toContain("cannot infer the format of cfg.ini");
  });

  test("TOML validates when the runtime supplies a parser", async () => {
    const withToml = createFerrogateConfigValidator({
      toml: () => ({ auth: { disabled: true } }),
    });
    const runtime = createTestRuntime({
      files: { "cfg.toml": "[auth]\ndisabled = true\n" },
      configValidator: withToml,
    });
    expect(await main(["validate", "-c", "cfg.toml"], runtime)).toBe(0);
    expect(runtime.stdout()).toContain("auth_required: false");
  });

  test("TOML is refused — not silently skipped — when the runtime has no parser", async () => {
    const withoutToml = createFerrogateConfigValidator({});
    const runtime = createTestRuntime({
      files: { "cfg.toml": "[auth]\ndisabled = true\n" },
      configValidator: withoutToml,
    });
    expect(await main(["validate", "-c", "cfg.toml"], runtime)).toBe(5);
    expect(runtime.stdout()).toContain("this runtime provides no TOML parser");
  });

  test("each format is wired to ITS OWN Bun parser, not the other one", () => {
    // This suite runs under Node, where both Bun parsers are absent — so a test
    // that only reads the real global cannot tell `Bun.YAML` from `Bun.TOML`.
    // A stand-in host makes the two distinguishable.
    const calls: string[] = [];
    const parsers = runtimeConfigTextParsers({
      Bun: {
        TOML: {
          parse: (text) => {
            calls.push(`toml:${text}`);
            return { from: "toml" };
          },
        },
        YAML: {
          parse: (text) => {
            calls.push(`yaml:${text}`);
            return { from: "yaml" };
          },
        },
      },
    });
    expect(parsers.yaml?.("a: 1")).toEqual({ from: "yaml" });
    expect(parsers.toml?.("a = 1")).toEqual({ from: "toml" });
    expect(calls).toEqual(["yaml:a: 1", "toml:a = 1"]);
  });

  test("a host that offers only one parser yields only that one", () => {
    const yamlOnly = runtimeConfigTextParsers({ Bun: { YAML: { parse: () => ({}) } } });
    expect(yamlOnly.yaml).toBeDefined();
    expect(yamlOnly.toml).toBeUndefined();
    const tomlOnly = runtimeConfigTextParsers({ Bun: { TOML: { parse: () => ({}) } } });
    expect(tomlOnly.toml).toBeDefined();
    expect(tomlOnly.yaml).toBeUndefined();
    expect(runtimeConfigTextParsers({})).toEqual({});
  });

  test("runtimeConfigTextParsers reports the truth about the host runtime", () => {
    const bun = (
      globalThis as {
        Bun?: { TOML?: { parse?: unknown }; YAML?: { parse?: unknown } };
      }
    ).Bun;
    const parsers = runtimeConfigTextParsers();
    // Never claims a parser it does not have, and never hides one it does —
    // both directions, because either lie produces a wrong `validate` verdict.
    expect(parsers.toml === undefined).toBe(bun?.TOML?.parse === undefined);
    expect(parsers.yaml === undefined).toBe(bun?.YAML?.parse === undefined);
  });
});

describe("reload runs the same gate before it pushes anything", () => {
  test("a posture-refused config never reaches the admin surface", async () => {
    const runtime = createTestRuntime({
      files: { Caddyfile: ":8080 {\n}\n" },
      configValidator,
      script: { "POST /admin/v1/config/reload": ok({ reloaded: true }) },
    });
    expect(await main(["reload", "-c", "Caddyfile", "--admin-url", "https://x"], runtime)).toBe(5);
    expect(runtime.stderr()).toContain("refusing to reload an invalid configuration");
    expect(runtime.client.requests).toHaveLength(0);
  });

  test("a stated-posture config does reach it", async () => {
    const runtime = createTestRuntime({
      files: { Caddyfile: OPEN_CADDYFILE },
      configValidator,
      script: { "POST /admin/v1/config/reload": ok({ reloaded: true }) },
    });
    expect(await main(["reload", "-c", "Caddyfile", "--admin-url", "https://x"], runtime)).toBe(0);
    expect(runtime.client.requests[0]?.spec.path).toBe("/admin/v1/config/reload");
  });
});

describe("--output json carries the machine-readable report", () => {
  test("the summary and diagnostics survive the JSON rendering", async () => {
    const result = await validate("Caddyfile", REPO_CADDYFILE, ["--output", "json"]);
    expect(result.code).toBe(0);
    const parsed = JSON.parse(result.stdout) as {
      ok: boolean;
      summary: Record<string, unknown>;
      diagnostics: unknown[];
    };
    expect(parsed.ok).toBe(true);
    expect(parsed.summary.auth_required).toBe(true);
    expect(parsed.summary.listen).toBe("0.0.0.0:8080");
    expect(parsed.diagnostics).toEqual([]);
  });
});
