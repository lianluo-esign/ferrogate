import { describe, expect, test } from "vitest";
import { parseCaddyfile } from "../src/caddyfile/parser.js";
import { CaddyfileDiagnostic } from "../src/diagnostic.js";
import { adaptSiteAddress, envReference } from "../src/caddyfile/parser-support.js";
import { fromCaddyfileStr, fromGatewayConfig, isCaddyfilePath } from "../src/loader.js";

describe("caddyfile helpers", () => {
  test("adaptSiteAddress maps :PORT / host:port / 0.0.0.0 / bare host", () => {
    expect(adaptSiteAddress(":8080")).toEqual({ listen: "127.0.0.1:8080", host: null });
    expect(adaptSiteAddress("localhost:9000")).toEqual({ listen: "127.0.0.1:9000", host: "localhost" });
    expect(adaptSiteAddress("0.0.0.0:8080")).toEqual({ listen: "0.0.0.0:8080", host: null });
    expect(adaptSiteAddress("api.example.com")).toEqual({ listen: null, host: "api.example.com" });
  });

  test("envReference reads env./{env.}/{$} forms", () => {
    expect(envReference("env.OPENAI_KEY")).toBe("OPENAI_KEY");
    expect(envReference("{env.OPENAI_KEY}")).toBe("OPENAI_KEY");
    expect(envReference("{$OPENAI_KEY}")).toBe("OPENAI_KEY");
    expect(envReference("plain")).toBeNull();
  });
});

describe("parseCaddyfile", () => {
  test("parses a reverse_proxy site block into an upstream + route", () => {
    const src = `:8080 {
      reverse_proxy http://127.0.0.1:9001 {
        header_up X-Env prod
      }
    }`;
    const config = parseCaddyfile(src, "Caddyfile");
    expect(config.listen).toBe("127.0.0.1:8080");
    expect(config.upstreams).toHaveLength(1);
    expect(config.upstreams[0]).toMatchObject({ name: "caddyfile-upstream-1", url: "http://127.0.0.1:9001" });
    expect(config.routes[0]).toMatchObject({ upstream: "caddyfile-upstream-1" });
    expect(config.routes[0]!.request_headers).toEqual([{ name: "X-Env", value: "prod" }]);
  });

  test("parses the ai_gateway block (provider / model / api_key) and auth off", () => {
    const src = `{
      auth off
    }
    :8080 {
      ai_gateway {
        provider openai {
          base_url https://api.openai.com
          api_key {env.OPENAI_KEY}
        }
        model gpt4 -> openai:gpt-4o {
          capabilities chat streaming
        }
        api_key k1 {
          key {env.K1}
          organization_id org-1
        }
      }
    }`;
    const config = parseCaddyfile(src, "Caddyfile");
    expect(config.auth_disabled).toBe(true);
    expect(config.providers[0]).toMatchObject({ name: "openai", base_url: "https://api.openai.com", api_key_env: "OPENAI_KEY" });
    expect(config.models[0]).toMatchObject({ name: "gpt4", provider: "openai", provider_model: "gpt-4o" });
    expect(config.models[0]!.capabilities).toEqual(["chat", "streaming"]);
    expect(config.api_keys[0]).toMatchObject({ id: "k1", key_env: "K1", organization_id: "org-1" });
  });

  test("throws a CaddyfileDiagnostic on an unsupported directive", () => {
    expect(() => parseCaddyfile(":8080 {\n  bogus_directive x\n}", "Caddyfile")).toThrow(CaddyfileDiagnostic);
  });

  /**
   * `model { capabilities ... }` parses each slug as `ModelCapability`
   * (`FromStr`), so an unknown one is a `capabilities` diagnostic carrying the
   * `FromStr` message as its suggestion — not a silently-retained free string.
   */
  describe("capabilities are parsed as ModelCapability", () => {
    const withCapabilities = (slugs: string) =>
      `:8080 {\n  ai_gateway {\n    model m -> openai:gpt-4o {\n      capabilities ${slugs}\n    }\n  }\n}`;

    test("accepts every ModelCapability slug", () => {
      const config = parseCaddyfile(
        withCapabilities("chat streaming vision images embeddings tools structured_output"),
        "Caddyfile",
      );
      expect(config.models[0]!.capabilities).toEqual([
        "chat",
        "streaming",
        "vision",
        "images",
        "embeddings",
        "tools",
        "structured_output",
      ]);
    });

    test("rejects an unknown slug with the Rust directive + suggestion", () => {
      let error: unknown;
      try {
        parseCaddyfile(withCapabilities("chat telepathy"), "Ferrogate/Caddyfile");
      } catch (thrown) {
        error = thrown;
      }
      expect(error).toBeInstanceOf(CaddyfileDiagnostic);
      const diagnostic = error as CaddyfileDiagnostic;
      expect(diagnostic.file).toBe("Ferrogate/Caddyfile");
      expect(diagnostic.directive).toBe("capabilities");
      expect(diagnostic.suggestion).toBe(
        'unknown model capability "telepathy"; expected one of chat, streaming, vision, images, ' +
          "embeddings, tools, structured_output",
      );
      expect(diagnostic.render()).toContain('unknown model capability "telepathy"');
      expect(diagnostic.render()).toContain("structured_output");
    });
  });

  test("organization_id resolves an env reference from the supplied env", () => {
    const src = `:8080 {
      ai_gateway {
        api_key k1 {
          key {env.K}
          organization_id {env.ORG}
        }
      }
    }`;
    const config = parseCaddyfile(src, "Caddyfile", { ORG: "tenant-9" });
    expect(config.api_keys[0]!.organization_id).toBe("tenant-9");
    expect(() => parseCaddyfile(src, "Caddyfile", {})).toThrow(/is not set/);
  });
});

describe("loader bridge", () => {
  test("isCaddyfilePath is case-insensitive on the filename", () => {
    expect(isCaddyfilePath("/etc/ferrogate/Caddyfile")).toBe(true);
    expect(isCaddyfilePath("caddyfile")).toBe(true);
    expect(isCaddyfilePath("config.toml")).toBe(false);
  });

  test("fromGatewayConfig + validate: a declared api_key loads; an undeclared one is refused", () => {
    const declared = `{
      auth off
    }
    :8080 {
      ai_gateway {
        api_key k1 {
          key {env.K}
          platform_operator on
        }
      }
    }`;
    const { config } = fromCaddyfileStr(declared, "Caddyfile");
    expect(config.api_keys[0]!.platform_operator).toBe(true);

    const undeclared = `{
      auth off
    }
    :8080 {
      ai_gateway {
        api_key k2 {
          key {env.K}
        }
      }
    }`;
    expect(() => fromCaddyfileStr(undeclared, "Caddyfile")).toThrow(/tenant_identity_required/);
  });

  test("fromGatewayConfig carries auth_disabled and maps upstream/routes", () => {
    const gateway = parseCaddyfile("{\n auth off\n}\n:8080 {\n reverse_proxy http://u:9000\n}", "Caddyfile");
    const raw = fromGatewayConfig(gateway);
    expect(raw.auth).toEqual({ disabled: true });
    expect((raw.upstreams as unknown[]).length).toBe(1);
  });
});
