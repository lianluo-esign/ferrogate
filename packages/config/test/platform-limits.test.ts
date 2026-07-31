/**
 * Pins for the `@ferrogate/config` behaviors that are KEPT as PORT-TODO markers
 * because the Cloudflare platform genuinely cannot express the Rust original.
 *
 * Each block asserts the APPROXIMATION that was actually implemented, so the
 * marker can never drift into a claim nobody checks, and so a future wave that
 * "fixes" one of these has to confront the limitation on purpose.
 *
 * The limits pinned here:
 *   1. `secrets.ts`        — workerd has no `std::env`; the env is an argument.
 *   2. `network-access.ts` — no socket peer address; no cross-isolate state.
 *   3. `loader.ts`         — no filesystem; the entry point takes an object.
 *   4. `schema/sections.ts`— CF terminates TLS: `[tls]`/`[tls.acme]` are inert.
 */
import { describe, expect, test } from "vitest";
import * as configPackage from "../src/index.js";
import { fromCaddyfileStr, loadConfigFromObject } from "../src/loader.js";
import { resolveClientIp, UnauthenticatedIpRateLimiter } from "../src/network-access.js";
import { configSchema } from "../src/schema/config.js";
import { resolveEnvPlaceholders } from "../src/secrets.js";
import { validateConfig } from "../src/validate.js";

describe("secrets: no std::env (the env is an explicit argument)", () => {
  test("resolves against a Worker-style `env` binding object handed in by the caller", () => {
    // What a Worker actually has: the per-invocation `env`, not process state.
    const workerEnv = { OPENAI_API_KEY: "sk-live", UNUSED: "x" };
    expect(resolveEnvPlaceholders("Bearer {env.OPENAI_API_KEY}", workerEnv)).toBe("Bearer sk-live");
  });

  test("the explicit env WINS over ambient process state", () => {
    const ambient = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process;
    expect(ambient?.env).toBeDefined(); // this suite runs under Node, unlike workerd
    ambient!.env!.FERROGATE_PLATFORM_LIMIT_PROBE = "from-process";
    try {
      expect(
        resolveEnvPlaceholders("{env.FERROGATE_PLATFORM_LIMIT_PROBE}", { FERROGATE_PLATFORM_LIMIT_PROBE: "from-binding" }),
      ).toBe("from-binding");
    } finally {
      delete ambient!.env!.FERROGATE_PLATFORM_LIMIT_PROBE;
    }
  });

  test("an empty environment (the workerd default) FAILS CLOSED, it does not interpolate ''", () => {
    expect(() => resolveEnvPlaceholders("Bearer {env.MISSING_ON_WORKERD}", {})).toThrow(
      "environment variable `MISSING_ON_WORKERD` is not set",
    );
  });
});

describe("network-access: no peer address, no cross-isolate state", () => {
  test("CF-Connecting-IP substitutes for the Rust socket peer address", () => {
    // Cloudflare sets CF-Connecting-IP and strips any client-supplied copy, so
    // it carries the trust property the Rust peer address had. Untrusted
    // forwarding headers must not be able to displace it.
    const headers = { "cf-connecting-ip": "203.0.113.9", "x-forwarded-for": "10.0.0.1" };
    expect(resolveClientIp(headers, headers["cf-connecting-ip"], false, 1)).toBe("203.0.113.9");
  });

  test("a spoofed leftmost XFF entry still cannot displace it when forwarding IS trusted", () => {
    const headers = { "x-forwarded-for": "1.2.3.4, 203.0.113.9" };
    expect(resolveClientIp(headers, "198.51.100.1", true, 1)).toBe("203.0.113.9");
  });

  test("the limiter is ISOLATE-LOCAL: separate instances do not share a window", () => {
    const isolateA = new UnauthenticatedIpRateLimiter();
    const isolateB = new UnauthenticatedIpRateLimiter();
    for (let i = 0; i < 3; i += 1) expect(isolateA.allow("203.0.113.1", 100, 3)).toBe(true);
    expect(isolateA.allow("203.0.113.1", 100, 3)).toBe(false);
    // The SAME source in a second isolate gets a fresh budget — the documented
    // weaker bound. A Durable Object hosting ONE instance restores the Rust rule.
    expect(isolateB.allow("203.0.113.1", 100, 3)).toBe(true);
  });

  test("`allow()` stays synchronous, so a Durable Object can host it verbatim", () => {
    const decision = new UnauthenticatedIpRateLimiter().allow("203.0.113.1", 100, 1);
    expect(decision).toBe(true);
    expect(decision).not.toBeInstanceOf(Promise);
  });
});

describe("loader: no filesystem", () => {
  test("the entry point takes an already-decoded object and still runs the full gate", () => {
    const loaded = loadConfigFromObject({ listen: "0.0.0.0:8080" });
    expect(loaded.config.listen).toBe("0.0.0.0:8080");
    expect(() => loadConfigFromObject({ listen: "nonsense" })).toThrow(
      "field listen: invalid listen address nonsense",
    );
  });

  test("no file/TOML/YAML entry point is exported (there is no path to read)", () => {
    const surface = Object.keys(configPackage);
    expect(surface).toContain("loadConfigFromObject");
    for (const absent of ["fromFile", "fromTomlStr", "fromTomlFile", "fromYamlStr", "fromYamlFile", "resolvePathsRelativeTo"]) {
      expect(surface).not.toContain(absent);
    }
  });

  test("the Caddyfile bridge needs no dependency and IS ported (string in, Config out)", () => {
    const loaded = fromCaddyfileStr(
      `{
  auth off
}
:8080 {
  reverse_proxy up1 http://backend.internal:9000
}`,
      "Caddyfile",
    );
    expect(loaded.config.upstreams).toHaveLength(1);
    expect(loaded.config.upstreams[0]!.url).toBe("http://backend.internal:9000");
    expect(loaded.config.listen).toBe("127.0.0.1:8080"); // adapt_site_address
    expect(loaded.config.auth.disabled).toBe(true);
  });
});

describe("tls/acme: Cloudflare terminates TLS, so the sections are inert", () => {
  test("the schema still DECODES a legacy [tls] + [tls.acme] block (migration round-trip)", () => {
    const config = configSchema.parse({
      tls: {
        enabled: true,
        cert_path: "/etc/ferrogate/cert.pem",
        key_path: "/etc/ferrogate/key.pem",
        acme: { domains: ["gw.example"], email: "ops@example" },
      },
    });
    expect(config.tls.cert_path).toBe("/etc/ferrogate/cert.pem");
    expect(config.tls.acme.domains).toEqual(["gw.example"]);
    expect(config.tls.acme.directory_url).toBe("https://acme-v02.api.letsencrypt.org/directory");
  });

  test("NOTHING validates it — a block Rust would REFUSE is accepted here", () => {
    // Rust `validate_tls`: `enabled` with no cert_path bails with
    // "field tls.cert_path: required when TLS is enabled". Removed as N/A: there
    // is no listener socket and no file to load behind Cloudflare's TLS edge.
    expect(() => validateConfig(configSchema.parse({ tls: { enabled: true } }))).not.toThrow();
    // Same for the ACME combination Rust refuses outright.
    expect(() =>
      validateConfig(
        configSchema.parse({
          tls: { enabled: true, cert_path: "/c.pem", key_path: "/k.pem", acme: { enabled: true } },
        }),
      ),
    ).not.toThrow();
  });

  /**
   * The COMPENSATING CONTROL for that removal: silence would tell an operator
   * TLS is configured when nothing reads it. `loadConfigFromObject` therefore
   * reports the section as inert. These assertions are deliberately made
   * through the LOADER, not by calling `inertTlsWarnings` directly, so they go
   * red if the warning is implemented but never mounted on the load path — the
   * failure mode this repo keeps hitting.
   */
  test("the LOADER reports a manual [tls] block as inert", () => {
    const { warnings } = loadConfigFromObject({
      tls: { enabled: true, cert_path: "/c.pem", key_path: "/k.pem" },
    });
    expect(warnings.join("\n")).toMatch(/\[tls\] is INERT on Cloudflare/);
    expect(warnings.join("\n")).toMatch(/cert_path\/key_path are not read/);
  });

  test("the LOADER reports an [tls.acme] block as inert, separately", () => {
    const { warnings } = loadConfigFromObject({
      tls: { acme: { enabled: true, domains: ["gw.example"], email: "ops@example" } },
    });
    expect(warnings.join("\n")).toMatch(/\[tls\.acme\] is INERT on Cloudflare/);
    // `tls.enabled` is false here, so the manual-TLS warning must NOT fire.
    expect(warnings.join("\n")).not.toMatch(/\[tls\] is INERT/);
  });

  test("a Caddyfile `tls` directive is reported as inert through the migration bridge", () => {
    // `fromGatewayConfig` emits `[tls]`; the operator must be told it is inert
    // rather than have the migration quietly imply certificates are handled.
    const { warnings } = fromCaddyfileStr(
      "gw.example {\n  tls /etc/cert.pem /etc/key.pem\n}\n",
      "Caddyfile",
    );
    expect(warnings.join("\n")).toMatch(/\[tls\] is INERT on Cloudflare/);
  });

  test("a config with no TLS section warns about nothing", () => {
    expect(loadConfigFromObject({}).warnings).toEqual([]);
  });

  test("no TLS/ACME validator is exported under any name", () => {
    const surface = Object.keys(configPackage);
    for (const absent of [
      "validateTls",
      "validateAcmeTls",
      "validateAcmeDns01Tls",
      "validateAcmeHttp01Tls",
      "validateManualTlsFiles",
    ]) {
      expect(surface).not.toContain(absent);
    }
  });
});
