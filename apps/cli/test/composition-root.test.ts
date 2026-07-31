/**
 * THE COMPOSITION-ROOT GATE for `createDefaultRuntime()` — all six ports.
 *
 * `docs/rewrite/parity-audit-dead-packages.md` §7.3 audited this file's subject
 * and found **no dead seam**: all six ports really are wired to real
 * implementations. What it also found is that only ONE of them (`client`) had a
 * test that would go red if it regressed — so five of six could be swapped for
 * their in-memory / structural stand-ins and the 325-test suite would stay
 * green. That is the same shape as every defect in the audit, one commit early.
 *
 * This file closes that. Each test below asserts a property that ONLY the
 * production implementation has, so swapping in the stand-in from
 * `test/helpers.ts` (`createTestRuntime`) or from `src/ports.ts`
 * (`createInMemory*` / `createStructuralConfigValidator` /
 * `createMemoryContextStorage`) turns exactly that test red.
 *
 * The `client` gate already exists in `test/transport.test.ts`
 * ("the shipped runtime wires the real transports") and is not duplicated here.
 *
 * Every stand-in named above is a legitimate TEST double — nothing here says
 * they should not exist. What this file says is that the SHIPPED BINARY must
 * not be built out of them, and that claim is now checked.
 */
import { describe, expect, test } from "vitest";
import { contextsPath } from "../src/context.js";
import { createDefaultRuntime, main } from "../src/index.js";
import { createTestRuntime } from "./helpers.js";

describe("createDefaultRuntime() wires the real io", () => {
  test("io.env IS process.env, not a fixture map", () => {
    const runtime = createDefaultRuntime();
    // Identity, not equality: `createTestRuntime` supplies `options.env ?? {}`,
    // a fresh object, so this comparison is what separates the two.
    expect(runtime.io.env).toBe(process.env);
    expect(runtime.io.platform).toBe(process.platform);
    expect(runtime.io.arch).toBe(process.arch);
  });

  test("io.readFile really reads the filesystem", async () => {
    const runtime = createDefaultRuntime();
    // A file that exists on disk and is NOT in any test fixture map. The
    // in-memory `Io` throws `no such test file:` for it.
    const text = await runtime.io.readFile(new URL("./helpers.ts", import.meta.url).pathname);
    expect(text).toContain("createTestRuntime");
  });

  test("io.randomBytes is a real CSPRNG, not a fixed buffer", () => {
    const runtime = createDefaultRuntime();
    const a = runtime.io.randomBytes(32);
    const b = runtime.io.randomBytes(32);
    expect(a).toHaveLength(32);
    // A stubbed RNG that returns a constant would fail here, and a constant
    // action-id nonce is a real security property, not a cosmetic one.
    expect(Buffer.from(a).toString("hex")).not.toBe(Buffer.from(b).toString("hex"));
    expect(Buffer.from(a).toString("hex")).not.toBe("0".repeat(64));
  });

  test("io.nowUnixSeconds is the wall clock", () => {
    const runtime = createDefaultRuntime();
    const now = Math.floor(Date.now() / 1000);
    expect(Math.abs(runtime.io.nowUnixSeconds() - now)).toBeLessThanOrEqual(2);
  });
});

describe("createDefaultRuntime() wires the real contextStorage", () => {
  test("contextStorage resolves the on-disk path from the runtime's OWN io.env", () => {
    // Two properties in one assertion, and both matter:
    //  1. it is `createFileContextStorage`, not `createMemoryContextStorage`
    //     (whose `path()` returns a synthetic marker, never `$HOME/...`);
    //  2. it was handed the SAME `io` the runtime carries — so a live change to
    //     `process.env` moves the store, which is what `--config-home` relies
    //     on. Building it from a second, private `Io` would break that.
    const previous = process.env.FERROGATE_CLI_HOME;
    process.env.FERROGATE_CLI_HOME = "/tmp/ferrogate-composition-root-probe";
    try {
      const runtime = createDefaultRuntime();
      expect(runtime.contextStorage.path()).toBe(
        "/tmp/ferrogate-composition-root-probe/contexts.toml",
      );
      expect(runtime.contextStorage.path()).toBe(contextsPath(process.env));

      // The live-env half: the SAME storage instance must follow the change.
      process.env.FERROGATE_CLI_HOME = "/tmp/ferrogate-composition-root-probe-2";
      expect(runtime.contextStorage.path()).toBe(
        "/tmp/ferrogate-composition-root-probe-2/contexts.toml",
      );
    } finally {
      // `delete` is what actually restores an ABSENT var: assigning `undefined`
      // to `process.env.X` writes the literal string "undefined" in Node, which
      // would leave a poisoned value behind for every later test.
      if (previous === undefined) {
        // biome-ignore lint/performance/noDelete: see above — assignment writes "undefined".
        delete process.env.FERROGATE_CLI_HOME;
      } else {
        process.env.FERROGATE_CLI_HOME = previous;
      }
    }
  });
});

describe("createDefaultRuntime() wires the REAL config validator", () => {
  test("it is createFerrogateConfigValidator, not the structural stand-in", async () => {
    const runtime = createDefaultRuntime();
    // `createStructuralConfigValidator` ALWAYS emits this warning, by design —
    // it announces that it did not load the schema or run the #542 gate. Its
    // presence is therefore a exact, unfakeable signature of the wrong wiring.
    const report = await runtime.configValidator.validate("Caddyfile", "{\n}\n");
    const messages = report.diagnostics.map((diagnostic) => diagnostic.message).join("\n");
    expect(messages).not.toContain("structural check only");
  });

  test("it rejects a document the structural validator would ACCEPT", async () => {
    // Braces balance, so the structural validator answers `ok: true`. The real
    // one has to decide the FORMAT first and refuses a name it cannot infer —
    // a schema-aware judgement the stand-in cannot make.
    const runtime = createDefaultRuntime();
    const report = await runtime.configValidator.validate("ferrogate.conf", "{\n}\n");
    expect(report.ok).toBe(false);
    expect(report.diagnostics.some((diagnostic) => diagnostic.severity === "error")).toBe(true);
    expect(report.diagnostics.map((d) => d.message).join("\n")).toContain(
      "cannot infer the format",
    );
  });

  test("it ACCEPTS a real Caddyfile (the refusals above are not blanket)", async () => {
    const runtime = createDefaultRuntime();
    // `{ auth off }` is the #542 explicit open posture. Without it the real
    // validator REFUSES a config with no credential source — which is itself
    // proof that the shipped gate is the one running.
    const report = await runtime.configValidator.validate(
      "Caddyfile",
      "{\n auth off\n}\n:8080 {\n reverse_proxy http://upstream:9000\n}\n",
    );
    expect(report.ok, JSON.stringify(report.diagnostics)).toBe(true);
  });
});

describe("createDefaultRuntime() wires the real key hasher", () => {
  test("hash() reproduces the gateway's stored BLAKE2b-512 construction", async () => {
    const runtime = createDefaultRuntime();
    // The known BLAKE2b-512 digest of the ASCII string "abc". A stub hasher —
    // or a silent downgrade to SHA-256 — cannot produce these bytes, and a
    // wrong hash here would have an operator write a key nobody can present.
    expect(await runtime.keyHasher.hash("abc")).toBe(
      "blake2b:ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d1" +
        "7d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923",
    );
  });
});

describe("createDefaultRuntime() wires the real gateway client", () => {
  test("a legacy `assets` verb reaches fetch, not the in-memory fake", async () => {
    // The `gatewayClient` twin of the existing `client` gate: if
    // `createDefaultRuntime` regressed to `createInMemoryGatewayClient`, this
    // command would answer offline and `seen` would stay empty.
    const original = globalThis.fetch;
    const seen: string[] = [];
    globalThis.fetch = (async (url: string | URL | Request) => {
      seen.push(String(url));
      return new Response(new Uint8Array([1, 2, 3]), {
        status: 200,
        headers: { "content-type": "application/octet-stream" },
      });
    }) as unknown as typeof fetch;
    try {
      const runtime = createDefaultRuntime();
      const harness = createTestRuntime();
      const code = await main(
        [
          "assets",
          "pull",
          "--gateway-url",
          "https://assets.example",
          "--api-key",
          "fg_composition_root_probe",
          "--type",
          "binary",
          "--name",
          "agent",
          "--version",
          "1.0.0",
          "--output",
          "-",
        ],
        {
          // The GATEWAY CLIENT stays the production one — that is the subject.
          // stdout/env/context are held in memory so the test writes nothing.
          ...runtime,
          io: { ...harness.io, env: {} },
          contextStorage: harness.contextStorage,
        },
      );
      expect(code, harness.stderr()).toBe(0);
      expect(seen).toHaveLength(1);
      expect(seen[0]).toContain("https://assets.example");
      expect(seen[0]).toContain("/v1/assets/binary/agent/1.0.0");
      // The bytes really came back through the binary path.
      expect(harness.stdoutBytes()).toHaveLength(1);
      expect(Array.from(harness.stdoutBytes()[0] as Uint8Array)).toEqual([1, 2, 3]);
    } finally {
      globalThis.fetch = original;
    }
  });
});
