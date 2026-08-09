/**
 * CLI-7 and CLI-8 — the two lines of `createDefaultRuntime()` /
 * `apps/cli/src/index.ts` that no test in this repository could see.
 *
 * ## CLI-7 — `const transport = { readFile: (path) => io.readFile(path) };`
 *
 * `docs/rewrite/MOUNT-SEAMS.md` §16.2 recorded this as NEWLY UNPROVEN in wave
 * 15 and wave 18 re-measured it: replacing the transport with
 * `{ readFile: async () => "" }` was GREEN across all 339 CLI tests.
 * `test/transport.test.ts` proves the TLS policy exhaustively — but every case
 * there hands `createFetchControlPlaneClient` a `readFile` the TEST built and
 * never calls `createDefaultRuntime()`. That is the factory-vs-mount confusion
 * that made GW-A1 a fake mount: the FACTORY honours `--ca-bundle`; whether the
 * SHIPPED runtime hands it a working reader was asserted by nothing.
 *
 * ### Why nobody could have written this gate by accident
 *
 * `createTlsPolicy` short-circuits on `runtimeHonorsFetchTls()`, which is
 * `typeof globalThis.Bun !== "undefined"`. Vitest runs this suite under **Node**,
 * where that is `false`, so a CA-bundle context throws
 * *"cannot be honoured: this runtime's fetch() ignores per-request TLS options"*
 * BEFORE `transport.readFile` is ever consulted — the seam is unreachable on
 * this host. The shipped artifact is a Bun binary, so the honoured branch is
 * the one production takes. `withBunHostShape()` below installs the one global
 * the probe reads, which is a faithful simulation of the shipped host and the
 * only way to reach the seam offline.
 *
 * ### Why no socket is opened
 *
 * `createFetchControlPlaneClient.send` resolves the TLS policy FIRST and builds
 * the URL SECOND. Both probes therefore terminate before `fetch` is reached:
 * one on an unreadable path, one on a deliberately invalid endpoint. The two
 * errors are DIFFERENT sentences under the real transport and collapse to the
 * SAME sentence (`contains no certificates`) under the mutated one, which is
 * what makes them a discriminator rather than a smoke test.
 *
 * ## CLI-8 — the process-entry guard
 *
 * `if (entry.endsWith("/index.ts") || entry.endsWith("/ferrogate")) process.exit(...)`
 * has been recorded **NO GATE** since wave 13: vitest imports `main` directly,
 * so the guard never runs and either arm could be deleted invisibly. Deleting
 * the `/ferrogate` arm breaks the COMPILED BINARY ONLY — `bun run src/index.ts`
 * keeps working, so a developer smoke test would not catch it either, and the
 * failure mode is a binary that exits 0 and prints nothing.
 *
 * Both arms are exercised here by spawning a real `bun` child process: one
 * invoking `src/index.ts` directly, one invoking a launcher named exactly
 * `ferrogate` (no extension) written to a temp dir, which is the `argv[1]`
 * shape the compiled binary produces. No network, no compile step.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { afterAll, describe, expect, test } from "vitest";
import { exitCode } from "../src/errors.js";
import { createDefaultRuntime } from "../src/index.js";
import type { RequestContext, RequestSpec } from "../src/ports.js";

const GET: RequestSpec = { method: "GET", path: "/admin/v1/tenants", query: [] };

const BASE_CONTEXT: RequestContext = {
  endpoint: "https://cp.invalid",
  token: "sk-token",
  timeoutMillis: 5_000,
  headers: {},
  tlsInsecureSkipVerify: false,
};

const CA_PEM = "-----BEGIN CERTIFICATE-----\nMIIBkTCB+w==\n-----END CERTIFICATE-----\n";

const TEMP_DIRS: string[] = [];

function tempDir(): string {
  const dir = mkdtempSync(join(tmpdir(), "ferrogate-cli-gate-"));
  TEMP_DIRS.push(dir);
  return dir;
}

afterAll(() => {
  for (const dir of TEMP_DIRS) rmSync(dir, { recursive: true, force: true });
});

/**
 * Build the runtime the way the shipped Bun binary builds it.
 *
 * `createTlsPolicy` reads `globalThis.Bun` ONCE, when the client is constructed,
 * so the global must be present across the `createDefaultRuntime()` call — not
 * merely across `send()`. Restored immediately afterwards.
 */
function runtimeAsShipped(): ReturnType<typeof createDefaultRuntime> {
  const globals = globalThis as { Bun?: unknown };
  const had = "Bun" in globals;
  const previous = globals.Bun;
  globals.Bun = previous ?? {};
  try {
    return createDefaultRuntime();
  } finally {
    if (had) globals.Bun = previous;
    // biome-ignore lint/performance/noDelete: removes the own-property key entirely; assigning undefined would leave an enumerable undefined-valued key and change JSON serialization, the 'in' operator, and Object.keys semantics
    else delete globals.Bun;
  }
}

async function refusal(promise: Promise<unknown>): Promise<{ message: string; code: number }> {
  try {
    await promise;
  } catch (thrown) {
    const error = thrown as { message?: string; exitCode?: () => number };
    return { message: String(error.message ?? thrown), code: error.exitCode?.() ?? -1 };
  }
  throw new Error("expected the call to be refused before the socket opened");
}

describe("CLI-7 — the shipped runtime's --ca-bundle transport reads the REAL filesystem", () => {
  test("an unreadable bundle is refused with the FILESYSTEM's error, not an empty read", async () => {
    const runtime = runtimeAsShipped();
    const missing = join(tempDir(), "definitely-absent.pem");

    const { message, code } = await refusal(
      runtime.client.send(GET, { ...BASE_CONTEXT, caBundlePath: missing }),
    );

    // The real `io.readFile` throws ENOENT, which `createTlsPolicy` reports as
    // "failed to read". A transport whose `readFile` resolves to "" instead
    // reports "contains no certificates" — the discriminator.
    expect(message).toContain(`failed to read CA bundle '${missing}'`);
    expect(message).not.toContain("contains no certificates");
    expect(code).toBe(exitCode("usage"));
  });

  test("a REAL bundle on disk is read through to the TLS policy, bytes and all", async () => {
    const runtime = runtimeAsShipped();
    const bundle = join(tempDir(), "corp-root.pem");
    writeFileSync(bundle, CA_PEM, "utf8");

    // The endpoint is deliberately un-parseable, so `buildUrl` refuses on the
    // line AFTER the TLS policy resolved: reaching that refusal proves the PEM
    // was read and accepted, and no socket is opened.
    const { message } = await refusal(
      runtime.client.send(GET, {
        ...BASE_CONTEXT,
        endpoint: "http://[not-a-host",
        caBundlePath: bundle,
      }),
    );

    expect(message).toContain("invalid endpoint URL");
    // Under a transport that reads "" the run never gets this far.
    expect(message).not.toContain("contains no certificates");
    expect(message).not.toContain("failed to read CA bundle");
  });

  test("the gatewayClient shares that same reader — both legacy paths honour --ca-bundle", async () => {
    const runtime = runtimeAsShipped();
    const missing = join(tempDir(), "gateway-absent.pem");

    const { message } = await refusal(
      runtime.gatewayClient.send(
        { method: "GET", path: "/v1/assets", query: [] },
        { ...BASE_CONTEXT, caBundlePath: missing },
      ),
    );

    expect(message).toContain(`failed to read CA bundle '${missing}'`);
    expect(message).not.toContain("contains no certificates");
  });
});

describe("CLI-8 — the process-entry guard actually starts the CLI", () => {
  const ENTRY = fileURLToPath(new URL("../src/index.ts", import.meta.url));

  function run(script: string): { status: number | null; stdout: string; stderr: string } {
    const result = spawnSync("bun", [script, "--version"], {
      encoding: "utf8",
      timeout: 60_000,
      // No network, no config: `--version` is answered before any port is used.
      env: { ...process.env, FERROGATE_CLI_HOME: tempDir() },
    });
    return {
      status: result.status,
      stdout: result.stdout ?? "",
      stderr: result.stderr ?? "",
    };
  }

  test("the `/index.ts` arm: running the source entry prints the version and exits 0", () => {
    const { status, stdout } = run(ENTRY);
    expect(stdout).toContain("ferrogate");
    expect(status).toBe(0);
  });

  test("the `/ferrogate` arm: an argv[1] with the BINARY's name starts it too", () => {
    // The compiled artifact is `dist/ferrogate` — no extension — so `argv[1]`
    // ends with `/ferrogate` and ONLY the second half of the guard admits it.
    // A launcher of that exact name reproduces the shape without a 40 MB build.
    const dir = tempDir();
    const launcher = join(dir, "ferrogate");
    writeFileSync(launcher, `import ${JSON.stringify(ENTRY)};\n`, "utf8");

    const { status, stdout } = run(launcher);
    expect(stdout).toContain("ferrogate");
    expect(status).toBe(0);
  });
});
