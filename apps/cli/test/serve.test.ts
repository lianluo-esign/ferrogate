/**
 * The `serve` family — the PORT-TODO that is KEPT, and what stands in for it.
 *
 * `src/commands/serve.ts` carries `PORT-TODO(inventory-edge-control.md §1.4)`:
 * the CLI's identity as a process launcher does not survive the port, because a
 * Worker never owns a listening socket. That marker is a claim about behaviour,
 * so it needs a test — otherwise "we refuse honestly" is just a comment, and
 * nothing stops a later wave from making `run` exit 0 with a Bun HTTP server
 * that has none of the gateway's bindings.
 *
 * These tests pin the approximation, not the impossibility:
 *   - the refusal is LOUD: non-zero exit, in the `usage` class;
 *   - stdout stays EMPTY, so a script piping stdout gets nothing that could be
 *     mistaken for a started service;
 *   - the full flag surface still parses, so a typo is still caught;
 *   - supplied settings are echoed, but secrets are redacted;
 *   - the marker itself is printed, so an operator reading stderr learns why.
 */
import { describe, expect, test } from "vitest";
import { exitCode } from "../src/errors.js";
import { main } from "../src/index.js";
import { createTestRuntime } from "./helpers.js";

async function run(argv: readonly string[], env: Record<string, string> = {}) {
  const runtime = createTestRuntime({ env });
  const code = await main(argv, runtime);
  return { code, stdout: runtime.stdout(), stderr: runtime.stderr() };
}

const SERVE_VERBS: readonly (readonly [string, readonly string[], string])[] = [
  ["run", ["run"], "gateway"],
  ["gateway (alias of run)", ["gateway"], "gateway"],
  ["auth serve", ["auth", "serve"], "control-plane"],
  ["control-api serve", ["control-api", "serve"], "control-plane"],
  ["admin-api serve", ["admin-api", "serve"], "control-plane"],
  ["billing serve", ["billing", "serve"], "control-plane"],
];

describe("PORT-TODO §1.4 KEPT: no serve verb can start a listener", () => {
  test.each(SERVE_VERBS)("`%s` refuses loudly and never exits 0", async (_label, argv, app) => {
    const result = await run(argv);
    // Non-zero, and specifically the usage class: a wrapper script branching on
    // the exit code must be able to tell "you asked for something this build
    // cannot do" from "the service died".
    expect(result.code).toBe(exitCode("usage"));
    expect(result.code).not.toBe(0);
    // Nothing on stdout: a pipeline reading stdout gets no output at all, so
    // there is no string it could parse as a started service.
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("this build has no local listener to bind");
    expect(result.stderr).toContain(`apps/${app}/wrangler.toml`);
    expect(result.stderr).toContain("bunx wrangler deploy");
    expect(result.stderr).toContain("bunx wrangler dev");
    // The health check that replaces "is it up?".
    expect(result.stderr).toContain("ferrogate ctl system ready --endpoint");
  });

  test("the marker is printed, not just left in the source", async () => {
    const result = await run(["run"]);
    expect(result.stderr).toContain("PORT-TODO(inventory-edge-control.md §1.4)");
    expect(result.stderr).toContain("Worker vars/secrets");
  });

  test("`admin-api serve` still warns that it is the deprecated spelling", async () => {
    const result = await run(["admin-api", "serve"]);
    expect(result.stderr).toContain("`admin-api serve` is deprecated");
    expect(result.stderr).toContain("use `control-api serve`");
  });
});

describe("the flag surface survives the refusal", () => {
  test("a typo in a flag is still a parse error, not a silent no-op", async () => {
    const result = await run(["run", "--upgarde"]);
    expect(result.code).toBe(exitCode("usage"));
    expect(result.stderr).toContain("--upgarde");
  });

  test("supplied settings are echoed so nothing is silently dropped", async () => {
    const result = await run([
      "auth",
      "serve",
      "--listen",
      "0.0.0.0:9999",
      "--supabase-schema",
      "s",
    ]);
    expect(result.stderr).toContain("resolved settings");
    expect(result.stderr).toContain("listen = 0.0.0.0:9999");
    expect(result.stderr).toContain("supabase-schema = s");
  });

  test("a secret the operator typed is redacted in the echo", async () => {
    const result = await run([
      "auth",
      "serve",
      "--admin-jwt-secret",
      "super-secret-value",
      "--supabase-dsn",
      "postgres://user:pw@host/db",
    ]);
    expect(result.stderr).toContain("admin-jwt-secret = <redacted>");
    expect(result.stderr).toContain("supabase-dsn = <redacted>");
    expect(result.stderr).not.toContain("super-secret-value");
    expect(result.stderr).not.toContain("postgres://user:pw@host/db");
  });

  test("`--upgrade` — the SIGQUIT fd hand-off — is accepted and refused, not ignored", async () => {
    const result = await run(["run", "--upgrade"]);
    expect(result.code).toBe(exitCode("usage"));
    expect(result.stderr).toContain("upgrade = true");
  });

  test("env-sourced flags reach the echo through the same precedence chain", async () => {
    const result = await run(["auth", "serve"], { FERROGATE_AUTH_LISTEN: "10.0.0.1:1234" });
    expect(result.stderr).toContain("listen = 10.0.0.1:1234");
  });
});

describe("PORT-TODO §1.1 KEPT: storage migrate-to-supabase has no target store", () => {
  test("it refuses, names D1, and names the deploy-time binding limit", async () => {
    const result = await run(["storage", "migrate-to-supabase", "--execute"]);
    expect(result.code).toBe(exitCode("usage"));
    expect(result.stdout).toBe("");
    expect(result.stderr).toContain("PORT-TODO(inventory-edge-control.md §1.1)");
    expect(result.stderr).toContain("DEPLOY-TIME binding");
    expect(result.stderr).toContain("no bind-by-uuid API");
    expect(result.stderr).toContain("bunx wrangler d1 migrations apply");
  });

  test("--execute without a mode is still refused before the marker is reached", async () => {
    const result = await run(["storage", "migrate-to-supabase"]);
    expect(result.code).toBe(exitCode("usage"));
    expect(result.stderr).toContain("requires exactly one of --dry-run or --execute");
    // The mode check runs FIRST, so the marker text is not what the operator
    // sees when the real problem is their invocation.
    expect(result.stderr).not.toContain("PORT-TODO");
  });

  test("--dry-run is refused too: a plan against a store that does not exist is not a plan", async () => {
    const result = await run(["storage", "migrate-to-supabase", "--dry-run"]);
    expect(result.code).toBe(exitCode("usage"));
    expect(result.stderr).toContain("Postgres/Supabase is not the durable store");
  });
});
