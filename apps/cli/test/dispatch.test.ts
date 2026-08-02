import { describe, expect, test } from "vitest";
import { main } from "../src/index.js";
import { createTestRuntime, ok } from "./helpers.js";

describe("top-level dispatch and exit codes", () => {
  test("no command prints help to stderr and exits 2", async () => {
    const runtime = createTestRuntime();
    expect(await main([], runtime)).toBe(2);
    expect(runtime.stderr()).toContain("usage: ferrogate <command>");
    expect(runtime.stdout()).toBe("");
  });

  test("an unknown command exits 2", async () => {
    const runtime = createTestRuntime();
    expect(await main(["frobnicate"], runtime)).toBe(2);
    expect(runtime.stderr()).toContain("unknown command 'frobnicate'");
  });

  test("an unknown subcommand exits 2", async () => {
    const runtime = createTestRuntime();
    expect(await main(["auth", "dance"], runtime)).toBe(2);
    expect(runtime.stderr()).toContain("unknown subcommand 'dance'");
  });

  test("a group command with no subcommand exits 2", async () => {
    const runtime = createTestRuntime();
    expect(await main(["context"], runtime)).toBe(2);
    expect(runtime.stderr()).toContain("a subcommand is required");
  });

  test("an unknown flag on a known command exits 2", async () => {
    const runtime = createTestRuntime();
    expect(await main(["hash-key", "--nope"], runtime)).toBe(2);
    expect(runtime.stderr()).toContain("unknown flag '--nope'");
  });

  test("--help exits 0 and writes to stdout", async () => {
    const runtime = createTestRuntime();
    expect(await main(["--help"], runtime)).toBe(0);
    expect(runtime.stdout()).toContain("commands:");
    expect(runtime.stderr()).toBe("");
  });

  test("--version exits 0", async () => {
    const runtime = createTestRuntime();
    expect(await main(["--version"], runtime)).toBe(0);
    expect(runtime.stdout()).toMatch(/^ferrogate \d/);
  });

  test("aliases resolve to the same command", async () => {
    const runtime = createTestRuntime();
    await main(["gateway", "--help"], runtime);
    expect(runtime.stdout()).toContain("usage: ferrogate run");
  });
});

describe("native commands", () => {
  test("hash-key hashes the secret from a flag", async () => {
    const runtime = createTestRuntime();
    expect(await main(["hash-key", "--secret", "s3cret"], runtime)).toBe(0);
    expect(runtime.stdout().trim()).toBe("blake2b:test(s3cret)");
  });

  test("hash-key reads FERROGATE_KEY_SECRET when the flag is absent", async () => {
    const runtime = createTestRuntime({ env: { FERROGATE_KEY_SECRET: "from-env" } });
    expect(await main(["hash-key"], runtime)).toBe(0);
    expect(runtime.stdout().trim()).toBe("blake2b:test(from-env)");
  });

  test("hash-key with no secret at all is a usage error", async () => {
    const runtime = createTestRuntime();
    expect(await main(["hash-key"], runtime)).toBe(2);
  });

  test("validate exits 5 on an invalid document, not 2", async () => {
    const runtime = createTestRuntime({ files: { cfg: "{ unbalanced" } });
    expect(await main(["validate", "-c", "cfg"], runtime)).toBe(5);
    expect(runtime.stdout()).toContain("status: invalid");
  });

  test("validate exits 0 on a well-formed document", async () => {
    const runtime = createTestRuntime({ files: { cfg: "{ ok }" } });
    expect(await main(["check", "-c", "cfg"], runtime)).toBe(0);
    expect(runtime.stdout()).toContain("status: ok");
  });

  test("validate on a missing file is a usage error", async () => {
    const runtime = createTestRuntime();
    expect(await main(["validate", "-c", "absent"], runtime)).toBe(2);
    expect(runtime.stderr()).toContain("does not exist");
  });

  test("reload without --admin-url validates only, and says so", async () => {
    const runtime = createTestRuntime({ files: { cfg: "{ ok }" } });
    expect(await main(["reload", "-c", "cfg"], runtime)).toBe(0);
    expect(runtime.stderr()).toContain("without reloading anything");
    expect(runtime.client.requests).toHaveLength(0);
  });

  test("reload refuses to push an invalid config", async () => {
    const runtime = createTestRuntime({ files: { cfg: "{{{" } });
    expect(await main(["reload", "-c", "cfg", "--admin-url", "https://x"], runtime)).toBe(5);
    expect(runtime.client.requests).toHaveLength(0);
  });

  test("reload posts to the admin surface when a URL is given", async () => {
    const runtime = createTestRuntime({
      files: { cfg: "{ ok }" },
      script: { "POST /admin/v1/config/reload": ok({ reloaded: true }) },
    });
    expect(await main(["reload", "-c", "cfg", "--admin-url", "https://x"], runtime)).toBe(0);
    expect(runtime.client.requests[0]?.spec.path).toBe("/admin/v1/config/reload");
  });

  test("admin-api serve warns about deprecation but keeps working", async () => {
    const runtime = createTestRuntime();
    await main(["admin-api", "serve"], runtime);
    expect(runtime.stderr()).toContain("`admin-api serve` is deprecated");
    expect(runtime.stderr()).toContain("control-api serve");
  });

  test("serve verbs name their Worker replacement instead of exiting 0", async () => {
    const runtime = createTestRuntime();
    expect(await main(["run"], runtime)).toBe(2);
    expect(runtime.stderr()).toContain("wrangler deploy");
    expect(runtime.stderr()).toContain("apps/gateway");
  });

  test("storage migrate-to-supabase demands an explicit mode", async () => {
    const runtime = createTestRuntime();
    expect(await main(["storage", "migrate-to-supabase"], runtime)).toBe(2);
    expect(runtime.stderr()).toContain("--dry-run or --execute");
  });
});

describe("context commands (local verbs)", () => {
  test("create then list marks the current context", async () => {
    const runtime = createTestRuntime();
    expect(
      await main(
        ["context", "create", "prod", "--endpoint", "https://x", "--token-env", "TOK", "--use"],
        runtime,
      ),
    ).toBe(0);
    expect(await main(["context", "list"], runtime)).toBe(0);
    expect(runtime.stdout()).toContain("prod");
    expect(runtime.stdout()).toContain("env:TOK");
    expect(runtime.stdout()).toMatch(/prod\s+\*/);
  });

  test("create refuses to clobber without --overwrite", async () => {
    const runtime = createTestRuntime();
    await main(["context", "create", "prod", "--endpoint", "https://x"], runtime);
    expect(await main(["context", "create", "prod", "--endpoint", "https://y"], runtime)).toBe(2);
    expect(runtime.stderr()).toContain("--overwrite");
  });

  test("use refuses an undefined context", async () => {
    const runtime = createTestRuntime();
    expect(await main(["context", "use", "ghost"], runtime)).toBe(2);
  });

  test("delete removes it and clears current", async () => {
    const runtime = createTestRuntime();
    await main(["context", "create", "prod", "--endpoint", "https://x", "--use"], runtime);
    expect(await main(["context", "delete", "prod"], runtime)).toBe(0);
    expect(await main(["context", "show", "prod"], runtime)).toBe(2);
  });

  test("a stored context never carries a token value", async () => {
    const runtime = createTestRuntime();
    await main(
      ["context", "create", "prod", "--endpoint", "https://x", "--token-env", "TOK"],
      runtime,
    );
    const store = await runtime.contextStorage.load();
    expect(JSON.stringify(store)).not.toContain("inline");
    expect(store.contexts[0]?.auth).toEqual({ kind: "env", var: "TOK" });
  });
});

describe("completions", () => {
  test("every supported shell renders and mentions the ctl tree", async () => {
    for (const shell of ["bash", "zsh", "fish", "powershell", "elvish"]) {
      const runtime = createTestRuntime();
      expect(await main(["completions", shell], runtime), shell).toBe(0);
      expect(runtime.stdout(), shell).toContain("ctl");
      expect(runtime.stdout(), shell).toContain("guardrail-policies");
    }
  });

  test("an unknown shell is a usage error", async () => {
    const runtime = createTestRuntime();
    expect(await main(["completions", "csh"], runtime)).toBe(2);
  });

  test("a missing shell argument is a usage error", async () => {
    const runtime = createTestRuntime();
    expect(await main(["completions"], runtime)).toBe(2);
  });
});
