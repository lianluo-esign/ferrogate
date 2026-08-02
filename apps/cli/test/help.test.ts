import { describe, expect, test } from "vitest";
import { commandPaths, renderRootHelp } from "../src/help.js";
import { main } from "../src/index.js";
import { GROUPS } from "../src/registry.js";
import { COMMANDS } from "../src/tree.js";
import { createTestRuntime } from "./helpers.js";

/** Every native command the Rust CLI shipped (inventory-edge-control.md §1.1). */
const NATIVE_PATHS = [
  "run",
  "auth",
  "auth serve",
  "control-api",
  "control-api serve",
  "admin-api",
  "admin-api serve",
  "billing",
  "billing serve",
  "storage",
  "storage migrate-to-supabase",
  "validate",
  "reload",
  "hash-key",
  "assets",
  "assets push",
  "assets pull",
  "assets list",
  "assets delete",
  "plans",
  "plans create",
  "plans list",
  "plans assign",
  "context",
  "context create",
  "context list",
  "context show",
  "context use",
  "context delete",
  "ops",
  "ops status",
  "completions",
  "ctl",
] as const;

describe("the help tree covers the whole command surface", () => {
  test("every native command from the inventory exists in the tree", () => {
    const paths = commandPaths(COMMANDS);
    for (const expected of NATIVE_PATHS) {
      expect(paths, `missing command: ${expected}`).toContain(expected);
    }
  });

  test("every registry group and verb is reachable as a ctl path", () => {
    const paths = new Set(commandPaths(COMMANDS));
    for (const group of GROUPS) {
      expect(paths).toContain(`ctl ${group.name}`);
      for (const verb of group.verbs) {
        expect(paths, `missing ctl ${group.name} ${verb.name}`).toContain(
          `ctl ${group.name} ${verb.name}`,
        );
      }
    }
  });

  test("root help names every top-level command and its aliases", () => {
    const help = renderRootHelp(COMMANDS);
    for (const node of COMMANDS) {
      expect(help, `help omits ${node.name}`).toContain(node.name);
    }
    expect(help).toContain("gateway"); // the `run` alias
    expect(help).toContain("check"); // the `validate` alias
  });

  test("root help lists every ctl group", () => {
    const help = renderRootHelp(COMMANDS);
    for (const group of GROUPS) {
      expect(help, `help omits ctl group ${group.name}`).toContain(group.name);
    }
  });

  test("the deprecated command is marked as such in help", () => {
    expect(renderRootHelp(COMMANDS)).toContain("[DEPRECATED]");
  });

  test("every leaf command has a handler and every group has children", () => {
    const visit = (nodes: readonly (typeof COMMANDS)[number][]): void => {
      for (const node of nodes) {
        if (node.sub === undefined) {
          expect(
            node.run !== undefined || node.runRaw !== undefined,
            `${node.name} has no handler`,
          ).toBe(true);
        } else {
          expect(node.sub.length, `${node.name} has no subcommands`).toBeGreaterThan(0);
          visit(node.sub);
        }
      }
    };
    visit(COMMANDS);
  });
});

describe("per-command help", () => {
  test("`<command> --help` exits 0 and shows the command's flags", async () => {
    const runtime = createTestRuntime();
    expect(await main(["assets", "push", "--help"], runtime)).toBe(0);
    expect(runtime.stdout()).toContain("--gateway-url");
    expect(runtime.stdout()).toContain("FERROGATE_GATEWAY_URL");
  });

  test("help renders for every native leaf without throwing", async () => {
    for (const path of NATIVE_PATHS) {
      if (path === "ctl") continue; // ctl owns its own help grammar
      const runtime = createTestRuntime();
      const code = await main([...path.split(" "), "--help"], runtime);
      expect(code, `help failed for ${path}`).toBe(0);
      expect(runtime.stdout(), `empty help for ${path}`).not.toBe("");
    }
  });

  test("`ctl <group> <verb> --help` shows the operation and effect", async () => {
    const runtime = createTestRuntime();
    expect(await main(["ctl", "wallets", "adjust", "--help"], runtime)).toBe(0);
    expect(runtime.stdout()).toContain("operation: adjustWallet");
    expect(runtime.stdout()).toContain("effect: mutating");
    expect(runtime.stdout()).toContain("--yes");
  });

  test("a read verb's help offers no --yes", async () => {
    const runtime = createTestRuntime();
    await main(["ctl", "projects", "list", "--help"], runtime);
    // Matched as a flag entry, not as prose: `--non-interactive`'s help text
    // legitimately mentions --yes.
    expect(runtime.stdout()).not.toMatch(/^\s+--yes\b/m);
  });
});
