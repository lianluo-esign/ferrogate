#!/usr/bin/env bun
/**
 * seam-proof — run a mount-seam mutation proof against ONLY the tests that seam
 * names, instead of the whole app suite.
 *
 * ## Why this exists
 *
 * A seam proof asks one question: *does the assertion that guards this mount go
 * RED when the mount is removed?* Answering it by running the app's entire suite
 * is 13x more work than answering it directly. Measured on this repo:
 *
 *   apps/gateway, full suite (111 files) ..... 51_000 ms
 *   apps/gateway, one test file .............. 3_870 ms
 *
 * At 194 seam rows that is ~100 minutes versus ~13, and it is the single largest
 * cost in a certification wave. `MOUNT-SEAMS.md` already records the expected-RED
 * test file for every row, so the information was always there — it just was not
 * being used.
 *
 * ## What this does NOT replace
 *
 * The narrow run proves the GATE. It does not prove the mutation left the rest of
 * the tree alone. That is what the full `bun run test` pass earlier in the wave is
 * for. Do not drop that pass: a seam proof and a regression sweep answer different
 * questions, and this script deliberately only answers the first.
 *
 * ## Usage
 *
 *   bun scripts/seam-proof.mjs --list                 # parse + resolve, run nothing
 *   bun scripts/seam-proof.mjs --tier T1              # print the T1 work plan
 *   bun scripts/seam-proof.mjs --app gateway --list
 *   bun scripts/seam-proof.mjs --id GW-E2 --run       # run that seam's tests as-is
 *
 * `--run` executes the named tests against the tree AS IT STANDS. It performs no
 * mutation: applying and reverting the edit stays with the caller, who is the only
 * one who can confirm the edit actually landed. Running a proof against a tree
 * somebody else is concurrently editing produces a meaningless result.
 */

import { readFileSync, existsSync } from "node:fs";
import { spawn } from "node:child_process";
import path from "node:path";

const ROOT = new URL("..", import.meta.url).pathname.replace(/\/$/, "");
const INVENTORY = path.join(ROOT, "docs/rewrite/MOUNT-SEAMS.md");

/** `GW-` → `apps/gateway`. The inventory's ID prefixes. */
const APP_BY_PREFIX = {
  GW: "apps/gateway",
  CP: "apps/control-plane",
  MCP: "apps/mcp",
  AR: "apps/agent-runtime",
  TEL: "apps/telemetry",
  CLI: "apps/cli",
};

/**
 * Pull `path/to/x.test.ts` out of a table cell.
 *
 * The cell is prose — "every `SELF.fetch` suite; `test/health.test.ts`" — so this
 * takes every backticked path ending in `.test.ts` and ignores the rest. A row
 * whose cell names no file yields none, and is reported rather than skipped
 * silently: an unproven seam that looks skipped is how a fake mount survives.
 */
function testFilesFrom(cell) {
  return [...cell.matchAll(/`([^`]*\.test\.ts)`/g)].map((m) => m[1]);
}

function parseInventory() {
  if (!existsSync(INVENTORY)) {
    console.error(`seam-proof: inventory not found at ${INVENTORY}`);
    process.exit(2);
  }
  const rows = [];
  for (const line of readFileSync(INVENTORY, "utf8").split("\n")) {
    const m = line.match(/^\|\s*((?:GW|CP|MCP|AR|TEL|CLI)-[A-Z0-9]+)\s*\|(.*)$/);
    if (m === null) continue;
    const cells = m[2].split("|").map((c) => c.trim());
    const id = m[1];
    const app = APP_BY_PREFIX[id.split("-")[0]];
    // Tier is the last non-empty cell; the expected-RED cell is the one before it.
    const nonEmpty = cells.filter((c) => c !== "");
    const tier = (nonEmpty.at(-1) ?? "").match(/T[123]/)?.[0] ?? "?";
    const expected = nonEmpty.at(-2) ?? "";
    rows.push({ id, app, tier, files: testFilesFrom(expected), expected });
  }
  return rows;
}

/** Resolve a recorded path against the app dir, tolerating both spellings. */
function resolveFile(app, file) {
  const candidates = file.startsWith("apps/")
    ? [path.join(ROOT, file)]
    : [path.join(ROOT, app, file), path.join(ROOT, app, "test", file)];
  return candidates.find((c) => existsSync(c)) ?? null;
}

function run(cmd, args, cwd) {
  return new Promise((resolve) => {
    const child = spawn(cmd, args, { cwd, stdio: ["ignore", "pipe", "pipe"] });
    let out = "";
    child.stdout.on("data", (d) => (out += d));
    child.stderr.on("data", (d) => (out += d));
    child.on("close", (code) => resolve({ code, out }));
  });
}

const argv = process.argv.slice(2);
const flag = (name) => {
  const i = argv.indexOf(name);
  return i === -1 ? undefined : (argv[i + 1] ?? true);
};

const rows = parseInventory();
const wanted = rows.filter(
  (r) =>
    (flag("--id") === undefined || r.id === flag("--id")) &&
    (flag("--tier") === undefined || r.tier === flag("--tier")) &&
    (flag("--app") === undefined || r.app === `apps/${flag("--app")}`),
);

if (wanted.length === 0) {
  console.error("seam-proof: no rows matched");
  process.exit(2);
}

// Resolve up front so a stale inventory path is a loud error, not a silent pass.
let unresolved = 0;
for (const r of wanted) {
  r.resolved = r.files.map((f) => resolveFile(r.app, f)).filter((f) => f !== null);
  if (r.resolved.length === 0) unresolved += 1;
}

if (flag("--run") === undefined) {
  const byApp = {};
  for (const r of wanted) (byApp[r.app] ??= []).push(r);
  console.log(`seam-proof: ${wanted.length} rows across ${Object.keys(byApp).length} apps`);
  for (const [app, rs] of Object.entries(byApp)) {
    console.log(`  ${app}: ${rs.length} rows`);
    for (const r of rs) {
      const n = r.resolved.length;
      console.log(`    ${r.id} [${r.tier}] → ${n === 0 ? "NO RESOLVABLE TEST FILE" : r.resolved.map((f) => path.relative(path.join(ROOT, app), f)).join(" ")}`);
    }
  }
  if (unresolved > 0) {
    console.log(`\n  ${unresolved} row(s) name no resolvable test file — those cannot be`);
    console.log("  proven narrowly and must fall back to the app suite. Fix the inventory.");
  }
  process.exit(0);
}

// --run: apps in parallel (mutations never cross app boundaries), rows serial
// within an app (two mutations in one tree would interfere).
const byApp = {};
for (const r of wanted) (byApp[r.app] ??= []).push(r);

const results = await Promise.all(
  Object.entries(byApp).map(async ([app, rs]) => {
    const out = [];
    for (const r of rs) {
      if (r.resolved.length === 0) {
        out.push({ id: r.id, status: "NO-FILE", ms: 0 });
        continue;
      }
      const started = Date.now();
      const { code } = await run(
        "bunx",
        ["vitest", "run", ...r.resolved.map((f) => path.relative(path.join(ROOT, app), f))],
        path.join(ROOT, app),
      );
      out.push({ id: r.id, status: code === 0 ? "GREEN" : "RED", ms: Date.now() - started });
    }
    return out;
  }),
);

const flat = results.flat();
for (const r of flat) console.log(`${r.id.padEnd(10)} ${r.status.padEnd(8)} ${r.ms}ms`);
const total = flat.reduce((a, r) => a + r.ms, 0);
console.log(`\n${flat.length} rows · ${(total / 1000).toFixed(1)}s of test time`);
console.log("GREEN here means the named gate did NOT fail. Against a MUTATED tree that");
console.log("is an unproven mount; against a clean tree it is the expected result.");
