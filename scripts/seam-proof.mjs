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
 * At ~190 seam rows that is ~100 minutes versus ~13, and it is the single largest
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
 * ## The three numbers this script exists to keep honest
 *
 * `--list` prints CLAIMED (rows the inventory's own §13 count declares), PARSED
 * (rows this parser actually recognises) and GATED (rows that resolve to at least
 * one test file on disk). Wave 21 found the first two disagreed by 20 and nobody
 * noticed, because the parser dropped every row whose ID cell was bold, whose ID
 * carried a lowercase suffix (`CP-C13b`), or which was a struck-through tombstone.
 * A scripted pass that looks complete while silently skipping 20 rows is worse
 * than one that admits it is partial, so a mismatch is now a NON-ZERO EXIT.
 *
 * ## Channels
 *
 * The inventory carries a machine-readable *Channel* column, `RUN · QUALITY?`:
 *
 *   DEF   run the app's own default vitest project (the narrow run)
 *   ESC   the gate is a `*.spec.ts` under a CHAINED vitest config (MOUNT-SEAMS
 *         §4). Under a bare `vitest run` those specs are not collected at all and
 *         the suite reports green — which is exactly how AR-P1/AR-P2 read as
 *         "ungated" until wave 20. This script runs them with `--config <the
 *         chained config>`, which is ~30x cheaper than the `bun run test` the
 *         inventory used to demand.
 *   NONE  no local gate of any kind. Nothing to run.
 *
 * and the optional QUALITY token, which is about how to READ a result, never
 * about how to run it:
 *
 *   DRIFT            the committed value is overridden by a pinned miniflare
 *                    binding (or is config the pool never reads), so the gate is
 *                    a NAME/PRESENCE assertion and cannot be behavioural.
 *   NOT-MUTABLE      the seam cannot be mutated BY CATEGORY — an absent stanza, a
 *                    deliberately-commented one. A skipped NOT-MUTABLE row is not
 *                    an unproven row, and this distinction is the whole reason
 *                    the column exists.
 *   WORKERD-REFUSAL  exercising the seam takes the runtime to a start-up refusal
 *                    and the suite to 0 collected tests; only its rot directions
 *                    are gated.
 *   RETIRED          a tombstone, kept for history. Not a seam. Never counted.
 *
 * ## Usage
 *
 *   bun scripts/seam-proof.mjs --list                 # parse + resolve, run nothing
 *   bun scripts/seam-proof.mjs --tier T1              # print the T1 work plan
 *   bun scripts/seam-proof.mjs --app gateway --list
 *   bun scripts/seam-proof.mjs --channel ESC --list   # just the escalated rows
 *   bun scripts/seam-proof.mjs --id GW-E2 --run       # run that seam's tests as-is
 *
 * `--run` executes the named tests against the tree AS IT STANDS. It performs no
 * mutation: applying and reverting the edit stays with the caller, who is the only
 * one who can confirm the edit actually landed. Running a proof against a tree
 * somebody else is concurrently editing produces a meaningless result.
 */

import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
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
 * The chained vitest projects an ESC row's gate lives under (MOUNT-SEAMS §4).
 *
 * Keyed by the directory a `*.spec.ts` sits in, because that is what the
 * inventory cites and what unambiguously identifies which config collects it.
 * `each app's package.json`'s `test` script chains exactly these.
 */
const CHAINED_CONFIGS = [
  ["apps/gateway", "test/ratelimit/", "test/ratelimit/harness/vitest.config.ts"],
  ["apps/gateway", "test/tenancy/", "test/tenancy/harness/vitest.config.ts"],
  ["apps/agent-runtime", "test/durable/", "test/durable/harness/vitest.config.ts"],
];

function chainedConfigFor(app, file) {
  // `.spec.ts` ONLY. All three chained configs are `include: ["**/*.spec.ts"]`,
  // and every chained directory also holds ordinary `*.test.ts` files that
  // belong to the app's DEFAULT project (`test/ratelimit/guards.test.ts` beside
  // `test/ratelimit/enforcement.spec.ts`). Keying on the directory alone sent
  // those to the chained config, which collects 0 tests and exits non-zero — a
  // FALSE RED on three T1 gateway rows (GW-E3, GW-C6, GW-W2) that had nothing
  // wrong with them. A runner that cries wolf is worse than no runner: the next
  // real RED gets read as "that one always fails".
  if (!file.endsWith(".spec.ts")) return null;
  for (const [chainedApp, prefix, config] of CHAINED_CONFIGS) {
    if (app === chainedApp && file.startsWith(prefix)) return config;
  }
  return null;
}

/**
 * Pull `path/to/x.test.ts` / `x.spec.ts` out of a table cell.
 *
 * The cell is prose, so this takes every backticked path ending in `.test.ts` or
 * `.spec.ts` and ignores the rest. Three things it deliberately does:
 *
 *  - **`.spec.ts` counts.** Dropping it is what made GW-C8, AR-P1 and AR-P2 read
 *    as "NO RESOLVABLE TEST FILE" when each had a perfectly good chained gate.
 *  - **A `:NNN` line suffix is stripped.** `test/contract.test.ts:432` names a
 *    real file and a line number that had already moved to 439.
 *  - **A struck-through citation is SKIPPED.** MOUNT-SEAMS §4 withdrew several
 *    citations that prove the harness rather than the mount, and writes them
 *    `**NOT** ~~`file`~~`. Grabbing those would run a suite that CANNOT go red
 *    for the seam and report the row as covered — the precise failure the
 *    withdrawals exist to stop.
 */
function testFilesFrom(cell) {
  const withdrawn = new Set(
    [...cell.matchAll(/~~`([^`]+)`~~/g)].map((m) => m[1].replace(/:\d+$/, "")),
  );
  const out = [];
  for (const m of cell.matchAll(/`([^`]*\.(?:test|spec)\.ts)(?::\d+)?`/g)) {
    const file = m[1];
    if (withdrawn.has(file) || out.includes(file)) continue;
    out.push(file);
  }
  return out;
}

/**
 * The row count the document claims for itself, read out of §13's totals table
 * rather than trusted from prose. Returned as `null` if the table cannot be
 * found, which is itself reported rather than silently treated as agreement.
 */
function claimedTotal(text) {
  const m = /^\|\s*\*\*Total\*\*\s*\|\s*\*\*(\d+)\*\*/m.exec(text);
  return m === null ? null : Number(m[1]);
}

function parseInventory() {
  if (!existsSync(INVENTORY)) {
    console.error(`seam-proof: inventory not found at ${INVENTORY}`);
    process.exit(2);
  }
  const text = readFileSync(INVENTORY, "utf8");
  const lines = text.split("\n");
  // Only §7-§12 hold seam rows. §3's findings table and §13's counts use the
  // same ID vocabulary, and counting those was how the totals drifted before.
  const start = lines.findIndex((l) => l.startsWith("## 7. "));
  const end = lines.findIndex((l) => l.startsWith("## 13. "));
  if (start < 0 || end < 0) {
    console.error("seam-proof: could not find the §7…§13 row region in the inventory");
    process.exit(2);
  }

  const rows = [];
  for (const line of lines.slice(start, end)) {
    // Tolerates `| GW-R4 |`, `| **GW-R4** |`, `| ~~GW-C11~~ |` and the lowercase
    // sub-row suffix `CP-C13b`. The old `[A-Z0-9]+` regex dropped all three.
    const m =
      /^\|\s*(?:\*\*|~~)?((?:GW|CP|MCP|AR|TEL|CLI)-[A-Za-z0-9]+)(?:\*\*|~~)?\s*\|(.*)$/.exec(line);
    if (m === null) continue;
    const id = m[1];
    const app = APP_BY_PREFIX[id.split("-")[0]];
    // Cells may contain escaped pipes (`\|\|`); split on unescaped ones only.
    const cells = m[2]
      .split(/(?<!\\)\|/)
      .map((c) => c.trim())
      .filter((c, i, all) => !(i === all.length - 1 && c === ""));
    // Fixed tail: … | Expected RED | Channel | Tier |
    const tier = (cells.at(-1) ?? "").match(/T[123]/)?.[0] ?? "—";
    const channel = cells.at(-2) ?? "";
    const expected = cells.at(-3) ?? "";
    const [run, quality] = channel.split("·").map((c) => c.trim());
    rows.push({
      id,
      app,
      tier,
      run: run === "" ? "?" : run,
      quality: quality ?? "",
      channel,
      files: run === "NONE" ? [] : testFilesFrom(expected),
      expected,
    });
  }
  return { rows, claimed: claimedTotal(text) };
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
    const collect = (d) => {
      out += d;
    };
    child.stdout.on("data", collect);
    child.stderr.on("data", collect);
    child.on("close", (code) => resolve({ code, out }));
  });
}

const argv = process.argv.slice(2);
const flag = (name) => {
  const i = argv.indexOf(name);
  return i === -1 ? undefined : (argv[i + 1] ?? true);
};

const { rows: allRows, claimed } = parseInventory();
const live = allRows.filter((r) => r.run !== "RETIRED");

const wanted = live.filter(
  (r) =>
    (flag("--id") === undefined || r.id === flag("--id")) &&
    (flag("--tier") === undefined || r.tier === flag("--tier")) &&
    (flag("--channel") === undefined ||
      r.run === flag("--channel") ||
      r.quality === flag("--channel")) &&
    (flag("--app") === undefined || r.app === `apps/${flag("--app")}`),
);

if (wanted.length === 0) {
  console.error("seam-proof: no rows matched");
  process.exit(2);
}

/**
 * Resolve up front so a stale inventory path is a loud error, not a silent pass,
 * and decide each row's command here rather than at run time — a row whose gate
 * is chained needs `--config`, and getting that wrong is a false GREEN.
 */
let ungated = 0;
for (const r of wanted) {
  r.plan = [];
  for (const file of r.files) {
    const resolved = resolveFile(r.app, file);
    if (resolved === null) continue;
    // A citation may name a gate in ANOTHER app — a FLEET gate, which is the
    // only place a cross-Worker property can be asserted at all (AR-P9 cites
    // `apps/gateway/test/routes/agent-upstream-fleet-withdrawal.test.ts`).
    // Such a file must be run from ITS OWN app directory: run from the citing
    // app it resolves no vitest project, exits non-zero, and the row reports a
    // RED that is the runner's error and not the seam's. Wave 21 hit exactly
    // that and it is the worst possible failure mode for this tool — a false
    // RED trains readers to ignore it, which is how a real one gets waved
    // through.
    const owner = ownerAppOf(resolved) ?? r.app;
    const rel = path.relative(path.join(ROOT, owner), resolved);
    r.plan.push({ file: rel, app: owner, config: chainedConfigFor(owner, rel) });
  }
  if (r.plan.length === 0 && r.run !== "NONE") ungated += 1;
  // An ESC row whose files resolve to no chained config is mislabelled: the
  // escalated command would silently degrade to the default project.
  r.mislabelled = r.run === "ESC" && r.plan.length > 0 && r.plan.every((p) => p.config === null);
}

/** Rows bucketed by app, in inventory order. */
function groupByApp(rows) {
  const out = {};
  for (const r of rows) {
    if (out[r.app] === undefined) out[r.app] = [];
    out[r.app].push(r);
  }
  return out;
}

/** The app a resolved absolute path belongs to, or `null` if it is outside one. */
function ownerAppOf(resolved) {
  const rel = path.relative(ROOT, resolved);
  const m = /^(apps\/[^/]+)\//.exec(rel);
  return m === null ? null : m[1];
}

/**
 * One vitest invocation per (app, config): a chained run cannot mix configs,
 * and two apps cannot share one working directory.
 */
function commandsFor(row) {
  const byKey = new Map();
  for (const p of row.plan) {
    const key = `${p.app}\u0000${p.config ?? ""}`;
    const bucket = byKey.get(key);
    if (bucket === undefined) byKey.set(key, { app: p.app, config: p.config, files: [p.file] });
    else bucket.files.push(p.file);
  }
  return [...byKey.values()].map(({ app, config, files }) => ({
    app,
    config,
    args: ["vitest", "run", ...(config === null ? [] : ["--config", config]), ...files],
  }));
}

if (flag("--run") === undefined) {
  const byApp = groupByApp(wanted);
  for (const [app, rs] of Object.entries(byApp)) {
    console.log(`  ${app}: ${rs.length} rows`);
    for (const r of rs) {
      const gate =
        r.plan.length === 0
          ? r.run === "NONE"
            ? `NO GATE BY DESIGN (${r.channel})`
            : "NO RESOLVABLE TEST FILE"
          : r.plan
              .map((p) => {
                const where = p.app === r.app ? "" : ` [in ${p.app}]`;
                const conf = p.config === null ? "" : ` [--config ${p.config}]`;
                return `${p.file}${where}${conf}`;
              })
              .join(" ");
      console.log(`    ${r.id} [${r.tier}/${r.channel}] → ${gate}`);
    }
  }

  const retired = allRows.length - live.length;
  const gated = wanted.filter((r) => r.plan.length > 0).length;
  const byDesign = wanted.filter((r) => r.plan.length === 0 && r.run === "NONE").length;
  const filtered = argv.some((a) => ["--id", "--tier", "--app", "--channel"].includes(a));

  console.log("");
  console.log(`  rows CLAIMED by the inventory's §13 total ... ${claimed ?? "UNREADABLE"}`);
  console.log(
    `  rows PARSED out of §7-§12 .................. ${live.length} (+${retired} retired)`,
  );
  console.log(`  rows with a RESOLVABLE gate ................ ${gated}`);
  console.log(`  rows with NO gate BY DESIGN ................ ${byDesign}`);
  console.log(`  rows with NO gate and no reason ............ ${ungated}`);

  let bad = false;
  if (!filtered && claimed !== null && claimed !== live.length) {
    console.log("");
    console.log(`  MISMATCH: §13 claims ${claimed} rows, this parser sees ${live.length}.`);
    console.log("  A scripted pass would silently under-run. Fix the inventory, not this number.");
    bad = true;
  }
  if (ungated > 0) {
    console.log("");
    console.log(`  ${ungated} row(s) name no resolvable test file and give no reason.`);
    console.log("  Each is an unproven mount wearing an inventory row. Point it at its gate,");
    console.log("  or write the gate, or mark the Channel NONE with the category reason.");
    bad = true;
  }
  for (const r of wanted.filter((x) => x.mislabelled)) {
    console.log(`  ${r.id} is marked ESC but none of its gates is under a chained config.`);
    bad = true;
  }
  process.exit(bad ? 1 : 0);
}

// --run: apps in parallel (mutations never cross app boundaries), rows serial
// within an app (two mutations in one tree would interfere).
const byApp = groupByApp(wanted);

const results = await Promise.all(
  Object.entries(byApp).map(async ([app, rs]) => {
    const out = [];
    for (const r of rs) {
      if (r.plan.length === 0) {
        out.push({ id: r.id, status: r.run === "NONE" ? "NO-GATE" : "NO-FILE", ms: 0 });
        continue;
      }
      const started = Date.now();
      let code = 0;
      for (const cmd of commandsFor(r)) {
        // `cmd.app`, not `app`: a cross-app fleet citation runs where it lives.
        const result = await run("bunx", cmd.args, path.join(ROOT, cmd.app));
        if (result.code !== 0) code = result.code;
      }
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
