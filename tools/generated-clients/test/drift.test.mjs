/**
 * The root-reachable gate over every generated client (#766).
 *
 * This suite exists because the previous gates were placed by artifact owners
 * rather than by reachability: `sdks/typescript` guarded itself inside a Bun
 * workspace, so root `bun run test` ran it; `admin-console` guarded itself just
 * as carefully but is NOT a Bun workspace, so root `bun run test` never reached
 * it and it went stale twice without a single report (#736, #737) — including
 * on the full run that caught its sibling. A guard nothing runs is not a guard.
 *
 * So the ownership is inverted here: this package is a workspace purely so the
 * root suite reaches it, and it checks artifacts that live elsewhere.
 *
 * Three things are asserted, and the middle one is the point:
 *   1. every artifact in the manifest matches the contract (the gate itself);
 *   2. every generated client in the TREE is in the manifest (so a third client
 *      cannot repeat the asymmetry by simply not being registered);
 *   3. the comparison actually detects a difference (so the gate cannot pass
 *      vacuously), and one command regenerates all of it.
 */
import { execFileSync, spawnSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { describe, expect, it } from "vitest";
import {
  ARTIFACTS,
  BANNER,
  GENERATE_COMMAND,
  REPO_ROOT,
  checkArtifact,
  render,
  writeArtifact,
} from "../artifacts.mjs";

/** Tracked files whose FIRST line is the generated-client banner. */
function discoverGeneratedClients() {
  // `git grep -l` over tracked files finds the banner wherever it appears —
  // including inside the scripts that WRITE it — so the first-line filter is
  // what separates an artifact from the machinery. Discovery is deliberately
  // not "files named *.generated.ts": the next generated client may be named
  // anything, and the failure mode being guarded is precisely "nobody
  // remembered to register it".
  const marker = "// GENERATED FILE — DO NOT EDIT.";
  const listed = execFileSync("git", ["grep", "-l", "--fixed-strings", marker, "--", "."], {
    cwd: REPO_ROOT,
    encoding: "utf8",
  })
    .split("\n")
    .filter(Boolean);

  return listed.filter((relative) => {
    const first = readFileSync(path.join(REPO_ROOT, relative), "utf8").split("\n", 1)[0];
    return first === marker;
  });
}

describe("generated clients", () => {
  it("allows enough time to render the complete contract", ({ task }) => {
    expect(task.timeout).toBe(30_000);
  });

  it.each(ARTIFACTS.map((artifact) => [artifact.slug, artifact]))(
    "%s is in sync with its contract",
    (_slug, artifact) => {
      const result = checkArtifact(artifact);
      expect(result.ok, result.reason).toBe(true);
    },
  );

  it("registers every generated client that exists in the tree", () => {
    const registered = new Set(ARTIFACTS.map((artifact) => artifact.output));
    const unregistered = discoverGeneratedClients().filter((file) => !registered.has(file));

    expect(
      unregistered,
      `these generated clients are not in tools/generated-clients/artifacts.mjs, so NOTHING reachable from root \`bun run test\` checks them and nothing regenerates them with \`${GENERATE_COMMAND}\`:\n${unregistered.map((f) => `  ${f}`).join("\n")}`,
    ).toEqual([]);
  });

  it("detects a client that drifted from the contract", () => {
    // Anti-vacuity. The gate above is green on a healthy tree by construction,
    // so on its own it cannot distinguish "comparison works" from "comparison
    // was neutered". Here a KNOWN-bad copy is fed through the same
    // checkArtifact() and must come back not-ok: a single deleted line — the
    // shape a forgotten regeneration actually takes — is enough.
    const scratch = mkdtempSync(path.join(tmpdir(), "ferrogate-drift-selftest-"));
    try {
      const [artifact] = ARTIFACTS;
      const tampered = path.join(scratch, "tampered.generated.ts");
      const lines = render(artifact).split("\n");
      const cut = Math.floor(lines.length / 2);
      writeFileSync(tampered, [...lines.slice(0, cut), ...lines.slice(cut + 1)].join("\n"));

      const verdict = checkArtifact({
        slug: "self-test",
        spec: artifact.spec,
        output: path.relative(REPO_ROOT, tampered),
      });

      expect(verdict.ok).toBe(false);
      expect(verdict.reason).toContain("STALE");
      expect(verdict.reason).toContain(GENERATE_COMMAND);
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });

  it("reports a client that was never generated at all", () => {
    const verdict = checkArtifact({
      slug: "self-test",
      spec: ARTIFACTS[0].spec,
      output: "tools/generated-clients/does-not-exist.generated.ts",
    });
    expect(verdict.ok).toBe(false);
    expect(verdict.reason).toContain("missing");
  });

  it("generates exactly the bytes the gate demands", () => {
    // Ties the writer to the checker: `bun run generate` on a clean tree must
    // be a no-op, or the gate would demand something the generator never
    // produces and every contract change would need a hand edit.
    const scratch = mkdtempSync(path.join(tmpdir(), "ferrogate-generate-selftest-"));
    try {
      const [artifact] = ARTIFACTS;
      const out = path.join(scratch, "written.generated.ts");
      const written = writeArtifact({
        slug: "self-test",
        spec: artifact.spec,
        output: path.relative(REPO_ROOT, out),
      });

      expect(written.changed).toBe(true);
      expect(readFileSync(out, "utf8")).toBe(
        readFileSync(path.join(REPO_ROOT, artifact.output), "utf8"),
      );
      // Second write is a no-op — this is what makes "run generate, commit
      // nothing" a meaningful clean-tree signal.
      expect(
        writeArtifact({
          slug: "self-test",
          spec: artifact.spec,
          output: path.relative(REPO_ROOT, out),
        }).changed,
      ).toBe(false);
    } finally {
      rmSync(scratch, { recursive: true, force: true });
    }
  });

  it("banners every artifact with the one root regeneration command", () => {
    for (const artifact of ARTIFACTS) {
      const committed = readFileSync(path.join(REPO_ROOT, artifact.output), "utf8");
      expect(
        committed.startsWith(BANNER),
        `${artifact.output} does not carry the shared banner`,
      ).toBe(true);
    }
    expect(BANNER).toContain(GENERATE_COMMAND);
  });
});

/** `git check-ignore` as a predicate: true when the path is not (and cannot be) committed. */
function isGitIgnored(absolutePath) {
  const result = spawnSync("git", ["check-ignore", "-q", absolutePath], { cwd: REPO_ROOT });
  return result.status === 0;
}

describe("generation is one command", () => {
  /** Every tracked package.json, as [relative path, parsed]. */
  function trackedPackageJson() {
    return execFileSync(
      "git",
      ["ls-files", "--", "package.json", "*/package.json", "*/*/package.json"],
      {
        cwd: REPO_ROOT,
        encoding: "utf8",
      },
    )
      .split("\n")
      .filter(Boolean)
      .map((relative) => [
        relative,
        JSON.parse(readFileSync(path.join(REPO_ROOT, relative), "utf8")),
      ]);
  }

  it("regenerates every client from the repo root", () => {
    const root = JSON.parse(readFileSync(path.join(REPO_ROOT, "package.json"), "utf8"));
    expect(root.scripts?.generate, "root package.json needs a `generate` script").toBeDefined();
    expect(root.scripts.generate).toContain("tools/generated-clients/generate.mjs");
    // No `--only`: the root command is the one that covers everything, which is
    // the whole point of the issue. A filtered root script would recreate the
    // "I ran the one I knew about" failure.
    expect(root.scripts.generate).not.toContain("--only");
  });

  it("leaves no package running the generator behind the manifest's back", () => {
    // The divergence guard. Two private pipelines are what allowed the two
    // artifacts to be regenerated independently — and therefore for one to be
    // regenerated and the other forgotten. Any npm script that invokes
    // openapi-typescript directly is a third pipeline in the making.
    //
    // Exempt: a script whose `-o` output is git-ignored. Such a script cannot
    // go stale, because nothing of it is committed — `tools/openapi-client-smoke`
    // regenerates into a scratch file and type-checks it on every run. The rule
    // is derived rather than allow-listed so a new scratch generator needs no
    // edit here, and a new COMMITTED one still fails.
    const offenders = [];
    for (const [file, pkg] of trackedPackageJson()) {
      for (const [name, command] of Object.entries(pkg.scripts ?? {})) {
        if (typeof command !== "string" || !command.includes("openapi-typescript")) continue;
        const output = /-o\s+(\S+)/.exec(command)?.[1];
        if (output && isGitIgnored(path.join(REPO_ROOT, path.dirname(file), output))) continue;
        offenders.push(`${file} -> ${name}: ${command}`);
      }
    }
    expect(
      offenders,
      `these scripts invoke the generator directly instead of tools/generated-clients/generate.mjs:\n${offenders.map((o) => `  ${o}`).join("\n")}`,
    ).toEqual([]);
  });

  it("agrees on one generator version across every package that installs it", () => {
    // checkArtifact() resolves ONE openapi-typescript install and uses it for
    // every artifact, so two packages pinning different versions would make the
    // gate's verdict depend on which install it happened to find.
    const pins = new Map();
    for (const [file, pkg] of trackedPackageJson()) {
      const pin =
        pkg.devDependencies?.["openapi-typescript"] ?? pkg.dependencies?.["openapi-typescript"];
      if (pin) pins.set(file, pin);
    }
    expect(pins.size, "no package installs openapi-typescript any more").toBeGreaterThan(0);
    expect(
      new Set(pins.values()).size,
      `conflicting pins: ${JSON.stringify(Object.fromEntries(pins))}`,
    ).toBe(1);
  });

  it("passes its own standalone CLI on a clean tree", () => {
    // `npm run check:api-types` (admin-console CI, scripts/check-admin-console.sh)
    // goes through check.mjs rather than Vitest; prove that path too.
    const cli = path.join(REPO_ROOT, "tools", "generated-clients", "check.mjs");
    expect(existsSync(cli)).toBe(true);
    execFileSync(process.execPath, [cli], {
      cwd: REPO_ROOT,
      stdio: ["ignore", "ignore", "inherit"],
    });
  });
});
