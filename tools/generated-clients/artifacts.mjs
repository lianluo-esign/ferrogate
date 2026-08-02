// The single declaration of every client that is GENERATED from the committed
// OpenAPI contract, plus the two primitives that act on it: write it, or
// compare it. #766.
//
// WHY THIS EXISTS AT THE ROOT. Before this file each generated client carried
// its own private copy of the pipeline — its own generator invocation, its own
// banner literal, its own drift guard — so "regenerate the clients" was two
// different commands in two different directories, one of which
// (`admin-console`) is not a Bun workspace and therefore invisible to the root
// `bun run test`. Three contract changes in one day (#676, #736, #737) shipped
// with a stale client, and `admin-console` was stale twice without anyone
// reporting it, including on the full run that caught its sibling. A step that
// is trivial, mandatory and unprompted gets skipped; the fix is to make one
// command regenerate everything and one root-reachable gate see everything.
//
// WHY THE CHECK NEVER WRITES. It would be easy to have the drift gate simply
// regenerate the file it is checking. That is deliberately NOT done: a check
// that rewrites the artifact makes the contract change invisible in review —
// the generated client would silently agree with whatever the document said,
// and nobody would ever see in a diff that an operation appeared. Generation is
// an explicit, reviewable act (`bun run generate`); the gate only ever
// compares, and it compares into a throwaway temp directory.
import { execFileSync } from "node:child_process";
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

/** Absolute path of the repository root (this file lives at tools/generated-clients/). */
export const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");

/** The one command that regenerates every artifact below. Quoted in the banner and in every failure message. */
export const GENERATE_COMMAND = "bun run generate";

/**
 * Prepended to every generated client, because openapi-typescript has no
 * banner option. It is part of the compared bytes, so a change here is a change
 * to every artifact and must be committed together with the regenerated files.
 *
 * It names the ROOT command on purpose: the reader of a stale file is usually
 * not the owner of the package it lives in.
 */
export const BANNER = `// GENERATED FILE — DO NOT EDIT.
// Source contract: docs/openapi/admin-api.openapi.json (repo root).
// Regenerate with: ${GENERATE_COMMAND}   (from the repo root).
`;

/**
 * Every generated client, keyed by a stable slug that `--only <slug>` accepts.
 *
 * `spec` and `output` are repo-root-relative POSIX paths so this table reads as
 * documentation. Adding a row here is all that is required to put a new
 * generated client under both the root generator and the root drift gate —
 * and `test/drift.test.mjs` fails if a generated client exists that has no row.
 */
export const ARTIFACTS = [
  {
    slug: "sdks/typescript",
    spec: "docs/openapi/admin-api.openapi.json",
    output: "sdks/typescript/src/api-types.generated.ts",
  },
];

/** @param {string} slug */
export function artifactBySlug(slug) {
  const found = ARTIFACTS.find((a) => a.slug === slug);
  if (!found) {
    throw new Error(
      `unknown generated client "${slug}"; known slugs: ${ARTIFACTS.map((a) => a.slug).join(", ")}`,
    );
  }
  return found;
}

/**
 * Locate the openapi-typescript CLI.
 *
 * Two installs can supply it and both are legitimate entry points: the root
 * Bun workspace install (`bun install`, which hoists it out of
 * sdks/typescript), and admin-console's own npm install — admin-console is not
 * a Bun workspace, and its CI job installs only its own dependencies. Trying
 * both means the same code backs `bun run generate` at the root and
 * `npm run check:api-types` inside admin-console.
 */
function resolveGeneratorCli() {
  const candidates = [
    path.join(REPO_ROOT, "node_modules", "openapi-typescript", "bin", "cli.js"),
    path.join(REPO_ROOT, "admin-console", "node_modules", "openapi-typescript", "bin", "cli.js"),
  ];
  const found = candidates.find((candidate) => existsSync(candidate));
  if (!found) {
    throw new Error(
      "openapi-typescript is not installed; looked in:\n" +
        candidates.map((c) => `  ${c}`).join("\n") +
        "\nRun `bun install` at the repo root (or `npm ci` in admin-console/).",
    );
  }
  return found;
}

/**
 * Generation is deterministic and every artifact currently shares one spec, so
 * the expensive part (spawning the generator) is memoised per spec. A full
 * check of N clients spawns the generator once, not N times.
 *
 * @type {Map<string, string>}
 */
const renderedBySpec = new Map();

/**
 * Produce the exact bytes the committed artifact must contain: run
 * openapi-typescript into a THROWAWAY temp file, then prepend the banner.
 * Never touches the committed file — see the header note.
 *
 * @param {{ spec: string }} artifact
 * @returns {string}
 */
export function render(artifact) {
  const cached = renderedBySpec.get(artifact.spec);
  if (cached !== undefined) return cached;

  const scratch = mkdtempSync(path.join(tmpdir(), "ferrogate-generated-clients-"));
  try {
    const tempOut = path.join(scratch, "api-types.generated.ts");
    // `process.execPath` is `bun` under the root suite and `node` under
    // admin-console's npm scripts. The CLI is plain JS and both runtimes
    // produce byte-identical output, so the gate cannot flap on who ran it.
    execFileSync(process.execPath, [resolveGeneratorCli(), path.join(REPO_ROOT, artifact.spec), "-o", tempOut], {
      cwd: REPO_ROOT,
      stdio: ["ignore", "ignore", "inherit"],
    });
    const text = BANNER + readFileSync(tempOut, "utf8");
    renderedBySpec.set(artifact.spec, text);
    return text;
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

/**
 * Compare a committed artifact against the contract. Pure: returns a verdict,
 * writes nothing, throws nothing for the ordinary "it is stale" case.
 *
 * @param {{ slug: string, spec: string, output: string }} artifact
 * @returns {{ slug: string, ok: boolean, reason: string }}
 */
export function checkArtifact(artifact) {
  const outputPath = path.join(REPO_ROOT, artifact.output);
  const expected = render(artifact);

  if (!existsSync(outputPath)) {
    return {
      slug: artifact.slug,
      ok: false,
      reason:
        `${artifact.output} is missing — the contract ${artifact.spec} describes a client ` +
        `that has never been generated.\nFix: run \`${GENERATE_COMMAND}\` at the repo root and commit the result.`,
    };
  }

  const committed = readFileSync(outputPath, "utf8");
  if (committed === expected) {
    return { slug: artifact.slug, ok: true, reason: `${artifact.output} is in sync with ${artifact.spec}` };
  }

  return {
    slug: artifact.slug,
    ok: false,
    reason:
      `${artifact.output} is STALE vs ${artifact.spec}.\n` +
      "The committed client no longer describes the contract, and stale types still compile, " +
      "so nothing downstream will notice.\n" +
      `Fix: run \`${GENERATE_COMMAND}\` at the repo root and commit the regenerated file ` +
      "(the diff is meant to be visible in review — it is how a reviewer sees the operation appear).",
  };
}

/**
 * Write the artifact. The only function in this file that touches a committed
 * path, and it is reachable only from `generate.mjs` — never from a check.
 *
 * @param {{ slug: string, spec: string, output: string }} artifact
 * @returns {{ slug: string, output: string, changed: boolean }}
 */
export function writeArtifact(artifact) {
  const outputPath = path.join(REPO_ROOT, artifact.output);
  const expected = render(artifact);
  const before = existsSync(outputPath) ? readFileSync(outputPath, "utf8") : null;
  if (before === expected) {
    return { slug: artifact.slug, output: artifact.output, changed: false };
  }
  writeFileSync(outputPath, expected);
  return { slug: artifact.slug, output: artifact.output, changed: true };
}

/**
 * Shared `--only <slug>` parsing for both CLIs, so `generate` and `check` can
 * never disagree about which artifacts exist.
 *
 * @param {string[]} argv
 */
export function selectArtifacts(argv) {
  const selected = [];
  for (let i = 0; i < argv.length; i += 1) {
    if (argv[i] === "--only") {
      const slug = argv[i + 1];
      if (!slug) throw new Error("--only requires a slug");
      selected.push(artifactBySlug(slug));
      i += 1;
      continue;
    }
    throw new Error(`unexpected argument "${argv[i]}"; usage: [--only <slug>]...`);
  }
  return selected.length > 0 ? selected : ARTIFACTS;
}
