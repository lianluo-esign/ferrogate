#!/usr/bin/env node
/**
 * Re-fetch and freshness-check the VENDORED MCP specification schema (#686).
 *
 * ## Why the schema is vendored at all
 *
 * `test/spec-2026-07-28.test.ts` pins four changelog clauses as PROSE in its
 * docstrings. That is a snapshot of one reader's understanding on one day: it
 * cannot notice that the specification moved, and the next person to read it
 * cannot tell "the spec says this" from "someone believed the spec said this".
 * `test/spec-2026-07-28-schema.test.ts` closes that by validating REAL Worker
 * responses against the machine-readable artifact the MCP project publishes,
 * committed here verbatim.
 *
 * The offline Worker suite may not reach the network (`docs/rewrite/TESTING.md`
 * — every suite in this tree is hermetic and docker-free), so the artifact has
 * to be committed rather than downloaded per run. A committed copy nobody can
 * tell is out of date is a hand-transcription with extra steps, so staleness is
 * made detectable in TWO independent directions:
 *
 *  1. **Local drift — caught offline, on every test run.** `PROVENANCE.json`
 *     records the SHA-256 of the vendored bytes and
 *     `test/spec-2026-07-28-schema.test.ts` recomputes it over the file it
 *     actually validates against. Editing `schema.json` to make a failing
 *     assertion pass — the way vendored artifacts usually die — turns that
 *     test red, and the recorded digest is what the fix has to be argued
 *     against.
 *  2. **Upstream drift — caught by running this script.** `--check` makes ONE
 *     unauthenticated GitHub API call and compares the recorded git BLOB sha
 *     against the blob currently at that path on `main`. A git blob sha is the
 *     content address of the file, so any upstream edit changes it, and it can
 *     be compared without downloading 181 KB. Exit 1 on drift, naming the new
 *     blob and the commit that produced it.
 *
 * The second check is deliberately NOT wired into `bun run test`: a network
 * call inside a hermetic unit suite is a flake generator, and an upstream edit
 * is a decision for a human (adopt the new bytes, re-run the conformance
 * suite, and see what actually changed) rather than an automatic red build on a
 * tree nobody touched. It is a script rather than a docblock so that the check
 * is one command, and so a CI job can pick it up later without re-deriving how.
 *
 * ## Usage
 *
 *   bun apps/mcp/spec/refresh.mjs --check   # exit 1 if upstream moved
 *   bun apps/mcp/spec/refresh.mjs --write   # re-vendor + rewrite PROVENANCE
 *
 * `--write` never edits the schema; it replaces it wholesale with the upstream
 * bytes and recomputes every digest from what it just wrote.
 */
import { createHash } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

/** The revision this tree serves. One directory per revision if that changes. */
const REVISION = "2026-07-28";

const SCHEMA_PATH = `schema/${REVISION}/schema.json`;
const REPO = "modelcontextprotocol/modelcontextprotocol";
const RAW_URL = `https://raw.githubusercontent.com/${REPO}/main/${SCHEMA_PATH}`;
const CONTENTS_API = `https://api.github.com/repos/${REPO}/contents/${SCHEMA_PATH}`;
const COMMITS_API = `https://api.github.com/repos/${REPO}/commits?path=${SCHEMA_PATH}&per_page=1`;

const schemaFile = fileURLToPath(new URL(`./${REVISION}/schema.json`, import.meta.url));
const provenanceFile = fileURLToPath(new URL(`./${REVISION}/PROVENANCE.json`, import.meta.url));

/** GitHub rejects unauthenticated API calls that send no User-Agent. */
const API_HEADERS = {
  accept: "application/vnd.github+json",
  "user-agent": "ferrogate-mcp-spec-refresh",
};

function sha256(bytes) {
  return createHash("sha256").update(bytes).digest("hex");
}

/**
 * Git's own content address for a blob: `sha1("blob <len>\0" + bytes)`.
 *
 * Recomputed locally rather than trusted from the API response so that
 * `--check` compares the bytes ON DISK against upstream. Taking the recorded
 * value at face value would let a hand-edited local copy pass the freshness
 * check — exactly the failure this file exists to make impossible.
 */
function gitBlobSha(bytes) {
  const header = Buffer.from(`blob ${bytes.length}\0`, "utf8");
  return createHash("sha1")
    .update(Buffer.concat([header, bytes]))
    .digest("hex");
}

async function fetchJson(url) {
  const res = await fetch(url, { headers: API_HEADERS });
  if (!res.ok) throw new Error(`GET ${url} -> HTTP ${res.status}`);
  return res.json();
}

async function upstreamState() {
  const [contents, commits] = await Promise.all([fetchJson(CONTENTS_API), fetchJson(COMMITS_API)]);
  return {
    gitBlobSha: contents.sha,
    bytes: contents.size,
    upstreamCommit: commits[0]?.sha,
    upstreamCommitDate: commits[0]?.commit?.committer?.date,
  };
}

async function check() {
  const local = readFileSync(schemaFile);
  const localBlob = gitBlobSha(local);
  const upstream = await upstreamState();
  if (localBlob === upstream.gitBlobSha) {
    console.log(`fresh: ${SCHEMA_PATH} blob ${localBlob} (${local.length} bytes)`);
    return 0;
  }
  console.error(
    [
      `STALE: the vendored ${REVISION} schema no longer matches upstream.`,
      `  vendored blob : ${localBlob} (${local.length} bytes)`,
      `  upstream blob : ${upstream.gitBlobSha} (${upstream.bytes} bytes)`,
      `  upstream commit: ${upstream.upstreamCommit} (${upstream.upstreamCommitDate})`,
      "",
      "Re-vendor with `bun apps/mcp/spec/refresh.mjs --write`, then run",
      "`bunx vitest run test/spec-2026-07-28-schema.test.ts` in apps/mcp and read",
      "what changed. A schema edit is a specification change, not a test failure.",
    ].join("\n"),
  );
  return 1;
}

async function write() {
  const res = await fetch(RAW_URL);
  if (!res.ok) throw new Error(`GET ${RAW_URL} -> HTTP ${res.status}`);
  const bytes = Buffer.from(await res.arrayBuffer());
  writeFileSync(schemaFile, bytes);
  const upstream = await upstreamState();
  const provenance = {
    _comment:
      "Provenance for the vendored MCP schema. Generated by apps/mcp/spec/refresh.mjs — do not hand-edit; re-run the script.",
    revision: REVISION,
    repository: `https://github.com/${REPO}`,
    path: SCHEMA_PATH,
    rawUrl: RAW_URL,
    upstreamCommit: upstream.upstreamCommit,
    upstreamCommitDate: upstream.upstreamCommitDate,
    gitBlobSha: gitBlobSha(bytes),
    sha256: sha256(bytes),
    bytes: bytes.length,
    fetchedAt: new Date().toISOString().slice(0, 10),
  };
  writeFileSync(provenanceFile, `${JSON.stringify(provenance, null, 2)}\n`);
  console.log(`wrote ${bytes.length} bytes; sha256 ${provenance.sha256}`);
  return 0;
}

const mode = process.argv[2];
if (mode !== "--check" && mode !== "--write") {
  console.error("usage: refresh.mjs --check | --write");
  process.exit(2);
}
process.exit(await (mode === "--check" ? check() : write()));
