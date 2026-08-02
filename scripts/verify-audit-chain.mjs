#!/usr/bin/env bun
/**
 * VERIFY A FERROGATE AUDIT TRAIL (#684) — the procedure a customer runs
 * themselves.
 *
 * Usage:
 *
 *     bun scripts/verify-audit-chain.mjs --trail trail.json [--anchors anchors.json]...
 *
 *   --trail    <file>   a `GET /admin/v1/audit-events` response, or a bare
 *                       array of its `data` elements. Repeatable, so a paged
 *                       export can be passed as several files.
 *   --anchors  <file>   an anchor object from the R2 bucket, or an array of
 *                       them. Repeatable. WITHOUT AT LEAST ONE ANCHOR THE
 *                       RESULT IS INCONCLUSIVE, by design.
 *   --json              machine-readable report on stdout.
 *
 * Exit codes, which are the point of running this from a job rather than by
 * eye:
 *
 *     0  VERIFIED      every row hashes as stored, links to its predecessor,
 *                      and the anchored head is present and matches.
 *     1  FAILED        a provable alteration. Read the failures.
 *     2  INCONCLUSIVE  nothing wrong found, but the evidence does not support a
 *                      clean verdict — an empty chain, an unanchored one, or
 *                      rows outside the chain. NOT a pass.
 *     3  usage / unreadable input.
 *
 * ## Why this script imports FerroGate's own code
 *
 * It calls the SAME `verifyAuditTrail` the gateway's tests use, so the
 * published procedure cannot drift from the implemented algorithm — the day a
 * second, doc-only copy diverged, this would start reporting healthy chains as
 * broken (or, worse, the reverse). If you would rather not run vendor code to
 * audit the vendor, `docs/audit-tamper-evidence.md` specifies the digest
 * preimage byte-for-byte, with a `sha256sum` one-liner you can reproduce in any
 * language. That is the point of publishing the format rather than a binary.
 */
import { readFileSync } from "node:fs";
import {
  auditChainRowFromAdminDocument,
  parseAuditChainAnchor,
  verifyAuditTrail,
} from "@ferrogate/storage";

const USAGE =
  "usage: bun scripts/verify-audit-chain.mjs --trail <file> [--trail <file>]... " +
  "[--anchors <file>]... [--json]";

/** Exit codes, named so the calls below read as intent rather than as numbers. */
const EXIT = { verified: 0, failed: 1, inconclusive: 2, usage: 3 };

function parseArgs(argv) {
  const trails = [];
  const anchors = [];
  let json = false;
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === "--json") {
      json = true;
    } else if (arg === "--help" || arg === "-h") {
      process.stdout.write(`${USAGE}\n`);
      process.exit(EXIT.verified);
    } else if (arg === "--trail" || arg === "--anchors" || arg === "--anchor") {
      const value = argv[i + 1];
      if (value === undefined) fail(`${arg} needs a file path`);
      (arg === "--trail" ? trails : anchors).push(value);
      i += 1;
    } else {
      fail(`unrecognised argument "${arg}"`);
    }
  }
  if (trails.length === 0) fail("no --trail given");
  return { trails, anchors, json };
}

function fail(message) {
  process.stderr.write(`verify-audit-chain: ${message}\n${USAGE}\n`);
  process.exit(EXIT.usage);
}

function readJson(path) {
  try {
    return JSON.parse(readFileSync(path, "utf8"));
  } catch (error) {
    fail(`cannot read ${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

/** Accept the admin envelope, a bare array, or a single document. */
function trailRows(parsed, path) {
  const data = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.data) ? parsed.data : null;
  if (data === null) fail(`${path} is neither an audit-events response nor an array of rows`);
  try {
    return data.map(auditChainRowFromAdminDocument);
  } catch (error) {
    fail(`${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

function anchorList(parsed, path) {
  const items = Array.isArray(parsed) ? parsed : [parsed];
  try {
    return items.map(parseAuditChainAnchor);
  } catch (error) {
    fail(`${path}: ${error instanceof Error ? error.message : String(error)}`);
  }
}

const options = parseArgs(process.argv.slice(2));
const rows = options.trails.flatMap((path) => trailRows(readJson(path), path));
const anchors = options.anchors.flatMap((path) => anchorList(readJson(path), path));

const report = await verifyAuditTrail(rows, anchors);

if (options.json) {
  process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
} else {
  process.stdout.write(
    `audit trail: ${rows.length} row(s), ${anchors.length} anchor(s), ` +
      `${report.chains.length} chain(s)\n`,
  );
  for (const chain of report.chains) {
    process.stdout.write(`  ${chain.summary}\n`);
    for (const failure of chain.failures) {
      process.stdout.write(
        `    - ${failure.code}${failure.id === null ? "" : ` [${failure.id}]`}: ${failure.detail}\n`,
      );
    }
  }
  process.stdout.write(`${report.status.toUpperCase()}\n`);
}

process.exit(EXIT[report.status]);
