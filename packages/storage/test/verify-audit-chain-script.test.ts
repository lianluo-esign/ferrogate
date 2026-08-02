/**
 * THE PUBLISHED PROCEDURE, EXECUTED (#684).
 *
 * `docs/audit-tamper-evidence.md` tells a customer to run
 * `bun scripts/verify-audit-chain.mjs` and to act on its EXIT CODE. A procedure
 * that is only described is a procedure nobody has ever run: the script could
 * fail to parse its own arguments, exit 0 on a tampered trail, or have rotted
 * against a rename in this package, and every other test in the tree would stay
 * green. So this spawns the real script, against files on disk, and asserts the
 * contract the documentation makes:
 *
 *     0  verified      1  failed      2  inconclusive      3  usage
 *
 * The trail fixtures are built with this package's own hash function, which is
 * fine here — the algorithm's own correctness is pinned by
 * `audit-chain.test.ts` (including a golden digest computed with node's crypto)
 * and end to end against a real D1 table by
 * `apps/control-plane/test/audit-chain-d1.test.ts`. What is under test HERE is
 * the script: its parsing, its wiring, and its exit codes.
 */
import { spawnSync } from "node:child_process";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { beforeAll, describe, expect, test } from "vitest";
import {
  AUDIT_CHAIN_GENESIS_HASH,
  type AuditChainAnchor,
  auditRowHash,
  storedAuditChainAnchor,
} from "../src/audit-chain.js";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const SCRIPT = path.join(repoRoot, "scripts/verify-audit-chain.mjs");

/** One element of a `GET /admin/v1/audit-events` response. */
interface AdminAuditDocument {
  object: string;
  action: string;
  id: string;
  request_id: string;
  agent_run_id: string | null;
  tenant_id: string | null;
  occurred_at_unix: number;
  audit_json: string;
  chain_key: string;
  seq: number;
  prev_hash: string;
  row_hash: string;
}

let trail: AdminAuditDocument[];
let anchor: AuditChainAnchor;

beforeAll(async () => {
  trail = [];
  let prev = AUDIT_CHAIN_GENESIS_HASH;
  for (let seq = 1; seq <= 3; seq += 1) {
    const audit_json = JSON.stringify({
      object: "control_plane_mutation",
      action: "create",
      resource_id: `pol-${seq}`,
    });
    const row = {
      chain_key: "t-1",
      seq,
      prev_hash: prev,
      id: `evt-${seq}`,
      request_id: `req-${seq}`,
      agent_run_id: null,
      tenant: "t-1" as string | null,
      occurred_at_unix: 1_700_000_000 + seq,
      audit_json,
    };
    const row_hash = await auditRowHash(row);
    trail.push({
      object: "control_plane_mutation",
      action: "create",
      id: row.id,
      request_id: row.request_id,
      agent_run_id: null,
      tenant_id: "t-1",
      occurred_at_unix: row.occurred_at_unix,
      audit_json,
      chain_key: "t-1",
      seq,
      prev_hash: prev,
      row_hash,
    });
    prev = row_hash;
  }
  anchor = {
    chain_key: "t-1",
    first_seq: 1,
    head_seq: 3,
    head_hash: prev,
    row_count: 3,
    anchored_at_unix: 1_700_001_000,
  };
});

interface Run {
  readonly status: number;
  readonly stdout: string;
  readonly stderr: string;
}

/** Write the fixtures into a fresh temp dir and run the script over them. */
function runScript(
  documents: readonly AdminAuditDocument[] | null,
  anchors: readonly AuditChainAnchor[] | null,
  extra: readonly string[] = [],
): Run {
  const dir = mkdtempSync(path.join(tmpdir(), "ferrogate-audit-"));
  const args: string[] = [SCRIPT];
  if (documents !== null) {
    const trailPath = path.join(dir, "trail.json");
    // The admin ENVELOPE, exactly as the API returns it — the script has to
    // accept what the documented `curl` actually produces.
    writeFileSync(trailPath, JSON.stringify({ object: "list", data: documents, total: 3 }));
    args.push("--trail", trailPath);
  }
  if (anchors !== null) {
    const anchorPath = path.join(dir, "anchors.json");
    writeFileSync(anchorPath, JSON.stringify(anchors.map(storedAuditChainAnchor)));
    args.push("--anchors", anchorPath);
  }
  const result = spawnSync("bun", [...args, ...extra], { encoding: "utf8" });
  if (result.error !== undefined) throw result.error;
  return {
    status: result.status ?? -1,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
  };
}

describe("the published verification script", () => {
  test("exits 0 and says VERIFIED for an intact anchored trail", () => {
    const run = runScript(trail, [anchor]);
    expect(run.stdout, run.stderr).toContain("VERIFIED");
    expect(run.status).toBe(0);
  });

  /** The headline case, from the customer's side of the desk. */
  test("exits 1 and names the row when one has been altered", () => {
    const tampered = trail.map((row) =>
      row.seq === 2 ? { ...row, audit_json: '{"object":"control_plane_mutation"}' } : row,
    );
    const run = runScript(tampered, [anchor]);
    expect(run.status).toBe(1);
    expect(run.stdout).toContain("FAILED");
    expect(run.stdout).toContain("row_hash_mismatch");
    expect(run.stdout).toContain("evt-2");
  });

  test("exits 1 when the tail was deleted below the anchor", () => {
    const run = runScript(trail.slice(0, 2), [anchor]);
    expect(run.status).toBe(1);
    expect(run.stdout).toContain("truncated_below_anchor");
  });

  /**
   * INCONCLUSIVE MUST NOT EXIT 0. A CI job that treated "no anchor" as a pass
   * would report a healthy trail for a deployment with no tamper-evidence at
   * all, which is the failure mode this whole feature exists to prevent.
   */
  test("exits 2 for an intact but unanchored trail", () => {
    const run = runScript(trail, null);
    expect(run.status).toBe(2);
    expect(run.stdout).toContain("INCONCLUSIVE");
    expect(run.stdout).toContain("no anchor pins the head");
  });

  test("exits 2 for an empty trail, and says why it is not a pass", () => {
    const run = runScript([], null);
    expect(run.status).toBe(2);
    expect(run.stdout).toContain("NOT a clean bill of health");
  });

  test("exits 1 for an empty trail that has an anchor claiming rows", () => {
    // Same empty input as above, opposite verdict — the distinction the anchor
    // is there to make.
    const run = runScript([], [anchor]);
    expect(run.status).toBe(1);
    expect(run.stdout).toContain("truncated_below_anchor");
  });

  test("emits a machine-readable report under --json", () => {
    const run = runScript(trail, [anchor], ["--json"]);
    const report = JSON.parse(run.stdout) as { status: string; chains: { chainKey: string }[] };
    expect(report.status).toBe("verified");
    expect(report.chains).toHaveLength(1);
    expect(report.chains[0]?.chainKey).toBe("t-1");
  });

  test("exits 3 rather than 0 when it was given nothing to verify", () => {
    // A typo in a cron job must not read as "the audit trail is fine".
    const run = runScript(null, null);
    expect(run.status).toBe(3);
    expect(run.stderr).toContain("no --trail given");
  });

  test("exits 3 on a file that is not an audit-events export", () => {
    const dir = mkdtempSync(path.join(tmpdir(), "ferrogate-audit-"));
    const bogus = path.join(dir, "bogus.json");
    writeFileSync(bogus, JSON.stringify({ hello: "world" }));
    const result = spawnSync("bun", [SCRIPT, "--trail", bogus], { encoding: "utf8" });
    expect(result.status).toBe(3);
    expect(result.stderr).toContain("neither an audit-events response nor an array");
  });
});
