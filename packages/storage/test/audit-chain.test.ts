/**
 * The tamper-evidence algorithm for `audit_events` (#684) — the ADVERSARIAL
 * suite.
 *
 * A hash chain nobody verifies is decoration, so almost every case below is
 * written from the attacker's side: take a well-formed trail, do the thing an
 * insider with write access to the control database would do (edit a row,
 * delete the tail, delete a row from the middle, re-order, re-forge the whole
 * chain), and assert that verification SAYS SO.
 *
 * ## The three verdicts, and why "inconclusive" exists
 *
 * The boring-but-fatal case an integrity check usually gets wrong is the empty
 * chain. "There are no rows" and "someone deleted every row" produce identical
 * bytes, so a verifier that answers PASS for an empty trail hands an attacker a
 * clean bill of health for a total wipe. This one answers three ways —
 * `verified`, `failed`, `inconclusive` — and an empty UNANCHORED chain is
 * `inconclusive`, while an empty chain that has an anchor claiming rows is
 * `failed`. The anchor is what turns "I saw nothing" into "something is
 * missing", which is exactly what the anchor is for.
 */
import { describe, expect, test } from "vitest";
import {
  AUDIT_CHAIN_GENESIS_HASH,
  type AuditChainAnchor,
  type AuditChainRow,
  auditChainKey,
  auditRowHash,
  verifyAuditChain,
  verifyAuditTrail,
} from "../src/audit-chain.js";

/** The row body the control-plane writer stores in `audit_json`. */
function auditJson(action: string, resource: string): string {
  return JSON.stringify({
    object: "control_plane_mutation",
    action,
    collection: "policies",
    resource_id: resource,
  });
}

/**
 * Build a valid chain the way the writer does: each row's `prev_hash` is its
 * predecessor's `row_hash`, and the first row's is the genesis constant.
 *
 * This uses the module's own hash function, which on its own would let a
 * degenerate hash (one that ignored its input) pass. That hole is closed by
 * the "preimage" describe block below, which pins a GOLDEN digest computed
 * independently from the documented preimage.
 */
async function buildChain(
  chainKey: string,
  count: number,
  tenant: string | null = chainKey === "" ? null : chainKey,
): Promise<AuditChainRow[]> {
  const rows: AuditChainRow[] = [];
  let prev = AUDIT_CHAIN_GENESIS_HASH;
  for (let i = 1; i <= count; i += 1) {
    const base = {
      id: `evt-${chainKey}-${i}`,
      request_id: `req-${i}`,
      agent_run_id: null,
      tenant,
      occurred_at_unix: 1_700_000_000 + i,
      audit_json: auditJson("create", `pol-${i}`),
      chain_key: chainKey,
      seq: i,
      prev_hash: prev,
    };
    const hash = await auditRowHash(base);
    rows.push({ ...base, row_hash: hash });
    prev = hash;
  }
  return rows;
}

/** The anchor a scheduled tick would have written for `rows`. */
function anchorFor(rows: readonly AuditChainRow[], chainKey: string): AuditChainAnchor {
  const head = rows[rows.length - 1] as AuditChainRow;
  return {
    chain_key: chainKey,
    first_seq: (rows[0] as AuditChainRow).seq as number,
    head_seq: head.seq as number,
    head_hash: head.row_hash as string,
    row_count: rows.length,
    anchored_at_unix: 1_700_001_000,
  };
}

// ---------------------------------------------------------------------------
// The preimage — the half a customer has to be able to reimplement
// ---------------------------------------------------------------------------

describe("the row preimage", () => {
  /**
   * GOLDEN VECTOR. Computed independently of `src/audit-chain.ts` — with
   * node's `crypto`, not this module — from the preimage documented in
   * `docs/audit-tamper-evidence.md`:
   *
   *   printf 'ferrogate.audit.v1\n7:chain-a\n1:1\n64:0000000000000000000000000000000000000000000000000000000000000000\n5:evt-1\n5:req-1\n-\n7:chain-a\n10:1700000001\n2:{}\n' | sha256sum
   *
   * Its job is to FREEZE the wire format. Change the field order, the
   * separator, the length prefix or the null marker and this goes red — which
   * is what stops the published procedure from quietly describing an algorithm
   * the code no longer implements.
   */
  test("matches the published golden digest", async () => {
    const hash = await auditRowHash({
      chain_key: "chain-a",
      seq: 1,
      prev_hash: AUDIT_CHAIN_GENESIS_HASH,
      id: "evt-1",
      request_id: "req-1",
      agent_run_id: null,
      tenant: "chain-a",
      occurred_at_unix: 1_700_000_001,
      audit_json: "{}",
    });
    expect(hash).toBe("62b04cd99f0869a73b2da2366f27a8343c8eedd345cc66be2bdb043b7aa25091");
  });

  test("commits to every field", async () => {
    const base = {
      chain_key: "c",
      seq: 4,
      prev_hash: AUDIT_CHAIN_GENESIS_HASH,
      id: "evt",
      request_id: "req",
      agent_run_id: "run",
      tenant: "t-1",
      occurred_at_unix: 10,
      audit_json: "{}",
    };
    const original = await auditRowHash(base);
    const mutations = [
      { ...base, chain_key: "d" },
      { ...base, seq: 5 },
      { ...base, prev_hash: "f".repeat(64) },
      { ...base, id: "evt2" },
      { ...base, request_id: "req2" },
      { ...base, agent_run_id: "run2" },
      { ...base, tenant: "t-2" },
      { ...base, occurred_at_unix: 11 },
      { ...base, audit_json: "{ }" },
    ];
    for (const mutated of mutations) {
      expect(await auditRowHash(mutated)).not.toBe(original);
    }
  });

  /**
   * Length-prefixing is not decoration: without it `("ab","c")` and
   * `("a","bc")` concatenate to the same bytes, so an attacker could move
   * characters across a field boundary and keep the digest.
   */
  test("cannot be aliased by moving bytes across a field boundary", async () => {
    const left = await auditRowHash({
      chain_key: "c",
      seq: 1,
      prev_hash: AUDIT_CHAIN_GENESIS_HASH,
      id: "ab",
      request_id: "c",
      agent_run_id: null,
      tenant: null,
      occurred_at_unix: 1,
      audit_json: "{}",
    });
    const right = await auditRowHash({
      chain_key: "c",
      seq: 1,
      prev_hash: AUDIT_CHAIN_GENESIS_HASH,
      id: "a",
      request_id: "bc",
      agent_run_id: null,
      tenant: null,
      occurred_at_unix: 1,
      audit_json: "{}",
    });
    expect(left).not.toBe(right);
  });

  /** A SQL NULL and an empty string are different facts about a row. */
  test("distinguishes NULL from the empty string", async () => {
    const base = {
      chain_key: "c",
      seq: 1,
      prev_hash: AUDIT_CHAIN_GENESIS_HASH,
      id: "evt",
      request_id: "",
      agent_run_id: null,
      tenant: null,
      occurred_at_unix: 1,
      audit_json: "{}",
    };
    expect(await auditRowHash(base)).not.toBe(await auditRowHash({ ...base, agent_run_id: "" }));
    expect(await auditRowHash(base)).not.toBe(await auditRowHash({ ...base, tenant: "" }));
  });

  test("chain key folds an un-attributed platform row onto the platform chain", () => {
    expect(auditChainKey(null)).toBe("");
    expect(auditChainKey("t-1")).toBe("t-1");
  });
});

// ---------------------------------------------------------------------------
// The happy path — asserted so the adversarial cases below mean something
// ---------------------------------------------------------------------------

describe("an untouched chain", () => {
  test("verifies against its anchor", async () => {
    const rows = await buildChain("t-1", 4);
    const result = await verifyAuditChain(rows, { anchors: [anchorFor(rows, "t-1")] });
    expect(result.failures).toEqual([]);
    expect(result.status).toBe("verified");
    expect(result.rowCount).toBe(4);
    expect(result.headSeq).toBe(4);
    expect(result.anchorsChecked).toBe(1);
  });

  /**
   * The anchor is the only thing that pins a chain's HEAD, so a chain with no
   * anchor is not "verified" — it is internally consistent, which is a weaker
   * claim, and saying so is the difference between evidence and decoration.
   */
  test("with no anchor is inconclusive, not verified", async () => {
    const rows = await buildChain("t-1", 4);
    const result = await verifyAuditChain(rows);
    expect(result.failures).toEqual([]);
    expect(result.status).toBe("inconclusive");
    expect(result.reasons).toContain("unanchored");
  });

  test("verifies a freshly-initialised one-row chain", async () => {
    const rows = await buildChain("t-1", 1);
    const result = await verifyAuditChain(rows, { anchors: [anchorFor(rows, "t-1")] });
    expect(result.status).toBe("verified");
    expect(result.headSeq).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// THE PROPERTY THAT MATTERS: detection
// ---------------------------------------------------------------------------

describe("a tampered trail", () => {
  test("a rewritten row body is caught, at that row", async () => {
    const rows = await buildChain("t-1", 4);
    // The insider edit: the deletion is relabelled as a read-only touch, and
    // every other column — id, timestamp, hashes — is left exactly as stored.
    const forged = rows.map((row) =>
      row.seq === 2 ? { ...row, audit_json: auditJson("merge", "pol-2") } : row,
    );
    const result = await verifyAuditChain(forged, { anchors: [anchorFor(rows, "t-1")] });
    expect(result.status).toBe("failed");
    expect(result.failures.map((f) => f.code)).toContain("row_hash_mismatch");
    expect(result.failures[0]?.seq).toBe(2);
    expect(result.failures[0]?.id).toBe("evt-t-1-2");
  });

  test("a changed timestamp is caught", async () => {
    const rows = await buildChain("t-1", 3);
    const forged = rows.map((row) => (row.seq === 1 ? { ...row, occurred_at_unix: 1 } : row));
    const result = await verifyAuditChain(forged, { anchors: [anchorFor(rows, "t-1")] });
    expect(result.status).toBe("failed");
    expect(result.failures.map((f) => f.code)).toContain("row_hash_mismatch");
  });

  test("a deleted middle row is caught with no anchor at all", async () => {
    const rows = await buildChain("t-1", 4);
    const result = await verifyAuditChain(rows.filter((row) => row.seq !== 3));
    expect(result.status).toBe("failed");
    expect(result.failures.map((f) => f.code)).toContain("seq_gap");
  });

  /**
   * Deleting the TAIL leaves a chain that is internally perfect — this is
   * precisely the attack a hash chain alone cannot see, and the reason the
   * anchor exists. Both halves are asserted so the anchor's contribution is
   * visible rather than assumed.
   */
  test("a deleted tail row is invisible without the anchor and caught with it", async () => {
    const rows = await buildChain("t-1", 4);
    const truncated = rows.slice(0, 3);

    const unanchored = await verifyAuditChain(truncated);
    expect(unanchored.failures).toEqual([]);
    expect(unanchored.status).toBe("inconclusive");

    const anchored = await verifyAuditChain(truncated, { anchors: [anchorFor(rows, "t-1")] });
    expect(anchored.status).toBe("failed");
    expect(anchored.failures.map((f) => f.code)).toContain("truncated_below_anchor");
  });

  test("re-ordering two rows is caught", async () => {
    const rows = await buildChain("t-1", 4);
    const swapped = [rows[0], rows[2], rows[1], rows[3]] as AuditChainRow[];
    const result = await verifyAuditChain(swapped, { anchors: [anchorFor(rows, "t-1")] });
    expect(result.status).toBe("failed");
    expect(result.failures.map((f) => f.code)).toContain("seq_disorder");
  });

  test("a duplicated sequence number is caught", async () => {
    const rows = await buildChain("t-1", 3);
    const doubled = [rows[0], rows[1], rows[1], rows[2]] as AuditChainRow[];
    const result = await verifyAuditChain(doubled, { anchors: [anchorFor(rows, "t-1")] });
    expect(result.status).toBe("failed");
    expect(result.failures.map((f) => f.code)).toContain("duplicate_seq");
  });

  /**
   * The competent attacker: edit row 2 AND recompute rows 2..4 so the chain is
   * internally flawless. Nothing inside the trail can tell — only the anchored
   * head can, which is the whole argument for anchoring off-database.
   */
  test("a wholesale re-forge is caught only by the anchor, and is caught", async () => {
    const original = await buildChain("t-1", 4);
    const anchor = anchorFor(original, "t-1");

    const forged: AuditChainRow[] = [];
    let prev = AUDIT_CHAIN_GENESIS_HASH;
    for (const row of original) {
      const base = {
        ...row,
        prev_hash: prev,
        audit_json: row.seq === 2 ? auditJson("merge", "pol-2") : row.audit_json,
      };
      const hash = await auditRowHash({
        chain_key: base.chain_key as string,
        seq: base.seq as number,
        prev_hash: prev,
        id: base.id,
        request_id: base.request_id,
        agent_run_id: base.agent_run_id,
        tenant: base.tenant,
        occurred_at_unix: base.occurred_at_unix,
        audit_json: base.audit_json,
      });
      forged.push({ ...base, row_hash: hash });
      prev = hash;
    }

    // Internally consistent: no per-row failure at all.
    const unanchored = await verifyAuditChain(forged);
    expect(unanchored.failures).toEqual([]);
    expect(unanchored.status).toBe("inconclusive");

    const anchored = await verifyAuditChain(forged, { anchors: [anchor] });
    expect(anchored.status).toBe("failed");
    expect(anchored.failures.map((f) => f.code)).toContain("anchor_head_mismatch");
  });

  test("a chain whose first row is not seq 1 is not silently accepted", async () => {
    const rows = await buildChain("t-1", 4);
    // Rows 1-2 deleted outright: what is left links perfectly to a predecessor
    // that no longer exists.
    const result = await verifyAuditChain(rows.slice(2));
    expect(result.status).toBe("failed");
    expect(result.failures.map((f) => f.code)).toContain("missing_head_of_chain");
  });

  test("a first row claiming genesis with a bogus prev_hash is caught", async () => {
    const rows = await buildChain("t-1", 2);
    const forged = rows.map((row) => (row.seq === 1 ? { ...row, prev_hash: "a".repeat(64) } : row));
    const result = await verifyAuditChain(forged);
    expect(result.status).toBe("failed");
    // The row hash commits to `prev_hash`, so this is caught twice over; the
    // genesis check is what names the actual problem.
    expect(result.failures.map((f) => f.code)).toContain("genesis_mismatch");
  });

  test("a broken prev link between two otherwise valid rows is caught", async () => {
    // Both rows self-verify, but row 2 does not point at row 1 — the shape a
    // spliced-in row from another chain has.
    const chainA = await buildChain("t-1", 2);
    const rows: AuditChainRow[] = [chainA[0] as AuditChainRow];
    const base = {
      id: "evt-spliced",
      request_id: "req-x",
      agent_run_id: null,
      tenant: "t-1",
      occurred_at_unix: 1_700_000_009,
      audit_json: auditJson("remove", "pol-x"),
      chain_key: "t-1",
      seq: 2,
      prev_hash: "b".repeat(64),
    };
    rows.push({ ...base, row_hash: await auditRowHash(base) });
    const result = await verifyAuditChain(rows);
    expect(result.status).toBe("failed");
    expect(result.failures.map((f) => f.code)).toContain("prev_hash_mismatch");
  });
});

// ---------------------------------------------------------------------------
// The empty chain — the case that must not read as a clean bill of health
// ---------------------------------------------------------------------------

describe("an empty or newly-initialised chain", () => {
  test("an empty unanchored chain is inconclusive and says why", async () => {
    const result = await verifyAuditChain([], { chainKey: "t-1" });
    expect(result.status).toBe("inconclusive");
    expect(result.reasons).toContain("empty_chain");
    expect(result.rowCount).toBe(0);
    expect(result.failures).toEqual([]);
    // The distinguishing sentence an operator actually reads.
    expect(result.summary).toMatch(/no audit rows/i);
  });

  test("an empty chain that HAS an anchor is a truncation, not an empty chain", async () => {
    const rows = await buildChain("t-1", 3);
    const result = await verifyAuditChain([], {
      chainKey: "t-1",
      anchors: [anchorFor(rows, "t-1")],
    });
    expect(result.status).toBe("failed");
    expect(result.failures.map((f) => f.code)).toContain("truncated_below_anchor");
    expect(result.reasons).not.toContain("empty_chain");
  });

  test("an anchor for a chain that never had rows is an empty chain", async () => {
    // `head_seq: 0` is what the anchor job writes for a chain with no rows —
    // it exists to make "we looked, there was nothing" a recorded fact.
    const result = await verifyAuditChain([], {
      chainKey: "t-1",
      anchors: [
        {
          chain_key: "t-1",
          first_seq: 0,
          head_seq: 0,
          head_hash: AUDIT_CHAIN_GENESIS_HASH,
          row_count: 0,
          anchored_at_unix: 1_700_001_000,
        },
      ],
    });
    expect(result.status).toBe("inconclusive");
    expect(result.reasons).toContain("empty_chain");
    expect(result.failures).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Rows outside the chain
// ---------------------------------------------------------------------------

describe("rows with no chain columns", () => {
  /**
   * `audit_events` has a SECOND writer — the gateway's asset audit sink
   * (`apps/gateway/src/assets/d1.ts`) — which does not chain its rows. Those
   * rows are real evidence and must not be dropped from the report, but they
   * are not covered by the chain, and a verifier that silently ignored them
   * would let an attacker APPEND a forged row simply by leaving the hash
   * columns NULL.
   */
  test("are counted, reported, and downgrade the verdict", async () => {
    const rows = await buildChain("t-1", 2);
    const unchained: AuditChainRow = {
      id: "evt-asset",
      request_id: "req-asset",
      agent_run_id: null,
      tenant: "t-1",
      occurred_at_unix: 1_700_000_050,
      audit_json: auditJson("create", "asset"),
      chain_key: null,
      seq: null,
      prev_hash: null,
      row_hash: null,
    };
    const result = await verifyAuditChain([...rows, unchained], {
      anchors: [anchorFor(rows, "t-1")],
    });
    expect(result.unchainedRows).toBe(1);
    expect(result.reasons).toContain("unchained_rows");
    expect(result.status).toBe("inconclusive");
    // The chain itself is intact — the downgrade is about coverage, not damage.
    expect(result.failures).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// Whole-trail verification (what the published script runs)
// ---------------------------------------------------------------------------

describe("verifyAuditTrail", () => {
  test("verifies every chain in a platform-wide export", async () => {
    const platform = await buildChain("", 2, null);
    const tenantA = await buildChain("t-1", 3);
    const result = await verifyAuditTrail(
      [...platform, ...tenantA],
      [anchorFor(platform, ""), anchorFor(tenantA, "t-1")],
    );
    expect(result.status).toBe("verified");
    expect(result.chains.map((c) => c.chainKey).sort()).toEqual(["", "t-1"]);
  });

  test("one broken chain fails the whole trail", async () => {
    const platform = await buildChain("", 2, null);
    const tenantA = await buildChain("t-1", 3);
    const forged = tenantA.map((row) =>
      row.seq === 2 ? { ...row, audit_json: '{"forged":true}' } : row,
    );
    const result = await verifyAuditTrail(
      [...platform, ...forged],
      [anchorFor(platform, ""), anchorFor(tenantA, "t-1")],
    );
    expect(result.status).toBe("failed");
    expect(result.chains.find((c) => c.chainKey === "t-1")?.status).toBe("failed");
    expect(result.chains.find((c) => c.chainKey === "")?.status).toBe("verified");
  });

  test("an anchor naming a chain with no rows at all is a full-chain deletion", async () => {
    const tenantA = await buildChain("t-1", 3);
    const result = await verifyAuditTrail([], [anchorFor(tenantA, "t-1")]);
    expect(result.status).toBe("failed");
    expect(result.chains).toHaveLength(1);
    expect(result.chains[0]?.failures.map((f) => f.code)).toContain("truncated_below_anchor");
  });
});
