/**
 * Tamper-evidence for the durable audit trail (#684), driven END TO END: real
 * admin mutations through the exported Worker, a real D1 `audit_events` table,
 * a real R2 bucket for the anchor, and the SAME verifier the published
 * customer-facing procedure runs.
 *
 * ## The defect this file pins
 *
 * `audit_events` was append-only by CONVENTION. The write half is real
 * (`src/store/d1.ts::#audit`) and the read half is real
 * (`src/routes/admin_request_log.ts::listAuditEventsHandler`, tenant-fenced on
 * strict equality) — but nothing committed a row to its predecessor, so an
 * `UPDATE audit_events SET audit_json = ...` or a `DELETE` left no trace
 * whatsoever. An auditor asking "could this record have been altered" had no
 * answer, and the trail's own contents could not distinguish a clean history
 * from a laundered one.
 *
 * ## The rule every case here obeys
 *
 * **Write through the admin API. Tamper with raw SQL. Verify through the
 * export.** No case seeds `audit_events`; every row was put there by a real
 * mutation, every alteration is the exact statement an insider with database
 * access would run, and every verdict comes from
 * `verifyAuditTrail(export, anchors)` — the function
 * `scripts/verify-audit-chain.mjs` calls. So a green case cannot be explained
 * by a fixture at either end, and a detection cannot be explained by the test
 * telling the verifier where to look.
 */
import { SELF, env } from "cloudflare:test";
import {
  type AuditChainAnchor,
  type AuditChainRow,
  auditChainRowFromAdminDocument,
  parseAuditChainAnchor,
  verifyAuditTrail,
} from "@ferrogate/storage";
import { beforeAll, beforeEach, describe, expect, it } from "vitest";
import { AUDIT_ANCHOR_PREFIX, anchorAuditChains } from "../src/audit/anchor.js";
import { runScheduledTick } from "../src/schedule/scheduled.js";
import { applySchema, db, resetD1 } from "./d1.js";
import { BASE, arm, bearer, jsonRequest, operatorKey, tenantKey } from "./harness.js";

const TICK_AT = 1_800_000_000;

function bucket(): R2Bucket {
  const found = (env as unknown as { AUDIT_ANCHORS?: R2Bucket }).AUDIT_ANCHORS;
  if (found === undefined) {
    // Loud, never a silent skip: with no `[[r2_buckets]] AUDIT_ANCHORS` stanza
    // the anchor half of the feature does not exist, and a suite that skipped
    // itself would report that as success.
    throw new Error("AUDIT_ANCHORS is not bound — check apps/control-plane/wrangler.toml");
  }
  return found;
}

/** Empty the anchor bucket, so no case can be satisfied by a previous one's anchor. */
async function resetAnchors(): Promise<void> {
  const listed = await bucket().list({ prefix: AUDIT_ANCHOR_PREFIX });
  for (const object of listed.objects) await bucket().delete(object.key);
}

/** `POST /admin/v1/policies` — a real, applied mutation. */
function createPolicy(secret: string, name: string): Promise<Response> {
  return SELF.fetch(
    `${BASE}/admin/v1/policies`,
    jsonRequest(secret, "POST", { name, id: name, rules: [], tenant_id: null }),
  );
}

function createTenantPolicy(secret: string, name: string, tenantId: string): Promise<Response> {
  return SELF.fetch(
    `${BASE}/admin/v1/policies`,
    jsonRequest(secret, "POST", { name, id: name, rules: [], tenant_id: tenantId }),
  );
}

/**
 * What a customer exports: `GET /admin/v1/audit-events`, as themselves.
 *
 * Nothing here reads the table. If the admin surface stops publishing the
 * chain columns the export becomes unverifiable and every case below fails,
 * which is the correct coupling — an unpublishable chain is not evidence.
 */
async function exportTrail(secret: string): Promise<AuditChainRow[]> {
  const response = await SELF.fetch(`${BASE}/admin/v1/audit-events?limit=100`, {
    headers: bearer(secret),
  });
  expect(response.status, await response.clone().text()).toBe(200);
  const body = (await response.json()) as { data: Record<string, unknown>[] };
  return body.data.map(auditChainRowFromAdminDocument);
}

/**
 * The export, in CHAIN order for one chain.
 *
 * The admin surface orders by `occurred_at_unix ASC, id ASC`, and three
 * mutations in the same second are tie-broken by a RANDOM uuid — so the wire
 * order genuinely is not `seq` order, as this suite discovered by failing.
 * Verification sorts for exactly that reason; assertions about linkage have to
 * do the same, or they would be asserting the tiebreak rather than the chain.
 */
function inChainOrder(rows: readonly AuditChainRow[], chainKey: string): AuditChainRow[] {
  return rows
    .filter((row) => row.chain_key === chainKey)
    .sort((left, right) => (left.seq ?? 0) - (right.seq ?? 0));
}

/** Run the periodic anchor job the cron tick runs, then read the anchors back out of R2. */
async function anchorAndRead(now = TICK_AT): Promise<AuditChainAnchor[]> {
  await anchorAuditChains(db(), bucket(), now);
  return readAnchors();
}

async function readAnchors(): Promise<AuditChainAnchor[]> {
  const listed = await bucket().list({ prefix: AUDIT_ANCHOR_PREFIX });
  const anchors: AuditChainAnchor[] = [];
  for (const object of listed.objects) {
    const stored = await bucket().get(object.key);
    if (stored === null) continue;
    anchors.push(parseAuditChainAnchor(await stored.json()));
  }
  return anchors;
}

/** The id of the audit row recording a given mutation, straight from the table. */
async function auditRowId(offset: number): Promise<string> {
  const row = await db()
    .prepare("SELECT id FROM audit_events ORDER BY seq ASC LIMIT 1 OFFSET ?")
    .bind(offset)
    .first<{ id: string }>();
  if (row === null) throw new Error(`no audit row at offset ${offset}`);
  return row.id;
}

beforeAll(applySchema);

beforeEach(async () => {
  await resetD1();
  await resetAnchors();
  arm({
    store: "d1",
    staticKeys: [operatorKey],
    nativeKeys: [tenantKey("k-tenant", "t-1")],
    rbac: {},
  });
});

// ---------------------------------------------------------------------------
// The chain the writer builds
// ---------------------------------------------------------------------------

describe("the durable writer", () => {
  it("chains every audit row it appends", async () => {
    for (const name of ["pol_a", "pol_b", "pol_c"]) {
      expect((await createPolicy(operatorKey.secret, name)).status).toBe(201);
    }

    const exported = await exportTrail(operatorKey.secret);
    expect(exported).toHaveLength(3);
    expect(exported.map((row) => row.chain_key)).toEqual(["", "", ""]);

    const rows = inChainOrder(exported, "");
    expect(rows.map((row) => row.seq)).toEqual([1, 2, 3]);
    // Each row commits to its predecessor; the first to the genesis constant.
    expect(rows[0]?.prev_hash).toBe("0".repeat(64));
    expect(rows[1]?.prev_hash).toBe(rows[0]?.row_hash);
    expect(rows[2]?.prev_hash).toBe(rows[1]?.row_hash);
  });

  /**
   * Two mutations racing for the same chain head. The insert is guarded by a
   * UNIQUE `(chain_key, seq)` index, so a loser must RETRY against the new
   * head rather than duplicating a sequence number or silently dropping its
   * row — an audit trail that loses a row under load is not an audit trail.
   */
  it("gives concurrent mutations distinct, contiguous sequence numbers", async () => {
    const responses = await Promise.all([
      createPolicy(operatorKey.secret, "pol_race_1"),
      createPolicy(operatorKey.secret, "pol_race_2"),
      createPolicy(operatorKey.secret, "pol_race_3"),
    ]);
    for (const response of responses) expect(response.status).toBe(201);

    const rows = await exportTrail(operatorKey.secret);
    expect(rows).toHaveLength(3);
    expect([...rows.map((row) => row.seq)].sort()).toEqual([1, 2, 3]);
    const anchors = await anchorAndRead();
    expect((await verifyAuditTrail(rows, anchors)).status).toBe("verified");
  });

  /**
   * A tenant sees only its own rows (the read fence is strict equality on
   * `tenant`), so its chain has to be COMPLETE on its own — otherwise every
   * tenant's export would look like a truncation attack.
   */
  it("keeps a separate, self-contained chain per tenant", async () => {
    expect((await createPolicy(operatorKey.secret, "pol_platform")).status).toBe(201);
    expect((await createTenantPolicy("k-tenant", "pol_tenant_1", "t-1")).status).toBe(201);
    expect((await createTenantPolicy("k-tenant", "pol_tenant_2", "t-1")).status).toBe(201);

    const tenantRows = await exportTrail("k-tenant");
    expect(inChainOrder(tenantRows, "t-1").map((row) => row.seq)).toEqual([1, 2]);
    expect(tenantRows.every((row) => row.chain_key === "t-1")).toBe(true);

    // The tenant verifies its OWN chain, holding only its own export and its
    // own anchors — it can neither see nor account for the platform chain's
    // rows, so being handed that chain's anchor would (correctly) report it as
    // fully truncated. Scoping the anchors is part of the procedure.
    const anchors = (await anchorAndRead()).filter((anchor) => anchor.chain_key === "t-1");
    const result = await verifyAuditTrail(tenantRows, anchors);
    expect(result.status).toBe("verified");
    expect(result.chains).toHaveLength(1);
  });
});

// ---------------------------------------------------------------------------
// The anchor
// ---------------------------------------------------------------------------

describe("the periodic anchor", () => {
  it("publishes each chain's head to R2", async () => {
    expect((await createPolicy(operatorKey.secret, "pol_a")).status).toBe(201);
    expect((await createTenantPolicy("k-tenant", "pol_t", "t-1")).status).toBe(201);

    const anchors = await anchorAndRead();
    expect(anchors.map((anchor) => anchor.chain_key).sort()).toEqual(["", "t-1"]);
    const platform = anchors.find((anchor) => anchor.chain_key === "");
    expect(platform).toMatchObject({ first_seq: 1, head_seq: 1, row_count: 1 });
    // The operator's export spans BOTH chains, so the platform head is the
    // seq-1 row OF THE PLATFORM CHAIN, not simply the first row on the wire.
    const platformHead = inChainOrder(await exportTrail(operatorKey.secret), "")[0];
    expect(platform?.head_hash).toBe(platformHead?.row_hash);
    expect(platform?.anchored_at_unix).toBe(TICK_AT);
  });

  /**
   * An anchor that can be rewritten is not an anchor. The job never overwrites
   * an existing object, so the operator's own tick cannot launder a head — and
   * a re-run after new rows land writes a NEW object rather than replacing the
   * old one, leaving the earlier head still provable.
   */
  it("never rewrites an anchor it has already written", async () => {
    expect((await createPolicy(operatorKey.secret, "pol_a")).status).toBe(201);
    await anchorAuditChains(db(), bucket(), TICK_AT);
    const first = await readAnchors();

    // A second tick with no new rows, then a tick after one more row.
    await anchorAuditChains(db(), bucket(), TICK_AT + 60);
    expect(await readAnchors()).toEqual(first);

    expect((await createPolicy(operatorKey.secret, "pol_b")).status).toBe(201);
    await anchorAuditChains(db(), bucket(), TICK_AT + 120);
    const both = await readAnchors();
    expect(both).toHaveLength(2);
    // The seq-1 anchor is untouched: its timestamp is still the first tick's.
    expect(both.find((anchor) => anchor.head_seq === 1)?.anchored_at_unix).toBe(TICK_AT);
    expect(both.find((anchor) => anchor.head_seq === 2)?.anchored_at_unix).toBe(TICK_AT + 120);
  });

  it("records an empty chain as an anchor with head_seq 0", async () => {
    const anchors = await anchorAndRead();
    // Nothing has been mutated, so the only chain is the platform one and it
    // is empty. Recording that fact is what makes "there were never any rows"
    // provable later.
    expect(anchors).toEqual([
      {
        chain_key: "",
        first_seq: 0,
        head_seq: 0,
        head_hash: "0".repeat(64),
        row_count: 0,
        anchored_at_unix: TICK_AT,
      },
    ]);
  });

  /**
   * THE MOUNT PROOF. Every case above calls `anchorAuditChains` directly, and
   * a job nothing invokes anchors nothing: a deployment would carry a hash
   * chain, a bucket, a green suite and no anchors at all. This drives the CRON
   * TICK — the same `runScheduledTick` `scheduled` dispatches — so removing the
   * anchor pass from it fails here.
   */
  it("is written by the cron tick, not only by a direct call", async () => {
    expect((await createPolicy(operatorKey.secret, "pol_a")).status).toBe(201);

    const report = await runScheduledTick(
      { ...(env as unknown as Record<string, unknown>), CONTROL_PLANE_STORE: undefined } as never,
      TICK_AT,
    );
    expect(report.auditAnchor).toEqual({ written: 1, skipped: 0 });

    const anchors = await readAnchors();
    expect(anchors).toHaveLength(1);
    expect(anchors[0]).toMatchObject({ chain_key: "", head_seq: 1, anchored_at_unix: TICK_AT });
  });

  it("does nothing, loudly, when no bucket is bound", async () => {
    expect((await createPolicy(operatorKey.secret, "pol_a")).status).toBe(201);
    const result = await anchorAuditChains(db(), null, TICK_AT);
    expect(result.unconfigured).toBe(true);
    expect(result.written).toBe(0);
    expect(await readAnchors()).toEqual([]);
  });
});

// ---------------------------------------------------------------------------
// THE PROPERTY THAT MATTERS: an alteration is detected
// ---------------------------------------------------------------------------

describe("tampering with the stored trail", () => {
  /** Three mutations, anchored — the state every attack below starts from. */
  async function seedAndAnchor(): Promise<AuditChainAnchor[]> {
    for (const name of ["pol_a", "pol_b", "pol_c"]) {
      expect((await createPolicy(operatorKey.secret, name)).status).toBe(201);
    }
    return anchorAndRead();
  }

  it("detects an edited audit row and names it", async () => {
    const anchors = await seedAndAnchor();
    const target = await auditRowId(1);

    // THE ATTACK: the insider rewrites what the middle row says happened,
    // leaving id, request_id, timestamp and every hash column exactly as
    // stored. Under the pre-#684 schema this was undetectable.
    await db()
      .prepare("UPDATE audit_events SET audit_json = ? WHERE id = ?")
      .bind('{"object":"control_plane_mutation","action":"create","collection":"policies"}', target)
      .run();

    const result = await verifyAuditTrail(await exportTrail(operatorKey.secret), anchors);
    expect(result.status).toBe("failed");
    const failures = result.chains[0]?.failures ?? [];
    expect(failures.map((failure) => failure.code)).toContain("row_hash_mismatch");
    expect(failures.find((failure) => failure.code === "row_hash_mismatch")?.id).toBe(target);
  });

  it("detects a back-dated audit row", async () => {
    const anchors = await seedAndAnchor();
    const target = await auditRowId(0);
    await db()
      .prepare("UPDATE audit_events SET occurred_at_unix = 1 WHERE id = ?")
      .bind(target)
      .run();

    const result = await verifyAuditTrail(await exportTrail(operatorKey.secret), anchors);
    expect(result.status).toBe("failed");
    expect(result.chains[0]?.failures.map((failure) => failure.code)).toContain(
      "row_hash_mismatch",
    );
  });

  it("detects a row deleted from the middle", async () => {
    const anchors = await seedAndAnchor();
    await db()
      .prepare("DELETE FROM audit_events WHERE id = ?")
      .bind(await auditRowId(1))
      .run();

    const result = await verifyAuditTrail(await exportTrail(operatorKey.secret), anchors);
    expect(result.status).toBe("failed");
    expect(result.chains[0]?.failures.map((failure) => failure.code)).toContain("seq_gap");
  });

  /**
   * The attack a hash chain alone CANNOT see: delete the tail and what remains
   * is a perfect chain. Only the anchored head catches it, which is the entire
   * argument for anchoring off-database.
   */
  it("detects a deleted tail row, because the anchor pinned it", async () => {
    const anchors = await seedAndAnchor();
    await db()
      .prepare("DELETE FROM audit_events WHERE id = ?")
      .bind(await auditRowId(2))
      .run();

    const rows = await exportTrail(operatorKey.secret);
    expect(rows).toHaveLength(2);

    // Without the anchor the remaining two rows verify as internally
    // consistent — asserted so the anchor's contribution is visible.
    expect((await verifyAuditTrail(rows, [])).status).toBe("inconclusive");

    const result = await verifyAuditTrail(rows, anchors);
    expect(result.status).toBe("failed");
    expect(result.chains[0]?.failures.map((failure) => failure.code)).toContain(
      "truncated_below_anchor",
    );
  });

  it("detects a wholesale deletion of the trail", async () => {
    const anchors = await seedAndAnchor();
    await db().prepare("DELETE FROM audit_events").run();

    const result = await verifyAuditTrail(await exportTrail(operatorKey.secret), anchors);
    expect(result.status).toBe("failed");
    expect(result.chains[0]?.failures.map((failure) => failure.code)).toContain(
      "truncated_below_anchor",
    );
  });

  /**
   * An attacker who understands the chain will recompute it. The rows below
   * are internally flawless — every hash is the real hash of its own row — and
   * the anchored head is what refuses them.
   */
  it("detects a re-forged chain whose hashes were recomputed", async () => {
    const anchors = await seedAndAnchor();
    // In CHAIN order: a re-forge has to walk the chain, and the wire order is
    // not it (see `inChainOrder`).
    const forged = inChainOrder(await exportTrail(operatorKey.secret), "");
    const { auditRowHash } = await import("@ferrogate/storage");

    let prev = "0".repeat(64);
    for (const row of forged) {
      const audit_json = row.seq === 2 ? '{"object":"control_plane_mutation"}' : row.audit_json;
      const hash = await auditRowHash({
        chain_key: row.chain_key as string,
        seq: row.seq as number,
        prev_hash: prev,
        id: row.id,
        request_id: row.request_id,
        agent_run_id: row.agent_run_id,
        tenant: row.tenant,
        occurred_at_unix: row.occurred_at_unix,
        audit_json,
      });
      await db()
        .prepare("UPDATE audit_events SET audit_json = ?, prev_hash = ?, row_hash = ? WHERE id = ?")
        .bind(audit_json, prev, hash, row.id)
        .run();
      prev = hash;
    }

    const rows = await exportTrail(operatorKey.secret);
    // Internally perfect — no per-row failure at all.
    expect((await verifyAuditTrail(rows, [])).chains[0]?.failures).toEqual([]);

    const result = await verifyAuditTrail(rows, anchors);
    expect(result.status).toBe("failed");
    expect(result.chains[0]?.failures.map((failure) => failure.code)).toContain(
      "anchor_head_mismatch",
    );
  });

  /**
   * The forged APPEND: a row inserted with no chain columns at all. It must
   * not be silently ignored, or leaving the hash columns NULL would be a
   * complete bypass of the whole mechanism.
   */
  it("refuses to ignore an unchained row spliced into the table", async () => {
    const anchors = await seedAndAnchor();
    await db()
      .prepare(
        `INSERT INTO audit_events (id, request_id, agent_run_id, tenant, occurred_at_unix, audit_json)
         VALUES ('evt-forged', 'req-forged', NULL, NULL, 1800000500, '{"action":"create"}')`,
      )
      .run();

    const result = await verifyAuditTrail(await exportTrail(operatorKey.secret), anchors);
    expect(result.status).toBe("inconclusive");
    expect(result.chains[0]?.unchainedRows).toBe(1);
    expect(result.chains[0]?.reasons).toContain("unchained_rows");
  });
});

// ---------------------------------------------------------------------------
// The empty chain — the case that must not read as a clean bill of health
// ---------------------------------------------------------------------------

describe("a newly-initialised deployment", () => {
  it("reports an empty unanchored trail as inconclusive, not verified", async () => {
    const result = await verifyAuditTrail(await exportTrail(operatorKey.secret), []);
    expect(result.status).toBe("inconclusive");
    expect(result.chains[0]?.reasons).toContain("empty_chain");
    expect(result.chains[0]?.summary).toMatch(/NOT a clean bill of health/);
  });

  it("distinguishes 'never had rows' from 'rows were deleted'", async () => {
    // Anchored while empty: the anchor records head_seq 0.
    const emptyAnchors = await anchorAndRead();
    const empty = await verifyAuditTrail(await exportTrail(operatorKey.secret), emptyAnchors);
    expect(empty.status).toBe("inconclusive");
    expect(empty.chains[0]?.reasons).toContain("empty_chain");

    // Now a row lands, is anchored, and is deleted. Same empty table, opposite
    // verdict — which is exactly the distinction the anchor buys.
    expect((await createPolicy(operatorKey.secret, "pol_a")).status).toBe(201);
    const anchors = await anchorAndRead(TICK_AT + 60);
    await db().prepare("DELETE FROM audit_events").run();

    const wiped = await verifyAuditTrail(await exportTrail(operatorKey.secret), anchors);
    expect(wiped.status).toBe("failed");
    expect(wiped.chains[0]?.failures.map((failure) => failure.code)).toContain(
      "truncated_below_anchor",
    );
  });
});
