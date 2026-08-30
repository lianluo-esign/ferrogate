/**
 * The periodic AUDIT ANCHOR (#684): publish each audit chain's head to
 * immutable storage outside the database.
 *
 * ## Why the chain is not enough
 *
 * `audit_events` rows commit to their predecessors
 * (`packages/storage/src/audit-chain.ts`), which makes an edit or an in-place
 * deletion detectable from an export alone. It does NOT catch the two attacks
 * that leave a perfect chain behind:
 *
 *   * deleting the TAIL — what remains links flawlessly, it is simply shorter;
 *   * RE-FORGING — recomputing every hash after an edit.
 *
 * Both move the chain's head. So the head is published, periodically, to a
 * store the database operator does not write through: an R2 bucket. A trail
 * whose head disagrees with a published anchor is provably not the trail that
 * was anchored. The anchor is four numbers and a hash, which is what makes
 * "keep it somewhere else, forever" affordable.
 *
 * ## What this does NOT claim
 *
 * 1. **The detection window is the anchor cadence.** A row appended and
 *    deleted BETWEEN two ticks was never anchored and cannot be missed by
 *    comparison. The cron trigger runs every minute
 *    (`wrangler.toml [triggers]`), so the window is under a minute — but it is
 *    not zero, and pretending otherwise would be the kind of overclaim an
 *    auditor is entitled to reject.
 * 2. **This code does not make R2 immutable.** It never overwrites an object
 *    it has already written, which stops an operator's own tick from laundering
 *    a head, but a principal holding R2 write credentials can still delete an
 *    anchor. Making that impossible is a BUCKET-level control (R2 object lock /
 *    a retention policy, and ideally an account separate from the one that owns
 *    the database) and is a deployment step, documented in
 *    `docs/audit-tamper-evidence.md`. What the code guarantees is that anchors
 *    are append-only *from this Worker*.
 */
import {
  AUDIT_CHAIN_GENESIS_HASH,
  type AuditChainAnchor,
  parseAuditChainAnchor,
  storedAuditChainAnchor,
} from "@ferrogate/storage";
import { AUDIT_TABLE } from "../store/d1.js";

/** Key prefix for every anchor object. Versioned, so a format change is a new tree. */
export const AUDIT_ANCHOR_PREFIX = "audit-anchors/v1/";

/**
 * `audit-anchors/v1/k-<chain>/<seq>.json`.
 *
 * The `k-` prefix and `encodeURIComponent` together make the mapping
 * INJECTIVE: without the prefix the platform chain (`""`) would produce an
 * empty segment, and without the encoding a tenant id containing `/` would
 * invent directory levels — either way two chains could share a key and one
 * tenant's anchor would answer for another's.
 *
 * The sequence number is zero-padded to 20 digits so R2's lexical `list` order
 * IS chain order; a verifier walking anchors oldest-first needs no sort.
 */
export function auditAnchorKey(chainKey: string, headSeq: number): string {
  return `${AUDIT_ANCHOR_PREFIX}k-${encodeURIComponent(chainKey)}/${String(headSeq).padStart(20, "0")}.json`;
}

/** What one tick did, so a tail log says something an operator can act on. */
export interface AnchorAuditChainsResult {
  /** Chains considered this tick. */
  readonly chains: number;
  /** Anchors newly written. */
  readonly written: number;
  /** Chains whose head was already anchored. */
  readonly skipped: number;
  /** No bucket bound: the deployment has a hash chain and NO anchor. */
  readonly unconfigured: boolean;
}

interface ChainHeadRow {
  readonly chain_key: string;
  readonly first_seq: number;
  readonly head_seq: number;
  readonly row_count: number;
  readonly head_hash: string | null;
}

/**
 * Anchor every chain that has rows, plus the platform chain even when it has
 * none.
 *
 * The empty PLATFORM anchor is load-bearing rather than tidy: an empty chain
 * and a fully-deleted one are the same bytes, so a deployment with no anchor at
 * all cannot prove it was never wiped. The platform chain exists on every
 * deployment (its rows are the operator's own mutations), so recording "this
 * chain had no rows at time T" is a fact worth publishing. A TENANT chain that
 * has never had a row is not knowable from this table — it gets its first
 * anchor with its first row, which is soon enough: there is nothing to truncate
 * before then.
 */
export async function anchorAuditChains(
  db: D1Database,
  bucket: R2Bucket | null,
  now: number,
): Promise<AnchorAuditChainsResult> {
  if (bucket === null) {
    // Swallowing this would leave a deployment believing it is anchored. The
    // tick report carries `unconfigured` and the caller logs it.
    return { chains: 0, written: 0, skipped: 0, unconfigured: true };
  }

  // CHANGE-DETECTION GATE — skip the full-table scan below when nothing new can
  // be anchored.
  //
  // The scan is a `GROUP BY chain_key` over the WHOLE table, run every minute.
  // Since the gateway stopped mirroring asset audits, `audit_events` grows only
  // on the operator's own (rare) mutations, so on almost every tick the heads
  // are unchanged and the scan reads thousands of rows to write zero anchors.
  //
  // A head moves ONLY when a row is appended, and the newest-inserted anchorable
  // row IS its chain's head (seq increases with insertion order within a chain).
  // So: is that one head already anchored? If yes, every head is — a scan runs
  // on every append, so all heads stay anchored — and this tick can produce
  // nothing new. The probe is one indexed row (`rowid` DESC) plus one R2 `head`,
  // versus the whole table.
  //
  // This does NOT weaken tamper-evidence. Anchors are append-only and never
  // deleted here, so a truncated or re-forged tail is still caught at
  // VERIFICATION against the anchor that was published when that head appeared;
  // skipping a redundant scan removes no evidence. The detection window is
  // unchanged: the probe runs every tick, and the FIRST tick after any append
  // sees an unanchored head and falls through to the scan.
  const newestHead = await db
    .prepare(
      `SELECT chain_key, seq
         FROM ${AUDIT_TABLE}
        WHERE chain_key IS NOT NULL AND seq IS NOT NULL AND row_hash IS NOT NULL
        ORDER BY rowid DESC
        LIMIT 1`,
    )
    .first<{ chain_key: string; seq: number }>();
  // An empty table still owes the platform "no rows at time T" anchor (the
  // load-bearing empty anchor below); probe for it so a settled empty
  // deployment also skips the scan once that anchor exists.
  const probeKey =
    newestHead === null
      ? auditAnchorKey("", 0)
      : auditAnchorKey(newestHead.chain_key, newestHead.seq);
  if ((await bucket.head(probeKey)) !== null) {
    return { chains: 0, written: 0, skipped: 0, unconfigured: false };
  }

  // ONE statement, so `first_seq` / `head_seq` / `row_count` / `head_hash`
  // cannot disagree with each other: computed separately, a concurrent append
  // between two queries would produce an anchor whose count belongs to one
  // moment and whose head belongs to another, and a verifier would report that
  // self-inconsistent anchor as tampering.
  //
  // The aggregate is a subquery JOINed back to the table rather than a
  // correlated `MAX()`: SQLite rejects an aggregate of the outer query inside a
  // subquery ("misuse of aggregate function MAX()"), and the bare-column-with-
  // MAX() shortcut it does allow is a SQLite extension that reads as an
  // accident.
  const heads = await db
    .prepare(
      `SELECT grouped.chain_key,
              grouped.first_seq,
              grouped.head_seq,
              grouped.row_count,
              head.row_hash AS head_hash
         FROM (SELECT chain_key,
                      MIN(seq) AS first_seq,
                      MAX(seq) AS head_seq,
                      COUNT(*) AS row_count
                 FROM ${AUDIT_TABLE}
                WHERE chain_key IS NOT NULL AND seq IS NOT NULL AND row_hash IS NOT NULL
                GROUP BY chain_key) AS grouped
         JOIN ${AUDIT_TABLE} AS head
           ON head.chain_key = grouped.chain_key AND head.seq = grouped.head_seq`,
    )
    .all<ChainHeadRow>();

  const anchors: AuditChainAnchor[] = heads.results.map((row) => ({
    chain_key: row.chain_key,
    first_seq: row.first_seq,
    head_seq: row.head_seq,
    head_hash: row.head_hash ?? AUDIT_CHAIN_GENESIS_HASH,
    row_count: row.row_count,
    anchored_at_unix: now,
  }));

  if (!anchors.some((anchor) => anchor.chain_key === "")) {
    anchors.push({
      chain_key: "",
      first_seq: 0,
      head_seq: 0,
      head_hash: AUDIT_CHAIN_GENESIS_HASH,
      row_count: 0,
      anchored_at_unix: now,
    });
  }

  let written = 0;
  let skipped = 0;
  for (const anchor of anchors) {
    const key = auditAnchorKey(anchor.chain_key, anchor.head_seq);
    // APPEND-ONLY: an already-anchored head is never re-written, so a later
    // tick cannot restate a head that was published with different contents.
    if ((await bucket.head(key)) !== null) {
      skipped += 1;
      continue;
    }
    await bucket.put(key, JSON.stringify(storedAuditChainAnchor(anchor), null, 2), {
      httpMetadata: { contentType: "application/json" },
    });
    written += 1;
  }

  return { chains: anchors.length, written, skipped, unconfigured: false };
}

/**
 * Read anchors back out of the bucket — what the verification procedure does,
 * and what the tests use.
 *
 * A malformed object is a REFUSAL, not a skip: an anchor that silently
 * disappeared from the comparison would turn a truncation into a clean pass,
 * which is the one failure mode this whole feature exists to prevent.
 */
export async function readAuditAnchors(
  bucket: R2Bucket,
  chainKey?: string,
): Promise<AuditChainAnchor[]> {
  const prefix =
    chainKey === undefined
      ? AUDIT_ANCHOR_PREFIX
      : `${AUDIT_ANCHOR_PREFIX}k-${encodeURIComponent(chainKey)}/`;
  const anchors: AuditChainAnchor[] = [];
  let cursor: string | undefined;
  do {
    const listed = await bucket.list({ prefix, cursor });
    for (const object of listed.objects) {
      const stored = await bucket.get(object.key);
      if (stored === null) continue; // deleted between list and get
      anchors.push(parseAuditChainAnchor(await stored.json()));
    }
    cursor = listed.truncated ? listed.cursor : undefined;
  } while (cursor !== undefined);
  return anchors;
}
