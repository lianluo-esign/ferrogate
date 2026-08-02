/**
 * Tamper-evidence for the `audit_events` table (#684): the hash chain, the
 * anchor document, and the verification a customer runs themselves.
 *
 * ## The question this answers
 *
 * "Could this audit record have been altered?" Before this module the honest
 * answer was "yes, and you would not be able to tell": `audit_events` is
 * append-only by CONVENTION, and anyone with write access to the control D1
 * database — a platform operator, a leaked API token, a compromised support
 * tool — could edit a row's `audit_json`, delete the row that records their own
 * deletion, or re-order the trail, leaving no trace at all.
 *
 * ## The two mechanisms, and why NEITHER is sufficient alone
 *
 *  1. **The chain.** Every row carries `(chain_key, seq, prev_hash, row_hash)`,
 *     where `row_hash = H(row fields ‖ prev_hash)`. Editing any field of any
 *     row changes its `row_hash`, and because the next row commits to that
 *     hash, an edit invalidates every row after it too. This makes an edit or
 *     an in-place deletion detectable **from the data alone** — no external
 *     state required, which is what makes it verifiable by a customer holding
 *     only an export.
 *
 *     What it CANNOT catch on its own: an attacker who recomputes the whole
 *     chain after their edit, or who simply deletes the TAIL. Both leave a
 *     chain that is internally flawless.
 *
 *  2. **The anchor.** A periodic job writes `(chain_key, head_seq, head_hash,
 *     row_count)` to immutable storage OUTSIDE the database (R2 — see
 *     `apps/control-plane/src/audit/anchor.ts`). The chain's head at time T is
 *     then a published fact, so a re-forge or a truncation that moves the head
 *     is caught by comparing the trail against the anchor. The anchor is small
 *     and constant-size, which is what makes "write it somewhere the database
 *     operator cannot rewrite" affordable.
 *
 * Together they give the property that matters: **detection**. Neither stops a
 * privileged actor from writing to the table — nothing running inside the same
 * trust boundary can — but any alteration of an anchored row is provable after
 * the fact, which is exactly what an EU AI Act "immutable change history"
 * checklist is asking for.
 *
 * ## Why the verifier lives HERE
 *
 * One implementation, shared by the writer (`apps/control-plane/src/store/d1.ts`),
 * the anchor job, and the published customer-facing script
 * (`scripts/verify-audit-chain.mjs`). A second copy written for the docs would
 * drift from the one the writer uses, and the day it drifted the published
 * procedure would start reporting a healthy chain as broken (or worse, the
 * reverse). The PREIMAGE is documented byte-for-byte in
 * `docs/audit-tamper-evidence.md` so a third party can reimplement it in any
 * language without reading this file — a verifier only the vendor can run is
 * not evidence.
 */

// ---------------------------------------------------------------------------
// The wire format
// ---------------------------------------------------------------------------

/**
 * Domain separator and format version, the first line of every preimage.
 *
 * It is inside the hash, not beside it: a digest computed under v1 rules can
 * therefore never be mistaken for a v2 digest of different fields, which is how
 * a format change stays a loud failure instead of a silent re-interpretation.
 */
export const AUDIT_CHAIN_HASH_VERSION = "ferrogate.audit.v1";

/**
 * The `prev_hash` of the FIRST row of a chain — 64 zeros, i.e. a digest no
 * SHA-256 input is going to produce.
 *
 * A literal constant rather than SQL `NULL`: the genesis link is then something
 * the hash COMMITS to, so "this row claims to be the start of the chain" is
 * itself protected. With `NULL` an attacker could delete rows 1..n and promote
 * row n+1 to the head of the chain without touching its digest.
 */
export const AUDIT_CHAIN_GENESIS_HASH = "0".repeat(64);

/** `seq` of the first row of a chain. 1-based so `head_seq = 0` can mean "no rows". */
export const AUDIT_CHAIN_FIRST_SEQ = 1;

/**
 * One `audit_events` row, as both the table and
 * `GET /admin/v1/audit-events` expose it.
 *
 * The four chain columns are NULLABLE because two things legitimately produce
 * unchained rows: rows written before the chain migration, and the gateway's
 * asset audit sink (`apps/gateway/src/assets/d1.ts`), which writes this same
 * table and is not chained yet. {@link verifyAuditChain} reports them rather
 * than dropping them — see {@link AuditChainVerification.unchainedRows}.
 */
export interface AuditChainRow {
  readonly id: string;
  readonly request_id: string;
  readonly agent_run_id: string | null;
  readonly tenant: string | null;
  readonly occurred_at_unix: number;
  /** The EXACT stored bytes of the audit document; the chain commits to these. */
  readonly audit_json: string;
  readonly chain_key: string | null;
  readonly seq: number | null;
  readonly prev_hash: string | null;
  readonly row_hash: string | null;
}

/** Everything the digest of a row commits to. */
export interface AuditRowHashInput {
  readonly chain_key: string;
  readonly seq: number;
  readonly prev_hash: string;
  readonly id: string;
  readonly request_id: string;
  readonly agent_run_id: string | null;
  readonly tenant: string | null;
  readonly occurred_at_unix: number;
  readonly audit_json: string;
}

/**
 * Which chain a row belongs to.
 *
 * ONE CHAIN PER TENANT, with the empty string for un-attributed platform rows,
 * and that is a deliberate consequence of the READ fence: a tenant-scoped
 * caller can only see its own `audit_events` rows
 * (`apps/control-plane/src/routes/admin_request_log.ts::auditTenantFence` is
 * strict equality on `tenant`). A single global chain would therefore be
 * unverifiable by any tenant — they would see a trail full of holes and could
 * not tell it from a truncation attack. Per-tenant chains make every customer's
 * own export a COMPLETE chain they can verify end to end without being shown
 * another tenant's evidence.
 */
export function auditChainKey(tenant: string | null): string {
  return tenant ?? "";
}

/**
 * One preimage field: `<utf8-byte-length>:<value>\n`, or `-\n` for SQL NULL.
 *
 * Length-prefixed because plain concatenation is forgeable: without the prefix
 * `(id="ab", request_id="c")` and `(id="a", request_id="bc")` produce identical
 * bytes, so an attacker could move characters across a field boundary and keep
 * the digest. The length is in BYTES, not UTF-16 code units, so a non-ASCII
 * resource id hashes the same in every language that implements the documented
 * format.
 *
 * `-` for NULL keeps "no agent run" distinct from "agent run id is the empty
 * string" — different facts, which must not share a digest.
 */
function field(value: string | number | null): string {
  if (value === null) return "-\n";
  const text = typeof value === "number" ? String(value) : value;
  return `${new TextEncoder().encode(text).length}:${text}\n`;
}

/**
 * The canonical preimage. Exported for the documentation gate and for anyone
 * debugging a mismatch — seeing the two preimages side by side is the fastest
 * way to find which field disagrees.
 */
export function auditRowPreimage(input: AuditRowHashInput): string {
  // FIELD ORDER IS PART OF THE FORMAT. It is written as a list so a reviewer
  // can compare it line-by-line against the table in
  // `docs/audit-tamper-evidence.md`; re-ordering it silently invalidates every
  // digest ever computed, which is why the golden vector in
  // `test/audit-chain.test.ts` pins it.
  return [
    `${AUDIT_CHAIN_HASH_VERSION}\n`,
    field(input.chain_key),
    field(input.seq),
    field(input.prev_hash),
    field(input.id),
    field(input.request_id),
    field(input.agent_run_id),
    field(input.tenant),
    field(input.occurred_at_unix),
    field(input.audit_json),
  ].join("");
}

/** SHA-256 of {@link auditRowPreimage}, lowercase hex. */
export async function auditRowHash(input: AuditRowHashInput): Promise<string> {
  const bytes = new TextEncoder().encode(auditRowPreimage(input));
  const digest = await crypto.subtle.digest("SHA-256", bytes as unknown as ArrayBuffer);
  let out = "";
  for (const byte of new Uint8Array(digest)) out += byte.toString(16).padStart(2, "0");
  return out;
}

// ---------------------------------------------------------------------------
// The anchor
// ---------------------------------------------------------------------------

/** `object` discriminator of a stored anchor document. */
export const AUDIT_ANCHOR_OBJECT = "ferrogate.audit_anchor";

/** Schema version of the anchor document. */
export const AUDIT_ANCHOR_VERSION = 1;

/**
 * The periodic digest, as written to immutable storage.
 *
 * Deliberately TINY and free of row content: it is published outside the
 * database, so anything it carried would be a second copy of evidence to keep
 * in sync. `head_hash` already commits — transitively, through the chain — to
 * every row at or below `head_seq`, so these four numbers are a complete
 * fingerprint of the trail at anchoring time.
 *
 * `head_seq: 0` with `row_count: 0` is a legitimate, meaningful anchor: it
 * records "at time T this chain had no rows", which is what stops a
 * newly-initialised chain from being indistinguishable from a wiped one.
 */
export interface AuditChainAnchor {
  readonly chain_key: string;
  readonly first_seq: number;
  readonly head_seq: number;
  readonly head_hash: string;
  readonly row_count: number;
  readonly anchored_at_unix: number;
}

/** The anchor plus its self-describing envelope, as stored. */
export interface StoredAuditChainAnchor extends AuditChainAnchor {
  readonly object: typeof AUDIT_ANCHOR_OBJECT;
  readonly version: number;
}

export function storedAuditChainAnchor(anchor: AuditChainAnchor): StoredAuditChainAnchor {
  return { object: AUDIT_ANCHOR_OBJECT, version: AUDIT_ANCHOR_VERSION, ...anchor };
}

/**
 * Parse an anchor read back from storage, REFUSING anything malformed.
 *
 * Throwing rather than returning a partial anchor is the safe direction: an
 * anchor that silently degraded to `head_seq: 0` would turn "the head is
 * pinned" into "nothing to check" and a truncation would verify clean.
 */
export function parseAuditChainAnchor(value: unknown): AuditChainAnchor {
  if (value === null || typeof value !== "object") {
    throw new Error("audit anchor: not an object");
  }
  const raw = value as Record<string, unknown>;
  if (raw.object !== undefined && raw.object !== AUDIT_ANCHOR_OBJECT) {
    throw new Error(`audit anchor: unexpected object "${String(raw.object)}"`);
  }
  if (raw.version !== undefined && raw.version !== AUDIT_ANCHOR_VERSION) {
    throw new Error(`audit anchor: unsupported version ${String(raw.version)}`);
  }
  const chainKey = raw.chain_key;
  const headHash = raw.head_hash;
  if (typeof chainKey !== "string" || typeof headHash !== "string") {
    throw new Error("audit anchor: chain_key and head_hash must be strings");
  }
  const numbers = ["first_seq", "head_seq", "row_count", "anchored_at_unix"] as const;
  for (const key of numbers) {
    if (typeof raw[key] !== "number" || !Number.isFinite(raw[key])) {
      throw new Error(`audit anchor: ${key} must be a number`);
    }
  }
  return {
    chain_key: chainKey,
    first_seq: raw.first_seq as number,
    head_seq: raw.head_seq as number,
    head_hash: headHash,
    row_count: raw.row_count as number,
    anchored_at_unix: raw.anchored_at_unix as number,
  };
}

// ---------------------------------------------------------------------------
// Verification
// ---------------------------------------------------------------------------

/**
 * Why a chain could not be VERIFIED even though nothing is provably wrong.
 *
 * These are not failures and must not be reported as failures — but they are
 * not a pass either, and the distinction is the whole point of this enum. An
 * "inconclusive" verdict says "the evidence does not support a conclusion",
 * which is the honest answer for an unanchored or empty chain.
 */
export type AuditChainReason =
  /** No rows AND no anchor claiming any: nothing is proven in either direction. */
  | "empty_chain"
  /** Rows are self-consistent but no anchor pins the head, so a re-forge is possible. */
  | "unanchored"
  /** Rows present with no chain columns (legacy rows, or the gateway asset sink). */
  | "unchained_rows";

/** A provable defect in the trail. */
export type AuditChainFailureCode =
  /** The row's stored digest is not the digest of the row's contents: it was edited. */
  | "row_hash_mismatch"
  /** The row does not commit to its predecessor: a row was replaced or spliced in. */
  | "prev_hash_mismatch"
  /** The first row does not start from the genesis constant. */
  | "genesis_mismatch"
  /** The chain does not start at seq 1: rows were removed from the front. */
  | "missing_head_of_chain"
  /** A sequence number is missing: a row was deleted from the middle. */
  | "seq_gap"
  /** Rows are not in ascending sequence order. */
  | "seq_disorder"
  /** The same sequence number appears twice. */
  | "duplicate_seq"
  /** The trail stops below an anchored head, or the anchored row is gone: truncation. */
  | "truncated_below_anchor"
  /** The anchored row exists but hashes differently: the chain was re-forged. */
  | "anchor_head_mismatch"
  /** A row is structurally unusable (bad hash format, non-integer seq). */
  | "malformed_row";

export interface AuditChainFailure {
  readonly code: AuditChainFailureCode;
  readonly seq: number | null;
  readonly id: string | null;
  readonly detail: string;
}

/**
 * `verified` — every row hashes as stored, links to its predecessor, and the
 * anchored head is present and matches. `failed` — a provable alteration.
 * `inconclusive` — no alteration found, but the evidence does not support a
 * clean verdict (see {@link AuditChainReason}).
 */
export type AuditChainStatus = "verified" | "failed" | "inconclusive";

export interface AuditChainVerification {
  readonly status: AuditChainStatus;
  readonly chainKey: string;
  readonly rowCount: number;
  readonly unchainedRows: number;
  readonly firstSeq: number | null;
  readonly headSeq: number | null;
  readonly headHash: string | null;
  readonly anchorsChecked: number;
  readonly failures: readonly AuditChainFailure[];
  readonly reasons: readonly AuditChainReason[];
  /** One human-readable line; what the published script prints. */
  readonly summary: string;
}

export interface VerifyAuditChainOptions {
  readonly anchors?: readonly AuditChainAnchor[];
  /** The chain being verified. Required when `rows` is empty — there is nothing to infer it from. */
  readonly chainKey?: string;
}

const HEX64 = /^[0-9a-f]{64}$/;

/**
 * Verify ONE chain.
 *
 * Rows may arrive in any order from the caller's point of view, but order is
 * itself evidence: the admin API returns them oldest-first, so a trail whose
 * `seq` values are not ascending has been re-ordered and that is reported
 * (`seq_disorder`) rather than quietly sorted away.
 */
export async function verifyAuditChain(
  rows: readonly AuditChainRow[],
  options: VerifyAuditChainOptions = {},
): Promise<AuditChainVerification> {
  const failures: AuditChainFailure[] = [];
  const reasons: AuditChainReason[] = [];

  const chained = rows.filter((row) => row.row_hash !== null || row.seq !== null);
  const unchainedRows = rows.length - chained.length;
  const chainKey = options.chainKey ?? chained[0]?.chain_key ?? rows[0]?.tenant ?? "" ?? "";
  const anchors = (options.anchors ?? []).filter((anchor) => anchor.chain_key === chainKey);

  if (unchainedRows > 0) reasons.push("unchained_rows");

  // -- structure ------------------------------------------------------------
  let previousSeq: number | null = null;
  let previousHash: string | null = null;
  for (const row of chained) {
    const seq = row.seq;
    const rowHash = row.row_hash;
    const prevHash = row.prev_hash;
    if (
      typeof seq !== "number" ||
      !Number.isInteger(seq) ||
      typeof rowHash !== "string" ||
      !HEX64.test(rowHash) ||
      typeof prevHash !== "string" ||
      !HEX64.test(prevHash) ||
      typeof row.chain_key !== "string"
    ) {
      failures.push({
        code: "malformed_row",
        seq: typeof seq === "number" ? seq : null,
        id: row.id,
        detail: "row carries chain columns that are absent or not well-formed",
      });
      continue;
    }

    if (previousSeq === null) {
      if (seq !== AUDIT_CHAIN_FIRST_SEQ) {
        // Not "the export started late": the published procedure exports the
        // WHOLE trail, so a chain that starts at 4 is missing rows 1..3.
        failures.push({
          code: "missing_head_of_chain",
          seq,
          id: row.id,
          detail: `chain starts at seq ${seq}, not ${AUDIT_CHAIN_FIRST_SEQ}; earlier rows are missing`,
        });
      } else if (prevHash !== AUDIT_CHAIN_GENESIS_HASH) {
        failures.push({
          code: "genesis_mismatch",
          seq,
          id: row.id,
          detail: "first row does not link to the genesis hash",
        });
      }
    } else if (seq === previousSeq) {
      failures.push({
        code: "duplicate_seq",
        seq,
        id: row.id,
        detail: `sequence ${seq} appears more than once`,
      });
    } else if (seq < previousSeq) {
      failures.push({
        code: "seq_disorder",
        seq,
        id: row.id,
        detail: `sequence ${seq} follows ${previousSeq}: the trail is out of order`,
      });
    } else if (seq !== previousSeq + 1) {
      failures.push({
        code: "seq_gap",
        seq,
        id: row.id,
        detail: `sequence jumps ${previousSeq} → ${seq}: ${seq - previousSeq - 1} row(s) missing`,
      });
    } else if (previousHash !== null && prevHash !== previousHash) {
      failures.push({
        code: "prev_hash_mismatch",
        seq,
        id: row.id,
        detail: "row does not commit to its predecessor's hash",
      });
    }

    // -- content ------------------------------------------------------------
    const recomputed = await auditRowHash({
      chain_key: row.chain_key as string,
      seq,
      prev_hash: prevHash,
      id: row.id,
      request_id: row.request_id,
      agent_run_id: row.agent_run_id,
      tenant: row.tenant,
      occurred_at_unix: row.occurred_at_unix,
      audit_json: row.audit_json,
    });
    if (recomputed !== rowHash) {
      failures.push({
        code: "row_hash_mismatch",
        seq,
        id: row.id,
        detail: `stored digest ${rowHash.slice(0, 12)}… but the row's contents hash to ${recomputed.slice(0, 12)}…`,
      });
    }

    previousSeq = seq;
    previousHash = rowHash;
  }

  const first = chained[0];
  const head = chained[chained.length - 1];
  const firstSeq = first?.seq ?? null;
  const headSeq = head?.seq ?? null;
  const headHash = head?.row_hash ?? null;

  // -- anchors --------------------------------------------------------------
  const byRow = new Map<number, AuditChainRow>();
  for (const row of chained) if (typeof row.seq === "number") byRow.set(row.seq, row);

  for (const anchor of anchors) {
    if (anchor.head_seq === 0) continue; // "there was nothing here" — checked below.
    const anchored = byRow.get(anchor.head_seq);
    if (anchored === undefined) {
      failures.push({
        code: "truncated_below_anchor",
        seq: anchor.head_seq,
        id: null,
        detail:
          `anchor of ${anchor.anchored_at_unix} records ${anchor.row_count} row(s) up to seq ` +
          `${anchor.head_seq}, but the trail has no such row (highest seq present: ${headSeq ?? "none"})`,
      });
      continue;
    }
    if (anchored.row_hash !== anchor.head_hash) {
      failures.push({
        code: "anchor_head_mismatch",
        seq: anchor.head_seq,
        id: anchored.id,
        detail:
          `anchored head hash ${anchor.head_hash.slice(0, 12)}… does not match the stored row's ` +
          `${String(anchored.row_hash).slice(0, 12)}…: the chain was rewritten after it was anchored`,
      });
    }
  }

  // -- verdict --------------------------------------------------------------
  const anchoredHeads = anchors.filter((anchor) => anchor.head_seq > 0);
  if (chained.length === 0 && anchoredHeads.length === 0) reasons.push("empty_chain");
  else if (anchoredHeads.length === 0) reasons.push("unanchored");

  // A provable defect always wins; anything that merely weakens the evidence
  // downgrades a pass to `inconclusive` rather than being dropped.
  const status: AuditChainStatus =
    failures.length > 0 ? "failed" : reasons.length > 0 ? "inconclusive" : "verified";

  return {
    status,
    chainKey,
    rowCount: chained.length,
    unchainedRows,
    firstSeq,
    headSeq,
    headHash,
    anchorsChecked: anchors.length,
    failures,
    reasons,
    summary: summarize(chainKey, chained.length, unchainedRows, failures, reasons, anchors.length),
  };
}

/** The one line an operator reads. It has to name the DISTINCTION, not just the verdict. */
function summarize(
  chainKey: string,
  rowCount: number,
  unchainedRows: number,
  failures: readonly AuditChainFailure[],
  reasons: readonly AuditChainReason[],
  anchorsChecked: number,
): string {
  const name = chainKey === "" ? "the platform chain" : `chain "${chainKey}"`;
  if (failures.length > 0) {
    return `FAILED: ${name} — ${failures.length} problem(s): ${failures
      .map((failure) => `${failure.code}${failure.seq === null ? "" : ` at seq ${failure.seq}`}`)
      .join(", ")}`;
  }
  const notes: string[] = [];
  if (reasons.includes("empty_chain")) {
    notes.push(
      "no audit rows and no anchor recording any: a newly-initialised chain and a fully-deleted one are indistinguishable here, so this is NOT a clean bill of health",
    );
  }
  if (reasons.includes("unanchored")) {
    notes.push(
      `${rowCount} row(s) link correctly, but no anchor pins the head, so a wholesale rewrite would also look like this`,
    );
  }
  if (reasons.includes("unchained_rows")) {
    notes.push(
      `${unchainedRows} row(s) carry no chain columns and are OUTSIDE the tamper-evident set`,
    );
  }
  if (notes.length > 0) return `INCONCLUSIVE: ${name} — ${notes.join("; ")}`;
  return `VERIFIED: ${name} — ${rowCount} row(s) hash-chained and confirmed against ${anchorsChecked} anchor(s)`;
}

// ---------------------------------------------------------------------------
// Whole-trail verification
// ---------------------------------------------------------------------------

export interface AuditTrailVerification {
  readonly status: AuditChainStatus;
  readonly chains: readonly AuditChainVerification[];
}

/**
 * Verify a whole export: group by chain and verify each.
 *
 * The trail's verdict is the WORST of its chains, and an anchor naming a chain
 * with no rows at all still produces a chain report — otherwise deleting every
 * row of a tenant's trail would delete the evidence that the trail existed,
 * which is the attack this whole module is about.
 */
export async function verifyAuditTrail(
  rows: readonly AuditChainRow[],
  anchors: readonly AuditChainAnchor[] = [],
): Promise<AuditTrailVerification> {
  const keys = new Set<string>();
  for (const row of rows) keys.add(row.chain_key ?? auditChainKey(row.tenant));
  for (const anchor of anchors) keys.add(anchor.chain_key);

  const chains: AuditChainVerification[] = [];
  for (const key of [...keys].sort()) {
    const chainRows = rows.filter((row) => (row.chain_key ?? auditChainKey(row.tenant)) === key);
    chains.push(await verifyAuditChain(chainRows, { chainKey: key, anchors }));
  }

  const status: AuditChainStatus = chains.some((chain) => chain.status === "failed")
    ? "failed"
    : chains.some((chain) => chain.status === "inconclusive")
      ? "inconclusive"
      : "verified";
  return { status, chains };
}
