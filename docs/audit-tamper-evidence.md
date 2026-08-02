# Tamper-evident audit trail — and how to verify it yourself

FerroGate records every applied control-plane mutation as a row in
`audit_events`. This document answers the question an auditor actually asks:

> Could this record have been altered?

and gives you a procedure to answer it **without trusting us** — including the
exit codes to wire into a job, and the digest format specified byte-for-byte so
you can reimplement the check in any language.

Issue: [#684](https://github.com/lianluo-esign/ferrogate/issues/684).

---

## 1. What is protected, and what is not

| | Covered today |
|---|---|
| `audit_events` rows written by the **control plane** (`create` / `replace` / `merge` / `remove` on every admin collection) | **Yes** — hash-chained and anchored |
| `audit_events` rows written by the **gateway's asset audit sink** (`apps/gateway/src/assets/d1.ts`) | **No** — these carry no chain columns. Verification COUNTS them, reports `unchained_rows`, and downgrades its verdict to `inconclusive` rather than ignoring them |
| Rows written before the chain migration (`sql/d1-ts/control/0003_audit_chain.sql`) | **No**, same treatment as above — there is no honest digest to invent retroactively |
| `request_logs`, `guardrail_evaluations` | **No** — those tables have no writer yet (see the PORT-TODO in `apps/control-plane/src/routes/admin_request_log.ts`) |

Two mechanisms, and **neither is sufficient alone**:

1. **The hash chain.** Each row carries `(chain_key, seq, prev_hash, row_hash)`,
   where `row_hash` is a SHA-256 over the row's own fields *and* its
   predecessor's `row_hash`. Editing any field of any row changes its digest,
   and every later row commits to that digest, so an edit or an in-place
   deletion is detectable **from an export alone** — no external state, which is
   what lets you check it with nothing but your own data.

   What it cannot catch by itself: deleting the **tail**, or recomputing the
   whole chain after an edit. Both leave a chain that is internally flawless.

2. **The anchor.** A cron job publishes each chain's head —
   `(chain_key, head_seq, head_hash, row_count)`, a few hundred bytes — to an R2
   bucket, once per new head, never overwriting an object it has already
   written. A trail whose head disagrees with a published anchor is provably not
   the trail that was anchored.

### Limits we are not going to hide from you

* **The detection window is the anchor cadence.** A row appended and deleted
  between two ticks was never anchored and cannot be missed by comparison. The
  trigger is `* * * * *`, so the window is under a minute — not zero.
* **Nothing here stops a privileged actor from writing to the table.** Code
  inside the trust boundary cannot. The claim is *detection after the fact*, and
  it is the claim compliance frameworks actually make.
* **The anchor bucket's immutability is a deployment control, not a code
  control.** FerroGate never overwrites an anchor, but a principal holding R2
  credentials can still delete one. See §5.
* **One chain per tenant** (`chain_key = tenant`, empty string for
  un-attributed platform rows). The audit read fence is strict equality on
  `tenant`, so a single global chain would look full of holes to every tenant
  and be verifiable by none. Your export is a complete chain; verify it with
  *your* anchors.

---

## 2. The procedure

### Step 1 — export your trail

```bash
curl -s -H "Authorization: Bearer $FERROGATE_ADMIN_TOKEN" \
  "$FERROGATE_CONTROL_PLANE/admin/v1/audit-events?limit=1000&offset=0" \
  > trail-0.json
```

Page until you have the whole trail (`total` in the envelope tells you how far);
pass each page to the verifier with its own `--trail`. Each element carries the
chain columns and the **raw `audit_json` string** — the digest commits to those
exact bytes, so never re-serialize the parsed object before verifying.

### Step 2 — fetch your anchors

```bash
wrangler r2 object get ferrogate-audit-anchors \
  "audit-anchors/v1/k-$(printf %s "$TENANT_ID" | jq -sRr @uri)/00000000000000000042.json" \
  --file anchor.json
```

or list them all and concatenate into a JSON array:

```bash
wrangler r2 object list ferrogate-audit-anchors --prefix "audit-anchors/v1/k-$TENANT_ID/"
```

The platform chain lives under `audit-anchors/v1/k-/`. Keys are zero-padded, so
lexical order is chain order and the last key is the latest head.

Anchors are also readable with any S3-compatible client against your own R2
credentials — no FerroGate API is in the path, which is the point.

### Step 3 — verify

```bash
bun scripts/verify-audit-chain.mjs --trail trail-0.json --anchors anchor.json
```

Exit codes — **wire these into a job, do not read the output by eye**:

| Code | Meaning |
|---|---|
| `0` | **VERIFIED** — every row hashes as stored, links to its predecessor, and the anchored head is present and matches. |
| `1` | **FAILED** — a provable alteration. The output names the failure code, the sequence number and the row id. |
| `2` | **INCONCLUSIVE** — nothing wrong found, but the evidence does not support a clean verdict: an empty chain, an unanchored one, or rows outside the chain. **This is not a pass.** |
| `3` | Usage or unreadable input — a typo in your cron job, not a statement about the trail. |

`--json` prints the whole report for a machine.

### What the failure codes mean

| Code | What happened |
|---|---|
| `row_hash_mismatch` | The row's stored digest is not the digest of its contents: it was edited. |
| `prev_hash_mismatch` | A row does not commit to its predecessor: a row was replaced or spliced in. |
| `seq_gap` | A sequence number is missing: a row was deleted from the middle. |
| `duplicate_seq` | The same sequence number appears twice. |
| `missing_head_of_chain` | The chain does not start at 1: rows were removed from the front. |
| `genesis_mismatch` | The first row does not link to the genesis constant. |
| `truncated_below_anchor` | The trail stops below an anchored head, or the anchored row is gone: truncation. |
| `anchor_head_mismatch` | The anchored row exists but hashes differently: the chain was re-forged after being anchored. |
| `malformed_row` | A row's chain columns are absent or not well-formed. |

---

## 3. The digest format, so you can reimplement it

The preimage is a UTF-8 string: a version line, then nine
**length-prefixed** fields, each terminated by `\n`.

```
ferrogate.audit.v1\n
<field: chain_key>
<field: seq>
<field: prev_hash>
<field: id>
<field: request_id>
<field: agent_run_id>
<field: tenant>            # the row's `tenant` column, published as `tenant_id`
<field: occurred_at_unix>
<field: audit_json>        # the EXACT stored string
```

where a field is

* `<utf8-byte-length>:<value>\n` for a value, or
* `-\n` for SQL `NULL`.

`row_hash` is the lowercase hex SHA-256 of that string. `prev_hash` for the
first row of a chain is 64 `0`s.

Length-prefixing and the explicit NULL marker are load-bearing: without them
`(id="ab", request_id="c")` and `(id="a", request_id="bc")` would hash
identically, and an absent agent run would be indistinguishable from one whose
id is the empty string.

**Golden vector** (reproduce it before trusting your implementation):

```bash
printf 'ferrogate.audit.v1\n7:chain-a\n1:1\n64:0000000000000000000000000000000000000000000000000000000000000000\n5:evt-1\n5:req-1\n-\n7:chain-a\n10:1700000001\n2:{}\n' | sha256sum
# 62b04cd99f0869a73b2da2366f27a8343c8eedd345cc66be2bdb043b7aa25091
```

The anchor document:

```json
{
  "object": "ferrogate.audit_anchor",
  "version": 1,
  "chain_key": "t-1",
  "first_seq": 1,
  "head_seq": 42,
  "head_hash": "<row_hash of seq 42>",
  "row_count": 42,
  "anchored_at_unix": 1750000000
}
```

`head_seq: 0` with `row_count: 0` is a valid, meaningful anchor: it records that
a chain had **no rows** at that time. That is what stops a newly-initialised
chain from being indistinguishable from a wiped one.

---

## 4. Empty is not the same as verified

An integrity check that answers PASS for an empty trail hands an attacker a
clean bill of health for a total wipe. FerroGate's verifier deliberately has
three verdicts, and the empty cases resolve like this:

| Situation | Verdict |
|---|---|
| No rows, no anchor | `inconclusive` / `empty_chain` — "a newly-initialised chain and a fully-deleted one are indistinguishable here" |
| No rows, an anchor recording `head_seq: 0` | `inconclusive` / `empty_chain` — the chain provably had nothing to lose |
| No rows, an anchor recording rows | **`failed` / `truncated_below_anchor`** — the trail was deleted |
| Rows that link correctly, no anchor | `inconclusive` / `unanchored` — a wholesale rewrite would look like this too |

This is tested, not merely stated: see `packages/storage/test/audit-chain.test.ts`
("an empty or newly-initialised chain"),
`apps/control-plane/test/audit-chain-d1.test.ts` ("distinguishes 'never had
rows' from 'rows were deleted'") and
`packages/storage/test/verify-audit-chain-script.test.ts`, which executes the
script above and asserts its exit codes.

---

## 5. Operator setup

1. Create the bucket and bind it:

   ```toml
   # apps/control-plane/wrangler.toml
   [[r2_buckets]]
   binding = "AUDIT_ANCHORS"
   bucket_name = "<your bucket>"
   ```

   With no binding the deployment keeps the hash chain but loses truncation
   detection, and every tick logs
   `audit chains are NOT anchored`. Check for that line before claiming
   tamper-evidence to a customer.

2. **Turn on R2 object lock / a retention policy for the bucket.** FerroGate
   never overwrites an anchor, so anchors are append-only *from the Worker* —
   but only a bucket-level retention rule stops someone with R2 credentials
   deleting one, and only the account owner can set it.

3. **Prefer credentials (ideally an account) separate from the one that owns the
   D1 database.** An anchor is worth exactly as much as the difficulty of
   forging it and the database in the same breath.

4. Apply the migration: `wrangler d1 migrations apply ferrogate-control`.
   Rows written before it stay unchained and are reported as such.

---

## 6. Where the code is

| Part | File |
|---|---|
| Digest, anchor format, verifier | `packages/storage/src/audit-chain.ts` |
| Chained writer | `apps/control-plane/src/store/d1.ts` (`#audit`) |
| Anchor job | `apps/control-plane/src/audit/anchor.ts` |
| Cron wiring | `apps/control-plane/src/schedule/scheduled.ts` |
| Schema | `sql/d1-ts/control/0003_audit_chain.sql` |
| Published verifier | `scripts/verify-audit-chain.mjs` |
