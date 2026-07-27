<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  description: Atomic channel/version lifecycle invariant + truth table (#367).
-->

# Asset channel/version lifecycle invariant (issue #367)

A channel pointer (`latest` / `stable` / `canary` or a free-form tag) is a
mutable pointer from `{tenant, asset_type, name, channel}` to a concrete
`version`. A version is made of one or more variant rows (`stored_assets`, one
per platform/arch). This document defines the single invariant every lifecycle
mutation preserves, and the truth table each backend enforces atomically.

## The invariant

> Every durable `asset_channels` row points at a **resolvable** version: the
> version has at least one variant row present and **none** of its variant rows
> is yanked.

"Resolvable" here matches channel resolution semantics (`asset_registry.rs`):
resolution treats a whole logical version as yanked when any single variant is
yanked, so a channel target is resolvable only when the version is present and
no variant is yanked.

Before #367 the channel move did two independent repository ops — read/confirm
the target is non-yanked, then upsert the channel row — with a gap in which a
concurrent yank/delete could land, leaving a durable channel on an absent or
yanked version. #367 makes each coordinating mutation atomic so the gap cannot
exist, in either direction.

## Enforcement mechanism

Every coordinating mutation performs its check and its write under **one
serialization point**, so a concurrent lifecycle change can never interleave
between the check and the write:

- **In-memory backend:** the whole check-and-mutate runs under the single
  control-plane `Mutex` the facade already holds.
- **Postgres backend:** a short, bounded transaction takes a
  `SELECT ... FOR UPDATE` row lock on the target version's `stored_assets` rows
  **first** (a single shared lock ordering used by move, yank, and delete
  alike), then reads/writes the `asset_channels` row inside the same
  transaction. Because move (writes `asset_channels`, guards on `stored_assets`)
  and yank/delete (write `stored_assets`, guard on `asset_channels`) touch two
  tables in opposite directions, two independent single statements under READ
  COMMITTED would be a write-skew hazard; contending on the same version rows
  removes it. `lock_timeout` and `statement_timeout` are pinned per transaction,
  so no lock wait is unbounded. No `pg_sleep`, no retry loop, no external work,
  no long computation runs inside the transaction (per AGENTS.md).

A mutation that can cross the async timeout uses the existing commit fence:
after `begin_commit`, a commit error is reported as `OperationCommitOutcomeUnknown`
rather than assumed-failed — a stale reread never proves failure. The guarded
upsert/update/delete are idempotent under re-drive.

## Truth table

`R` = target version resolvable (present, no yanked variant) at the
serialization point. `C` = a channel still references the version.

| Operation | Precondition | Outcome | Effect | HTTP |
|---|---|---|---|---|
| **move** `channel -> v` | `v` present, no variant yanked (`R`) | `Moved { prior_version }` | channel upserted to `v` | 200 |
| **move** `channel -> v` | `v` absent, or any variant of `v` yanked | `TargetNotResolvable` | no channel write | 404 `channel_target_not_found` |
| **yank** `v` | `v` present, not channel-referenced (`¬C`) | `Applied` | every variant of `v` set `yanked=true` | 200 |
| **yank** `v` | `v` present, channel-referenced (`C`) | `ReferencedByChannel` | no yank applied | 409 `asset_version_referenced` |
| **yank** `v` | `v` absent | `NotFound` | none | 404 `asset_not_found` |
| **unyank** `v` | `v` present | `Applied` | every variant of `v` set `yanked=false` | 200 |
| **unyank** `v` | `v` absent | `NotFound` | none | 404 `asset_not_found` |
| **variant delete** (row of `v`) | other non-yanked variant of `v` remains, OR `v` not channel-referenced | `Deleted` | that one variant row removed | 200 |
| **variant delete** (row of `v`) | it is the last resolvable variant AND `v` is channel-referenced | `BlockedByChannel` | no delete | 409 `asset_version_referenced` |
| **variant delete** | no row matches the id | `NotFound` | none | 404 `asset_not_found` |
| **whole-version delete** | modeled as deleting each variant row of `v`; the last row that would strand a referenced channel is `BlockedByChannel`, the rest `Deleted` | — | — | per-row as above |

### Policy notes

- **Yank is fail-closed while referenced** (reject, not cascade). Yank is
  reversible (unyank restores the version); silently deleting a channel pointer
  on yank and losing it on unyank would be data loss. The operator moves the
  channel off the version first, then yanks. Unyank never coordinates — restoring
  resolvability can never strand a channel.
- **Variant delete is rejected only when it would strand a referenced channel**
  (remove the last resolvable variant of a version a channel points at).
  Multi-variant versions and unreferenced versions delete freely. The bucket
  object is reaped only **after** the row delete commits, so a rejected delete
  never orphans the bucket object away from a still-live row; the #263 GC sweeper
  reclaims any object left behind by a best-effort bucket-delete failure.

## Audit evidence

Every coordinating mutation records an admin audit event carrying the prior
target, the requested target, the outcome (`committed` / `rejected`), and the
request id (via the standard audit draft):

- `asset.channel.move` — `committed` with `{prior} -> {version}`, or `rejected`
  when the target is absent/yanked.
- `asset.yank` / `asset.unyank` — `committed`, or `rejected` when still
  referenced by a channel.
- `asset.delete` — `committed`, or `rejected` when it is the last resolvable
  variant of a channel-referenced version.

## Static-site serve resolution + retained bundles (issue #397)

A `static_site` publish reuses this channel model so console rollback (#345) is
truthful at the runtime. The keying (`crates/ferrogate-gateway/src/server/sites.rs`):

- Each published bundle version is RETAINED and immutable, keyed under the
  `static_site` asset type / `name = {site}`:
  - the **bundle manifest** row lives at the bare `{bundle_version}` version and
    is the channel-resolvable target (its single row is the version's only
    variant);
  - each **file object** lives at `__site_file__:{bundle_version}:{path}`, so a
    new publish never overwrites a prior version's objects in place.
- A well-known **`serving` channel** (`{tenant}/static_site/{site}/serving`)
  points at the active bundle version. The serve path
  (`serve_site_file` → `resolve_active_site_bundle`) reads the ACTIVE bundle
  through exactly this channel, so a channel move re-points what is served —
  write-path == read-path (#188). Publishing moves `serving` to the new version
  through the atomic [`move_asset_channel_if_resolvable`] CAS above; a console
  rollback is the SAME CAS moving `serving` back to a retained prior version.

### Migration / backward compatibility

- The mutable `__site_manifest__` marker row is still rewritten on every publish
  (newest bundle). It keeps the `/admin/v1/site-domains` existence check working
  and is the **backward-compat serve source**: a site published before #397 has
  no `serving` channel, so `resolve_active_site_bundle` falls back to the marker
  and the legacy bare-`{path}` file keying. Such sites keep serving unchanged and
  migrate forward on their next publish (which writes the versioned rows + moves
  the `serving` channel). No offline backfill is required.
- Retained bundles are ADDITIVE for tenant asset-storage quota: a new version
  keeps every prior version's bytes (nothing is subtracted); reclaiming space is
  an explicit yank/delete of an old version. Re-publishing an existing
  `{bundle_version}` is rejected `409 site_version_immutable`.

## Tests

- `crates/ferrogate-storage/src/asset_channel_lifecycle_test.rs` — the truth
  table on the in-memory backend, plus the barrier-based
  `concurrent_move_and_yank_never_strand_a_channel` race proof (no timing sleep).
- `crates/ferrogate-gateway/src/server/sites_test.rs` — the #397 static-site slice
  on the in-memory backend: two bundle versions retain both, the serve path
  resolves the active version through the `serving` channel, a channel move to a
  prior version changes the served bytes (write == read), a legacy
  manifest-only site still serves, and a barrier-aligned concurrent
  `serving`-channel race never strands the pointer (no timing sleep).
- Live-Postgres coverage of the `FOR UPDATE` serialization is proved by
  inspection of the SQL here + the equivalent in-memory proof; a live Supabase
  scenario is deferred where no local Postgres is available.
