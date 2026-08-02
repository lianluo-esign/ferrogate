/**
 * Pure artifact-registry resolution: channel / semver-range → concrete version,
 * plus platform-variant selection.
 *
 * Clean-room port of `crates/ferrogate-gateway/src/asset_registry.rs`
 * (Rust issue #260). Deliberately free of I/O so the resolution rules can be
 * unit-tested directly against row slices — the handler does only the storage
 * fetch and the HTTP wiring around them.
 */
import type { StoredAsset, StoredAssetChannel } from "./ports.js";
import type { SemverRange, SemverVersion } from "./semver.js";
import { compareVersions, parseRange, parseVersion, rangeMatches } from "./semver.js";

/** How a pull reference resolved — surfaced as `x-ferrogate-asset-resolved`. */
export type VersionResolution =
  | { kind: "exact" }
  | { kind: "channel"; channel: string }
  | { kind: "range"; range: string };

export interface ResolvedVersion {
  readonly version: string;
  /**
   * `true` only for an EXACT pull of a yanked version (which still succeeds,
   * with a deprecation warning). Channel/range resolution never yields one.
   */
  readonly yanked: boolean;
  readonly how: VersionResolution;
}

/** The `x-ferrogate-asset-resolved` header value. */
export function resolutionHeaderValue(how: VersionResolution, version: string): string {
  switch (how.kind) {
    case "exact":
      return `exact=${version}`;
    case "channel":
      return `channel=${how.channel};version=${version}`;
    case "range":
      return `range=${how.range};version=${version}`;
  }
}

interface VersionState {
  readonly version: string;
  readonly yanked: boolean;
}

/**
 * Distinct versions present in `assets`, each tagged with whether it is yanked.
 * A version counts as yanked when ANY of its variant rows is yanked (the yank
 * handler marks every variant of a version together). First-seen order is
 * preserved for determinism.
 */
function versionStates(assets: readonly StoredAsset[]): VersionState[] {
  const out: { version: string; yanked: boolean }[] = [];
  for (const asset of assets) {
    const entry = out.find((candidate) => candidate.version === asset.version);
    if (entry) {
      entry.yanked = entry.yanked || asset.yanked;
    } else {
      out.push({ version: asset.version, yanked: asset.yanked });
    }
  }
  return out;
}

/**
 * Highest NON-YANKED version that parses as semver and (when a range is given)
 * satisfies it. Versions that do not parse as semver are ignored — range and
 * channel resolution are defined only over semver-shaped versions.
 */
function highestMatching(
  versions: readonly VersionState[],
  range: SemverRange | null,
): string | null {
  let best: { parsed: SemverVersion; version: string } | null = null;
  for (const state of versions) {
    if (state.yanked) continue;
    const parsed = parseVersion(state.version);
    if (!parsed) continue;
    if (range && !rangeMatches(range, parsed)) continue;
    if (best === null || compareVersions(parsed, best.parsed) > 0) {
      best = { parsed, version: state.version };
    }
  }
  return best?.version ?? null;
}

/**
 * Resolve a pull reference to a concrete version.
 *
 * Precedence, exactly as Rust `resolve_version`:
 *  1. an **exact** version match always wins and is served even when yanked
 *     (existing pins keep working, cargo-style);
 *  2. a **channel** pointer — explicit, or the implicit `latest` — resolving to
 *     its target unless that target is yanked/missing, in which case it falls
 *     back to the highest non-yanked version;
 *  3. a **semver range**.
 *
 * `null` means the reference does not resolve (HTTP 404).
 */
export function resolveVersion(
  assets: readonly StoredAsset[],
  channels: readonly StoredAssetChannel[],
  reference: string,
): ResolvedVersion | null {
  const versions = versionStates(assets);
  if (versions.length === 0) return null;

  // 1. Exact version — yanked-inclusive.
  const exact = versions.find((state) => state.version === reference);
  if (exact) {
    return { version: exact.version, yanked: exact.yanked, how: { kind: "exact" } };
  }

  // 2. Channel pointer (explicit) or the implicit `latest` channel.
  const explicit = channels.find((channel) => channel.channel === reference);
  if (explicit !== undefined || reference === "latest") {
    if (explicit) {
      const target = versions.find((state) => state.version === explicit.version);
      // A yanked target is skipped, which is the whole point of yank: the
      // version stays fetchable by exact pin but drops out of channel
      // resolution.
      if (target && !target.yanked) {
        return {
          version: target.version,
          yanked: false,
          how: { kind: "channel", channel: reference },
        };
      }
    }
    const fallback = highestMatching(versions, null);
    if (fallback !== null) {
      return {
        version: fallback,
        yanked: false,
        how: { kind: "channel", channel: reference },
      };
    }
    return null;
  }

  // 3. Semver range (`^1.2`, `~2.0`, `1`, …).
  const range = parseRange(reference);
  if (range) {
    const matched = highestMatching(versions, range);
    if (matched !== null) {
      return {
        version: matched,
        yanked: false,
        how: { kind: "range", range: reference },
      };
    }
  }

  return null;
}

/** Outcome of selecting a platform/arch variant — Rust `VariantChoice`. */
export type VariantChoice =
  | { kind: "selected"; asset: StoredAsset }
  | { kind: "not_found" }
  | { kind: "ambiguous" };

/**
 * Select the artifact for a resolved version. With an explicit `requested`
 * platform, only an exact variant match is served. Without one, the default
 * (empty-variant) artifact is preferred; failing that, a lone variant is
 * served; more than one variant is ambiguous and the client must disambiguate
 * with `?platform=`.
 */
export function selectVariant(
  rows: readonly StoredAsset[],
  requested: string | undefined,
): VariantChoice {
  if (requested !== undefined) {
    const match = rows.find((row) => row.variant === requested);
    return match ? { kind: "selected", asset: match } : { kind: "not_found" };
  }
  const fallback = rows.find((row) => row.variant === "");
  if (fallback) return { kind: "selected", asset: fallback };
  if (rows.length === 1) {
    const only = rows[0];
    return only ? { kind: "selected", asset: only } : { kind: "not_found" };
  }
  if (rows.length === 0) return { kind: "not_found" };
  return { kind: "ambiguous" };
}

/**
 * Newest-first ordering used by the manifest: semver-parseable versions sort by
 * semver descending; the rest fall back to reverse-lexical and are kept after
 * the semver ones (Rust `build_manifest`).
 */
export function compareVersionsNewestFirst(a: string, b: string): number {
  const left = parseVersion(a);
  const right = parseVersion(b);
  if (left && right) return compareVersions(right, left);
  if (left && !right) return -1;
  if (!left && right) return 1;
  return b < a ? -1 : b > a ? 1 : 0;
}
