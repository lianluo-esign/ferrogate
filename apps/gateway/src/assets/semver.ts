/**
 * Minimal semver parse / compare / range matcher.
 *
 * Clean-room re-implementation of the subset of the Rust `semver` crate that
 * `asset_registry.rs` and `assets.rs::build_manifest` relied on:
 * `Version::parse`, `Version: Ord`, `VersionReq::parse` and `VersionReq::matches`.
 *
 * Written here rather than pulled from npm because this app must not add a
 * dependency (a concurrent workflow owns `node_modules` and the lockfile), and
 * because the matching rules are load-bearing for asset resolution — a silent
 * behavioral difference between the Rust and TS range matchers would move which
 * version a `^1.2` pull resolves to.
 *
 * Rules reproduced from the Rust crate:
 *  - the default comparator operator is **caret** (`1.2` ≡ `^1.2`);
 *  - comma-separated comparators are ANDed;
 *  - a **pre-release** version only matches a comparator that pins the same
 *    `major.minor.patch` *and* itself carries a pre-release;
 *  - pre-release precedence: numeric identifiers compare numerically, numeric
 *    sorts below alphanumeric, and a version with a pre-release sorts below the
 *    same version without one;
 *  - build metadata is ignored for precedence.
 */

export interface SemverVersion {
  readonly major: number;
  readonly minor: number;
  readonly patch: number;
  /** Dot-separated pre-release identifiers; empty when absent. */
  readonly prerelease: readonly string[];
  readonly build: string;
}

const VERSION_RE = /^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?(?:\+([0-9A-Za-z.-]+))?$/;

/** Rust `semver::Version::parse` — `null` when the string is not semver. */
export function parseVersion(value: string): SemverVersion | null {
  const match = VERSION_RE.exec(value.trim());
  if (!match) return null;
  const [, major, minor, patch, prerelease, build] = match;
  if (major === undefined || minor === undefined || patch === undefined) {
    return null;
  }
  const pre = prerelease === undefined ? [] : prerelease.split(".");
  // An empty pre-release identifier (`1.0.0-`) is invalid.
  if (pre.some((identifier) => identifier.length === 0)) return null;
  return {
    major: Number(major),
    minor: Number(minor),
    patch: Number(patch),
    prerelease: pre,
    build: build ?? "",
  };
}

function comparePrerelease(a: readonly string[], b: readonly string[]): number {
  // No pre-release outranks any pre-release.
  if (a.length === 0 && b.length === 0) return 0;
  if (a.length === 0) return 1;
  if (b.length === 0) return -1;
  const length = Math.max(a.length, b.length);
  for (let i = 0; i < length; i += 1) {
    const left = a[i];
    const right = b[i];
    if (left === undefined) return -1;
    if (right === undefined) return 1;
    const leftNumeric = /^\d+$/.test(left);
    const rightNumeric = /^\d+$/.test(right);
    if (leftNumeric && rightNumeric) {
      const diff = Number(left) - Number(right);
      if (diff !== 0) return diff < 0 ? -1 : 1;
      continue;
    }
    // Numeric identifiers always have lower precedence than alphanumeric ones.
    if (leftNumeric) return -1;
    if (rightNumeric) return 1;
    if (left !== right) return left < right ? -1 : 1;
  }
  return 0;
}

/** Total order over versions (build metadata ignored) — Rust `Version: Ord`. */
export function compareVersions(a: SemverVersion, b: SemverVersion): number {
  if (a.major !== b.major) return a.major < b.major ? -1 : 1;
  if (a.minor !== b.minor) return a.minor < b.minor ? -1 : 1;
  if (a.patch !== b.patch) return a.patch < b.patch ? -1 : 1;
  return comparePrerelease(a.prerelease, b.prerelease);
}

type ComparatorOp = "=" | ">" | ">=" | "<" | "<=" | "^" | "~" | "*";

interface Comparator {
  readonly op: ComparatorOp;
  readonly major: number;
  /** `undefined` for a partial comparator such as `^1` or `1.2`. */
  readonly minor: number | undefined;
  readonly patch: number | undefined;
  readonly prerelease: readonly string[];
}

/** A parsed range: a conjunction of comparators. */
export interface SemverRange {
  readonly comparators: readonly Comparator[];
}

const COMPARATOR_RE =
  /^(\^|~|=|>=|<=|>|<)?\s*(\d+|\*|x|X)(?:\.(\d+|\*|x|X))?(?:\.(\d+|\*|x|X))?(?:-([0-9A-Za-z.-]+))?(?:\+[0-9A-Za-z.-]+)?$/;

function parseComparator(value: string): Comparator | null {
  const trimmed = value.trim();
  if (trimmed === "") return null;
  if (trimmed === "*") {
    return {
      op: "*",
      major: 0,
      minor: undefined,
      patch: undefined,
      prerelease: [],
    };
  }
  const match = COMPARATOR_RE.exec(trimmed);
  if (!match) return null;
  const [, rawOp, rawMajor, rawMinor, rawPatch, rawPre] = match;
  if (rawMajor === undefined) return null;
  const wildcard = (part: string | undefined): number | undefined =>
    part === undefined || part === "*" || part === "x" || part === "X" ? undefined : Number(part);
  if (rawMajor === "*" || rawMajor === "x" || rawMajor === "X") {
    return { op: "*", major: 0, minor: undefined, patch: undefined, prerelease: [] };
  }
  const minor = wildcard(rawMinor);
  const patch = wildcard(rawPatch);
  // `1.*.3` is nonsense; a wildcard minor forces a wildcard patch.
  if (minor === undefined && patch !== undefined) return null;
  const pre = rawPre === undefined ? [] : rawPre.split(".");
  if (pre.some((identifier) => identifier.length === 0)) return null;
  return {
    // Rust's default comparator operator is Caret, not Exact.
    op: (rawOp as ComparatorOp | undefined) ?? "^",
    major: Number(rawMajor),
    minor,
    patch,
    prerelease: pre,
  };
}

/**
 * Rust `semver::VersionReq::parse`. Returns `null` for anything that is not a
 * range — which is what makes an unresolvable pull reference a 404 rather than
 * an accidental match.
 */
export function parseRange(value: string): SemverRange | null {
  const trimmed = value.trim();
  if (trimmed === "") return null;
  if (trimmed === "*") {
    return {
      comparators: [{ op: "*", major: 0, minor: undefined, patch: undefined, prerelease: [] }],
    };
  }
  const parts = trimmed.split(",");
  const comparators: Comparator[] = [];
  for (const part of parts) {
    const comparator = parseComparator(part);
    if (!comparator) return null;
    comparators.push(comparator);
  }
  return comparators.length > 0 ? { comparators } : null;
}

function comparatorLowerBound(comparator: Comparator): SemverVersion {
  return {
    major: comparator.major,
    minor: comparator.minor ?? 0,
    patch: comparator.patch ?? 0,
    prerelease: comparator.prerelease,
    build: "",
  };
}

/** Upper bound (exclusive) of a caret/tilde/partial comparator. */
function comparatorUpperBound(comparator: Comparator): SemverVersion | null {
  const { op, major, minor, patch } = comparator;
  const bound = (nextMajor: number, nextMinor: number, nextPatch: number): SemverVersion => ({
    major: nextMajor,
    minor: nextMinor,
    patch: nextPatch,
    // `-0` is the lowest possible pre-release, making the bound exclusive of
    // every pre-release of the boundary version (Rust's semantics).
    prerelease: ["0"],
    build: "",
  });
  if (op === "^") {
    if (minor === undefined) return bound(major + 1, 0, 0);
    if (patch === undefined) {
      return major > 0 ? bound(major + 1, 0, 0) : bound(0, minor + 1, 0);
    }
    if (major > 0) return bound(major + 1, 0, 0);
    if (minor > 0) return bound(0, minor + 1, 0);
    return bound(0, 0, patch + 1);
  }
  if (op === "~") {
    if (minor === undefined) return bound(major + 1, 0, 0);
    return bound(major, minor + 1, 0);
  }
  if (op === "=") {
    if (minor === undefined) return bound(major + 1, 0, 0);
    if (patch === undefined) return bound(major, minor + 1, 0);
    return null; // fully pinned: handled by exact comparison
  }
  return null;
}

function matchesComparator(version: SemverVersion, comparator: Comparator): boolean {
  if (comparator.op === "*") return version.prerelease.length === 0;

  // Rust: a pre-release version only satisfies a comparator that pins the same
  // major.minor.patch AND itself carries a pre-release. Otherwise `^1.0.0` would
  // silently hand out `1.1.0-alpha`.
  if (version.prerelease.length > 0) {
    const samePin =
      comparator.minor !== undefined &&
      comparator.patch !== undefined &&
      comparator.major === version.major &&
      comparator.minor === version.minor &&
      comparator.patch === version.patch;
    if (!samePin || comparator.prerelease.length === 0) return false;
  }

  const lower = comparatorLowerBound(comparator);
  switch (comparator.op) {
    case ">":
      return compareVersions(version, lower) > 0;
    case ">=":
      return compareVersions(version, lower) >= 0;
    case "<":
      return compareVersions(version, lower) < 0;
    case "<=":
      return compareVersions(version, lower) <= 0;
    case "=": {
      if (comparator.minor !== undefined && comparator.patch !== undefined) {
        return compareVersions(version, lower) === 0;
      }
      const upper = comparatorUpperBound(comparator);
      return (
        compareVersions(version, lower) >= 0 &&
        (upper === null || compareVersions(version, upper) < 0)
      );
    }
    case "^":
    case "~": {
      const upper = comparatorUpperBound(comparator);
      return (
        compareVersions(version, lower) >= 0 &&
        (upper === null || compareVersions(version, upper) < 0)
      );
    }
    default:
      return false;
  }
}

/** Rust `VersionReq::matches`. */
export function rangeMatches(range: SemverRange, version: SemverVersion): boolean {
  return range.comparators.every((comparator) => matchesComparator(version, comparator));
}
