/**
 * The pure resolution rules (`registry.ts` + `semver.ts`), asserted directly
 * against row slices.
 *
 * These are exercised end-to-end by `service.test.ts` too; they are pinned
 * separately here because a silent behavioral difference from the Rust `semver`
 * crate would quietly move which version a `^1.2` pull resolves to — a defect
 * with no error message anywhere.
 */
import { describe, expect, test } from "vitest";
import type { StoredAsset, StoredAssetChannel } from "../../src/assets/ports.js";
import {
  compareVersionsNewestFirst,
  resolutionHeaderValue,
  resolveVersion,
  selectVariant,
} from "../../src/assets/registry.js";
import {
  compareVersions,
  parseRange,
  parseVersion,
  rangeMatches,
  type SemverRange,
  type SemverVersion,
} from "../../src/assets/semver.js";

function row(version: string, over: Partial<StoredAsset> = {}): StoredAsset {
  return {
    id: `tenant_a:cli:fg:${version}`,
    tenant_id: "tenant_a",
    asset_type: "cli",
    name: "fg",
    version,
    content_type: "application/octet-stream",
    content_hash: "0".repeat(64),
    size_bytes: 1,
    storage_uri: `assets/v1/t/tenant_a/obj/cli/fg/${version}/_/obj_x`,
    variant: "",
    yanked: false,
    visibility: "visible",
    created_at_unix: 0,
    updated_at_unix: 0,
    ...over,
  };
}

function channel(name: string, version: string): StoredAssetChannel {
  return {
    id: `tenant_a:cli:fg:${name}`,
    tenant_id: "tenant_a",
    asset_type: "cli",
    name: "fg",
    channel: name,
    version,
    updated_at_unix: 0,
  };
}

describe("resolveVersion precedence", () => {
  const rows = [row("1.0.0"), row("1.4.2"), row("2.0.0")];

  test("an exact version always wins over a same-named channel", () => {
    // A channel literally named `1.0.0` must not shadow the version `1.0.0`.
    const resolved = resolveVersion(rows, [channel("1.0.0", "2.0.0")], "1.0.0");
    expect(resolved).toEqual({ version: "1.0.0", yanked: false, how: { kind: "exact" } });
  });

  test("a channel resolves to its target", () => {
    const resolved = resolveVersion(rows, [channel("stable", "1.4.2")], "stable");
    expect(resolved?.version).toBe("1.4.2");
    expect(resolved?.how).toEqual({ kind: "channel", channel: "stable" });
  });

  test("a channel whose target is yanked falls back to the highest live version", () => {
    const yanked = [row("1.0.0"), row("1.4.2", { yanked: true }), row("2.0.0")];
    const resolved = resolveVersion(yanked, [channel("stable", "1.4.2")], "stable");
    expect(resolved?.version).toBe("2.0.0");
  });

  test("`latest` is implicit even with no channel row", () => {
    expect(resolveVersion(rows, [], "latest")?.version).toBe("2.0.0");
  });

  test("an unresolvable reference is null, never a lucky match", () => {
    expect(resolveVersion(rows, [], "3.0.0")).toBeNull();
    expect(resolveVersion(rows, [], "not-a-range")).toBeNull();
    expect(resolveVersion([], [], "latest")).toBeNull();
  });

  test("a version counts as yanked when ANY of its variants is", () => {
    const mixed = [
      row("1.0.0", { id: "a", variant: "linux" }),
      row("1.0.0", { id: "b", variant: "darwin", yanked: true }),
      row("0.9.0"),
    ];
    expect(resolveVersion(mixed, [], "latest")?.version).toBe("0.9.0");
    // ...but the exact pin still resolves, and reports the yank.
    expect(resolveVersion(mixed, [], "1.0.0")).toEqual({
      version: "1.0.0",
      yanked: true,
      how: { kind: "exact" },
    });
  });

  test("the resolution header names how the reference resolved", () => {
    expect(resolutionHeaderValue({ kind: "exact" }, "1.0.0")).toBe("exact=1.0.0");
    expect(resolutionHeaderValue({ kind: "channel", channel: "stable" }, "1.0.0")).toBe(
      "channel=stable;version=1.0.0",
    );
    expect(resolutionHeaderValue({ kind: "range", range: "^1" }, "1.4.2")).toBe(
      "range=^1;version=1.4.2",
    );
  });
});

/**
 * Parse-or-fail helpers. A `!` would silently coerce a parser regression into a
 * `TypeError` deep inside the assertion; these name the input that failed.
 */
function ver(value: string): SemverVersion {
  const parsed = parseVersion(value);
  if (parsed === null) throw new Error(`not a semver version: ${value}`);
  return parsed;
}

function range(value: string): SemverRange {
  const parsed = parseRange(value);
  if (parsed === null) throw new Error(`not a semver range: ${value}`);
  return parsed;
}

describe("semver rules ported from the Rust crate", () => {
  test("the default comparator operator is caret, not exact", () => {
    expect(rangeMatches(range("1.2"), ver("1.9.0"))).toBe(true);
    expect(rangeMatches(range("1.2"), ver("2.0.0"))).toBe(false);
  });

  test("caret below 1.0.0 pins the minor", () => {
    expect(rangeMatches(range("^0.2.1"), ver("0.2.9"))).toBe(true);
    expect(rangeMatches(range("^0.2.1"), ver("0.3.0"))).toBe(false);
  });

  test("a pre-release only satisfies a comparator that pins it", () => {
    // Without this rule `^1.0.0` would silently hand out `1.1.0-alpha`.
    expect(rangeMatches(range("^1.0.0"), ver("1.1.0-alpha"))).toBe(false);
    expect(rangeMatches(range("^1.1.0-alpha"), ver("1.1.0-beta"))).toBe(true);
  });

  test("numeric pre-release identifiers compare numerically", () => {
    expect(compareVersions(ver("1.0.0-2"), ver("1.0.0-10"))).toBeLessThan(0);
    // ...and sort below alphanumeric ones.
    expect(compareVersions(ver("1.0.0-2"), ver("1.0.0-alpha"))).toBeLessThan(0);
    // A release outranks any of its pre-releases.
    expect(compareVersions(ver("1.0.0"), ver("1.0.0-rc.1"))).toBeGreaterThan(0);
  });

  test("build metadata is ignored for precedence", () => {
    expect(compareVersions(ver("1.0.0+a"), ver("1.0.0+b"))).toBe(0);
  });

  test("comma-separated comparators are ANDed", () => {
    expect(rangeMatches(range(">=1.2.0,<1.5.0"), ver("1.4.9"))).toBe(true);
    expect(rangeMatches(range(">=1.2.0,<1.5.0"), ver("1.5.0"))).toBe(false);
  });

  test("garbage is not a range", () => {
    expect(parseRange("stable")).toBeNull();
    expect(parseVersion("1.0")).toBeNull();
    expect(parseVersion("1.0.0-")).toBeNull();
  });
});

describe("manifest ordering", () => {
  test("semver sorts newest-first and non-semver is kept after it", () => {
    const versions = ["1.9.0", "nightly", "1.10.0", "alpha"];
    expect([...versions].sort(compareVersionsNewestFirst)).toEqual([
      "1.10.0",
      "1.9.0",
      "nightly",
      "alpha",
    ]);
  });
});

describe("selectVariant", () => {
  const linux = row("1.0.0", { id: "a", variant: "linux" });
  const mac = row("1.0.0", { id: "b", variant: "mac" });
  const rows = [linux, mac];

  test("an explicit request is matched exactly or not at all", () => {
    expect(selectVariant(rows, "linux")).toEqual({ kind: "selected", asset: linux });
    expect(selectVariant(rows, "windows")).toEqual({ kind: "not_found" });
  });

  test("several variants with no request is ambiguous, never a guess", () => {
    expect(selectVariant(rows, undefined)).toEqual({ kind: "ambiguous" });
  });

  test("a lone variant is served without a request", () => {
    expect(selectVariant([mac], undefined)).toEqual({ kind: "selected", asset: mac });
  });

  test("the default (empty) variant is preferred", () => {
    const fallback = row("1.0.0", { id: "c" });
    expect(selectVariant([...rows, fallback], undefined)).toEqual({
      kind: "selected",
      asset: fallback,
    });
  });
});
