# Versioning

## The scheme

```
v<YYYY>.<MM>.<DD>-betav<N>        while in beta
v<YYYY>.<MM>.<DD>                 after graduation
```

Examples: `v2026.08.02-betav1`, `v2026.08.02-betav2`, `v2026.09.14-betav7`,
then one day `v2026.10.01`.

**CalVer for the date part.** This carries over unchanged from the Rust era
(`v2026.05.05` … `v2026.07.18`), so the tag history stays sortable and the
pre-rewrite releases keep their meaning.

## The beta suffix

`-betav<N>` is **not decoration and not a formality.** It is a claim about the
product, and it comes off only when FerroGate is genuinely bug-free and
feature-complete. Until that is true, every release carries it.

**`N` grows monotonically across dates.** It is not a counter of releases made on
a given day — it counts iterations of the beta *phase*, which is the thing the
suffix is about:

```
v2026.08.02-betav1     ← first beta
v2026.08.05-betav2     ← next one, whenever it lands
v2026.08.05-betav3     ← same day is fine; N still just increments
v2026.09.20-betav11
v2026.10.01            ← graduation: the suffix is dropped, N is retired
```

If two releases land on the same date, the date repeats and `N` increments —
that is the whole reason `N` exists, and it also means a tag is never ambiguous.

**Dropping the suffix is a graduation event.** It should be a deliberate decision
with the open P0 list empty, not something that happens because a release felt
significant. Once dropped, do not reintroduce it for the same line; if the
product regresses that far, that is a defect to fix, not a version to relabel.

## GitHub release flags

A `-betav<N>` release is published with `--prerelease`. That is the machine-
readable half of the same claim the suffix makes in the tag name, and tooling
that resolves "the newest stable release" should skip it.

## Practical notes

- Tags are **annotated** (`git tag -a`), never lightweight — the message carries
  the same headline as the release notes, so `git show <tag>` is informative
  without network access.
- Cut the tag on a commit CI has already proven green, not on whatever `main`
  happens to be at the moment of tagging.
- Release notes lead with known defects. A reader deciding whether to deploy
  needs those in the first screen, not in an appendix.

## What the version does NOT currently track

Every Worker self-reports `version: "0.0.0"` at `/healthz` and `/readyz`. The
string is hard-coded independently in six places and pinned by three test
assertions, so it does not follow this scheme and does not change when a tag is
cut. Single-sourcing it — and redeploying so the live fleet agrees — is
outstanding work; until it lands, do not read a deployed Worker's `version`
field as the release it came from.
