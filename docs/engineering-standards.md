<!--
  Token4AI Cloud Attribution
  Developed by the commercial cloud service company represented by https://token4ai.cloud.
  Author: jamesduan (X: https://x.com/JamesDuanL)
  Created: 2026-07-24
  description: Token4AI Cloud, FerroGate AI Gateway, engineering standards:
  modular file layout for Cloudflare-scope crates, thin lib.rs rule, and the
  check-module-layout.py enforcement gate (issue #429).
-->

# Engineering Standards

Binding, repo-local engineering standards that are narrower than the
project-wide rules in `AGENTS.md`. Each standard cites the issue that created
it so the decision context stays discoverable.

## Modular file layout for Cloudflare work — keep `lib.rs` thin (issue #429)

### Problem

Feature implementations accumulate directly in `lib.rs` until the file is
unmaintainable. Measured on the current tree (2026-07-24):

| Crate `lib.rs` | Lines | Status |
|---|---:|---|
| `ferrogate-storage` | 21,146 | cautionary tale; refactor tracked separately (#419/#425) |
| `ferrogate-auth-service` | 4,395 | pre-existing offender |
| `ferrogate-mcp` | 1,837 | pre-existing offender; contains inline Cloudflare managed-MCP logic |
| `ferrogate-secrets` | 1,032 | pre-existing offender; the `cf://` Secrets Store backend lives inline |
| `ferrogate-runtime` | 166 | good: `cloudflare_worker.rs`, `cloudflare_gateway_deploy.rs`, … are sibling modules |
| `ferrogate-cloudflare` | 66 | good: the reference layout (below) |
| `ferrogate-providers` | 57 | good: `cloudflare.rs` adapter is its own module |

`ferrogate-storage/src/lib.rs` was ~13k lines when #429 was filed and is
21,146 lines now — monolith files do not stay put, they compound. New
Cloudflare (CF) work must not repeat this.

### The standard

1. **`lib.rs` stays thin.** Only `mod` / `pub use` declarations, top-level
   wiring, and crate-level docs. No substantial logic, no type definitions of
   consequence, no impl blocks beyond trivial glue.
2. **One concern per module.** `client.rs`, `config.rs`, `error.rs`,
   `types.rs`; each adapter, resolver, backend, route group, or target in its
   own file. When a concern spans multiple files, promote it to a directory
   module (`foo/mod.rs` + submodules) instead of letting one file absorb it.
3. **Soft size cap: ~500–800 lines per file.** Split *before* exceeding it,
   not after. 800 is the hard gate the lint script enforces for `lib.rs` /
   `main.rs` entry files (see below); treat 500 as the point where you start
   planning the split.
4. **Scope.** The `ferrogate-cloudflare` crate AND any CF backend added inside
   existing crates: `ferrogate-secrets` (`cf://` Secrets Store),
   `ferrogate-storage` / `ferrogate-cli` (CF-native asset backend),
   `ferrogate-runtime` (Workers deploy/control), `ferrogate-mcp` (managed
   MCP + Worker deploy), `ferrogate-providers` (AI Gateway routing adapter).
5. **Splits are internal-only.** Keep the public API stable via `pub use`
   re-exports from `lib.rs`, so callers never see the file layout change.
6. **Tests follow the testing architecture.** Test bodies live in dedicated
   sibling `*_test.rs` files wired with
   `#[cfg(test)] #[path = "..."] mod ...;` — never inline `mod tests` blocks
   (see the Testing Architecture section of `AGENTS.md`).

### Reference layout

`crates/ferrogate-cloudflare` is the canonical shape (66-line `lib.rs`):

```
src/
  lib.rs        # mod + pub use + crate docs only
  client.rs     # CloudflareClient, transport/clock seams, retry policy
  config.rs     # CloudflareConfig, base-URL defaults
  envelope.rs   # CloudflareEnvelope decode
  error.rs      # CloudflareError taxonomy
  resolver.rs   # TokenResolver seam
  scopes.rs     # required token permission groups
  *_test.rs     # sibling test files per module
```

`ferrogate-runtime` shows the same rule inside a pre-existing crate: each CF
concern (`cloudflare_worker.rs`, `cloudflare_gateway_control.rs`,
`cloudflare_gateway_deploy.rs`) is a sibling module and `lib.rs` stays at 166
lines of wiring.

### Enforcement

`scripts/check-module-layout.py` gates the rule locally:

```bash
python3 scripts/check-module-layout.py
```

- Checks `src/lib.rs` and `src/main.rs` of every CF-scope crate against the
  800-line hard cap.
- Exits nonzero on any violation; passes on the current tree because
  pre-existing offenders (`ferrogate-storage`, `ferrogate-mcp`,
  `ferrogate-secrets`) carry explicit per-file baseline ceilings.
- Baselines are a **ratchet**: they may be lowered (or removed) when the
  refactor issues (#419/#425) land, never raised. Adding a new baseline entry
  requires the same justification as raising one — i.e. it is a review-visible
  event, not a convenience.
- `--threshold N` overrides the cap for local experiments;
  `--root PATH` points the scan at a synthetic tree (used by
  `scripts/test_module_layout.py`).

Run it alongside the other lightweight local checks (`cargo fmt`,
`scripts/check-openapi.py`, `git diff --check`) before committing CF-scope
work.
