/**
 * `@ferrogate/config` — clean-room TypeScript port of the Rust crate
 * `ferrogate-config` (inventory §5).
 *
 * The operator-facing configuration: the `Config` model, its loader and the
 * validation that refuses a bad one, the Caddyfile→Config compatibility bridge,
 * secret-placeholder resolution, R2/asset endpoint decomposition, pre-auth
 * network-access primitives, upstream/route URI building, config-snapshot ids,
 * and Ed25519-signed cluster config snapshots.
 *
 * Public surface is a curated re-export list (mirroring the Rust `lib.rs` `pub
 * use` contract).
 *
 * Every remaining PORT-TODO marker in this package is tagged with WHY it is
 * still there, so a reader never has to guess whether it is pending work:
 *   - `PLATFORM LIMIT, NOT CLOSED` — workerd genuinely cannot express the Rust
 *     behavior (no filesystem, no `std::env`, no socket peer address, no
 *     cross-isolate shared state, no synchronous Ed25519, CF-terminated TLS).
 *     The closest behavior is implemented and PINNED by a test; see
 *     `test/platform-limits.test.ts` and the per-module marker.
 *   - `PACKAGE RELOCATION ONLY, BEHAVIOR IS CLOSED` — logic ported verbatim and
 *     inlined here so this package validates standalone; only the import edge
 *     to a sibling is outstanding. The `@ferrogate/{providers,storage,guardrails}`
 *     enum edges are now CLOSED (imported from their owner, pinned by
 *     `test/sibling-enum-parity.test.ts`); what remains has no owning
 *     `packages/*` library to import FROM — `ferrogate-mcp` is ported inside the
 *     `apps/mcp` Worker and there is no `@ferrogate/cloudflare` package, and a
 *     library must not depend on an app.
 *   - `DELIBERATE PRODUCT DECISION` — x402/Solana payments are deprioritized.
 *
 * The TLS/ACME validators are not marked at all: they were REMOVED as N/A on
 * Cloudflare, with the reason recorded at their old call site in `./validate.ts`.
 */

// The Config model (Zod schema tree + inferred types + defaults + accessors).
export * from "./schema/index.js";

// Loader: alias migration, object loader, Caddyfile bridge.
export {
  isCaddyfilePath,
  migrateControlPlaneAliases,
  loadConfigFromObject,
  fromGatewayConfig,
  fromCaddyfileStr,
} from "./loader.js";
export type { AliasMigration } from "./loader.js";

// Validation: the whole `Config::validate()` surface — the entry point, every
// per-section/per-entity validator, and the shared helpers (`./validate.ts`
// re-exports `./validate/*`, so this is one module's worth of exports).
export * from "./validate.js";
export type { ValidateOptions } from "./validate.js";

// Caddyfile compatibility layer.
export { parseCaddyfile } from "./caddyfile/parser.js";
export { lex } from "./caddyfile/lexer.js";
export type { Token, TokenKind } from "./caddyfile/lexer.js";
export * from "./caddyfile/types.js";
export {
  adaptSiteAddress,
  caddyPathToPrefix,
  envReference,
  looksLikeUpstream,
  modelRefArg,
  globalSuggestion,
} from "./caddyfile/parser-support.js";
export { CaddyfileDiagnostic } from "./diagnostic.js";
export type { CaddyfileDiagnosticData } from "./diagnostic.js";

// Asset endpoint (R2) decomposition.
export * from "./asset-endpoint.js";

// Network access primitives.
export * from "./network-access.js";

// Routing / upstream URI building.
export * from "./routing.js";

// Config snapshot id + env placeholders.
export { configSnapshotId, fnv1a64 } from "./snapshot.js";
export { resolveEnvPlaceholders } from "./secrets.js";
export type { EnvSource } from "./secrets.js";

// x402 hold-TTL floor + scope surface (deprioritized).
export { x402ConfirmationWindowSecs, x402HoldTtlFloorSecs } from "./x402-hold.js";
export type { X402ReconcilerLike } from "./x402-hold.js";
export * from "./x402-scope.js";

// Declarative desired-state document + the pure GitOps diff engine (#702).
export * from "./desired-state.js";

// Signed cluster config snapshots (Ed25519).
export * from "./signed-snapshot.js";

// Prompt deployment labels: the `label -> revision` pointer and its KV key.
// Exported from the CONFIG package rather than either Worker because
// `apps/control-plane` writes the pointer and `apps/gateway` reads it, and a
// key derivation that exists twice is a key derivation that drifts silently.
export * from "./prompt-label.js";
