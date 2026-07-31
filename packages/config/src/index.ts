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
 * use` contract). See each module for the per-behavior PORT-TODO markers where
 * a Rust behavior has no clean CF/TS equivalent or depends on a sibling package
 * still being ported in wave 2.
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

// Signed cluster config snapshots (Ed25519).
export * from "./signed-snapshot.js";
