/**
 * `apps/gateway` asset surface — the 18 `/v1/assets/**` operations in the
 * `assets` route group of `docs/openapi/runtime-api-contract.json`.
 *
 * Mount it from the app shell:
 *
 * ```ts
 * import { assetRouteModule } from "./assets/index.js";
 * const { app } = createGatewayApp({ modules: [assetRouteModule({ deps })] });
 * ```
 *
 * With no arguments every port falls back to the offline in-memory default:
 * enough to boot and to test, but no bucket is configured, so the presign
 * family answers `503 asset_bucket_unavailable` exactly as an unconfigured Rust
 * gateway does — it never silently routes object bytes through the Worker.
 *
 * PRODUCTION WIRING IS LIVE. `src/index.ts` mounts
 * `assetRouteModule({ depsFromEnv: assetDepsFromEnv })`, which reads the real
 * `env.ASSETS` R2 bucket and — when the five `ASSET_S3_*` values are bound —
 * a real `SigV4Presigner`, per request, memoized on the `env` object. The
 * object-store port is R2-shaped, so a live `R2Bucket` satisfies it with no
 * adapter and no cast.
 */
export {
  ORDERED_ASSET_OPERATION_IDS,
  assetDepsFromEnv,
  assetRouteModule,
  buildAssetService,
  defaultCallerResolver,
  configuredEntitlementsFromEnv,
  entitlementsFromEnv,
  sigV4PresignerFromEnv,
  NO_ASSET_HOSTING,
} from "./handlers.js";
export type {
  AssetBindings,
  AssetCallerResolver,
  AssetEntitlements,
  AssetEntitlementsPort,
  AssetObjectBindings,
  AssetRouteModuleOptions,
} from "./handlers.js";

export * from "./content-gate.js";
export * from "./d1.js";
export * from "./egress.js";
export * from "./entitlements.js";
export * from "./service.js";
export * from "./ports.js";
export * from "./scan.js";
export * from "./signature.js";
export * from "./signature-screener.js";
export * from "./guardrail-screener.js";
export * from "./keys.js";
export * from "./registry.js";
export * from "./schemas.js";
export { SigV4Presigner, formatTimestamps } from "./sigv4.js";
export type { R2S3Endpoint } from "./sigv4.js";
export {
  isHexSha256,
  randomHex128,
  sha256Hex,
  timingSafeEqual,
  toHex,
} from "./hash.js";
export {
  compareVersions,
  parseRange,
  parseVersion,
  rangeMatches,
} from "./semver.js";
export type { SemverRange, SemverVersion } from "./semver.js";
