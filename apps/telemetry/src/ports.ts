/**
 * The Worker's environment and the one place a binding is turned into a port.
 *
 * `apps/gateway` degrades to `503 asset_bucket_unavailable` when its R2 binding
 * is absent rather than throwing a binding-is-undefined `TypeError`; the sink
 * here follows exactly that pattern — {@link resolveSink} returns `null` and
 * the ingest routes answer `503 telemetry_sink_unavailable`.
 */
import { type AnalyticsEngineLike, AnalyticsEngineSink, type TelemetrySink } from "./sink.js";

/** Bindings + vars this Worker reads. Everything is OPTIONAL by design. */
export interface TelemetryEnv {
  /**
   * The Analytics Engine dataset. `writeDataPoint()` is the ONLY write path
   * Cloudflare offers; the dataset's HTTP API is SQL read-only. Declared in
   * `wrangler.toml` as `[[analytics_engine_datasets]] binding = "TELEMETRY"`.
   */
  TELEMETRY?: AnalyticsEngineLike;
  /**
   * Shared secret every ingest request must present as `Authorization: Bearer`
   * (`@ferrogate/observability`'s `CloudflareBackend` sends exactly this).
   * Seeded with `wrangler secret put COLLECTOR_TOKEN`, never committed. With it
   * unset the collector fails CLOSED rather than accepting anonymous telemetry.
   */
  COLLECTOR_TOKEN?: string;
  /** Per-request body ceiling in bytes, as a string (Worker vars are strings). */
  MAX_BODY_BYTES?: string;
}

/** Hono binding generic for this Worker. */
export type TelemetryBindings = { Bindings: TelemetryEnv };

/**
 * Turn the environment into the sink port, or `null` when this Worker has no
 * Analytics Engine binding.
 *
 * `null` is not an error here — it is the *unconfigured* state, which the ingest
 * routes report as `503`. The `typeof` check is deliberate: a Worker deployed
 * without the dataset gets `undefined`, and a misconfigured one could get an
 * object that is not the binding.
 */
export function resolveSink(env: TelemetryEnv | undefined): TelemetrySink | null {
  const dataset = env?.TELEMETRY;
  if (!dataset || typeof dataset.writeDataPoint !== "function") return null;
  return new AnalyticsEngineSink(dataset);
}
