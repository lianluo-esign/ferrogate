/**
 * The telemetry backend contract: the seam a concrete observability
 * destination plugs into (#520). Clean-room port of
 * `ferrogate-observability::backend`.
 *
 * Backends **build** requests; they never send them (transport lives in the
 * CLI/edge caller). Each `*Request` returns `null` when there is nothing to
 * send — empty batch or an unsupported signal — so callers never pair a
 * `supports()` check with an emptiness check. Config problems (bad endpoint,
 * missing credential) surface as a thrown {@link ObservabilityConfigError}, and
 * {@link TelemetryBackend.validate} returns that error (or `null`) so a
 * misconfigured backend fails fast at startup.
 */
import type { ObservabilityConfigError } from "./config.js";
import { ObservabilitySignal } from "./config.js";
import type { GatewayMetricsSnapshot } from "./metrics.js";
import {
  buildOtlpLogsRequest,
  buildOtlpMetricsRequest,
  buildOtlpTracesRequest,
} from "./otlp.js";
import type {
  OtlpHttpRequest,
  OtlpLogRecord,
  OtlpSpanRecord,
} from "./otlp.js";

/** A destination for FerroGate telemetry. */
export interface TelemetryBackend {
  /** Stable identifier used in status output and export error messages. */
  name(): string;
  /** Whether this backend carries `signal` at all. */
  supports(signal: ObservabilitySignal): boolean;
  metricsRequest(snapshot: GatewayMetricsSnapshot): OtlpHttpRequest | null;
  tracesRequest(
    serviceName: string,
    spans: readonly OtlpSpanRecord[],
  ): OtlpHttpRequest | null;
  logsRequest(
    serviceName: string,
    logs: readonly OtlpLogRecord[],
  ): OtlpHttpRequest | null;
  /** Checked once at startup; returns the error (or `null`) instead of throwing. */
  validate(): ObservabilityConfigError | null;
}

/** Every signal, in the order the export loop emits them. */
export const ALL_SIGNALS: readonly ObservabilitySignal[] = [
  ObservabilitySignal.Metric,
  ObservabilitySignal.Trace,
  ObservabilitySignal.Log,
];

/**
 * Plain OTLP/HTTP+JSON to a collector that needs no credential — kept as a
 * first-class backend so the generic export loop has no special case for it.
 */
export class OtlpBackend implements TelemetryBackend {
  private readonly endpoint_: string;
  private signals: ObservabilitySignal[];

  constructor(endpoint: string) {
    this.endpoint_ = endpoint;
    this.signals = [...ALL_SIGNALS];
  }

  withSignals(signals: ObservabilitySignal[]): this {
    this.signals = signals;
    return this;
  }

  endpoint(): string {
    return this.endpoint_;
  }

  name(): string {
    return "otlp";
  }

  supports(signal: ObservabilitySignal): boolean {
    return this.signals.includes(signal);
  }

  metricsRequest(snapshot: GatewayMetricsSnapshot): OtlpHttpRequest | null {
    if (!this.supports(ObservabilitySignal.Metric)) {
      return null;
    }
    return buildOtlpMetricsRequest(this.endpoint_, snapshot);
  }

  tracesRequest(
    serviceName: string,
    spans: readonly OtlpSpanRecord[],
  ): OtlpHttpRequest | null {
    if (spans.length === 0 || !this.supports(ObservabilitySignal.Trace)) {
      return null;
    }
    return buildOtlpTracesRequest(this.endpoint_, serviceName, spans);
  }

  logsRequest(
    serviceName: string,
    logs: readonly OtlpLogRecord[],
  ): OtlpHttpRequest | null {
    if (logs.length === 0 || !this.supports(ObservabilitySignal.Log)) {
      return null;
    }
    return buildOtlpLogsRequest(this.endpoint_, serviceName, logs);
  }

  validate(): ObservabilityConfigError | null {
    // Reuse the endpoint scheme/emptiness checks the builders enforce, against
    // a throwaway empty batch.
    try {
      buildOtlpTracesRequest(this.endpoint_, "ferrogate", []);
      return null;
    } catch (error) {
      return error as ObservabilityConfigError;
    }
  }
}
