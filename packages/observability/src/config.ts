/**
 * Observability pipeline/exporter configuration types, the exporter plugin
 * contract, exporter validation, and the config error taxonomy.
 *
 * Clean-room port of `ferrogate-observability::config`. The Rust
 * `ObservabilityConfigError` enum becomes a discriminated-union error class
 * ({@link ObservabilityConfigError}); `validate()` returns that error (or
 * `null` for ok) rather than throwing, mirroring Rust's `Result<(), E>` while
 * staying deep-equality testable. Zod schemas ({@link observabilityConfigSchema},
 * {@link observabilityExporterConfigSchema}) validate the wire shape per the
 * inventory mapping (§4.5).
 */
import { z } from "zod";

export interface ObservabilityConfig {
  serviceName: string;
  tracesEnabled: boolean;
  metricsEnabled: boolean;
  logsEnabled: boolean;
}

export function defaultObservabilityConfig(): ObservabilityConfig {
  return {
    serviceName: "ferrogate",
    tracesEnabled: true,
    metricsEnabled: true,
    logsEnabled: true,
  };
}

export const ObservabilitySignal = {
  Trace: "Trace",
  Metric: "Metric",
  Log: "Log",
} as const;
export type ObservabilitySignal =
  (typeof ObservabilitySignal)[keyof typeof ObservabilitySignal];

export const ObservabilityExporterKind = {
  Stdout: "Stdout",
  Otlp: "Otlp",
  Prometheus: "Prometheus",
  File: "File",
  /**
   * OTLP/HTTP+JSON to the FerroGate `telemetry-collector` Worker (#520).
   * Distinct from `Otlp` because it carries a bearer credential and therefore
   * refuses non-loopback plaintext endpoints.
   */
  Cloudflare: "Cloudflare",
} as const;
export type ObservabilityExporterKind =
  (typeof ObservabilityExporterKind)[keyof typeof ObservabilityExporterKind];

// --------------------------------------------------------------------------
// Error taxonomy — discriminated union mirroring the Rust enum + its Display.
// --------------------------------------------------------------------------

export type ObservabilityConfigErrorKind =
  | "MissingServiceName"
  | "MissingExporterName"
  | "MissingSignals"
  | "MissingEndpoint"
  | "MissingPath"
  | "InvalidHttpPath"
  | "InvalidEndpoint"
  | "UnsupportedSignal"
  | "MissingCredential"
  | "InvalidCredential"
  | "InsecureEndpoint";

export interface ObservabilityConfigErrorFields {
  exporter?: string;
  kind?: ObservabilityExporterKind;
  signal?: ObservabilitySignal;
  path?: string;
  endpoint?: string;
}

/** Boundary error for observability configuration/exporter validation. */
export class ObservabilityConfigError extends Error {
  readonly errorKind: ObservabilityConfigErrorKind;
  readonly exporter?: string;
  readonly exporterKind?: ObservabilityExporterKind;
  readonly signal?: ObservabilitySignal;
  readonly path?: string;
  readonly endpoint?: string;

  constructor(
    errorKind: ObservabilityConfigErrorKind,
    fields: ObservabilityConfigErrorFields = {},
  ) {
    super(formatConfigError(errorKind, fields));
    this.name = "ObservabilityConfigError";
    this.errorKind = errorKind;
    this.exporter = fields.exporter;
    this.exporterKind = fields.kind;
    this.signal = fields.signal;
    this.path = fields.path;
    this.endpoint = fields.endpoint;
  }
}

function formatConfigError(
  kind: ObservabilityConfigErrorKind,
  f: ObservabilityConfigErrorFields,
): string {
  switch (kind) {
    case "MissingServiceName":
      return "observability service name is required";
    case "MissingExporterName":
      return "observability exporter name is required";
    case "MissingSignals":
      return `observability exporter \`${f.exporter}\` must declare signals`;
    case "MissingEndpoint":
      return `observability exporter \`${f.exporter}\` of kind ${f.kind} requires an endpoint`;
    case "MissingPath":
      return `observability exporter \`${f.exporter}\` of kind ${f.kind} requires a path`;
    case "InvalidHttpPath":
      return `observability exporter \`${f.exporter}\` requires an absolute HTTP path, got \`${f.path}\``;
    case "InvalidEndpoint":
      return `observability exporter \`${f.exporter}\` requires an http or https endpoint, got \`${f.endpoint}\``;
    case "UnsupportedSignal":
      return `observability exporter \`${f.exporter}\` of kind ${f.kind} does not support ${f.signal}`;
    case "MissingCredential":
      return `observability exporter \`${f.exporter}\` requires a non-empty credential`;
    case "InvalidCredential":
      return `observability exporter \`${f.exporter}\` credential must not contain CR/LF`;
    case "InsecureEndpoint":
      return `observability exporter \`${f.exporter}\` refuses to send its credential over plaintext to \`${f.endpoint}\`; use https (loopback http is allowed for local development)`;
  }
}

// --------------------------------------------------------------------------
// Exporter config + plugin contract.
// --------------------------------------------------------------------------

/**
 * The exporter plugin contract: anything that can be validated as an
 * observability destination. Mirrors the Rust `ObservabilityPlugin` trait.
 */
export interface ObservabilityPlugin {
  name(): string;
  kind(): ObservabilityExporterKind;
  signals(): readonly ObservabilitySignal[];
  endpoint(): string | undefined;
  path(): string | undefined;
  validate(): ObservabilityConfigError | null;
}

export class ObservabilityExporterConfig implements ObservabilityPlugin {
  name_: string;
  kind_: ObservabilityExporterKind;
  signals_: ObservabilitySignal[];
  endpoint_?: string;
  path_?: string;
  enabled: boolean;

  constructor(
    name: string,
    kind: ObservabilityExporterKind,
    signals: ObservabilitySignal[],
  ) {
    this.name_ = name;
    this.kind_ = kind;
    this.signals_ = signals;
    this.endpoint_ = undefined;
    this.path_ = undefined;
    this.enabled = true;
  }

  static stdoutLogs(): ObservabilityExporterConfig {
    return new ObservabilityExporterConfig(
      "stdout-logs",
      ObservabilityExporterKind.Stdout,
      [ObservabilitySignal.Log],
    );
  }

  static otlp(endpoint: string): ObservabilityExporterConfig {
    const exporter = new ObservabilityExporterConfig(
      "otlp",
      ObservabilityExporterKind.Otlp,
      [
        ObservabilitySignal.Trace,
        ObservabilitySignal.Metric,
        ObservabilitySignal.Log,
      ],
    );
    exporter.endpoint_ = endpoint;
    return exporter;
  }

  /** The FerroGate `telemetry-collector` Worker on Cloudflare (#520). */
  static cloudflare(collectorEndpoint: string): ObservabilityExporterConfig {
    const exporter = new ObservabilityExporterConfig(
      "cloudflare",
      ObservabilityExporterKind.Cloudflare,
      [
        ObservabilitySignal.Trace,
        ObservabilitySignal.Metric,
        ObservabilitySignal.Log,
      ],
    );
    exporter.endpoint_ = collectorEndpoint;
    return exporter;
  }

  static prometheusMetrics(path: string): ObservabilityExporterConfig {
    const exporter = new ObservabilityExporterConfig(
      "prometheus",
      ObservabilityExporterKind.Prometheus,
      [ObservabilitySignal.Metric],
    );
    exporter.path_ = path;
    return exporter;
  }

  static fileLogs(path: string): ObservabilityExporterConfig {
    const exporter = new ObservabilityExporterConfig(
      "file-logs",
      ObservabilityExporterKind.File,
      [ObservabilitySignal.Log],
    );
    exporter.path_ = path;
    return exporter;
  }

  name(): string {
    return this.name_;
  }

  kind(): ObservabilityExporterKind {
    return this.kind_;
  }

  signals(): readonly ObservabilitySignal[] {
    return this.signals_;
  }

  endpoint(): string | undefined {
    return this.endpoint_;
  }

  path(): string | undefined {
    return this.path_;
  }

  validate(): ObservabilityConfigError | null {
    return validateExporterParts(
      this.name_,
      this.kind_,
      this.signals_,
      this.endpoint_,
      this.path_,
    );
  }
}

export class ObservabilityPipelineConfig {
  serviceName: string;
  exporters: ObservabilityExporterConfig[];

  constructor(serviceName: string) {
    this.serviceName = serviceName;
    this.exporters = [];
  }

  static default(): ObservabilityPipelineConfig {
    return new ObservabilityPipelineConfig(
      defaultObservabilityConfig().serviceName,
    );
  }

  withExporter(exporter: ObservabilityExporterConfig): this {
    this.exporters.push(exporter);
    return this;
  }

  validate(): ObservabilityConfigError | null {
    if (this.serviceName.trim() === "") {
      return new ObservabilityConfigError("MissingServiceName");
    }
    for (const exporter of this.exporters) {
      const error = exporter.validate();
      if (error !== null) {
        return error;
      }
    }
    return null;
  }
}

/**
 * Shared validation for a single exporter's parts — used by both
 * {@link ObservabilityExporterConfig.validate} and any {@link ObservabilityPlugin}.
 * Returns `null` when valid.
 */
export function validateExporterParts(
  name: string,
  kind: ObservabilityExporterKind,
  signals: readonly ObservabilitySignal[],
  endpoint: string | undefined,
  path: string | undefined,
): ObservabilityConfigError | null {
  const exporter = name.trim();
  if (exporter === "") {
    return new ObservabilityConfigError("MissingExporterName");
  }

  if (signals.length === 0) {
    return new ObservabilityConfigError("MissingSignals", { exporter });
  }

  switch (kind) {
    case ObservabilityExporterKind.Otlp:
    case ObservabilityExporterKind.Cloudflare: {
      if (endpoint === undefined || endpoint.trim() === "") {
        return new ObservabilityConfigError("MissingEndpoint", {
          exporter,
          kind,
        });
      }
      break;
    }
    case ObservabilityExporterKind.Prometheus: {
      for (const signal of signals) {
        if (signal !== ObservabilitySignal.Metric) {
          return new ObservabilityConfigError("UnsupportedSignal", {
            exporter,
            kind,
            signal,
          });
        }
      }
      if (path === undefined) {
        return new ObservabilityConfigError("MissingPath", { exporter, kind });
      }
      if (!path.startsWith("/") || path.trim() === "/") {
        return new ObservabilityConfigError("InvalidHttpPath", {
          exporter,
          path,
        });
      }
      break;
    }
    case ObservabilityExporterKind.File: {
      if (path === undefined || path.trim() === "") {
        return new ObservabilityConfigError("MissingPath", { exporter, kind });
      }
      break;
    }
    case ObservabilityExporterKind.Stdout:
      break;
  }

  return null;
}

// --------------------------------------------------------------------------
// Zod wire schemas (inventory §4.5: config/exporter validation → Zod).
// --------------------------------------------------------------------------

export const observabilitySignalSchema = z.enum(["Trace", "Metric", "Log"]);

export const observabilityExporterKindSchema = z.enum([
  "Stdout",
  "Otlp",
  "Prometheus",
  "File",
  "Cloudflare",
]);

export const observabilityConfigSchema = z.object({
  serviceName: z.string(),
  tracesEnabled: z.boolean().default(true),
  metricsEnabled: z.boolean().default(true),
  logsEnabled: z.boolean().default(true),
});

export const observabilityExporterConfigSchema = z.object({
  name: z.string(),
  kind: observabilityExporterKindSchema,
  signals: z.array(observabilitySignalSchema),
  endpoint: z.string().optional(),
  path: z.string().optional(),
  enabled: z.boolean().default(true),
});

export type ObservabilityExporterConfigWire = z.infer<
  typeof observabilityExporterConfigSchema
>;

/** Parse an untrusted exporter-config object and hydrate the class form. */
export function parseExporterConfig(
  input: unknown,
): ObservabilityExporterConfig {
  const wire = observabilityExporterConfigSchema.parse(input);
  const exporter = new ObservabilityExporterConfig(
    wire.name,
    wire.kind,
    wire.signals,
  );
  exporter.endpoint_ = wire.endpoint;
  exporter.path_ = wire.path;
  exporter.enabled = wire.enabled;
  return exporter;
}
