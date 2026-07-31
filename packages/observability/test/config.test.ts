import { describe, expect, test } from "vitest";
import {
  defaultObservabilityConfig,
  ObservabilityConfigError,
  ObservabilityExporterConfig,
  ObservabilityExporterKind,
  ObservabilityPipelineConfig,
  ObservabilitySignal,
  parseExporterConfig,
} from "../src/index.js";

describe("ObservabilityConfig", () => {
  test("default enables all signal types", () => {
    const config = defaultObservabilityConfig();
    expect(config.serviceName).toBe("ferrogate");
    expect(config.tracesEnabled).toBe(true);
    expect(config.metricsEnabled).toBe(true);
    expect(config.logsEnabled).toBe(true);
  });
});

describe("exporter config validation", () => {
  test("prometheus exporter is a metrics plugin boundary", () => {
    const exporter = ObservabilityExporterConfig.prometheusMetrics("/metrics");
    const pipeline = new ObservabilityPipelineConfig("ferrogate").withExporter(
      exporter,
    );

    expect(exporter.kind()).toBe(ObservabilityExporterKind.Prometheus);
    expect(exporter.signals()).toEqual([ObservabilitySignal.Metric]);
    expect(exporter.path()).toBe("/metrics");
    expect(pipeline.validate()).toBeNull();
  });

  test("rejects prometheus log plugin misconfiguration", () => {
    const exporter = new ObservabilityExporterConfig(
      "prometheus-logs",
      ObservabilityExporterKind.Prometheus,
      [ObservabilitySignal.Log],
    );
    const error = exporter.validate();
    expect(error).toBeInstanceOf(ObservabilityConfigError);
    expect(error?.errorKind).toBe("UnsupportedSignal");
    expect(error?.exporter).toBe("prometheus-logs");
    expect(error?.exporterKind).toBe(ObservabilityExporterKind.Prometheus);
    expect(error?.signal).toBe(ObservabilitySignal.Log);
  });

  test("allows multiple exporters for different signal types", () => {
    const pipeline = new ObservabilityPipelineConfig("ferrogate")
      .withExporter(ObservabilityExporterConfig.stdoutLogs())
      .withExporter(ObservabilityExporterConfig.prometheusMetrics("/metrics"))
      .withExporter(
        ObservabilityExporterConfig.otlp("http://localhost:4318/v1/traces"),
      );

    expect(pipeline.validate()).toBeNull();
    expect(pipeline.exporters.length).toBe(3);
  });

  test("validates exporter required fields", () => {
    const emptyName = new ObservabilityExporterConfig(
      " ",
      ObservabilityExporterKind.Stdout,
      [ObservabilitySignal.Log],
    );
    const emptySignals = new ObservabilityExporterConfig(
      "empty",
      ObservabilityExporterKind.Stdout,
      [],
    );
    const badPrometheusPath =
      ObservabilityExporterConfig.prometheusMetrics("metrics");

    expect(emptyName.validate()?.errorKind).toBe("MissingExporterName");
    const signalsErr = emptySignals.validate();
    expect(signalsErr?.errorKind).toBe("MissingSignals");
    expect(signalsErr?.exporter).toBe("empty");
    const pathErr = badPrometheusPath.validate();
    expect(pathErr?.errorKind).toBe("InvalidHttpPath");
    expect(pathErr?.exporter).toBe("prometheus");
    expect(pathErr?.path).toBe("metrics");
  });

  test("prometheus root path '/' is rejected as non-absolute", () => {
    const exporter = ObservabilityExporterConfig.prometheusMetrics("/");
    expect(exporter.validate()?.errorKind).toBe("InvalidHttpPath");
  });

  test("otlp/cloudflare exporters require an endpoint", () => {
    const otlp = new ObservabilityExporterConfig(
      "otlp",
      ObservabilityExporterKind.Otlp,
      [ObservabilitySignal.Trace],
    );
    expect(otlp.validate()?.errorKind).toBe("MissingEndpoint");
  });

  test("file exporter requires a path", () => {
    const file = new ObservabilityExporterConfig(
      "file",
      ObservabilityExporterKind.File,
      [ObservabilitySignal.Log],
    );
    expect(file.validate()?.errorKind).toBe("MissingPath");
    expect(ObservabilityExporterConfig.fileLogs("/var/log/fg.log").validate()).toBeNull();
  });

  test("pipeline rejects a blank service name", () => {
    const pipeline = new ObservabilityPipelineConfig("   ");
    expect(pipeline.validate()?.errorKind).toBe("MissingServiceName");
  });

  test("default pipeline carries the default service name and no exporters", () => {
    const pipeline = ObservabilityPipelineConfig.default();
    expect(pipeline.serviceName).toBe("ferrogate");
    expect(pipeline.exporters).toEqual([]);
  });

  test("Zod parseExporterConfig round-trips the wire shape", () => {
    const exporter = parseExporterConfig({
      name: "otlp",
      kind: "Otlp",
      signals: ["Trace", "Metric"],
      endpoint: "http://collector:4318",
    });
    expect(exporter.name()).toBe("otlp");
    expect(exporter.endpoint()).toBe("http://collector:4318");
    expect(exporter.enabled).toBe(true);
    expect(exporter.validate()).toBeNull();
  });

  test("Zod parseExporterConfig rejects an unknown kind", () => {
    expect(() =>
      parseExporterConfig({ name: "x", kind: "Bogus", signals: ["Log"] }),
    ).toThrow();
  });
});
