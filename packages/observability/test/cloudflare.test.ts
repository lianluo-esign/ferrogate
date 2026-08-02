import { describe, expect, test } from "vitest";
import {
  CloudflareBackend,
  defaultGatewayMetricsSnapshot,
  endpointProtectsCredentials,
  ObservabilitySignal,
  otlpAttribute,
  TENANT_HEADER,
  type GatewayMetricsSnapshot,
  type OtlpHttpRequest,
  type OtlpLogRecord,
  type OtlpSpanRecord,
} from "../src/index.js";

const TOKEN = "s3cr3t-collector-token";
const ENDPOINT = "https://telemetry-collector.example.workers.dev";

function backend(): CloudflareBackend {
  return new CloudflareBackend(ENDPOINT, TOKEN);
}

function snapshot(): GatewayMetricsSnapshot {
  return { ...defaultGatewayMetricsSnapshot(), serviceName: "ferrogate" };
}

function span(): OtlpSpanRecord {
  return {
    traceId: "0af7651916cd43dd8448eb211c80319c",
    spanId: "b7ad6b7169203331",
    name: "ferrogate.gateway.request",
    startTimeUnixNano: 1,
    endTimeUnixNano: 2,
    attributes: [otlpAttribute("tenant", "acme")],
  };
}

function log(): OtlpLogRecord {
  return { severityText: "INFO", body: "request", timeUnixNano: 1, attributes: [] };
}

function header(request: OtlpHttpRequest, name: string): string | undefined {
  return request.headers.find(
    ([key]) => key.toLowerCase() === name.toLowerCase(),
  )?.[1];
}

describe("CloudflareBackend", () => {
  test("every signal carries the bearer credential", () => {
    const b = backend();
    const requests = [
      b.metricsRequest(snapshot()),
      b.tracesRequest("ferrogate", [span()]),
      b.logsRequest("ferrogate", [log()]),
    ];
    for (const request of requests) {
      expect(request).not.toBeNull();
      expect(header(request as OtlpHttpRequest, "authorization")).toBe(
        `Bearer ${TOKEN}`,
      );
    }
  });

  test("signals target the standard OTLP paths", () => {
    const b = backend();
    expect(b.metricsRequest(snapshot())?.url).toBe(`${ENDPOINT}/v1/metrics`);
    expect(b.tracesRequest("ferrogate", [span()])?.url).toBe(
      `${ENDPOINT}/v1/traces`,
    );
    expect(b.logsRequest("ferrogate", [log()])?.url).toBe(`${ENDPOINT}/v1/logs`);
  });

  test("debug output redacts the credential", () => {
    const rendered = backend().redactedDebug();
    expect(rendered).not.toContain(TOKEN);
    expect(rendered).toContain("<redacted>");
    expect(rendered).toContain("telemetry-collector.example.workers.dev");
  });

  test("default tenant is sent only when configured", () => {
    const without = backend().metricsRequest(snapshot()) as OtlpHttpRequest;
    expect(header(without, TENANT_HEADER)).toBeUndefined();

    const withTenant = new CloudflareBackend(ENDPOINT, TOKEN)
      .withDefaultTenant("acme")
      .metricsRequest(snapshot()) as OtlpHttpRequest;
    expect(header(withTenant, TENANT_HEADER)).toBe("acme");
  });

  test("blank default tenant is treated as unset", () => {
    const b = new CloudflareBackend(ENDPOINT, TOKEN).withDefaultTenant("  ");
    expect(b.defaultTenant()).toBeUndefined();
  });

  test("empty batches produce no request", () => {
    const b = backend();
    expect(b.tracesRequest("ferrogate", [])).toBeNull();
    expect(b.logsRequest("ferrogate", [])).toBeNull();
  });

  test("unsupported signals are skipped", () => {
    const b = new CloudflareBackend(ENDPOINT, TOKEN).withSignals([
      ObservabilitySignal.Trace,
      ObservabilitySignal.Log,
    ]);
    expect(b.metricsRequest(snapshot())).toBeNull();
    expect(b.tracesRequest("ferrogate", [span()])).not.toBeNull();
  });

  test("validate accepts an https collector", () => {
    expect(backend().validate()).toBeNull();
  });

  test("validate refuses plaintext to a remote collector", () => {
    expect(
      new CloudflareBackend("http://collector.example.com", TOKEN).validate()
        ?.errorKind,
    ).toBe("InsecureEndpoint");
  });

  test("validate allows plaintext loopback for wrangler dev", () => {
    for (const endpoint of [
      "http://localhost:8787",
      "http://127.0.0.1:8787",
      "http://[::1]:8787",
      "http://localhost:8787/ingest",
    ]) {
      expect(new CloudflareBackend(endpoint, TOKEN).validate()).toBeNull();
    }
  });

  test("validate refuses a host that merely looks like loopback", () => {
    for (const endpoint of [
      "http://localhost.evil.com",
      "http://127.0.0.1.evil.com",
      "http://user@evil.com",
      "http://evil.com/localhost",
    ]) {
      expect(
        new CloudflareBackend(endpoint, TOKEN).validate()?.errorKind,
      ).toBe("InsecureEndpoint");
    }
  });

  test("validate requires a credential", () => {
    expect(
      new CloudflareBackend(ENDPOINT, "   ").validate()?.errorKind,
    ).toBe("MissingCredential");
  });

  test("validate refuses a credential that could split the request", () => {
    expect(
      new CloudflareBackend(ENDPOINT, "token\r\nX-Injected: 1").validate()
        ?.errorKind,
    ).toBe("InvalidCredential");
  });

  test("validate still checks the endpoint shape", () => {
    expect(new CloudflareBackend("", TOKEN).validate()?.errorKind).toBe(
      "MissingEndpoint",
    );
  });
});

describe("endpointProtectsCredentials", () => {
  test("https always protects; loopback http protects; remote http does not", () => {
    expect(endpointProtectsCredentials("https://anything")).toBe(true);
    expect(endpointProtectsCredentials("http://localhost")).toBe(true);
    expect(endpointProtectsCredentials("http://[::1]:9000/x")).toBe(true);
    expect(endpointProtectsCredentials("http://remote.example.com")).toBe(false);
    expect(endpointProtectsCredentials("ftp://localhost")).toBe(false);
  });
});
