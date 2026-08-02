/**
 * The GenAI semconv vocabulary (#669), unit level.
 *
 * The END-TO-END gate — "the deployed Worker really puts these on the wire" —
 * is `apps/gateway/test/telemetry/genai.test.ts`. This file pins the things a
 * mount gate cannot see because they never arise on the happy path: the
 * provider-kind mapping for families the test deployment does not use, what a
 * missing token count does, and the profile parser's fallbacks.
 */
import { describe, expect, it } from "vitest";
import {
  ERROR_TYPE,
  GEN_AI_CLIENT_OPERATION_DURATION,
  GEN_AI_CLIENT_TOKEN_USAGE,
  GEN_AI_OPERATION_DURATION_BUCKETS,
  GEN_AI_TOKEN_USAGE_BUCKETS,
  GenAiOperationName,
  TelemetryAttributeProfile,
  buildOtlpMetricsRequest,
  defaultGatewayMetricsSnapshot,
  genAiMetricsJson,
  genAiProviderName,
  genAiSpanAttributes,
  genAiSpanName,
  profileEmitsFerrogate,
  profileEmitsGenAi,
  telemetryAttributeProfile,
} from "../src/index.js";
import type { GenAiInvocation } from "../src/index.js";

const CHAT: GenAiInvocation = {
  operationName: GenAiOperationName.Chat,
  providerName: "anthropic",
  requestModel: "claude-sonnet",
  responseModel: "claude-sonnet-4-20250514",
  inputTokens: 17,
  outputTokens: 5,
  durationSeconds: 0.12,
};

/** `[{key, value}]` → a plain lookup. */
function bag(attributes: readonly { key: string; value: string }[]): Record<string, string> {
  return Object.fromEntries(attributes.map((a) => [a.key, a.value]));
}

describe("genAiProviderName maps FerroGate kinds onto semconv values", () => {
  it("covers every adapter family FerroGate ships", () => {
    // The left column is `SUPPORTED_PROVIDER_ADAPTER_FAMILIES` in
    // `packages/providers/src/types.ts` — canonical kinds AND their aliases,
    // because `ProviderConfig.kind` is operator-authored and either spelling
    // reaches here. This is the checked half of the duplication that module's
    // doc admits to.
    expect(genAiProviderName("openai")).toBe("openai");
    expect(genAiProviderName("anthropic")).toBe("anthropic");
    expect(genAiProviderName("gemini")).toBe("gcp.gemini");
    expect(genAiProviderName("grok")).toBe("x_ai");
    expect(genAiProviderName("xai")).toBe("x_ai");
    expect(genAiProviderName("azure-openai")).toBe("azure.ai.openai");
    expect(genAiProviderName("azure")).toBe("azure.ai.openai");
    expect(genAiProviderName("bedrock")).toBe("aws.bedrock");
    expect(genAiProviderName("aws-bedrock")).toBe("aws.bedrock");
    expect(genAiProviderName("vertex")).toBe("gcp.vertex_ai");
    expect(genAiProviderName("vertex-ai")).toBe("gcp.vertex_ai");
    expect(genAiProviderName("deepseek")).toBe("deepseek");
  });

  it("normalizes the case and whitespace an operator can type", () => {
    expect(genAiProviderName("  AWS-Bedrock ")).toBe("aws.bedrock");
  });

  it("passes an unmapped kind through rather than guessing openai", () => {
    // `openrouter`, `vllm` and `ollama` all speak the OpenAI WIRE FORMAT, and
    // calling them `openai` would attribute a self-hosted Llama run to OpenAI
    // in every cost panel downstream. The spec permits a custom value; a wrong
    // well-known one is not a permitted trade.
    expect(genAiProviderName("openrouter")).toBe("openrouter");
    expect(genAiProviderName("vllm")).toBe("vllm");
    expect(genAiProviderName("ollama")).toBe("ollama");
    expect(genAiProviderName("openai-compatible")).toBe("openai-compatible");
  });
});

describe("genAiSpanAttributes", () => {
  it("emits gen_ai.system as an alias of gen_ai.provider.name", () => {
    const attributes = bag(genAiSpanAttributes(CHAT));
    expect(attributes["gen_ai.provider.name"]).toBe("anthropic");
    // Deprecated by the spec, kept because shipped Datadog/Langfuse mappings
    // read it. Same VALUE — two keys that could drift apart would be worse
    // than one.
    expect(attributes["gen_ai.system"]).toBe("anthropic");
  });

  it("carries the request and response models as distinct attributes", () => {
    const attributes = bag(genAiSpanAttributes(CHAT));
    expect(attributes["gen_ai.request.model"]).toBe("claude-sonnet");
    expect(attributes["gen_ai.response.model"]).toBe("claude-sonnet-4-20250514");
    expect(attributes["gen_ai.operation.name"]).toBe("chat");
    expect(attributes["gen_ai.usage.input_tokens"]).toBe("17");
    expect(attributes["gen_ai.usage.output_tokens"]).toBe("5");
  });

  it("OMITS a token count the provider never reported", () => {
    // Not zero. A zero is indistinguishable from a genuinely empty completion,
    // and every average built on the series would be dragged down by every
    // streamed request whose usage frame arrives after the span.
    const attributes = bag(
      genAiSpanAttributes({
        operationName: GenAiOperationName.Chat,
        providerName: "openai",
        requestModel: "gpt-4",
      }),
    );
    expect(attributes["gen_ai.usage.input_tokens"]).toBeUndefined();
    expect(attributes["gen_ai.usage.output_tokens"]).toBeUndefined();
    expect(attributes["gen_ai.response.model"]).toBeUndefined();
    // The two REQUIRED attributes are still there.
    expect(attributes["gen_ai.operation.name"]).toBe("chat");
    expect(attributes["gen_ai.request.model"]).toBe("gpt-4");
  });

  it("adds error.type only when the operation failed", () => {
    expect(bag(genAiSpanAttributes(CHAT))[ERROR_TYPE]).toBeUndefined();
    expect(bag(genAiSpanAttributes({ ...CHAT, errorType: "503" }))[ERROR_TYPE]).toBe("503");
  });

  it("names a span the way the convention asks", () => {
    expect(genAiSpanName(CHAT)).toBe("chat claude-sonnet");
  });
});

describe("genAiMetricsJson", () => {
  interface WirePoint {
    readonly sum: number;
    readonly count: string;
    readonly explicitBounds: number[];
    readonly bucketCounts: string[];
    readonly attributes: { key: string; value: { stringValue: string } }[];
  }
  interface WireMetric {
    readonly name: string;
    readonly unit: string;
    readonly histogram: { aggregationTemporality: number; dataPoints: WirePoint[] };
  }

  function metrics(invocation: GenAiInvocation): Map<string, WireMetric> {
    return new Map(
      (genAiMetricsJson(invocation) as WireMetric[]).map((metric) => [metric.name, metric]),
    );
  }

  function pointBag(point: WirePoint): Record<string, string> {
    return Object.fromEntries(point.attributes.map((a) => [a.key, a.value.stringValue]));
  }

  it("splits token usage into input and output points on one metric", () => {
    const metric = metrics(CHAT).get(GEN_AI_CLIENT_TOKEN_USAGE);
    expect(metric?.unit).toBe("{token}");
    const points = metric?.histogram.dataPoints ?? [];
    expect(points).toHaveLength(2);
    expect(pointBag(points[0] as WirePoint)["gen_ai.token.type"]).toBe("input");
    expect(points[0]?.sum).toBe(17);
    expect(pointBag(points[1] as WirePoint)["gen_ai.token.type"]).toBe("output");
    expect(points[1]?.sum).toBe(5);
  });

  it("publishes DELTA temporality, not the counter bag's CUMULATIVE", () => {
    // `otlp.ts::sumMetricJson` hard-codes `2` (CUMULATIVE) and its own doc
    // admits that is inaccurate for a per-request delta. These points get it
    // right, and that is the reason they are built separately rather than
    // folded into the sum renderer.
    expect(metrics(CHAT).get(GEN_AI_CLIENT_TOKEN_USAGE)?.histogram.aggregationTemporality).toBe(1);
    expect(
      metrics(CHAT).get(GEN_AI_CLIENT_OPERATION_DURATION)?.histogram.aggregationTemporality,
    ).toBe(1);
  });

  it("lands each observation in the bucket the spec's boundaries put it in", () => {
    const point = metrics(CHAT).get(GEN_AI_CLIENT_TOKEN_USAGE)?.histogram.dataPoints[0];
    expect(point?.explicitBounds).toEqual([...GEN_AI_TOKEN_USAGE_BUCKETS]);
    // 17 > 16 and <= 64, i.e. index 3 of [1, 4, 16, 64, …]. A `bucketCounts`
    // that did not line up with `explicitBounds` would make every quantile a
    // collector computes from these wrong, silently.
    expect(point?.bucketCounts).toHaveLength(GEN_AI_TOKEN_USAGE_BUCKETS.length + 1);
    expect(point?.bucketCounts[3]).toBe("1");
    expect(point?.bucketCounts.filter((c) => c !== "0")).toEqual(["1"]);
  });

  it("puts a value past the last boundary in the +Inf bucket", () => {
    const huge = { ...CHAT, inputTokens: 999_999_999, outputTokens: undefined };
    const point = metrics(huge).get(GEN_AI_CLIENT_TOKEN_USAGE)?.histogram.dataPoints[0];
    expect(point?.bucketCounts[GEN_AI_TOKEN_USAGE_BUCKETS.length]).toBe("1");
  });

  it("publishes the duration in seconds with the spec's boundaries", () => {
    const metric = metrics(CHAT).get(GEN_AI_CLIENT_OPERATION_DURATION);
    expect(metric?.unit).toBe("s");
    const point = metric?.histogram.dataPoints[0];
    expect(point?.sum).toBe(0.12);
    expect(point?.explicitBounds).toEqual([...GEN_AI_OPERATION_DURATION_BUCKETS]);
  });

  it("emits NO series at all when there is nothing to observe", () => {
    // A streamed request whose usage frame has not arrived and whose duration
    // was not measured must contribute nothing — not a zero-valued point that
    // a dashboard would average in.
    expect(
      genAiMetricsJson({
        operationName: GenAiOperationName.Chat,
        providerName: "openai",
        requestModel: "gpt-4",
      }),
    ).toEqual([]);
  });

  it("carries error.type on the duration metric only when the call failed", () => {
    const ok = metrics(CHAT).get(GEN_AI_CLIENT_OPERATION_DURATION)?.histogram.dataPoints[0];
    expect(pointBag(ok as WirePoint)[ERROR_TYPE]).toBeUndefined();
    const failed = metrics({ ...CHAT, errorType: "429" }).get(GEN_AI_CLIENT_OPERATION_DURATION)
      ?.histogram.dataPoints[0];
    expect(pointBag(failed as WirePoint)[ERROR_TYPE]).toBe("429");
  });
});

describe("the OTLP metrics request carries the GenAI histograms", () => {
  it("splices them in alongside the ferrogate.* counters", () => {
    // The wiring assertion for `otlp.ts`: a snapshot with an invocation must
    // produce BOTH vocabularies in one batch, because that is what dual
    // emission means at the metrics layer.
    const request = buildOtlpMetricsRequest("https://collector.test", {
      ...defaultGatewayMetricsSnapshot(),
      serviceName: "ferrogate-gateway",
      requestLogTotal: 1,
      genAiInvocations: [CHAT],
    });
    const body = JSON.parse(new TextDecoder().decode(request.body)) as {
      resourceMetrics: [{ scopeMetrics: [{ metrics: { name: string }[] }] }];
    };
    const names = body.resourceMetrics[0].scopeMetrics[0].metrics.map((m) => m.name);
    expect(names).toContain(GEN_AI_CLIENT_TOKEN_USAGE);
    expect(names).toContain(GEN_AI_CLIENT_OPERATION_DURATION);
    expect(names).toContain("ferrogate.request_logs");
  });

  it("adds no gen_ai.* series to a snapshot that observed none", () => {
    const request = buildOtlpMetricsRequest(
      "https://collector.test",
      defaultGatewayMetricsSnapshot(),
    );
    const body = JSON.parse(new TextDecoder().decode(request.body)) as {
      resourceMetrics: [{ scopeMetrics: [{ metrics: { name: string }[] }] }];
    };
    const names = body.resourceMetrics[0].scopeMetrics[0].metrics.map((m) => m.name);
    expect(names.some((name) => name.startsWith("gen_ai."))).toBe(false);
  });
});

describe("telemetryAttributeProfile", () => {
  it("DEFAULTS to dual, so an upgrade breaks no existing dashboard", () => {
    // The single most important assertion in this file. If the default ever
    // becomes `genai`, every deployment loses its `ferrogate.*` panels on the
    // release that ships it — which is precisely what #669 says not to do.
    expect(telemetryAttributeProfile(undefined)).toBe(TelemetryAttributeProfile.Dual);
    expect(telemetryAttributeProfile("")).toBe(TelemetryAttributeProfile.Dual);
    expect(telemetryAttributeProfile("   ")).toBe(TelemetryAttributeProfile.Dual);
    expect(telemetryAttributeProfile("dual")).toBe(TelemetryAttributeProfile.Dual);
  });

  it("falls back to dual for a value nobody defined", () => {
    // A typo in an observability var must not silently NARROW what a
    // deployment emits — same posture `TELEMETRY_SIGNALS` takes for an unknown
    // token.
    expect(telemetryAttributeProfile("gen-ai")).toBe(TelemetryAttributeProfile.Dual);
    expect(telemetryAttributeProfile("both")).toBe(TelemetryAttributeProfile.Dual);
  });

  it("accepts the narrowing profiles and their spellings", () => {
    expect(telemetryAttributeProfile("genai")).toBe(TelemetryAttributeProfile.GenAi);
    expect(telemetryAttributeProfile("GEN_AI")).toBe(TelemetryAttributeProfile.GenAi);
    expect(telemetryAttributeProfile("otel")).toBe(TelemetryAttributeProfile.GenAi);
    expect(telemetryAttributeProfile("ferrogate")).toBe(TelemetryAttributeProfile.Ferrogate);
    expect(telemetryAttributeProfile("legacy")).toBe(TelemetryAttributeProfile.Ferrogate);
  });

  it("gates the two halves the way the names promise", () => {
    expect(profileEmitsGenAi(TelemetryAttributeProfile.Dual)).toBe(true);
    expect(profileEmitsFerrogate(TelemetryAttributeProfile.Dual)).toBe(true);
    expect(profileEmitsGenAi(TelemetryAttributeProfile.GenAi)).toBe(true);
    expect(profileEmitsFerrogate(TelemetryAttributeProfile.GenAi)).toBe(false);
    expect(profileEmitsGenAi(TelemetryAttributeProfile.Ferrogate)).toBe(false);
    expect(profileEmitsFerrogate(TelemetryAttributeProfile.Ferrogate)).toBe(true);
  });
});
