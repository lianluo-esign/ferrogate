import type { SeedProviderChannel } from "@ferrogate/storage";
import {
  defaultAdapterRegistry,
  defaultAuthScheme,
} from "../../../gateway/src/inference/adapters.js";
import { readBoundedProviderBody } from "../../../gateway/src/inference/dispatch.js";
import type { PhysicalRoute } from "../../../gateway/src/inference/ports.js";
import { fetchUpstreamModels } from "./platform-provider-sync.js";

const MAX_TEST_RESPONSE_BYTES = 1_048_576;

export const PROVIDER_CONNECTIVITY_PROTOCOLS = [
  "openai.responses",
  "openai.chat.completions",
  "anthropic.messages",
  "gemini.generateContent",
  "grok.chat.completions",
  "deepseek.chat.completions",
  "minimax.chat.completions",
] as const;

export type ProviderConnectivityProtocol = (typeof PROVIDER_CONNECTIVITY_PROTOCOLS)[number];

export class ProviderConnectivityError extends Error {
  readonly status: number;
  readonly code: string;

  constructor(status: number, code: string, message: string) {
    super(message);
    this.name = "ProviderConnectivityError";
    this.status = status;
    this.code = code;
  }
}

export async function listProviderConnectivityModels(options: {
  readonly provider: SeedProviderChannel;
  readonly apiKey?: string;
  readonly fetchImpl?: typeof fetch;
}): Promise<readonly string[]> {
  const fetchImpl = options.fetchImpl ?? fetch;
  const boundedFetch: typeof fetch = async (input, init) => {
    const timeout = AbortSignal.timeout(30_000);
    const signal = init?.signal ? AbortSignal.any([init.signal, timeout]) : timeout;
    const upstream = await fetchImpl(input, { ...init, signal });
    const raw = await readBoundedProviderBody(upstream, MAX_TEST_RESPONSE_BYTES);
    const body = [101, 204, 205, 304].includes(upstream.status) ? null : raw;
    return new Response(body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: upstream.headers,
    });
  };
  const models = await fetchUpstreamModels({ ...options, fetchImpl: boundedFetch });
  return [...new Set(models.map((model) => model.id))].sort((a, b) => a.localeCompare(b));
}

export interface ProviderConnectivityResult {
  readonly model: string;
  readonly protocol: ProviderConnectivityProtocol;
  readonly latencyMs: number;
  readonly status: number;
  readonly response: unknown;
  readonly answer: string | null;
}

function nonEmptyText(value: unknown): string | null {
  return typeof value === "string" && value.trim() !== "" ? value.trim() : null;
}

/** Extract the assistant text from the supported provider response envelopes. */
export function providerConnectivityAnswer(payload: unknown): string | null {
  if (typeof payload !== "object" || payload === null) return null;
  const record = payload as Record<string, unknown>;
  const direct = nonEmptyText(record.output_text);
  if (direct !== null) return direct;

  if (Array.isArray(record.output)) {
    const parts: string[] = [];
    for (const item of record.output) {
      if (typeof item !== "object" || item === null) continue;
      const content = (item as Record<string, unknown>).content;
      if (!Array.isArray(content)) continue;
      for (const block of content) {
        if (typeof block !== "object" || block === null) continue;
        const text = nonEmptyText((block as Record<string, unknown>).text);
        if (text !== null) parts.push(text);
      }
    }
    if (parts.length > 0) return parts.join("\n");
  }

  if (Array.isArray(record.choices)) {
    const first = record.choices[0];
    if (typeof first === "object" && first !== null) {
      const message = (first as Record<string, unknown>).message;
      if (typeof message === "object" && message !== null) {
        return nonEmptyText((message as Record<string, unknown>).content);
      }
    }
  }

  if (Array.isArray(record.content)) {
    const text = record.content
      .map((block) =>
        typeof block === "object" && block !== null
          ? nonEmptyText((block as Record<string, unknown>).text)
          : null,
      )
      .filter((part): part is string => part !== null);
    if (text.length > 0) return text.join("\n");
  }

  if (Array.isArray(record.candidates)) {
    const first = record.candidates[0];
    if (typeof first === "object" && first !== null) {
      const content = (first as Record<string, unknown>).content;
      if (typeof content === "object" && content !== null) {
        const parts = (content as Record<string, unknown>).parts;
        if (Array.isArray(parts)) {
          const text = parts
            .map((part) =>
              typeof part === "object" && part !== null
                ? nonEmptyText((part as Record<string, unknown>).text)
                : null,
            )
            .filter((part): part is string => part !== null);
          if (text.length > 0) return text.join("\n");
        }
      }
    }
  }
  return null;
}

function connectivityPlan(
  protocol: ProviderConnectivityProtocol,
  model: string,
): {
  readonly adapterKind: "openai-compatible" | "anthropic" | "gemini" | "grok";
  readonly operation: "responses" | "chat.completions";
  readonly body: Record<string, unknown>;
} {
  if (protocol === "openai.responses") {
    return {
      adapterKind: "openai-compatible",
      operation: "responses",
      body: { model, input: "hi", stream: false },
    };
  }

  const adapterKind =
    protocol === "anthropic.messages"
      ? "anthropic"
      : protocol === "gemini.generateContent"
        ? "gemini"
        : protocol === "grok.chat.completions"
          ? "grok"
          : "openai-compatible";
  return {
    adapterKind,
    operation: "chat.completions",
    body: { model, messages: [{ role: "user", content: "hi" }], stream: false },
  };
}

export async function testProviderConnectivity(options: {
  readonly provider: SeedProviderChannel;
  readonly apiKey?: string;
  readonly model: string;
  readonly protocol: ProviderConnectivityProtocol;
  readonly fetchImpl?: typeof fetch;
  readonly now?: () => number;
}): Promise<ProviderConnectivityResult> {
  const plan = connectivityPlan(options.protocol, options.model);
  const adapter = defaultAdapterRegistry.adapterFor(plan.adapterKind);
  if (adapter === null) {
    throw new ProviderConnectivityError(
      400,
      "provider_adapter_unsupported",
      `unsupported provider kind ${plan.adapterKind}`,
    );
  }

  const route: PhysicalRoute = {
    logicalModel: options.model,
    providerId: options.provider.id,
    provider: options.provider.name,
    providerModel: options.model,
    providerKind: plan.adapterKind,
    baseUrl: options.provider.base_url,
    ...(options.apiKey === undefined ? {} : { apiKey: options.apiKey }),
    authScheme:
      options.provider.auth_scheme === "bearer" || options.provider.auth_scheme === "x-api-key"
        ? options.provider.auth_scheme
        : defaultAuthScheme(plan.adapterKind),
    enabled: options.provider.enabled !== 0,
  };
  const built = adapter.buildUpstreamRequest({
    operation: plan.operation,
    route,
    logicalModel: options.model,
    providerModel: options.model,
    stream: false,
    body: plan.body,
  });
  if (!built.ok) {
    const detail =
      built.error.kind === "unsupported_provider_kind"
        ? `unsupported provider kind ${built.error.providerKind}`
        : built.error.kind === "unsupported_capability"
          ? `provider kind ${built.error.providerKind} does not support ${built.error.capability}`
          : built.error.message;
    throw new ProviderConnectivityError(400, "provider_test_invalid", detail);
  }

  const fetchImpl = options.fetchImpl ?? fetch;
  const now = options.now ?? Date.now;
  const startedAt = now();
  let upstream: Response;
  try {
    upstream = await fetchImpl(built.request.endpoint, {
      method: built.request.method,
      headers: built.request.headers,
      body:
        built.request.body === undefined
          ? undefined
          : built.request.body instanceof FormData
            ? built.request.body
            : JSON.stringify(built.request.body),
      redirect: "manual",
      signal: AbortSignal.timeout(30_000),
    });
  } catch (error) {
    throw new ProviderConnectivityError(
      502,
      "provider_unreachable",
      `could not reach upstream: ${error instanceof Error ? error.message : String(error)}`,
    );
  }

  const latencyMs = Math.max(0, now() - startedAt);
  let raw: string;
  try {
    raw = await readBoundedProviderBody(upstream, MAX_TEST_RESPONSE_BYTES);
  } catch (error) {
    throw new ProviderConnectivityError(
      502,
      "provider_response_invalid",
      error instanceof Error ? error.message : String(error),
    );
  }
  if (!upstream.ok) {
    throw new ProviderConnectivityError(
      502,
      "provider_test_failed",
      `upstream returned HTTP ${upstream.status}`,
    );
  }

  let payload: unknown;
  try {
    payload = JSON.parse(raw);
  } catch {
    throw new ProviderConnectivityError(
      502,
      "provider_response_invalid",
      "upstream did not return a JSON chat response",
    );
  }
  const response = adapter.translateChatCompletionResponse(payload, options.model) ?? payload;
  return {
    model: options.model,
    protocol: options.protocol,
    latencyMs,
    status: upstream.status,
    response,
    answer: providerConnectivityAnswer(payload) ?? providerConnectivityAnswer(response),
  };
}
