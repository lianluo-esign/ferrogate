/** Native Gemini generateContent path and routing helpers. */

export interface GeminiRequestTarget {
  readonly logicalModel: string;
  readonly stream: boolean;
}

const GENERATE_SUFFIX = ":generateContent";
const STREAM_SUFFIX = ":streamGenerateContent";

/** Parse `/v1beta/models/{model}:{generateContent|streamGenerateContent}`. */
export function geminiRequestTarget(pathname: string): GeminiRequestTarget | null {
  const encoded = pathname.split("/").at(-1) ?? "";
  const stream = encoded.endsWith(STREAM_SUFFIX);
  const suffix = stream ? STREAM_SUFFIX : GENERATE_SUFFIX;
  if (!encoded.endsWith(suffix)) return null;

  let logicalModel: string;
  try {
    logicalModel = decodeURIComponent(encoded.slice(0, -suffix.length));
  } catch {
    return null;
  }
  logicalModel = logicalModel.replace(/^models\//, "").trim();
  if (logicalModel === "" || logicalModel.includes("/")) return null;
  return { logicalModel, stream };
}

/** Address a Gemini-compatible supplier without exposing the tenant key. */
export function geminiGenerateContentEndpoint(
  baseUrl: string,
  providerModel: string,
  stream: boolean,
): string {
  const model = providerModel.replace(/^models\//, "");
  const action = stream ? "streamGenerateContent?alt=sse" : "generateContent";
  return `${baseUrl.replace(/\/+$/, "")}/models/${encodeURIComponent(model)}:${action}`;
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

/**
 * Internal OpenAI-shaped projection used only by routing, estimation and
 * cross-family fallbacks. The Gemini supplier still receives the original
 * request via `UpstreamPlan.nativeBody`.
 */
export function geminiRequestRoutingBody(
  body: Record<string, unknown>,
  logicalModel: string,
  stream: boolean,
): Record<string, unknown> {
  const messages: Record<string, unknown>[] = [];
  const systemInstruction = asRecord(body.systemInstruction);
  if (systemInstruction !== undefined) {
    messages.push({ role: "system", content: routingParts(systemInstruction.parts) });
  }

  for (const item of Array.isArray(body.contents) ? body.contents : []) {
    const content = asRecord(item);
    if (content === undefined) continue;
    messages.push({
      role: content.role === "model" ? "assistant" : "user",
      content: routingParts(content.parts),
    });
  }

  const generationConfig = asRecord(body.generationConfig);
  return {
    model: logicalModel,
    messages,
    stream,
    ...(generationConfig?.maxOutputTokens === undefined
      ? {}
      : { max_tokens: generationConfig.maxOutputTokens }),
    ...(Array.isArray(body.tools) ? { tools: body.tools } : {}),
  };
}

function routingParts(value: unknown): unknown[] {
  const parts: unknown[] = [];
  for (const item of Array.isArray(value) ? value : []) {
    const part = asRecord(item);
    if (part === undefined) continue;
    if (typeof part.text === "string") {
      parts.push({ type: "text", text: part.text });
      continue;
    }
    const inlineData = asRecord(part.inlineData ?? part.inline_data);
    if (inlineData !== undefined) {
      const mimeType =
        typeof inlineData.mimeType === "string"
          ? inlineData.mimeType
          : typeof inlineData.mime_type === "string"
            ? inlineData.mime_type
            : "application/octet-stream";
      const data = typeof inlineData.data === "string" ? inlineData.data : "";
      parts.push({ type: "image_url", image_url: { url: `data:${mimeType};base64,${data}` } });
      continue;
    }
    parts.push({ type: "text", text: JSON.stringify(part) });
  }
  return parts;
}
