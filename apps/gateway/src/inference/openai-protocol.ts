import type { ProviderUpstreamProtocol } from "./ports.js";

function record(value: unknown): Record<string, unknown> | undefined {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function responsesTool(tool: unknown): unknown {
  const source = record(tool);
  const fn = record(source?.function);
  if (source?.type !== "function" || fn === undefined || typeof fn.name !== "string") return tool;
  return {
    type: "function",
    name: fn.name,
    ...(typeof fn.description === "string" ? { description: fn.description } : {}),
    ...(fn.parameters === undefined ? {} : { parameters: fn.parameters }),
    ...(typeof fn.strict === "boolean" ? { strict: fn.strict } : {}),
  };
}

function responsesToolChoice(value: unknown): unknown {
  const source = record(value);
  const fn = record(source?.function);
  return source?.type === "function" && typeof fn?.name === "string"
    ? { type: "function", name: fn.name }
    : value;
}

function responsesTextFormat(value: unknown): unknown {
  const source = record(value);
  if (source?.type !== "json_schema") return value;
  const schema = record(source.json_schema);
  if (schema === undefined) return value;
  return {
    type: "json_schema",
    ...(typeof schema.name === "string" ? { name: schema.name } : {}),
    ...(schema.schema === undefined ? {} : { schema: schema.schema }),
    ...(typeof schema.strict === "boolean" ? { strict: schema.strict } : {}),
    ...(typeof schema.description === "string" ? { description: schema.description } : {}),
  };
}

function responsesMessageContent(value: unknown): unknown {
  if (!Array.isArray(value)) return value;
  return value.map((part) => {
    const source = record(part);
    if (source?.type === "text" && typeof source.text === "string") {
      return { type: "input_text", text: source.text };
    }
    if (source?.type === "image_url") {
      const image = record(source.image_url);
      const imageUrl = typeof source.image_url === "string" ? source.image_url : image?.url;
      if (typeof imageUrl === "string") {
        return {
          type: "input_image",
          image_url: imageUrl,
          ...(typeof image?.detail === "string" ? { detail: image.detail } : {}),
        };
      }
    }
    return part;
  });
}

function toolOutput(value: unknown): string {
  if (typeof value === "string") return value;
  if (value === null || value === undefined) return "";
  return JSON.stringify(value);
}

function responsesInput(messages: unknown): unknown[] {
  if (!Array.isArray(messages)) return [];
  const input: unknown[] = [];
  for (const message of messages) {
    const source = record(message);
    if (source === undefined || typeof source.role !== "string") {
      input.push(message);
      continue;
    }
    if (source.role === "tool" && typeof source.tool_call_id === "string") {
      input.push({
        type: "function_call_output",
        call_id: source.tool_call_id,
        output: toolOutput(source.content),
      });
      continue;
    }

    const content = responsesMessageContent(source.content);
    const hasContent =
      content !== null && content !== undefined && (!Array.isArray(content) || content.length > 0);
    if (hasContent) input.push({ role: source.role, content });

    if (source.role !== "assistant" || !Array.isArray(source.tool_calls)) continue;
    for (const toolCall of source.tool_calls) {
      const call = record(toolCall);
      const fn = record(call?.function);
      if (call?.type !== "function" || typeof fn?.name !== "string") continue;
      input.push({
        type: "function_call",
        call_id: typeof call.id === "string" ? call.id : `call_${input.length.toString(36)}`,
        name: fn.name,
        arguments: typeof fn.arguments === "string" ? fn.arguments : "{}",
      });
    }
  }
  return input;
}

/** OpenAI Chat Completions request -> OpenAI Responses request. */
export function chatRequestToResponses(source: Record<string, unknown>): Record<string, unknown> {
  const owned = structuredClone(source);
  const {
    messages,
    stream_options: _streamOptions,
    n: _n,
    max_completion_tokens: maxCompletionTokens,
    max_tokens: maxTokens,
    response_format: responseFormat,
    reasoning_effort: reasoningEffort,
    functions,
    function_call: functionCall,
    frequency_penalty: _frequencyPenalty,
    presence_penalty: _presencePenalty,
    logit_bias: _logitBias,
    logprobs: _logprobs,
    modalities: _modalities,
    audio: _audio,
    prediction: _prediction,
    seed: _seed,
    stop: _stop,
    ...body
  } = owned;
  body.input = responsesInput(messages);

  const maxOutputTokens = maxCompletionTokens ?? maxTokens;
  if (maxOutputTokens !== undefined) body.max_output_tokens = maxOutputTokens;

  if (!Array.isArray(body.tools) && Array.isArray(functions)) {
    body.tools = functions.map((fn) => responsesTool({ type: "function", function: fn }));
  } else if (Array.isArray(body.tools)) {
    body.tools = body.tools.map(responsesTool);
  }
  if (body.tool_choice !== undefined) {
    body.tool_choice = responsesToolChoice(body.tool_choice);
  } else if (functionCall !== undefined) {
    body.tool_choice =
      typeof functionCall === "string"
        ? functionCall
        : responsesToolChoice({ type: "function", function: functionCall });
  }
  if (responseFormat !== undefined) {
    body.text = {
      ...(record(body.text) ?? {}),
      format: responsesTextFormat(responseFormat),
    };
  }
  if (reasoningEffort !== undefined) {
    body.reasoning = { ...(record(body.reasoning) ?? {}), effort: reasoningEffort };
  }
  return body;
}

function responseText(output: readonly unknown[]): string | null {
  const parts: string[] = [];
  for (const item of output) {
    const content = record(item)?.content;
    if (!Array.isArray(content)) continue;
    for (const block of content) {
      const value = record(block);
      const text = value?.text ?? value?.refusal;
      if (
        (value?.type === "output_text" || value?.type === "text" || value?.type === "refusal") &&
        typeof text === "string"
      ) {
        parts.push(text);
      }
    }
  }
  return parts.length === 0 ? null : parts.join("");
}

function responseToolCalls(output: readonly unknown[]): unknown[] {
  const calls: unknown[] = [];
  for (const item of output) {
    const value = record(item);
    if (value?.type !== "function_call" || typeof value.name !== "string") continue;
    calls.push({
      id:
        typeof value.call_id === "string"
          ? value.call_id
          : typeof value.id === "string"
            ? value.id
            : `call_${calls.length}`,
      type: "function",
      function: {
        name: value.name,
        arguments: typeof value.arguments === "string" ? value.arguments : "{}",
      },
    });
  }
  return calls;
}

/** OpenAI Responses document -> OpenAI Chat Completions document. */
export function responsesToChatCompletion(payload: unknown, logicalModel: string): unknown | null {
  const source = record(payload);
  if (source === undefined || source.object !== "response" || !Array.isArray(source.output)) {
    return null;
  }
  const toolCalls = responseToolCalls(source.output);
  const usage = record(source.usage);
  const inputDetails = record(usage?.input_tokens_details);
  const outputDetails = record(usage?.output_tokens_details);
  const chatUsage =
    usage === undefined
      ? undefined
      : {
          ...(typeof usage.input_tokens === "number" ? { prompt_tokens: usage.input_tokens } : {}),
          ...(typeof usage.output_tokens === "number"
            ? { completion_tokens: usage.output_tokens }
            : {}),
          ...(typeof usage.total_tokens === "number" ? { total_tokens: usage.total_tokens } : {}),
          ...(typeof inputDetails?.cached_tokens === "number"
            ? { prompt_tokens_details: { cached_tokens: inputDetails.cached_tokens } }
            : {}),
          ...(typeof outputDetails?.reasoning_tokens === "number"
            ? { completion_tokens_details: { reasoning_tokens: outputDetails.reasoning_tokens } }
            : {}),
        };
  const sourceId = typeof source.id === "string" ? source.id : "resp_ferrogate";
  return {
    id: sourceId.startsWith("resp") ? sourceId.replace(/^resp_?/, "chatcmpl_") : sourceId,
    object: "chat.completion",
    created:
      typeof source.created_at === "number" ? source.created_at : Math.floor(Date.now() / 1000),
    model: typeof source.model === "string" ? source.model : logicalModel,
    choices: [
      {
        index: 0,
        message: {
          role: "assistant",
          content: responseText(source.output),
          ...(toolCalls.length === 0 ? {} : { tool_calls: toolCalls }),
        },
        finish_reason:
          toolCalls.length > 0
            ? "tool_calls"
            : record(source.incomplete_details)?.reason === "max_output_tokens"
              ? "length"
              : "stop",
      },
    ],
    ...(chatUsage === undefined ? {} : { usage: chatUsage }),
  };
}

export function usesResponsesUpstream(protocol: ProviderUpstreamProtocol | undefined): boolean {
  return protocol === "openai.responses";
}

/** A buffered successful AI response must match the actual upstream surface. */
export function validOpenAiSuccessPayload(
  payload: unknown,
  protocol: ProviderUpstreamProtocol | undefined,
  ingress: "chat.completions" | "responses",
): boolean {
  const source = record(payload);
  if (source === undefined) return false;
  if (usesResponsesUpstream(protocol) || ingress === "responses") {
    return source.object === "response" && Array.isArray(source.output);
  }
  return (
    (source.object === "chat.completion" || source.object === undefined) &&
    Array.isArray(source.choices)
  );
}
