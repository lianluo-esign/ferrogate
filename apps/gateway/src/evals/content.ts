/**
 * The bounded CAPTURE of what was actually said — the only place in this tree
 * that copies prompt or completion CONTENT out of a request.
 *
 * ## Why this is a separate module with its own docblock
 *
 * `residency/middleware.ts` records, correctly, that as of #681 "neither the
 * durable log nor the metering rows store prompt or completion CONTENT, today,
 * at all". This slice is the change to that sentence, so the copy is confined to
 * one small pure module rather than smeared through a middleware: what is
 * copied, how much of it, and what is dropped are all readable in one place, and
 * the gate that decides WHETHER any of it happens lives upstream in
 * `./policy.ts`.
 *
 * ## The three ingress dialects
 *
 * The gateway serves OpenAI chat completions, OpenAI responses and Anthropic
 * messages over the same routes, and their bodies disagree about everything.
 * Extraction is therefore structural and total: anything unrecognised yields
 * `undefined`, which the caller turns into "not evaluable" rather than into an
 * empty string. An empty prompt handed to a judge produces a confident score of
 * nothing.
 *
 * ## Truncation is asymmetric, and the row says it happened
 *
 * A long prompt is truncated from the FRONT (the most recent turn — the thing
 * the response is actually answering — is at the end) and a long completion from
 * the BACK. Both carry a marker in the captured text AND a boolean on the
 * record, because a judge shown 6k of a 40k-token context is answering a
 * different question from the one the column name implies, and a reader
 * comparing truncated and untruncated populations needs to be able to exclude
 * them.
 */

/**
 * The per-field capture ceiling, in UTF-16 code units.
 *
 * Chosen against the JUDGE, not against the storage: the judge is charged for
 * every captured character on every sampled request, and a 100k-token context
 * shipped to a judge for scoring would make evaluation cost more than the
 * traffic it measures. 6000 characters is roughly 1.5k tokens per field, so a
 * sampled exchange costs the judge ~3k input tokens plus its own reasoning.
 */
export const MAX_CAPTURED_CHARS = 6000;

/** Appended/prepended where content was dropped, so the judge sees the cut. */
const HEAD_MARKER = "[… earlier turns omitted …]\n";
const TAIL_MARKER = "\n[… response truncated …]";

export interface CapturedText {
  readonly text: string;
  readonly truncated: boolean;
}

/** Keep the END of `value` (the most recent turn). */
export function captureTail(value: string, limit = MAX_CAPTURED_CHARS): CapturedText {
  if (value.length <= limit) return { text: value, truncated: false };
  return { text: HEAD_MARKER + value.slice(value.length - limit), truncated: true };
}

/** Keep the START of `value` (a response is answered from its beginning). */
export function captureHead(value: string, limit = MAX_CAPTURED_CHARS): CapturedText {
  if (value.length <= limit) return { text: value, truncated: false };
  return { text: value.slice(0, limit) + TAIL_MARKER, truncated: true };
}

/**
 * Flatten one message `content` field: a bare string, or the content-part array
 * both OpenAI and Anthropic use. Non-text parts (images, audio, tool payloads)
 * are named by TYPE rather than embedded — a base64 image in a judge prompt is
 * megabytes of cost for no signal, and dropping it silently would let a judge
 * score a multimodal answer as if the picture had never been there.
 */
export function flattenContent(content: unknown): string {
  if (typeof content === "string") return content;
  if (!Array.isArray(content)) return "";
  const parts: string[] = [];
  for (const part of content) {
    if (typeof part === "string") {
      parts.push(part);
      continue;
    }
    if (typeof part !== "object" || part === null) continue;
    const record = part as { type?: unknown; text?: unknown };
    if (typeof record.text === "string") {
      parts.push(record.text);
      continue;
    }
    if (typeof record.type === "string" && record.type !== "") {
      parts.push(`[${record.type}]`);
    }
  }
  return parts.join("\n");
}

function messageLines(messages: unknown): string[] {
  if (!Array.isArray(messages)) return [];
  const lines: string[] = [];
  for (const message of messages) {
    if (typeof message !== "object" || message === null) continue;
    const role = (message as { role?: unknown }).role;
    const text = flattenContent((message as { content?: unknown }).content);
    if (text === "") continue;
    lines.push(`${typeof role === "string" && role !== "" ? role : "user"}: ${text}`);
  }
  return lines;
}

/**
 * The caller's prompt as one transcript, or `undefined` when the body carries
 * none this module recognises.
 *
 * The transcript keeps ROLES, because a judge asked "does the answer address the
 * question" needs to know which turn was the question. It does not keep tool
 * definitions, tool results or response-format schemas: those are instructions
 * to the model, not the exchange being judged, and including them systematically
 * biases a judge toward answers that echo the schema.
 */
export function promptTranscriptFrom(body: unknown): string | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const record = body as Record<string, unknown>;
  const lines: string[] = [];

  // Anthropic's top-level `system`, which is NOT a message in that dialect.
  const system = record["system"];
  const systemText = typeof system === "string" ? system : flattenContent(system);
  if (systemText !== "") lines.push(`system: ${systemText}`);

  // OpenAI `/v1/responses` puts its system prompt on `instructions`.
  const instructions = record["instructions"];
  if (typeof instructions === "string" && instructions !== "") {
    lines.push(`system: ${instructions}`);
  }

  lines.push(...messageLines(record["messages"]));

  // `/v1/responses` `input`: a bare string, or the message-shaped array.
  const input = record["input"];
  if (typeof input === "string" && input !== "") lines.push(`user: ${input}`);
  else if (Array.isArray(input)) lines.push(...messageLines(input));

  if (lines.length === 0) return undefined;
  return lines.join("\n");
}

/**
 * The served response text, or `undefined` when the body carries none.
 *
 * Only the FIRST choice / first output item is read. Scoring an n>1 completion
 * would need a decision about which sample represents the response, and the
 * client only ever showed its user one of them; taking the first is what the
 * client's own default does.
 */
export function completionTextFrom(body: unknown): string | undefined {
  if (typeof body !== "object" || body === null) return undefined;
  const record = body as Record<string, unknown>;

  // OpenAI chat completions.
  const choices = record["choices"];
  if (Array.isArray(choices) && choices.length > 0) {
    const first = choices[0] as { message?: { content?: unknown }; text?: unknown };
    const text = flattenContent(first?.message?.content);
    if (text !== "") return text;
    if (typeof first?.text === "string" && first.text !== "") return first.text;
  }

  // OpenAI responses — the convenience field first, then the output array.
  const outputText = record["output_text"];
  if (typeof outputText === "string" && outputText !== "") return outputText;
  const output = record["output"];
  if (Array.isArray(output)) {
    const parts: string[] = [];
    for (const item of output) {
      if (typeof item !== "object" || item === null) continue;
      const text = flattenContent((item as { content?: unknown }).content);
      if (text !== "") parts.push(text);
    }
    if (parts.length > 0) return parts.join("\n");
  }

  // Anthropic messages.
  const content = record["content"];
  const anthropic = flattenContent(content);
  if (anthropic !== "") return anthropic;

  return undefined;
}
