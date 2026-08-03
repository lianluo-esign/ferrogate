/**
 * The request-scoped capability used when `/v1/responses` replays a turn that
 * was screened under another credential (#779).
 *
 * The guardrail middleware owns the compiled engine and policy context; the
 * inference router owns chain assembly. A WeakMap keyed by their shared outer
 * Request crosses that boundary without module-global current-request state.
 */

export interface ConversationReplayScreeningInput {
  readonly requestId: string;
  readonly input: readonly unknown[];
  readonly response: Record<string, unknown>;
}

export type ConversationReplayScreeningResult =
  | { readonly ok: true; readonly response: Record<string, unknown> }
  | { readonly ok: false; readonly code: string; readonly message: string };

export type ConversationReplayScreener = (
  input: ConversationReplayScreeningInput,
) => Promise<ConversationReplayScreeningResult>;

const SCREENERS = new WeakMap<Request, ConversationReplayScreener>();

export function publishConversationReplayScreener(
  request: Request,
  screener: ConversationReplayScreener,
): void {
  SCREENERS.set(request, screener);
}

export function conversationReplayScreenerFor(
  request: Request,
): ConversationReplayScreener | undefined {
  return SCREENERS.get(request);
}
