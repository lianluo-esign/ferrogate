/**
 * The request-scoped capability used when `/v1/responses` replays a turn whose
 * screening credential or selected policy revision differs (#779, #808).
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

export interface ConversationReplayScreener {
  /** Canonical identity of every active policy revision selected for this request. */
  readonly policyRevisionMarker: string;
  screen(input: ConversationReplayScreeningInput): Promise<ConversationReplayScreeningResult>;
}

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
