/**
 * `503 node_draining` — the operator drain, honoured on the AI request path.
 *
 * ## The finding this closes (cutover D6, 5 operations)
 *
 * `GATEWAY_DRAIN=true` flipped `/readyz` to 503 and nothing else.
 * `grep -rn "node_draining" apps/` returned nothing, so an operator draining a
 * deployment ahead of a migration watched the load balancer take the node out
 * of rotation while `/v1/chat/completions` kept accepting new billable work —
 * the exact inverse of what draining is for.
 *
 * In Rust the SAME `AtomicBool` `/readyz` reports is re-checked per request by
 * `plan_ai_ingress` (`chat.rs:2862`) and by its four siblings
 * (`embeddings.rs:98`, `images.rs:115`, `messages.rs:145`,
 * `governed_decision.rs:502`), each refusing with the status, code and message
 * reproduced verbatim below.
 *
 * ## This is NOT the platform limit `readiness.ts` documents
 *
 * That marker is about how fast the FLAG can be flipped — a Worker has no
 * long-lived process, so the drain is a deploy-time var rather than a runtime
 * `AtomicBool`. This module is about the flag being READ on one route out of
 * 31. The two are independent, and the second was always closeable:
 * `drainStatus(env)` is a pure synchronous env read, so honouring it per
 * request costs a string comparison.
 *
 * ## Why the flag is read per request, and never memoised
 *
 * A `const draining = drainStatus(env)` at module scope would pass every test
 * that only ever drains, and would pin the FIRST request's posture for the life
 * of the isolate — so a deployment drained after an isolate warmed would keep
 * serving from it. `test/routes/drain.test.ts` flips the var both ways inside
 * one isolate for exactly that reason.
 *
 * ## Which operations, and why not all of them
 *
 * The five that SPEND. `listModels` is the sixth inference operation and is
 * deliberately absent: Rust does not guard it, it produces no provider call,
 * and refusing a catalogue read would break a client's failover discovery at
 * the moment it needs it most. The asset, tooling and health families keep
 * their own ladders — a drain that swallowed every route would hide real
 * divergences behind a 503.
 */
import type { Context, MiddlewareHandler } from "hono";
import { HttpError } from "../middleware/errors.js";
import type { GatewayEnv } from "../ports.js";
import {
  DRAIN_UNAVAILABLE_CODE,
  type DrainState,
  type ReadinessBindings,
  resolveDrainState,
} from "./readiness.js";

/** Rust `node_draining`'s message, byte for byte — operators grep for it. */
export const NODE_DRAINING_MESSAGE =
  "gateway node is draining and is not accepting new AI requests";

/**
 * The operations Rust re-checks `is_draining()` on.
 *
 * `createChatCompletion` and `createResponse` share `plan_ai_ingress`;
 * `createEmbedding`, `createImage` and `createMessage` each carry the check in
 * their own handler. `createRerank` has no Rust site at all (issue #676) and is
 * in the list below on the rule, not the census — see the entry. Rust's sixth site, `governed_decision.rs:502`, sits behind
 * `executeTool`, which this deployment does not offer at all: it is a DROPPED
 * capability (owner decision 2026-08-02, cluster S2 —
 * `docs/rewrite/DROPPED-CAPABILITIES.md`) answering
 * `501 capability_not_offered`. It is named here rather than silently omitted
 * so the count against Rust stays legible, and it is deliberately NOT in the
 * list below: draining an operation this deployment refuses outright would
 * replace a decided refusal with a temporary one. If the drop is ever revisited
 * it belongs in this list on the same day the handler lands.
 *
 * `countMessageTokens` (`POST /v1/messages/count_tokens`, issue #671) is also
 * deliberately absent, and for a different reason than `executeTool`: it is
 * offered, it just produces no spend and consumes no provider capacity — it
 * answers from the local estimator without contacting an upstream. A drain says
 * "stop sending this node new AI work"; refusing a count would additionally say
 * "stop answering questions about work", which is not what the operator asked
 * for and would break a client's budget pre-flight while it is trying to move
 * traffic away from the draining node.
 */
export const DRAIN_GUARDED_OPERATION_IDS: readonly string[] = [
  "createChatCompletion",
  "createResponse",
  "createMessage",
  // `geminiGenerateContent` (Gemini-native ingress) dispatches to a provider
  // and costs money, which is exactly the work a drained node is being told to
  // stop taking — same rule as `createRerank` below.
  "geminiGenerateContent",
  "createEmbedding",
  // `createRerank` (issue #676) has no Rust site to count against — the
  // operation is new — but it belongs here on the rule the list encodes rather
  // than on the census: it dispatches to a provider and it costs money, which is
  // exactly the work a drained node is being told to stop taking.
  "createRerank",
  // The audio surface (issue #703), on the same rule and with the same absence
  // of a Rust site. It is the strongest case on this list, not the weakest: a
  // transcription is the largest single unit of work the gateway accepts — up to
  // `MAX_AUDIO_UPLOAD_BYTES` of body and a provider call whose latency scales
  // with the length of the recording — so a drained node that kept accepting
  // them would keep working long after it was told to stop.
  "createTranscription",
  "createTranslation",
  "createSpeech",
  "createImage",
];

/**
 * Is this deployment draining, as of THIS request?
 *
 * ASYNC since wave 22 (FC-1's third leg): the answer is the durable
 * `runtime-state/drain` document OR the `GATEWAY_DRAIN` var, resolved by
 * `./readiness.ts::resolveDrainState` — this file's ONE call into that parse,
 * not a second copy of it, so `/readyz` and the data plane can never disagree
 * about whether a deployment is draining.
 */
export async function isDraining(env: unknown): Promise<boolean> {
  const state = await resolveDrainState(env as ReadinessBindings | undefined);
  return state.draining;
}

/**
 * The refusal a drain state produces, or `null` when the request may proceed.
 *
 * Two codes, both 503 and both refusals, identical to
 * `apps/mcp/src/drain.ts::drainRefusal`: `node_draining` is Rust's answer for
 * "the operator drained this deployment", `drain_state_unavailable` is "the
 * control could not be evaluated". Collapsing them would tell an operator the
 * node is draining while `GET /admin/v1/drain` says it is not.
 */
export function drainRefusal(state: DrainState): HttpError | null {
  if (state.source === "unavailable") {
    return new HttpError(
      503,
      DRAIN_UNAVAILABLE_CODE,
      `operator drain state is unavailable: ${state.detail ?? "control database lookup failed"}`,
    );
  }
  if (!state.draining) return null;
  return new HttpError(503, "node_draining", NODE_DRAINING_MESSAGE);
}

/**
 * Post-auth middleware refusing new AI work while the node is draining.
 *
 * Mounted by `createGatewayApp` AFTER the caller-supplied cross-cutting
 * middleware, which is where Rust puts it: `plan_ai_ingress` runs inside the
 * handler, i.e. after `finalize_auth` has already charged the RPM and quota
 * windows. Putting it earlier would be defensible on cost grounds and WRONG on
 * parity grounds — a drained node would stop charging admission counters that
 * Rust still charges, and the counter state an operator sees after a drain
 * would diverge.
 *
 * The operation id comes from `c.get("operation")`, set by `contractAuth` from
 * the contract table, so this gate cannot drift from the route it guards by a
 * path typo.
 */
export function nodeDrainGate(
  operationIds: readonly string[] = DRAIN_GUARDED_OPERATION_IDS,
): MiddlewareHandler<GatewayEnv> {
  const guarded = new Set(operationIds);
  return async function nodeDrainGateMiddleware(c, next): Promise<void> {
    const operation = (c as Context<GatewayEnv>).get("operation");
    if (operation !== null && operation !== undefined && guarded.has(operation.operationId)) {
      // ONE durable read, and only on the five guarded operations — every other
      // operation costs nothing, which is what keeps this affordable on the hot
      // path. The caller has already paid for the credential and admission
      // lookups by the time this line runs.
      const refusal = drainRefusal(await resolveDrainState(c.env as ReadinessBindings));
      if (refusal !== null) throw refusal;
    }
    await next();
  };
}
