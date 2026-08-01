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
import { type ReadinessBindings, drainStatus } from "./readiness.js";

/** Rust `node_draining`'s message, byte for byte — operators grep for it. */
export const NODE_DRAINING_MESSAGE =
  "gateway node is draining and is not accepting new AI requests";

/**
 * The operations Rust re-checks `is_draining()` on.
 *
 * `createChatCompletion` and `createResponse` share `plan_ai_ingress`;
 * `createEmbedding`, `createImage` and `createMessage` each carry the check in
 * their own handler. Rust's sixth site, `governed_decision.rs:502`, has no
 * mounted TS counterpart yet (`executeTool` is the gateway's documented 501),
 * so it is named here rather than silently dropped: when that handler lands it
 * belongs in this list.
 */
export const DRAIN_GUARDED_OPERATION_IDS: readonly string[] = [
  "createChatCompletion",
  "createResponse",
  "createMessage",
  "createEmbedding",
  "createImage",
];

/** Is this deployment draining, as of THIS request? */
export function isDraining(env: unknown): boolean {
  return drainStatus(env as ReadinessBindings | undefined).draining;
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
      if (isDraining(c.env)) {
        throw new HttpError(503, "node_draining", NODE_DRAINING_MESSAGE);
      }
    }
    await next();
  };
}
