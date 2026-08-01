/**
 * `x-ferrogate-agent-run-id` → the metering record (issues #305 / #522).
 *
 * ## The finding this closes (cutover D3, 5 operations)
 *
 * ```
 * $ grep -rn "agent-run-id" apps/gateway/src/inference/ apps/gateway/src/metering/
 * (no output)
 * ```
 *
 * Rust threads `agent_run_id` through the whole chat pipeline (28 call sites in
 * `chat.rs`) and stamps it on the metering event in
 * `state_billing_metering.rs::settle_request`. This tree read the header on
 * assets (`assets/handlers.ts:366`), on MCP (`mcp/src/protocol.ts:65`) and in
 * `apps/agent-runtime` — but not on the surface that produces the actual token
 * spend. So an operator investigating "why did this run cost $400" could see
 * the run's asset pulls and its tool calls, and not one of its model calls.
 *
 * Nothing was MISSING downstream: `@ferrogate/billing`'s `BillingEvent` has
 * declared `agent_run_id` since wave 2 and `./wire.ts:49` already serialises it
 * into `event_json`. The field simply had no producer. That is the same shape
 * of defect as the `semantic_hit` counter with no incrementer, and it is why
 * `test/metering/agent-run-correlation.test.ts` reads the value back out of
 * SQLite rather than off an in-memory charge.
 *
 * ## Where the id is picked up, and why HERE rather than at ingress
 *
 * Two independent sources, in priority order:
 *
 *  1. **`Usage.agentRunId`** — the request path's own, validated at ingress.
 *     `src/inference/` is another slice's directory, so this side is built to
 *     receive it and {@link billingEventFromUsage} honours it the moment it
 *     appears. See the ONE-LINE change documented in `./event.ts`.
 *  2. **the request header, read by `meteringDrain`** — the fallback that makes
 *     the correlation real TODAY, with no edit outside this slice. It travels
 *     on {@link MeteringAttribution}, exactly as the api-key id already does
 *     (`./middleware.ts` is "the ONLY place the api-key id is available to
 *     metering", and the run id has the same shape of problem), and it is
 *     applied under the SAME request-id guard.
 *
 * The guard is not decoration. One drain pass can settle an outbox row left
 * behind by an EARLIER request whose drain failed; stamping this request's run
 * id onto that charge would attribute one run's spend to another. Under-
 * attribution, never mis-attribution — the rule `./usage-ledger.ts` states at
 * length and this module obeys.
 */
import type { MeteredCharge } from "./ports.js";
import type { MeteringAttribution } from "./usage-ledger.js";

/** Rust `#305` declaration header, spelled once for the whole slice. */
export const AGENT_RUN_ID_HEADER = "x-ferrogate-agent-run-id";

/**
 * Rust `declared_agent_run_id`'s accepted shape: 1–128 characters of
 * `[A-Za-z0-9_:.-]`, starting alphanumeric.
 *
 * Deliberately re-stated rather than imported from `src/assets/handlers.ts`,
 * where the identical regex is a module-private `const`: importing the ASSET
 * request path into the metering slice to reach it would couple two unrelated
 * directories through a private. The duplication is pinned instead — the
 * pattern text is asserted character for character in
 * `test/metering/agent-run-correlation.test.ts`, against the same accept/reject
 * table `test/assets/` uses, so the twins cannot drift silently.
 */
export const AGENT_RUN_ID_PATTERN = /^[A-Za-z0-9][A-Za-z0-9_:.-]{0,127}$/;

/**
 * The run id to file spend under, or `undefined`.
 *
 * A malformed value is DROPPED here rather than carried: the id is a join key,
 * and admitting an unbounded or punctuated string would poison the join it
 * exists to enable (and, through `usage_metadata_rollups`, its cardinality).
 * The gateway does not fabricate one either — Rust's rule, and the reason
 * `resolve_asset_action_id` refuses to synthesize: a made-up correlation id
 * makes an UNJOINABLE action look joined, which is worse than the gap.
 *
 * The corresponding `400 invalid_agent_run_id_header` REFUSAL is an ingress
 * decision and belongs to `src/inference/`'s validation ladder — see
 * `./event.ts` for the exact one-line change. Refusing from a middleware that
 * runs on the way OUT is not possible: by then the response is served.
 */
export function agentRunIdFor(declared: string | null | undefined): string | undefined {
  if (declared === null || declared === undefined) return undefined;
  const trimmed = declared.trim();
  if (trimmed === "" || !AGENT_RUN_ID_PATTERN.test(trimmed)) return undefined;
  return trimmed;
}

/**
 * Stamp a settled charge with the run that caused it, when — and only when —
 * the attribution belongs to that charge's own request.
 *
 * Returns the charge UNCHANGED (by identity, so a caller can assert on it) in
 * every case where nothing should be stamped:
 *
 *  - no attribution, or an attribution naming a different request;
 *  - no declared run id;
 *  - an id already threaded by the request path, which WINS. That value was
 *    validated at ingress against the Rust ladder and is the one Rust itself
 *    stamps, so a header re-read must never overwrite it.
 *
 * `id`, `entry` and `credits` are carried through untouched. `ledgerEntryId` is
 * derived from `request_id`/`provider_attempt` and never from `agent_run_id`
 * (`packages/billing/src/ledger.ts:277`), so stamping after the id is minted
 * cannot move the PRIMARY KEY of `billing_events` / `billing_ledger` /
 * `billing_report_outbox` — which would turn an idempotent retry into a double
 * bill.
 */
export function chargeWithAgentRun(
  charge: MeteredCharge,
  attribution: MeteringAttribution | undefined,
): MeteredCharge {
  if (attribution === undefined) return charge;
  if (attribution.requestId !== charge.requestId) return charge;
  const agentRunId = agentRunIdFor(attribution.agentRunId);
  if (agentRunId === undefined) return charge;
  if (charge.event.agent_run_id !== undefined) return charge;
  return { ...charge, event: { ...charge.event, agent_run_id: agentRunId } };
}
