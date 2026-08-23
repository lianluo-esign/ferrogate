/**
 * The POLICY half of Responses-API conversation state (#689): who may continue
 * a chain, whether this deployment may persist one at all, how long it lives,
 * how deep it may go, and how a stored chain becomes the `input` the next
 * upstream call is given. No I/O, no bindings, no Hono — `conversation-store.ts`
 * owns the D1 side and `handlers.ts` owns the request path.
 *
 * ============================================================================
 * THE DEFECT (#689)
 * ============================================================================
 *
 * `/v1/responses` was a pass-through. `previous_response_id` and `store` went
 * out to whichever provider the ladder picked, which fails two ways and the
 * second is the dangerous one:
 *
 *  - against a provider that does not know the id, the caller gets an upstream
 *    404 they cannot act on; and
 *  - against a provider that answers anyway (or a caller whose id happened to
 *    resolve to a DIFFERENT conversation), the model answers confidently from
 *    half a conversation. Silent context loss is worse than a hard failure
 *    because nothing in the response says it happened.
 *
 * So the rule this module enforces everywhere is: **a `previous_response_id`
 * that cannot be resolved is REFUSED**. Never treated as a fresh conversation,
 * never truncated to what happens to be left.
 *
 * ============================================================================
 * THE CHAIN IS OURS, NOT THE PROVIDER'S
 * ============================================================================
 *
 * {@link conversationInput} rebuilds the whole prior transcript as `input`
 * items and {@link upstreamConversationBody} STRIPS `previous_response_id` from
 * the body that goes upstream. That is not a workaround, it is the only shape a
 * gateway can honour: the ladder may have served turn 1 from `openai-main`,
 * turn 2 from `openai-eu` after a failover, and turn 3 from Anthropic. An id
 * minted by one provider account is meaningless to the other two, so a gateway
 * that relayed the id would offer continuity that silently depends on routing
 * luck.
 *
 * `store` is rewritten to `false` for the same reason plus a compliance one:
 * FerroGate is the store of record here, and leaving `store: true` on the
 * upstream body would ALSO have the provider retain the conversation — a second
 * copy, under a retention policy the tenant never agreed to and this gateway
 * cannot expire. Omitting the member is not sufficient because Responses
 * providers may default it on; the upstream contract must be explicit.
 *
 * ============================================================================
 * ZERO DATA RETENTION (#681) GOVERNS THIS, BECAUSE IT IS PROMPT CONTENT
 * ============================================================================
 *
 * `residency/middleware.ts` documents that the request log and the metering
 * rows hold no prompt content. This table does — the input items and the served
 * output ARE the prompt and the completion. So a tenant whose policy sets
 * `requireZeroDataRetention` must never have a row written, and
 * {@link responseStoreDecision} enforces that ABOVE every other input:
 *
 *  - an explicit `store: true` is REFUSED (`403 zero_data_retention_conflict`)
 *    rather than silently ignored. Ignoring it would tell the caller the state
 *    exists, and they would discover otherwise on the next turn — a silent
 *    failure two requests away from its cause.
 *  - `previous_response_id` is refused with the same code, because under ZDR
 *    there is nothing to continue and `404 not found` would suggest expiry and
 *    send the caller looking for a retention setting.
 *  - an ABSENT `store` reads as "do not store", which is the safe reading and
 *    the one that keeps ordinary ZDR traffic working untouched.
 *
 * ============================================================================
 * THE OPERATOR LADDER, AND WHY THE DEFAULT IS OPT-IN
 * ============================================================================
 *
 * OpenAI's own default is `store: true`. Inheriting that verbatim would mean
 * every `/v1/responses` call on every FerroGate deployment starts persisting
 * prompt content the day this ships, on a data-handling posture nobody opted
 * into. `GATEWAY_RESPONSES_STORE` is the operator's decision:
 *
 *   `opt_in`     (default) — persist only when the request says `store: true`.
 *   `default_on`           — OpenAI parity: persist unless `store: false`.
 *   `off`                  — persist nothing, and REFUSE a request that asks
 *                            for it (`403 response_store_disabled`), never
 *                            accept-and-ignore.
 *
 * `off` refusing rather than ignoring is the same rule as ZDR's, and the same
 * rule #690 applied to prompt caching: what cannot be expressed is refused.
 */
import type { Caller } from "./ports.js";

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

/**
 * The deepest chain that may be continued.
 *
 * A chain nobody ends is state that never goes away — the growth #765 is open
 * on. Time bounds it (see {@link resolveRetentionSeconds}) and this bounds the
 * other axis: the number of turns one chain may accumulate, which is also the
 * work a single reconstruction has to do.
 *
 * At the cap the continuation is REFUSED (`409 conversation_chain_too_long`),
 * not truncated. Truncating the oldest turns is the identical failure mode this
 * whole issue exists to prevent — the model answers from half a conversation
 * and nothing says so — and it would arrive precisely when a conversation has
 * become valuable enough to be long. The caller's remedy is to start a new
 * chain, which they can do because they still hold the text.
 *
 * 100 is chosen against the other bound rather than from a benchmark: at the
 * default 128 KiB per turn a capped chain is ~12 MiB of D1 rows, and no real
 * agent turn sequence reaches it before the model's own context window does.
 */
export const MAX_CONVERSATION_TURNS = 100;

/**
 * The largest single turn (its input items plus the served body) that will be
 * persisted, in bytes.
 *
 * The issue suggests R2 for item overflow. That is deliberately NOT in this
 * slice: an R2 spill is a SECOND store with a second lifetime, and this
 * repository already has one control (#765) whose objects are never reclaimed
 * because the reaper only knows about the first store. A bound that refuses is
 * a complete answer; a spill whose expiry is unimplemented is a leak with a
 * feature name on it. When it lands it must be swept on the same tick as the
 * row that references it.
 */
export const MAX_STORED_TURN_BYTES = 128 * 1024;

/** Retention when the deployment configures none: one day. */
export const DEFAULT_RETENTION_SECONDS = 24 * 60 * 60;

// ---------------------------------------------------------------------------
// Ownership — the fence
// ---------------------------------------------------------------------------

/**
 * The pair every stored row is keyed by and every read is fenced on.
 *
 * Project as well as tenant, following `ports.ts::scopeCanSeeModel`, which
 * already treats a project as an isolation boundary INSIDE a tenant for model
 * visibility. Inventing a different boundary for conversation state would mean
 * this surface disagrees with that one about what "same caller" means.
 */
export interface ConversationOwner {
  readonly tenantId: string;
  readonly projectId: string;
}

/**
 * The owner of this caller's conversation state, or `null` when it has none.
 *
 * `null` for a PLATFORM-OPERATOR credential, and that is the same call
 * `tenancy/middleware.ts` makes for the per-tenant database: a credential that
 * is not confined to a tenant has no tenant state, and picking one would be a
 * cross-tenant read. An operator credential that asks to store is refused
 * rather than filed under a fabricated tenant id — see
 * {@link CONVERSATION_STORE_UNSCOPED}.
 */
export function conversationOwner(caller: Caller): ConversationOwner | null {
  if (caller.scope.kind !== "tenant") return null;
  const tenantId = caller.scope.tenantId;
  // The empty tenant id is what `callerScope` produces for an unclassified
  // credential; it is unforgeable as a real tenant, so it can address no rows.
  // Refusing here is the same fail-closed reading `EnvBindingTenantDatabaseRouter`
  // applies to `forTenant("")`.
  if (tenantId === "") return null;
  return { tenantId, projectId: caller.projectId ?? "" };
}

// ---------------------------------------------------------------------------
// The operator switch
// ---------------------------------------------------------------------------

export type ResponseStoreMode = "off" | "opt_in" | "default_on";

/** The committed default. See the module docs for why it is not `default_on`. */
export const DEFAULT_RESPONSE_STORE_MODE: ResponseStoreMode = "opt_in";

/**
 * Read `GATEWAY_RESPONSES_STORE`.
 *
 * An UNRECOGNISED value falls back to the default rather than throwing, and
 * unlike `residency/policy.ts` that is the right direction here: a typo in this
 * var cannot leak anything (the fallback stores less, not more) and a Worker
 * that refuses to start is worse than one that persists nothing.
 */
export function responseStoreMode(raw: unknown): ResponseStoreMode {
  if (raw === "off" || raw === "opt_in" || raw === "default_on") return raw;
  return DEFAULT_RESPONSE_STORE_MODE;
}

/**
 * Read `GATEWAY_RESPONSES_RETENTION` for one tenant.
 *
 * Two accepted forms, in HOURS: a bare number (`"24"`) is the fleet-wide
 * window, and a JSON object (`{"default": 24, "tenant_acme": 2}`) adds
 * per-tenant overrides. The bare form is what ships, because most deployments
 * have one answer and a committed `{"default": 24}` would be a JSON string in
 * `wrangler.toml` that nobody can read at a glance.
 *
 * Per-tenant at all because "with per-tenant retention" is the issue's
 * acceptance criterion, and because retention is exactly the knob a regulated
 * tenant negotiates. A tenant entry of `0` means "do not retain", honoured as a
 * hard zero (nothing is stored) rather than rounded up to the default — that
 * would be a silent grant.
 */
export function resolveRetentionSeconds(raw: unknown, tenantId: string): number {
  const table = parseRetentionTable(raw);
  const perTenant = table[tenantId];
  if (perTenant !== undefined) return perTenant;
  return table.default ?? DEFAULT_RETENTION_SECONDS;
}

function parseRetentionTable(raw: unknown): Record<string, number> {
  let source: unknown = raw;
  if (typeof raw === "number") {
    source = { default: raw };
  } else if (typeof raw === "string") {
    const trimmed = raw.trim();
    if (trimmed === "") return {};
    const bare = Number(trimmed);
    if (Number.isFinite(bare)) {
      source = { default: bare };
    } else {
      try {
        source = JSON.parse(trimmed);
      } catch {
        return {};
      }
    }
  }
  if (typeof source !== "object" || source === null || Array.isArray(source)) return {};
  const out: Record<string, number> = {};
  for (const [key, value] of Object.entries(source as Record<string, unknown>)) {
    const hours = typeof value === "number" ? value : Number(value);
    // A negative or non-finite entry is DROPPED, not clamped: an entry that
    // cannot be read must not silently become "keep forever" or "keep nothing".
    if (Number.isFinite(hours) && hours >= 0) {
      out[key] = Math.floor(hours * 3600);
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// The refusal vocabulary
// ---------------------------------------------------------------------------

/** `previous_response_id` names nothing this caller owns. */
export const PREVIOUS_RESPONSE_NOT_FOUND = "previous_response_not_found";
/** The row is this caller's, but the retention window has passed. */
export const PREVIOUS_RESPONSE_EXPIRED = "previous_response_expired";
/** An ancestor was deleted, so the prefix cannot be replayed in full. */
export const CONVERSATION_CHAIN_BROKEN = "conversation_chain_broken";
/** {@link MAX_CONVERSATION_TURNS} reached. */
export const CONVERSATION_CHAIN_TOO_LONG = "conversation_chain_too_long";
/** The tenant's residency policy forbids retaining prompt content. */
export const ZERO_DATA_RETENTION_CONFLICT = "zero_data_retention_conflict";
/** `GATEWAY_RESPONSES_STORE = "off"`, or nothing durable is bound. */
export const RESPONSE_STORE_DISABLED = "response_store_disabled";
/** The credential is not confined to a tenant, so it owns no conversation state. */
export const CONVERSATION_STORE_UNSCOPED = "conversation_store_unscoped";
/** The turn exceeds {@link MAX_STORED_TURN_BYTES}. */
export const RESPONSE_STATE_TOO_LARGE = "response_state_too_large";

/**
 * `404` for BOTH "never existed" and "belongs to another tenant".
 *
 * Same argument `handlers.ts::handleModel` makes for its single 404: a
 * distinguishable "403, that is someone else's" would turn `previous_response_id`
 * into an existence oracle over every other tenant's conversation ids, which is
 * precisely the boundary this slice exists to hold. EXPIRED is distinguishable
 * — but only within the caller's own fence, where it leaks nothing and is the
 * one thing an operator can act on (raise the retention window).
 */
export const CONVERSATION_NOT_FOUND_STATUS = 404;

// ---------------------------------------------------------------------------
// The store decision
// ---------------------------------------------------------------------------

/** What one request may do with conversation state. */
export type StoreDecision =
  | { readonly ok: true; readonly store: boolean }
  | {
      readonly ok: false;
      readonly status: number;
      readonly code: string;
      readonly message: string;
    };

export interface StoreDecisionInput {
  /** The request's `store` member, as sent (absent ⇒ `undefined`). */
  readonly requestedStore: boolean | undefined;
  /** Does the request continue a chain? */
  readonly continuing: boolean;
  readonly mode: ResponseStoreMode;
  /** The tenant's #681 policy demands zero data retention. */
  readonly zeroDataRetention: boolean;
  /** Is a durable store actually bound on this deployment? */
  readonly durable: boolean;
  /** Resolved retention window; `0` means "retain nothing". */
  readonly retentionSeconds: number;
}

/**
 * Decide whether this request persists, refuses, or simply does not store.
 *
 * The order of the guards IS the policy, so it is written as a ladder rather
 * than a boolean expression: ZDR outranks the operator switch, which outranks
 * the request. Every layer refuses an EXPLICIT ask it cannot honour and stays
 * silent about an absent one.
 */
export function responseStoreDecision(input: StoreDecisionInput): StoreDecision {
  const { requestedStore, continuing, mode, zeroDataRetention, durable } = input;
  const asked = requestedStore === true || continuing;

  if (zeroDataRetention) {
    if (asked) {
      return {
        ok: false,
        status: 403,
        code: ZERO_DATA_RETENTION_CONFLICT,
        message:
          "this tenant's residency policy requires zero data retention, so " +
          "/v1/responses conversation state is never persisted here; " +
          "resend the full conversation as `input` instead of using " +
          "`previous_response_id` or `store: true`",
      };
    }
    return { ok: true, store: false };
  }

  if (mode === "off") {
    if (asked) {
      return {
        ok: false,
        status: 403,
        code: RESPONSE_STORE_DISABLED,
        message:
          "this gateway does not persist /v1/responses conversation state " +
          '(GATEWAY_RESPONSES_STORE = "off"), so `store: true` and ' +
          "`previous_response_id` cannot be honoured",
      };
    }
    return { ok: true, store: false };
  }

  if (!durable) {
    if (asked) {
      return {
        ok: false,
        status: 503,
        code: RESPONSE_STORE_DISABLED,
        message:
          "no durable store is bound for /v1/responses conversation state, so " +
          "`store: true` and `previous_response_id` cannot be honoured; bind " +
          "the tenant D1 database (`DB`)",
      };
    }
    return { ok: true, store: false };
  }

  if (input.retentionSeconds <= 0) {
    if (asked) {
      return {
        ok: false,
        status: 403,
        code: RESPONSE_STORE_DISABLED,
        message:
          "this tenant's /v1/responses retention window is zero, so conversation " +
          "state is never persisted; raise GATEWAY_RESPONSES_RETENTION for it",
      };
    }
    return { ok: true, store: false };
  }

  if (requestedStore === false) {
    // Explicit `store: false` with a `previous_response_id` is LEGAL and is
    // OpenAI's own semantics: read the prior chain, answer, persist nothing.
    // The chain simply ends here, which the caller chose.
    return { ok: true, store: false };
  }
  if (requestedStore === true) return { ok: true, store: true };
  return { ok: true, store: mode === "default_on" || continuing };
}

// ---------------------------------------------------------------------------
// Item assembly
// ---------------------------------------------------------------------------

/**
 * Normalize the Responses `input` member into an item ARRAY.
 *
 * `input` is `string | item[]`. A bare string is the shorthand for one user
 * message, so it is expanded rather than dropped — a chain that lost the first
 * turn because it was sent as a string would be the silent context loss again,
 * one layer down.
 */
export function normalizeInputItems(input: unknown): unknown[] {
  if (input === undefined || input === null) return [];
  if (typeof input === "string") {
    return input === "" ? [] : [{ role: "user", content: input }];
  }
  if (Array.isArray(input)) return [...input];
  // An object `input` is not a shape the Responses API defines; passing it
  // through as a single item keeps it out of the transcript's way while losing
  // nothing.
  return [input];
}

/** The `output` items of a stored response body, or `[]`. */
export function outputItemsOf(response: unknown): unknown[] {
  if (typeof response !== "object" || response === null) return [];
  const output = (response as Record<string, unknown>).output;
  return Array.isArray(output) ? [...output] : [];
}

/** One prior turn, as {@link conversationInput} needs it. */
export interface ConversationTurnItems {
  readonly input: readonly unknown[];
  readonly output: readonly unknown[];
}

/**
 * The full `input` array for the next upstream call: every prior turn's input
 * items followed by that turn's output items, in order, then this turn's own
 * input.
 *
 * Output items are replayed VERBATIM. The Responses API defines its output
 * items as valid input items precisely so a client can do this, and it is what
 * keeps a reasoning trace, a tool call and its result attached to the turn they
 * belong to — flattening them to text is how "reasoning-trace continuity"
 * (#689's own words) gets lost.
 */
export function conversationInput(
  prior: readonly ConversationTurnItems[],
  current: unknown,
): unknown[] {
  const items: unknown[] = [];
  for (const turn of prior) {
    items.push(...turn.input, ...turn.output);
  }
  items.push(...normalizeInputItems(current));
  return items;
}

/**
 * The body that goes UPSTREAM: our reconstructed `input`, no
 * `previous_response_id`, and an explicit `store: false`.
 *
 * See the module docs. Both members are ours to honour. Relaying the id or a true
 * store value would create a second, provider-side conversation with its own id
 * space and retention — invisible to `GET`/`DELETE /v1/responses/{id}` and to
 * the retention sweep. `false` is sent instead of omitting `store`, so an
 * upstream whose default is to retain cannot silently create that second copy.
 */
export function upstreamConversationBody(
  request: Record<string, unknown>,
  input: readonly unknown[] | undefined,
): Record<string, unknown> {
  const body: Record<string, unknown> = { ...request };
  // biome-ignore lint/performance/noDelete: removes the own-property key entirely; assigning undefined would leave an enumerable undefined-valued key and change JSON serialization, the 'in' operator, and Object.keys semantics
  delete body.previous_response_id;
  body.store = false;
  if (input !== undefined) body.input = [...input];
  return body;
}

// ---------------------------------------------------------------------------
// Identity
// ---------------------------------------------------------------------------

/**
 * Mint the id the caller will be handed back, and continue from.
 *
 * OURS, never the upstream's, and the `id` of the served body is rewritten to
 * it. Three reasons: the id must be resolvable after a failover moved the next
 * turn to a different provider account; two providers must not be able to
 * collide in one tenant's id space; and a streamed turn has no provider id to
 * borrow at all (the normalized `response.*` event sequence carries none). The
 * upstream's own id is not lost — it stays inside the stored body under
 * `x-ferrogate-upstream-response-id`.
 *
 * The `resp_` prefix is OpenAI's, kept so client code that pattern-matches on
 * it keeps working.
 */
export function mintResponseId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  let hex = "";
  for (const byte of bytes) hex += byte.toString(16).padStart(2, "0");
  return `resp_${hex}`;
}

/** Where the provider's own id is preserved inside the stored/served body. */
export const UPSTREAM_RESPONSE_ID_MEMBER = "x-ferrogate-upstream-response-id";

/** Header naming the id a caller passes as the next `previous_response_id`. */
export const RESPONSE_ID_HEADER = "x-ferrogate-response-id";
/**
 * Header stating whether the state was actually persisted.
 *
 * It exists for the one case that cannot be answered by the status code: the
 * provider call succeeded, the caller asked to store, and the D1 write failed.
 * Failing the request there would destroy a completion the tenant has already
 * paid for; storing nothing and saying nothing would be the silent failure this
 * issue is about. So the body is served with `false` here, and the NEXT turn's
 * `previous_response_id` refuses loudly instead of restarting quietly.
 */
export const RESPONSE_STORED_HEADER = "x-ferrogate-response-stored";
