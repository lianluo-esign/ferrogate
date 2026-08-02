/**
 * The attribution-tag policy and the DECISION it produces — pure, no I/O.
 *
 * ============================================================================
 * THE DEFECT THIS SLICE CLOSES (#678)
 * ============================================================================
 *
 * #677 made per-request cost queryable by tenant, project, key, model, TAG and
 * agent run. The tag half of that promise is only as good as the tags that
 * arrive, and until this file existed nothing made one arrive: a request with no
 * `metadata` map settled a `billing_events` row whose `metadata` is `{}`, and no
 * later query — no export, no rollup, no reconciliation — can ever recover who
 * it was for. Cost allocation therefore decays silently as teams forget, and the
 * decay is invisible precisely because every request succeeded.
 *
 * ============================================================================
 * THE SHAPE IS #677's, NOT A SECOND ONE
 * ============================================================================
 *
 * A "tag" here is an entry of the request's `metadata` map (issue #171) — the
 * same map `Usage.metadata` carries, that `metering/event.ts` writes to
 * `billing_events.event_json -> metadata`, and that
 * `admin_cost_record.ts::tagPredicate` matches with `?tag=key` / `?tag=key:value`.
 * A policy names required KEYS, because that is the granularity the chargeback
 * query filters on and the only granularity an operator can state in advance
 * ("every request must say which `team`"), not required values.
 *
 * ============================================================================
 * TWO BRANCHES, AND WHY THE OPERATOR MUST PICK ONE EXPLICITLY
 * ============================================================================
 *
 * The issue asks for refusal OR defaulting from the virtual key's own
 * attribution, "operator's choice, explicitly configured rather than implicit".
 * So {@link AttributionPolicy.onMissing} has no default: a row that does not
 * state it configures NO enforcement ({@link parseAttributionPolicy} returns
 * `null`), rather than quietly picking the softer branch. An implicit default
 * would be the same class of silent behaviour the issue is about — one layer up.
 */

/** What to do with a request that is missing a required tag. */
export type MissingTagAction = "reject" | "default_from_key";

/** The two spellings a policy row may carry, as a runtime guard. */
export function parseMissingTagAction(raw: unknown): MissingTagAction | null {
  return raw === "reject" || raw === "default_from_key" ? raw : null;
}

/** One tenant's attribution requirement. */
export interface AttributionPolicy {
  /**
   * The metadata KEYS every request must carry. Never empty — a policy that
   * requires nothing is not a policy, and {@link parseAttributionPolicy}
   * collapses it to `null` so the enforcement path can treat "no policy" and
   * "an empty policy" as the same, cheapest thing.
   */
  readonly requiredTagKeys: readonly string[];
  readonly onMissing: MissingTagAction;
}

/** A caller-supplied or key-declared tag map, as it arrives. */
export type TagMap = Readonly<Record<string, string>>;

/**
 * Is this tag PRESENT, for the purpose of attribution?
 *
 * A key whose value is empty or blank is not attribution — it is a form field
 * nobody filled in, and accepting it would let `{"team": ""}` satisfy a policy
 * while producing a `billing_events` row that answers the chargeback question
 * with an empty string. The bounds validator (`inference/schemas.ts`) already
 * refuses empty KEYS; empty VALUES are legal there and are rejected here, which
 * is the narrower reading and the one attribution needs.
 */
function stated(tags: TagMap | undefined, key: string): boolean {
  const value = tags?.[key];
  return typeof value === "string" && value.trim() !== "";
}

/**
 * Normalize a stored/declared policy into {@link AttributionPolicy}, or `null`
 * for "this tenant is not enforced".
 *
 * Fail-OPEN on a malformed row, and that direction is deliberate even though
 * the sibling quota reader fails CLOSED on its own malformed columns. The two
 * are protecting different things: a quota that cannot be read might otherwise
 * WIDEN a spend limit, so refusing is the safe side. An attribution requirement
 * that cannot be read can only ever refuse traffic that was previously served —
 * turning a typo in one tenant's config row into a total outage for that
 * tenant's inference. The failure that matters here is silent NON-attribution,
 * and this arm is reached only when an operator wrote something this file
 * cannot parse, which is visible in config review rather than in a bill.
 */
export function parseAttributionPolicy(row: {
  readonly requiredTagKeys?: unknown;
  readonly onMissing?: unknown;
}): AttributionPolicy | null {
  const action = parseMissingTagAction(row.onMissing);
  if (action === null) return null;
  const raw = row.requiredTagKeys;
  if (!Array.isArray(raw)) return null;
  const keys = raw
    .filter((key): key is string => typeof key === "string")
    .map((key) => key.trim())
    .filter((key) => key !== "");
  if (keys.length === 0) return null;
  // De-duplicated so a row listing `["team","team"]` cannot name the same tag
  // twice in the refusal message.
  return { requiredTagKeys: [...new Set(keys)], onMissing: action };
}

/**
 * What the gate should do with one request.
 *
 * `allow` carries the DEFAULTS that were applied — never the whole effective
 * map — so the caller-supplied entries stay the caller's and the merge stays
 * one direction. It is empty for every request that already stated everything,
 * which is the overwhelmingly common case and costs nothing downstream.
 */
export type AttributionDecision =
  | { readonly kind: "allow"; readonly defaults: TagMap }
  | { readonly kind: "refuse"; readonly missing: readonly string[] };

/** The `allow` with nothing to add — hoisted so the common path allocates nothing. */
const ALLOW_UNCHANGED: AttributionDecision = { kind: "allow", defaults: {} };

/**
 * Decide one request against one policy.
 *
 * ## Why `default_from_key` can still REFUSE
 *
 * Defaulting is "fill what the presented credential can answer for", not "admit
 * whatever arrives". A key that declares no value for a required tag has nothing
 * to attribute the spend to, so admitting the request would put back exactly the
 * unattributable row this issue exists to remove — with the added insult that an
 * operator who chose the lenient branch would believe they were covered. The
 * refusal names only the tags that could NOT be defaulted, so the message stays
 * actionable.
 *
 * ## Why the caller always wins a collision
 *
 * A request that states `team=platform` on a key whose default is `growth` is
 * not a conflict to resolve — it is a caller being MORE specific than their
 * credential, which is the whole reason per-request tags exist. Overwriting it
 * from the key would silently re-attribute spend the caller explicitly labelled.
 */
export function attributionDecision(
  policy: AttributionPolicy | null,
  requestTags: TagMap | undefined,
  keyTags: TagMap | undefined,
): AttributionDecision {
  if (policy === null) return ALLOW_UNCHANGED;

  const missing = policy.requiredTagKeys.filter((key) => !stated(requestTags, key));
  if (missing.length === 0) return ALLOW_UNCHANGED;
  if (policy.onMissing === "reject") return { kind: "refuse", missing };

  const defaults: Record<string, string> = {};
  const undefaultable: string[] = [];
  for (const key of missing) {
    // Only the REQUIRED keys are ever defaulted, never the key's whole tag map.
    // That bounds how much a default can grow the metadata map: an operator's
    // key annotations cannot push a caller's request past the #171 entry cap
    // and turn a served request into `invalid_request_metadata`.
    if (stated(keyTags, key)) defaults[key] = (keyTags as TagMap)[key] as string;
    else undefaultable.push(key);
  }
  return undefaultable.length === 0
    ? { kind: "allow", defaults }
    : { kind: "refuse", missing: undefaultable };
}

/** The refusal message, with the tag names quoted so an empty one is visible. */
export function missingTagMessage(missing: readonly string[]): string {
  return `request is missing required attribution tags: ${missing
    .map((key) => JSON.stringify(key))
    .join(", ")}`;
}
