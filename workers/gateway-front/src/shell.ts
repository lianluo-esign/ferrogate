// Token4AI Cloud Attribution
// Developed by the commercial cloud service company represented by https://token4ai.cloud.
// Author: jamesduan (X: https://x.com/JamesDuanL)
// Created: 2026-07-25
// description: Token4AI Cloud, FerroGate AI Gateway, the veto-only Worker shell
// contract from the #470 data-plane decision record (§6): the entire set of
// calls the fronting Worker is allowed to make, as a pure function over facts
// it can compute at the edge, plus the canonical GovernedDecision encoding.

/**
 * The Worker shell's governed surface, in one file, on purpose.
 *
 * `docs/cloudflare-data-plane-decision.md` §6 forbids this Worker from making
 * governed decisions. It is *not* forbidden from denying: a veto is always
 * safe, because the origin would have had to admit the request for it to
 * proceed. The contract is therefore directional, and this module is the whole
 * of it -- if a governed call is ever added to the Worker and does not appear
 * here, the conformance runner will not see it, which is precisely why nothing
 * else in the Worker is allowed to author a decision.
 *
 * What the shell may reach on its own is narrow by construction: facts that
 * need no control-plane state. Absent credentials. A body over the cap. A body
 * that is not JSON. A credential the operator has revoked at the edge, matched
 * by hash of the presented secret -- never by a key id, because mapping a token
 * to a key id is a control-plane read and would make the shell a second
 * authenticator.
 */

export const GOVERNED_DECISION_SCHEMA = 1;

export type GovernedOutcome = "allow" | "deny" | "cache_hit" | "defer";

export interface GovernedMetered {
  prompt_tokens: number;
  completion_tokens: number;
  /** Decimal string parsed as an integer. Never a float, never compared lexically. */
  credits_reserved: string;
  credits_captured: string;
}

export interface GovernedDecisionRecord {
  schema: number;
  outcome: GovernedOutcome;
  status: number;
  code: string | null;
  metered: GovernedMetered;
  durable_writes: string[];
  audit_events: string[];
}

export const EMPTY_METERED: GovernedMetered = {
  prompt_tokens: 0,
  completion_tokens: 0,
  credits_reserved: "0",
  credits_captured: "0",
};

/** "I made no governed call; ask the authority." Not producible by the origin. */
export function defer(): GovernedDecisionRecord {
  return {
    schema: GOVERNED_DECISION_SCHEMA,
    outcome: "defer",
    status: 0,
    code: null,
    metered: { ...EMPTY_METERED },
    durable_writes: [],
    audit_events: [],
  };
}

/**
 * The shell never writes a durable row and never emits an audit event: it has
 * no control-plane connection, and inventing one at the edge would put a second
 * writer on the request log.
 */
export function veto(status: number, code: string): GovernedDecisionRecord {
  return {
    schema: GOVERNED_DECISION_SCHEMA,
    outcome: "deny",
    status,
    code,
    metered: { ...EMPTY_METERED },
    durable_writes: [],
    audit_events: [],
  };
}

export interface ShellRequestFacts {
  /** Lower-cased header names to values, as the edge sees them. */
  headers: Record<string, string>;
  /** The raw body, or `null` when the shell did not read one. */
  bodyText: string | null;
  /** The body read hit the configured cap. */
  bodyOverLimit: boolean;
  /** Operator-managed revocations, as SHA-256 hex of the presented secret. */
  denyList: string[];
}

export interface ShellLimits {
  /** Mirrors the origin's `limits.inference_body_max_bytes`. */
  bodyMaxBytes: number;
}

function bearerToken(headers: Record<string, string>): string | null {
  const raw = headers["authorization"] ?? headers["Authorization"];
  if (typeof raw !== "string") {
    return null;
  }
  const trimmed = raw.trim();
  const prefix = "bearer ";
  if (trimmed.toLowerCase().startsWith(prefix)) {
    const token = trimmed.slice(prefix.length).trim();
    return token.length > 0 ? token : null;
  }
  return trimmed.length > 0 ? trimmed : null;
}

export async function sha256Hex(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("");
}

/**
 * The shell's entire governed surface.
 *
 * Returns `defer` for everything it is not allowed to decide, which is almost
 * everything. Every branch that returns a veto is a fact the origin would also
 * have rejected on, computed without reading any control-plane state.
 */
export async function decideShell(
  facts: ShellRequestFacts,
  limits: ShellLimits,
): Promise<GovernedDecisionRecord> {
  // 1. Absent credentials. Host-independent: the origin has no key to find
  //    either, and a request with no credential can never be admitted.
  const token = bearerToken(facts.headers);
  if (token === null) {
    return veto(401, "missing_api_key");
  }

  // 2. Over the body cap. The cap is a deployment constant mirrored into the
  //    edge; exceeding it is not a policy question.
  if (facts.bodyOverLimit) {
    return veto(413, "payload_too_large");
  }
  if (facts.bodyText !== null && new TextEncoder().encode(facts.bodyText).length > limits.bodyMaxBytes) {
    return veto(413, "payload_too_large");
  }

  // 3. Not JSON at all. Note what is *not* here: no typed parse, no "does it
  //    look like a chat completion". A typed verdict needs the origin's schema
  //    to agree, and a shell that guesses would produce false rejections --
  //    which a directional contract permits and users would not forgive.
  if (facts.bodyText !== null && facts.bodyText.length > 0) {
    try {
      JSON.parse(facts.bodyText);
    } catch {
      return veto(400, "invalid_json");
    }
  }

  // 4. Operator-managed revocation, matched by hash of the presented secret so
  //    the shell never has to resolve a token to a key id (which would be a
  //    control-plane read, and would make this a second authenticator).
  if (facts.denyList.length > 0) {
    const presented = await sha256Hex(token);
    if (facts.denyList.includes(presented)) {
      return veto(401, "invalid_api_key");
    }
  }

  // Everything else -- scopes, quota, wallets, guardrails, models, routing,
  // caching, metering -- belongs to the authority.
  return defer();
}

/**
 * Canonical serialisation: sorted keys at every depth, no whitespace. Must
 * agree byte for byte with `GovernedDecisionRecord::canonical_json` on the Rust
 * side; that agreement is what makes cross-host comparison meaningful.
 */
export function canonicalJson(value: unknown): string {
  return JSON.stringify(sortValue(value));
}

function sortValue(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map(sortValue);
  }
  if (value !== null && typeof value === "object") {
    const source = value as Record<string, unknown>;
    const sorted: Record<string, unknown> = {};
    for (const key of Object.keys(source).sort()) {
      sorted[key] = sortValue(source[key]);
    }
    return sorted;
  }
  return value;
}

/**
 * The §8d directional predicate, implemented independently of the Rust side on
 * purpose: two implementations of the *check* is fine (a disagreement fails
 * loudly and neither can silently pass), two implementations of the *decision*
 * is the thing this whole record exists to avoid.
 */
export function directionalConformance(
  authority: GovernedDecisionRecord,
  candidate: GovernedDecisionRecord,
  vocabulary: ReadonlySet<string>,
): string | null {
  if (
    candidate.metered.prompt_tokens !== 0 ||
    candidate.metered.completion_tokens !== 0 ||
    candidate.metered.credits_reserved !== "0" ||
    candidate.metered.credits_captured !== "0"
  ) {
    return `veto-only host authored a metered amount: ${JSON.stringify(candidate.metered)}`;
  }
  if (candidate.outcome === "defer") {
    return null;
  }
  if (candidate.outcome === "deny") {
    if (candidate.code === null) {
      return "veto-only host denied without a code";
    }
    if (!vocabulary.has(candidate.code)) {
      return `veto-only host denied with ${candidate.code}, which is not in the governed vocabulary`;
    }
    return null;
  }
  return `veto-only host returned ${candidate.outcome}; a veto-only host may never author an allow or serve from cache (authority said ${authority.outcome})`;
}
