/**
 * Site-domain bindings + DNS-TXT ownership verification (ports
 * `ferrogate-storage::site_domain` + `site_domain_verification`, issues
 * #488/#576).
 *
 * Verification is a closed lifecycle (never a `verified: bool`) so a binding can
 * never sit in an ambiguous "maybe fine" state — absence and every non-servable
 * state fail closed at the serve gate. Expiry is applied at READ time so it never
 * depends on a sweeper. The per-`(tenant, hostname)` rate-limit CAS gates outbound
 * DNS before any lookup is built (#576).
 */
// `siteDomainVerificationKey` is exported from `./ids.js`.

/** One hostname → static-site binding. `hostname` is stored normalized. */
export interface StoredSiteDomain {
  hostname: string;
  tenantId: string;
  site: string;
  createdAtUnix: number;
  updatedAtUnix: number;
}

export const SITE_DOMAIN_CLAIM_CONFLICT_MESSAGE =
  "site domain hostname is already claimed by another tenant";

/** Issued challenge token TTL (7 days). */
export const SITE_DOMAIN_CHALLENGE_TTL_SECONDS = 7 * 24 * 60 * 60;
/** Completed verification validity before re-verification (90 days). */
export const SITE_DOMAIN_VERIFICATION_TTL_SECONDS = 90 * 24 * 60 * 60;
/** Minimum gap between two DNS lookups for one `(tenant, hostname)` (#576). */
export const SITE_DOMAIN_VERIFICATION_ATTEMPT_COOLDOWN_SECONDS = 30;

/** The explicit lifecycle of one `(tenant, hostname)` ownership proof. */
export type SiteDomainVerificationState =
  | "pending_verification"
  | "verified"
  | "grandfathered"
  | "expired";

/** Parse a persisted state; `undefined` for unknown (never a servable default). */
export function siteDomainVerificationStateFromString(
  raw: string,
): SiteDomainVerificationState | undefined {
  switch (raw) {
    case "pending_verification":
    case "verified":
    case "grandfathered":
    case "expired":
      return raw;
    default:
      return undefined;
  }
}

/** Only a live proof or the explicit migration grandfather may serve. */
export function siteDomainVerificationStateServes(state: SiteDomainVerificationState): boolean {
  return state === "verified" || state === "grandfathered";
}

export interface StoredSiteDomainVerification {
  tenantId: string;
  hostname: string;
  site: string;
  state: SiteDomainVerificationState;
  challengeToken: string;
  issuedAtUnix: number;
  tokenExpiresAtUnix: number;
  verifiedAtUnix?: number;
  verificationExpiresAtUnix?: number;
  lastCheckedAtUnix?: number;
  lastFailureReason?: string;
  attemptCount: number;
  updatedAtUnix: number;
}

/** A freshly issued, not-yet-proven challenge. */
export function pendingSiteDomainVerification(
  tenantId: string,
  hostname: string,
  site: string,
  challengeToken: string,
  nowUnix: number,
): StoredSiteDomainVerification {
  return {
    tenantId,
    hostname,
    site,
    state: "pending_verification",
    challengeToken,
    issuedAtUnix: nowUnix,
    tokenExpiresAtUnix: nowUnix + SITE_DOMAIN_CHALLENGE_TTL_SECONDS,
    verifiedAtUnix: undefined,
    verificationExpiresAtUnix: undefined,
    lastCheckedAtUnix: undefined,
    lastFailureReason: undefined,
    attemptCount: 0,
    updatedAtUnix: nowUnix,
  };
}

/** The one-time #488 migration record for a binding that predates verification. */
export function grandfatheredSiteDomainVerification(
  tenantId: string,
  hostname: string,
  site: string,
  challengeToken: string,
  nowUnix: number,
): StoredSiteDomainVerification {
  return {
    ...pendingSiteDomainVerification(tenantId, hostname, site, challengeToken, nowUnix),
    state: "grandfathered",
    lastFailureReason:
      "binding predates #488 DNS ownership verification; grandfathered at upgrade",
  };
}

/** Promote a matched challenge to `verified` and start the re-verification clock. */
export function markVerified(v: StoredSiteDomainVerification, nowUnix: number): void {
  v.state = "verified";
  v.verifiedAtUnix = nowUnix;
  v.verificationExpiresAtUnix = nowUnix + SITE_DOMAIN_VERIFICATION_TTL_SECONDS;
  v.lastCheckedAtUnix = nowUnix;
  v.lastFailureReason = undefined;
  v.attemptCount += 1;
  v.updatedAtUnix = nowUnix;
}

/** Record a check that did NOT prove ownership. Never promotes or demotes state. */
export function markCheckFailed(
  v: StoredSiteDomainVerification,
  nowUnix: number,
  reason: string,
): void {
  v.lastCheckedAtUnix = nowUnix;
  v.lastFailureReason = reason;
  v.attemptCount += 1;
  v.updatedAtUnix = nowUnix;
}

/**
 * The state as of `nowUnix`, with time-based transitions applied: an unredeemed
 * token past its TTL and a verification past its deadline both resolve to
 * `expired`. Applied at READ time so expiry never depends on a sweeper.
 */
export function effectiveSiteDomainVerificationState(
  v: StoredSiteDomainVerification,
  nowUnix: number,
): SiteDomainVerificationState {
  if (v.state === "pending_verification" && nowUnix >= v.tokenExpiresAtUnix) return "expired";
  if (v.state === "verified") {
    if (v.verificationExpiresAtUnix !== undefined && nowUnix >= v.verificationExpiresAtUnix) {
      return "expired";
    }
    return "verified";
  }
  return v.state;
}

/** Whether the binding may serve traffic as of `nowUnix`. */
export function siteDomainVerificationServes(
  v: StoredSiteDomainVerification,
  nowUnix: number,
): boolean {
  return siteDomainVerificationStateServes(effectiveSiteDomainVerificationState(v, nowUnix));
}

/** Whether this is a live DNS ownership proof (narrower than {@link siteDomainVerificationServes}). */
export function hasLiveDnsOwnershipProof(
  v: StoredSiteDomainVerification,
  nowUnix: number,
): boolean {
  return effectiveSiteDomainVerificationState(v, nowUnix) === "verified";
}

/** The verdict of the per-`(tenant, hostname)` verification rate-limit gate (#576). */
export type SiteDomainVerificationAttempt =
  | { kind: "allowed" }
  | { kind: "rate_limited"; retryAfterSecs: number };

/** Whether the DNS lookup slot was reserved. */
export function siteDomainVerificationAttemptIsAllowed(
  attempt: SiteDomainVerificationAttempt,
): boolean {
  return attempt.kind === "allowed";
}

/**
 * Pure cooldown decision (ports `site_domain_verification_attempt_decision`): the
 * first attempt (no prior check) is always allowed; otherwise a call inside the
 * cooldown is refused with a bounded, ≥1s `retryAfterSecs`. Every backend then
 * reserves the slot with an atomic conditional write on exactly this predicate.
 *
 * CLOSED — former marker inventory-data-billing §1.4.6
 * `try_begin_site_domain_verification_attempt`. the atomic half now exists as
 * {@link ./d1/site-domain-d1.js D1SiteDomainVerificationStore
 * .tryBeginVerificationAttempt}, which runs the Rust statement verbatim against
 * the typed `site_domain_verifications` table in the CONTROL database —
 * `UPDATE ... WHERE tenant_id = ? AND hostname = ? AND (last_checked_at_unix IS
 * NULL OR ? - last_checked_at_unix >= ?)` — so `changes() > 0` IS the grant and
 * THIS function runs only afterwards, to label a refusal with `retryAfterSecs`.
 * It never authorizes anything on its own.
 *
 * That matters because the read-decide-write shape it replaces was not a rate
 * limit: two concurrent `POST /admin/v1/site-domains/{hostname}/verify` calls
 * both read the same `lastCheckedAtUnix`, were both told `allowed`, and both
 * reached `lookupTxt` — the exact burst #576 exists to stop, given that the
 * whole point of the gate is that an `admin.write` credential cannot drive
 * unbounded outbound DNS. `test/d1/site-domain-d1.test.ts` races two callers
 * against one row and asserts EXACTLY ONE is granted, and mutation-pins the
 * guard: deleting the cooldown predicate from the UPDATE turns it red.
 *
 * STILL OPEN, and OUT OF THIS PACKAGE'S SCOPE: the call site.
 * `apps/control-plane/src/routes/site_domain.ts` still reads its record from
 * the generic `control_plane_resources` document store and calls this pure
 * function to decide. Swapping it to `D1SiteDomainVerificationStore` on
 * `env.CONTROL_DB` is an `apps/control-plane` edit; until it lands, the durable
 * guard exists but the deployed verify route does not use it.
 */
export function siteDomainVerificationAttemptDecision(
  lastCheckedAtUnix: number | undefined,
  nowUnix: number,
  cooldownSecs: number,
): SiteDomainVerificationAttempt {
  if (lastCheckedAtUnix === undefined) return { kind: "allowed" };
  const readyAt = lastCheckedAtUnix + cooldownSecs;
  if (nowUnix >= readyAt) return { kind: "allowed" };
  return { kind: "rate_limited", retryAfterSecs: Math.max(readyAt - nowUnix, 1) };
}
