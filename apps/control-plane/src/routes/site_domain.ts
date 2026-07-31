/**
 * Contract group `site_domain` (5 operations).
 *
 * ```
 *   GET/POST    /admin/v1/site-domains                 list / bind
 *   GET/DELETE  /admin/v1/site-domains/{hostname}      get / unbind
 *   POST        /admin/v1/site-domains/{hostname}/verify
 * ```
 *
 * Keyed by `{hostname}` — the hostname IS the identity, so `idField:
 * "hostname"` makes bind-then-get round-trip on the same key.
 *
 * `verify` runs the real #488 DNS-TXT ownership challenge
 * (`src/site_domain_txt.ts`, ported from
 * `crates/ferrogate-gateway/src/server/site_domain_verification.rs`). Three
 * orderings here are load-bearing and each of them is a security property, not
 * a style choice:
 *
 *  1. **The rate limit runs BEFORE the lookup.** An `admin.write` credential
 *     could otherwise drive unbounded outbound DNS through the gateway by
 *     looping over attacker-chosen hostnames. Rust's rule is "`lookup_txt` is
 *     NEVER awaited for an over-limit `admin.write` credential", and the cooldown
 *     slot is RESERVED (written) before the resolver is touched, so a caller
 *     cannot burst past it by firing concurrent requests that all read the same
 *     old `last_checked_at`.
 *  2. **A challenge is minted, not assumed.** The first `verify` on an unproven
 *     binding issues a per-`(tenant, hostname)` token and answers `409` with the
 *     record to publish — it does not fail as if the operator had done something
 *     wrong, and it does not verify.
 *  3. **`unavailable` is never `verified`.** A resolver that cannot answer is a
 *     `503`; the binding keeps whatever state it had. Folding "we could not
 *     check" into either verdict is the bug the whole module is shaped to
 *     prevent, and the DEFAULT resolver is the one that can never answer, so a
 *     deployment that has not configured DNS verification cannot accidentally
 *     verify anything.
 *
 * The verification record lives in its own collection keyed
 * `(tenant_id, hostname)` — NOT on hostname alone — exactly as the
 * `site_domain_verifications` table is (`sql/d1-ts/control/`): a challenge one
 * tenant started can never be redeemed by another, and several tenants may hold
 * a pending challenge for one hostname, so a squatter's unverified binding
 * cannot block the tenant that actually owns the domain.
 */
import {
  SITE_DOMAIN_VERIFICATION_ATTEMPT_COOLDOWN_SECONDS,
  type StoredSiteDomainVerification,
  effectiveSiteDomainVerificationState,
  markCheckFailed,
  markVerified,
  pendingSiteDomainVerification,
  siteDomainVerificationAttemptDecision,
} from "@ferrogate/storage";
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import type { StoreRecord } from "../ports.js";
import { adminItem } from "../responses.js";
import {
  challengeRecordName,
  challengeTxtValue,
  newChallengeToken,
  resolveChallenge,
} from "../site_domain_txt.js";
import {
  type GroupModule,
  adminRecordSchema,
  crudGroup,
  json,
  pathParam,
  scopeOf,
} from "./resource.js";

const SITE_DOMAINS = "site-domains";
/** `site_domain_verifications` — EVIDENCE, keyed `(tenant_id, hostname)`. */
const VERIFICATIONS = "site-domain-verifications";

export const siteDomainSchema = adminRecordSchema.extend({
  hostname: z.string().trim().min(1),
  site_id: z.string().trim().min(1).optional(),
  verified: z.boolean().optional(),
});

/**
 * Rust `SITE_DOMAIN_VERIFICATION_ATTEMPT_COOLDOWN_SECS` (#576), re-exported from
 * `@ferrogate/storage` rather than spelled again — the number is the rate limit
 * and two copies of it drift.
 */
export const VERIFY_MIN_INTERVAL_SECONDS = SITE_DOMAIN_VERIFICATION_ATTEMPT_COOLDOWN_SECONDS;

/** The evidence row's store id. Keyed on the PAIR, per the reference schema. */
function verificationId(tenantId: string, hostname: string): string {
  return `${tenantId}:${hostname}`;
}

/** Stored document → the `@ferrogate/storage` value type. */
function toVerification(record: StoreRecord): StoredSiteDomainVerification {
  const num = (value: unknown): number | undefined =>
    typeof value === "number" && Number.isFinite(value) ? value : undefined;
  return {
    tenantId: String(record.tenant_id ?? ""),
    hostname: String(record.hostname ?? ""),
    site: String(record.site ?? ""),
    // An UNPARSEABLE state is never a servable one; `pending_verification` is
    // the fail-closed reading.
    state:
      record.state === "verified" ||
      record.state === "grandfathered" ||
      record.state === "expired" ||
      record.state === "pending_verification"
        ? record.state
        : "pending_verification",
    challengeToken: String(record.challenge_token ?? ""),
    issuedAtUnix: num(record.issued_at_unix) ?? 0,
    tokenExpiresAtUnix: num(record.token_expires_at_unix) ?? 0,
    verifiedAtUnix: num(record.verified_at_unix),
    verificationExpiresAtUnix: num(record.verification_expires_at_unix),
    lastCheckedAtUnix: num(record.last_checked_at_unix),
    lastFailureReason:
      typeof record.last_failure_reason === "string" ? record.last_failure_reason : undefined,
    attemptCount: num(record.attempt_count) ?? 0,
    updatedAtUnix: num(record.updated_at_unix) ?? 0,
  };
}

/** The value type → the stored document (the `site_domain_verifications` columns). */
function toDocument(verification: StoredSiteDomainVerification): Record<string, unknown> {
  return {
    tenant_id: verification.tenantId,
    hostname: verification.hostname,
    site: verification.site,
    state: verification.state,
    challenge_token: verification.challengeToken,
    issued_at_unix: verification.issuedAtUnix,
    token_expires_at_unix: verification.tokenExpiresAtUnix,
    verified_at_unix: verification.verifiedAtUnix ?? null,
    verification_expires_at_unix: verification.verificationExpiresAtUnix ?? null,
    last_checked_at_unix: verification.lastCheckedAtUnix ?? null,
    last_failure_reason: verification.lastFailureReason ?? null,
    attempt_count: verification.attemptCount,
    updated_at_unix: verification.updatedAtUnix,
  };
}

export const siteDomainRoutes: GroupModule = crudGroup(
  "site_domain",
  [{ segment: SITE_DOMAINS, object: "site_domain", idField: "hostname", body: siteDomainSchema }],
  {
    verifySiteDomain: async (c) => {
      const deps = c.get("deps");
      const scope = scopeOf(c);
      const hostname = pathParam(c, "hostname");
      const record = await deps.store.get(SITE_DOMAINS, scope, hostname);
      if (record === null) {
        throw new HttpError(404, "not_found", `site domain ${hostname} not found`);
      }
      // A challenge is bound to a TENANT. A platform operator verifying on a
      // tenant's behalf uses the BINDING's tenant, never its own absent one, or
      // the digest it checks is not the one the tenant was told to publish.
      const tenantId =
        typeof record.tenant_id === "string" && record.tenant_id !== ""
          ? record.tenant_id
          : scope.kind === "tenant"
            ? scope.tenantId
            : null;
      if (tenantId === null) {
        throw new HttpError(
          409,
          "conflict",
          `site domain ${hostname} has no owning tenant to bind an ownership challenge to`,
        );
      }

      const now = Math.floor(Date.now() / 1000);
      const id = verificationId(tenantId, hostname);
      const existing = await deps.store.get(VERIFICATIONS, scope, id);

      // No challenge yet: mint one and tell the operator what to publish. This
      // is a 409, not a 200 — nothing was verified, and a 200 here would read as
      // "checked, still pending" when in fact no check was possible.
      if (existing === null) {
        const token = newChallengeToken();
        const issued = pendingSiteDomainVerification(
          tenantId,
          hostname,
          typeof record.site_id === "string" ? record.site_id : "",
          token,
          now,
        );
        await deps.store.create(VERIFICATIONS, scope, {
          id,
          ...toDocument(issued),
        });
        throw new HttpError(
          409,
          "site_domain_challenge_issued",
          `publish TXT ${challengeRecordName(hostname)} = ${await challengeTxtValue(tenantId, hostname, token)} and retry`,
        );
      }

      const verification = toVerification(existing);

      // (1) Rate limit BEFORE any outbound DNS — and the limit IS the write.
      //
      // This used to be `siteDomainVerificationAttemptDecision(...)` as a
      // standalone check followed by an UNCONDITIONAL `store.merge`. That is a
      // read-then-write, and under concurrency it is not a rate limit at all:
      // two `POST …/verify` calls read the same `lastCheckedAtUnix`, are both
      // told `allowed`, and both reach `lookupTxt`. `@ferrogate/storage`'s own
      // docblock on this decision function states the contract every backend
      // owes it — "every backend then reserves the slot with an atomic
      // conditional write on exactly this predicate" — and no backend did
      // (`docs/rewrite/parity-audit-storage.md` §4.7). #576 exists precisely so
      // an `admin.write` credential cannot drive unbounded outbound DNS, and a
      // burst is the cheapest way to try.
      //
      // The decision now runs ONLY inside `mergeIf`'s precondition. There is
      // deliberately no second, standalone call to it beforehand, for two
      // reasons:
      //
      //   * it would be a duplicate of the guard, and a duplicate of a security
      //     predicate is a thing that can disagree with the guard it shadows;
      //   * and — the practical one — a redundant pre-check makes the ONLY
      //     remaining evidence of the conditional write a concurrent race, which
      //     `SELF.fetch` cannot observe (the test pool dispatches Worker
      //     requests one at a time). With the check living in the guard, swapping
      //     `mergeIf` back to `merge` removes the rate limit outright and
      //     `test/site-domain-cas.test.ts` fails on a plain sequential retry.
      //
      // `mergeIf` re-evaluates the predicate on every attempt against the state
      // the winning writer left, so the loser of a race is refused by the
      // winner's own `last_checked_at_unix` rather than by the snapshot it read
      // before the winner committed.
      const reserved = await deps.store.mergeIf(
        VERIFICATIONS,
        scope,
        id,
        { last_checked_at_unix: now, updated_at_unix: now },
        (current) =>
          siteDomainVerificationAttemptDecision(
            toVerification(current).lastCheckedAtUnix,
            now,
            VERIFY_MIN_INTERVAL_SECONDS,
          ).kind === "allowed",
      );
      if (reserved.kind === "not_found") {
        throw new HttpError(404, "not_found", `site domain ${hostname} not found`);
      }
      if (reserved.kind === "precondition_failed") {
        // The slot is held. The refusal is LABELLED from the row that holds it,
        // so the retry-after is the real remaining cooldown rather than a
        // constant — and it is labelled, never decided, here: the guard already
        // said no.
        const holder = siteDomainVerificationAttemptDecision(
          toVerification(reserved.current).lastCheckedAtUnix,
          now,
          VERIFY_MIN_INTERVAL_SECONDS,
        );
        throw new HttpError(
          429,
          "rate_limited",
          `site domain verification for ${hostname} may be retried in ${
            holder.kind === "rate_limited" ? holder.retryAfterSecs : VERIFY_MIN_INTERVAL_SECONDS
          }s`,
        );
      }
      verification.lastCheckedAtUnix = now;

      // (2) Only now is the resolver reached.
      const expected = await challengeTxtValue(tenantId, hostname, verification.challengeToken);
      const name = challengeRecordName(hostname);
      const outcome = resolveChallenge(expected, await deps.txtResolver.lookupTxt(name));

      // (3) `unavailable` is its own answer. The binding keeps its state; the
      // caller gets a 503 it can retry, never a verdict.
      if (outcome.kind === "resolver_unavailable") {
        throw new HttpError(
          503,
          "site_domain_resolver_unavailable",
          `DNS ownership check for ${hostname} could not be completed (${deps.txtResolver.backendName}): ${outcome.reason}`,
        );
      }

      if (outcome.kind === "verified") {
        markVerified(verification, now);
      } else {
        markCheckFailed(verification, now, outcome.reason);
      }
      const stored = await deps.store.merge(VERIFICATIONS, scope, id, toDocument(verification));
      // The BINDING mirrors the verdict so the serve path needs one read. It is
      // only ever set from `outcome`, never optimistically.
      const state = effectiveSiteDomainVerificationState(verification, now);
      const domain = await deps.store.merge(SITE_DOMAINS, scope, hostname, {
        last_verify_at: now,
        verification_status: state,
        verified: state === "verified" || state === "grandfathered",
      });

      return json(c, 200, {
        ...adminItem("site_domain", domain),
        verification: stored,
        verification_state: state,
        challenge_record: name,
        resolver: deps.txtResolver.backendName,
        verified: outcome.kind === "verified",
        reason: outcome.kind === "verified" ? null : outcome.reason,
      });
    },
  },
);
