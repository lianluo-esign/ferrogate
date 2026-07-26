// Bound-hostname LIVENESS, shared by the two surfaces that display a site
// domain: the per-site detail drawer (src/pages/static-sites.tsx) and the
// bind/unbind page (src/pages/site-domains.tsx).
//
// Why this exists: `POST /admin/v1/site-domains` RECORDS a binding, it does not
// make the hostname serve. Post-#488 a bound hostname only serves while a
// DNS-TXT ownership proof resolves to `verified` or `grandfathered`, so the
// gateway reports two fields on EVERY `AdminSiteDomain` — unconditionally, with
// no `skip_serializing_if` (`admin_site_domain`, site_domains.rs):
//
//   * `serving` — commented in the gateway as "the single field an operator
//     should read to answer 'is my domain live?'";
//   * `verification_state` — `no_verification` | `pending_verification` |
//     `verified` | `grandfathered` | `expired`.
//
// The per-hostname detail read additionally carries the `verification` block:
// the exact `_ferrogate-challenge.<hostname>` TXT record still to be published,
// and when its token expires.
//
// Rendering a bound timestamp (and an ACME flag) while silently dropping all of
// that presents a server-reported UNHEALTHY state as implicitly healthy — the
// honesty rule (#458/#464) in its omission form: a hostname whose requests the
// gateway REFUSES would look identical to a live one. Both fields are optional
// in the generated client (#488 declared them so), so an absent value is
// reported as `Unknown` — never guessed, exactly as the ACME posture is.
import { Badge } from "@/components/ui/badge";
import { useI18n, type TranslationKey } from "@/i18n";
import type { AdminSchema } from "@/lib/gateway-client";

type SiteDomain = AdminSchema<"AdminSiteDomain">;
export type SiteDomainVerification = AdminSchema<"AdminSiteDomainVerification">;
export type SiteDomainVerificationState = NonNullable<
  SiteDomain["verification_state"]
>;

/** One localized label per gateway verification state. Exhaustive by
 * construction: adding a state to the contract fails this record's type. */
const VERIFICATION_STATE_LABEL: Record<
  SiteDomainVerificationState,
  TranslationKey
> = {
  no_verification: "page.siteDomains.verification.none",
  pending_verification: "page.siteDomains.verification.pending",
  verified: "page.siteDomains.verification.verified",
  grandfathered: "page.siteDomains.verification.grandfathered",
  expired: "page.siteDomains.verification.expired",
};

/**
 * The liveness cell for one bound hostname: whether the gateway would actually
 * serve a request arriving on it, plus the ownership-proof state behind that
 * verdict. An `undefined` field (read in flight, read failed, or a gateway that
 * predates #488) prints `Unknown` rather than asserting either posture.
 */
export function SiteDomainLiveness({
  serving,
  verificationState,
}: {
  serving: boolean | undefined;
  verificationState: SiteDomainVerificationState | undefined;
}) {
  const { t } = useI18n();
  return (
    <div className="flex flex-col gap-1">
      {serving === undefined ? (
        <Badge variant="outline">{t("common.unknown")}</Badge>
      ) : serving ? (
        <Badge variant="default">{t("page.siteDomains.serving")}</Badge>
      ) : (
        <Badge variant="destructive">{t("page.siteDomains.notServing")}</Badge>
      )}
      <span className="text-xs text-muted-foreground">
        {verificationState === undefined
          ? t("common.unknown")
          : t(VERIFICATION_STATE_LABEL[verificationState])}
      </span>
    </div>
  );
}

/**
 * Which ACME posture a BIND response actually justifies claiming.
 *
 * `acme.enabled` is the gateway-wide issuance flag, not this hostname's
 * enrolment: the bind handler only refreshes the ACME domain set when the
 * binding is `proven && holds_binding`, and otherwise returns the ambient state
 * untouched (`site_domains.rs`, the `#488` branch). The very same `proven` also
 * decides the response status — 202 for an unproven binding, 200/201 otherwise —
 * and is serialized in-band as `site_domain.serving` (`admin_site_domain`:
 * `serving: verification.is_some_and(|record| record.serves(now))`). So reading
 * `acme.enabled` alone tells an operator "ACME enabled" about a hostname that
 * was deliberately KEPT OUT of the certificate order set.
 *
 * The verdict is derived from `serving` rather than from the HTTP status
 * because it is the same boolean, travels with the payload the caller already
 * has, and — unlike a status code — is present on every later read of the same
 * binding. `undefined` (a gateway predating #488, or a field the contract marks
 * optional) yields `unknown`: never a guess, exactly as the liveness cell above.
 */
export function bindAcmeNoteKey(response: {
  site_domain: { serving?: boolean };
  acme: { enabled: boolean; reload_triggered: boolean };
}): TranslationKey {
  if (!response.acme.enabled) return "page.siteDomains.acme.disabled";
  const { serving } = response.site_domain;
  if (serving === undefined) return "page.siteDomains.acme.unknownEnrolment";
  if (!serving) return "page.siteDomains.acme.notEnrolled";
  return response.acme.reload_triggered
    ? "page.siteDomains.acme.reloadTriggered"
    : "page.siteDomains.acme.enabledNoReload";
}

/**
 * The actionable half: while a binding is pending verification the operator has
 * one concrete thing to do — publish a TXT record — and the gateway hands us
 * exactly that record. Showing "not serving" without it would report a problem
 * and withhold its remedy.
 */
export function SiteDomainChallenge({
  verification,
}: {
  verification: SiteDomainVerification;
}) {
  const { t, format } = useI18n();
  return (
    <div
      role="status"
      data-testid={`site-domain-challenge-${verification.hostname}`}
      className="flex flex-col gap-1 rounded-md border border-primary/40 bg-primary/5 px-3 py-2 text-xs"
    >
      <p>
        {t("page.siteDomains.challenge.title", {
          hostname: verification.hostname,
        })}
      </p>
      <p className="font-mono break-all">
        {verification.challenge_record_name} {verification.challenge_record_type}{" "}
        {verification.challenge_record_value}
      </p>
      <p className="text-muted-foreground">
        {t("page.siteDomains.challenge.expires", {
          expires: format.date(verification.token_expires_at_unix * 1000, {
            dateStyle: "medium",
            timeStyle: "short",
          }),
        })}
      </p>
    </div>
  );
}
