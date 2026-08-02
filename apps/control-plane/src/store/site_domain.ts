/**
 * The WRITE half of the site-domain binding — the typed `site_domains` and
 * `site_domain_verifications` rows `apps/gateway` routes an inbound hostname
 * through (issues #488/#576/#738).
 *
 * ## What this closes
 *
 * `routes/site_domain.ts` carried a PORT-TODO with two halves. #738 built the
 * first (a verified hostname now serves a bundle, `apps/gateway/src/sites/host.ts`);
 * this module is the second, and without it the first is unreachable: the admin
 * surface stored only `control_plane_resources` DOCUMENTS, the `site_domains`
 * table had no writer at all, and `D1SiteDomainVerificationStore` was imported
 * by no application module. A tenant could verify a hostname and the gateway —
 * which reads the TYPED tables, because a hostname lookup on the request path
 * of every authority cannot deserialize an opaque JSON blob per request — would
 * see nothing. Same defect class as the self-hosted worker registry
 * (`./worker_registry.ts`): reader mounted, data path into it absent.
 *
 * ## Why the typed row is written at VERIFY and not at BIND
 *
 * `site_domains.hostname` is a PRIMARY KEY: exactly one tenant can hold the
 * row. `site_domain_verifications` is keyed `(tenant_id, hostname)`, and the
 * schema says out loud why —
 *
 * > several tenants may hold a PENDING challenge for one hostname, so a
 * > squatter's unverified binding cannot block the tenant that actually owns
 * > the domain.
 *
 * Writing the `site_domains` row at BIND time would destroy exactly that
 * property: whoever POSTed first would hold the only row and the real owner
 * could never take it, having proved nothing. So an unproven claim stays a
 * per-tenant DOCUMENT (which the store scopes per tenant, so several may
 * coexist), and the typed row — the one that makes a hostname serve — is taken
 * only by a tenant that has just PROVEN control.
 *
 * ## One domain, one owner, and the loser is told
 *
 * {@link SITE_DOMAIN_CLAIM_SQL} is an `INSERT … ON CONFLICT DO UPDATE … WHERE
 * site_domains.tenant_id = excluded.tenant_id`. The conflict target is the
 * primary key and the `WHERE` is on the EXISTING row, so:
 *
 *  - no row yet ⇒ the insert lands, `changes() > 0`, the claim is granted;
 *  - a row this tenant already owns ⇒ the update lands (re-verification,
 *    or a move to a different site), `changes() > 0`;
 *  - a row ANOTHER tenant owns ⇒ the `WHERE` is false, `changes() === 0`, and
 *    the caller is refused with {@link SITE_DOMAIN_CLAIM_CONFLICT_MESSAGE}.
 *
 * The rule is therefore **the first tenant to complete a DNS proof wins**,
 * decided by the database in ONE statement rather than by a read-then-write
 * that two concurrent verifications would both pass. It is deterministic, and
 * the loser gets a 409 that names the reason instead of a silent no-op that
 * leaves it believing its domain is live.
 */
import { SITE_DOMAIN_CLAIM_CONFLICT_MESSAGE } from "@ferrogate/storage";

export { SITE_DOMAIN_CLAIM_CONFLICT_MESSAGE };

/** The typed table `apps/gateway/src/sites/domains.ts` reads to route a host. */
export const SITE_DOMAIN_TABLE = "site_domains";

/**
 * The guarded claim. Exported so the test can assert the OWNERSHIP PREDICATE is
 * in the SQL that actually runs — a test that only exercised the outcome would
 * still pass against a read-then-write, which two concurrent verifications
 * would both slip through.
 */
export const SITE_DOMAIN_CLAIM_SQL =
  "INSERT INTO site_domains (hostname, tenant_id, site, created_at_unix, updated_at_unix) " +
  "VALUES (?, ?, ?, ?, ?) " +
  "ON CONFLICT (hostname) DO UPDATE SET site = excluded.site, " +
  "updated_at_unix = excluded.updated_at_unix " +
  "WHERE site_domains.tenant_id = excluded.tenant_id";

function changed(result: D1Response): boolean {
  const meta = result.meta as { changes?: number } | undefined;
  return (meta?.changes ?? 0) > 0;
}

/**
 * Take (or renew) the serving claim on `hostname` for `tenantId`.
 *
 * `false` means another tenant holds it. The caller MUST surface that as a
 * refusal — a verification that succeeded but produced no claim is a hostname
 * the tenant believes is live and that serves somebody else.
 */
export async function claimSiteDomain(
  db: D1Database,
  hostname: string,
  tenantId: string,
  site: string,
  nowUnix: number,
): Promise<boolean> {
  const result = await db
    .prepare(SITE_DOMAIN_CLAIM_SQL)
    .bind(hostname, tenantId, site, nowUnix, nowUnix)
    .run();
  return changed(result);
}

/**
 * Drop the serving claim and the ownership evidence behind it.
 *
 * Both, and in this order, because they are two different lies if left behind:
 * a residual `site_domains` row keeps the hostname SERVING after the operator
 * was told the binding was deleted, and a residual verification row would let a
 * later re-bind serve on a proof nobody re-established.
 *
 * `tenantId` fences the delete when the caller's document carries one. A
 * platform-scope document may not, and then the delete is by hostname alone —
 * which is correct for a platform operator and is the only caller that can
 * reach it, since the tenancy fence in `ControlPlaneStore` has already refused
 * to show a tenant-scoped caller another tenant's document.
 */
export async function releaseSiteDomain(
  db: D1Database,
  hostname: string,
  tenantId: string | null,
): Promise<void> {
  if (tenantId === null) {
    await db.prepare("DELETE FROM site_domains WHERE hostname = ?").bind(hostname).run();
    await db
      .prepare("DELETE FROM site_domain_verifications WHERE hostname = ?")
      .bind(hostname)
      .run();
    return;
  }
  await db
    .prepare("DELETE FROM site_domains WHERE hostname = ? AND tenant_id = ?")
    .bind(hostname, tenantId)
    .run();
  await db
    .prepare("DELETE FROM site_domain_verifications WHERE hostname = ? AND tenant_id = ?")
    .bind(hostname, tenantId)
    .run();
}

/** The owning tenant of a stored document, or `null` for a platform record. */
export function documentTenantId(record: Record<string, unknown>): string | null {
  const tenantId = record.tenant_id;
  return typeof tenantId === "string" && tenantId.trim() !== "" ? tenantId.trim() : null;
}
