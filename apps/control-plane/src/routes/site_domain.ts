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
 * `verify` is the operation that triggers an outbound DNS TXT lookup, and it is
 * the one place in this group with a real abuse surface: an `admin.write`
 * credential could otherwise drive unbounded outbound DNS through the gateway
 * by looping over attacker-chosen hostnames. Rust rate-limits the verification
 * BEFORE the lookup (`site_domain_verification.rs`: "`lookup_txt` is NEVER
 * awaited [for] an over-limit `admin.write` credential"). That ordering is
 * preserved below: the attempt is recorded and throttled first, and the lookup
 * is only reached afterwards.
 */
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import { adminItem } from "../responses.js";
import {
  adminRecordSchema,
  crudGroup,
  json,
  pathParam,
  scopeOf,
  type GroupModule,
} from "./resource.js";

const SITE_DOMAINS = "site-domains";

export const siteDomainSchema = adminRecordSchema.extend({
  hostname: z.string().trim().min(1),
  site_id: z.string().trim().min(1).optional(),
  verified: z.boolean().optional(),
});

/** Rust: the verification attempt window, per hostname. */
export const VERIFY_MIN_INTERVAL_SECONDS = 30;

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

      // Rate limit BEFORE any outbound DNS. Ordering is the whole point: an
      // over-limit credential must not reach the lookup at all.
      const now = Math.floor(Date.now() / 1000);
      const last = typeof record.last_verify_at === "number" ? record.last_verify_at : 0;
      if (now - last < VERIFY_MIN_INTERVAL_SECONDS) {
        throw new HttpError(
          429,
          "rate_limited",
          `site domain verification for ${hostname} may be retried in ${VERIFY_MIN_INTERVAL_SECONDS - (now - last)}s`,
        );
      }

      // PORT-TODO(inventory-edge-control §site domains): perform the DNS TXT
      // challenge lookup here (DNS-over-HTTPS from the Worker) once the
      // resolver binding is configured. Until then the attempt is recorded and
      // the domain stays unverified — it is NEVER optimistically marked
      // verified, which would let anyone bind any hostname.
      const stored = await deps.store.merge(SITE_DOMAINS, scope, hostname, {
        last_verify_at: now,
        verification_status: "pending",
      });
      return json(c, 200, adminItem("site_domain", stored));
    },
  },
);
