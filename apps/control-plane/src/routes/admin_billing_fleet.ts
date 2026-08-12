/**
 * Contract group `admin_billing_fleet` — the cross-tenant billing fleet view
 * (#956 read side).
 *
 * ```
 *   GET /admin/v1/billing-fleet?group_by=&since=&until=&limit=
 * ```
 *
 * ONE cross-tenant SQL aggregate over the `BILLING_ANALYTICS` Analytics Engine
 * dataset the gateway dual-writes (`apps/gateway/src/metering/billing-analytics.ts`).
 * Answers "top spenders this month" / "fleet billed by model" without an O(N)
 * fan-out to every tenant object and without projecting tenant-private billing
 * into the control database. AE aggregates are sample-corrected estimates, never
 * the invoicing authority — that stays each tenant's Durable Object.
 *
 * PLATFORM-ONLY, modelled on `admin_billing_group.ts`: a tenant-scoped caller is
 * fenced with a leak-proof `404`. When the account query surface is unconfigured
 * (no account id / token — the AE read side is the account-scoped
 * `/analytics_engine/sql` REST endpoint, which has no offline emulation), the
 * endpoint answers `503`, never a fabricated empty report.
 */
import { z } from "zod";
import { HttpError } from "../middleware/errors.js";
import type { CallerScope } from "../ports.js";
import {
  BillingFleetUnavailableError,
  DEFAULT_FLEET_LIMIT,
  FLEET_GROUP_BY_VALUES,
  type FleetGroupBy,
  type FleetQuery,
  MAX_FLEET_LIMIT,
} from "../store/billing-fleet.js";
import { type GroupModule, type Handler, crudGroup, depsOf, json, scopeOf } from "./resource.js";

/** 30 days, the default window when neither bound is given. */
const DEFAULT_WINDOW_SECONDS = 30 * 24 * 60 * 60;

const querySchema = z
  .object({
    group_by: z.enum(FLEET_GROUP_BY_VALUES as [FleetGroupBy, ...FleetGroupBy[]]).default("tenant"),
    since: z.coerce.number().int().nonnegative().optional(),
    until: z.coerce.number().int().nonnegative().optional(),
    limit: z.coerce.number().int().positive().max(MAX_FLEET_LIMIT).default(DEFAULT_FLEET_LIMIT),
  })
  .strict();

/** Leak-proof platform fence: a tenant caller gets 404, not 403. */
function platformScope(c: Parameters<Handler>[0]): CallerScope {
  const scope = scopeOf(c);
  if (scope.kind === "tenant") {
    throw new HttpError(404, "not_found", "billing fleet report not found");
  }
  return scope;
}

function parseQuery(c: Parameters<Handler>[0], nowUnix: number): FleetQuery {
  const url = new URL(c.req.url);
  const parsed = querySchema.safeParse({
    group_by: url.searchParams.get("group_by") ?? undefined,
    since: url.searchParams.get("since") ?? undefined,
    until: url.searchParams.get("until") ?? undefined,
    limit: url.searchParams.get("limit") ?? undefined,
  });
  if (!parsed.success) {
    const issue = parsed.error.issues[0];
    throw new HttpError(
      400,
      "invalid_request",
      `invalid billing-fleet query: ${issue ? `${issue.path.join(".") || "<root>"}: ${issue.message}` : "bad parameters"}`,
    );
  }
  const untilUnix = parsed.data.until ?? nowUnix;
  const sinceUnix = parsed.data.since ?? untilUnix - DEFAULT_WINDOW_SECONDS;
  if (sinceUnix >= untilUnix) {
    throw new HttpError(400, "invalid_request", "since must be strictly before until");
  }
  return { groupBy: parsed.data.group_by, sinceUnix, untilUnix, limit: parsed.data.limit };
}

async function queryBillingFleet(c: Parameters<Handler>[0]): Promise<Response> {
  platformScope(c);
  const query = parseQuery(c, Math.floor(Date.now() / 1000));
  const service = depsOf(c).billingFleet;
  if (service === null) {
    throw new HttpError(
      503,
      "analytics_unavailable",
      "the billing Analytics Engine query surface is not configured (needs an account id and token)",
    );
  }
  try {
    return json(c, 200, await service.report(query));
  } catch (error) {
    if (error instanceof BillingFleetUnavailableError) {
      throw new HttpError(
        503,
        "analytics_unavailable",
        "the billing Analytics Engine query surface could not be reached",
      );
    }
    throw error;
  }
}

export const adminBillingFleetRoutes: GroupModule = crudGroup("admin_billing_fleet", [], {
  queryBillingFleet,
});
