/**
 * The committed-token FEEDBACK LOOP: `@ferrogate/storage`'s `D1UsageLedger`,
 * mounted on the metering drain.
 *
 * ## The loop that was open, from the write end
 *
 * `apps/gateway/src/ratelimit/quota.ts` reads `usage_monthly_rollups` to decide
 * the monthly USD budget, and `apps/gateway/src/ratelimit/token-budget.ts` reads
 * `usage_aggregate_rollups` (via `sumApiKeyCommittedTokens`) to decide
 * `api_keys.monthly_token_budget`. **Nothing in `apps/` wrote either table.**
 * The gateway's metering path settled into the CONTROL database's
 * `billing_events` / `billing_ledger` / `billing_report_outbox` and stopped.
 *
 * So both budgets read a table that stayed empty forever: the USD budget could
 * never trip, and the token budget had no `committed` operand at all. This
 * module is the missing write, and it does not re-implement it —
 * `D1UsageLedger.persistUsageAggregate` already batches `tenant_contexts` +
 * `usage_aggregate_rollups` + `usage_monthly_rollups` atomically, with tests.
 *
 * ## Ordering: claim first, accumulate second
 *
 * `packages/storage/src/d1/usage-d1.ts` states the contract this module obeys,
 * and states why it cannot be a single commit:
 *
 * > **D1 has no transaction spanning two databases.** … `billing_events` is in
 * > the CONTROL database and this accumulate is on a TENANT database … So: the
 * > CALLER still owns ordering (claim first, accumulate only on a win).
 *
 * The claim is `LedgerStore.record` returning `recorded` — the idempotent
 * `ON CONFLICT (billing_event_id) DO NOTHING` write keyed on
 * `ledgerEntryId(event)`. This accumulate therefore runs from exactly one place:
 * `MeteringUsageSink.#deliverOnce`, on the `recorded` branch only. A `duplicate`
 * or `conflict` outcome accumulates NOTHING, which is what keeps a replayed
 * outbox row from counting a request's tokens twice — the accumulate itself is
 * `existing + excluded`, deliberately additive and deliberately not idempotent.
 *
 * The residual window is the one the storage module names: a crash between a
 * won claim and this accumulate UNDER-counts one request's tokens. Under-count
 * is the correct direction — it can only fail to refuse, never wrongly refuse —
 * and closing it needs a `usage_event_claims` table in the tenant migration,
 * which is not this slice's file.
 *
 * ## Attribution, and the one case it is dropped
 *
 * `usage_aggregate_rollups` is joined to `tenant_contexts.api_key_id`, and
 * `Usage` (`src/inference/ports.ts`) carries no api-key id — that file is the
 * composition root's, not this slice's. The id is therefore taken from the
 * authenticated credential by `meteringDrain`, which holds `c.get("auth")`, and
 * travels on the drain's own {@link MeteringAttribution}.
 *
 * It is applied to a charge ONLY when `charge.requestId` matches the attribution's
 * request id. That guard is not decoration: one drain pass can pick up an outbox
 * row left behind by an EARLIER request whose drain failed, and stamping this
 * request's credential onto that charge would attribute one key's spend to
 * another. The unmatched case writes the tenant/project rollup with no api-key
 * id — the spend is still counted against the tenant's USD budget, it is only
 * the per-key token attribution that is dropped. Under-attribution, never
 * mis-attribution.
 */
import { D1UsageLedger, type UsageAggregateWrite } from "@ferrogate/storage";
import type { QuotaScopeKind } from "@ferrogate/storage";
import type { UsageRecordContext } from "../inference/ports.js";
import { gatewayTenantHandle } from "../ratelimit/wallet.js";
import type { MeteredCharge } from "./ports.js";

/**
 * Who a request's usage is attributed to, resolved from the authenticated
 * credential by `meteringDrain` (`./middleware.ts`).
 *
 * `requestId` is a guard, not attribution: see the module doc.
 */
export interface MeteringAttribution {
  readonly requestId: string;
  readonly tenantId?: string | undefined;
  readonly projectId?: string | undefined;
  readonly workspaceId?: string | undefined;
  readonly apiKeyId?: string | undefined;
}

/**
 * The drain's context, widened with attribution.
 *
 * `UsageRecordContext` is declared in `src/inference/ports.ts`, which this slice
 * does not own, so it is EXTENDED here rather than edited. Structural typing
 * makes the wider value acceptable everywhere the narrower one is expected, and
 * a caller that supplies no attribution is unchanged.
 */
export interface MeteringDrainContext extends UsageRecordContext {
  readonly attribution?: MeteringAttribution | undefined;
}

/** Bindings this module reads. */
export interface UsageLedgerBindings {
  /**
   * The TENANT database (`sql/d1-ts/tenant/`), holding `tenant_contexts`,
   * `usage_aggregate_rollups` and `usage_monthly_rollups`.
   *
   * NOT `BILLING_DB`: that is the CONTROL database, whose migration carries the
   * billing tables and NOT these. The two halves of a settled request really do
   * live in two databases — that is the cross-database limit above, not a
   * misconfiguration.
   */
  readonly DB?: D1Database | undefined;
}

/** The seam the sink writes the accumulate through. */
export interface UsageAggregateSink {
  accumulate(write: UsageAggregateWrite): Promise<void>;
}

/** `env.DB`, when it is really a D1 binding (a `[vars]` `DB` is a string). */
export function usageDatabaseFrom(env: unknown): D1Database | undefined {
  if (typeof env !== "object" || env === null) return undefined;
  const candidate = (env as UsageLedgerBindings).DB;
  return candidate !== undefined && typeof candidate.prepare === "function" ? candidate : undefined;
}

/** `D1UsageLedger` on one tenant's database. */
export function d1UsageAggregateSink(db: D1Database, tenantId: string): UsageAggregateSink {
  const ledger = new D1UsageLedger(gatewayTenantHandle(db, tenantId));
  return {
    async accumulate(write: UsageAggregateWrite): Promise<void> {
      await ledger.persistUsageAggregate(write);
    },
  };
}

/**
 * The scope chain a settled call folds into.
 *
 * One row per level the caller occupies, which is what Rust writes — and the
 * overview read sums ONLY the `tenant` rows, so the fan-out cannot double-count
 * a request. The `key` scope is the one the token budget's sibling read needs;
 * dropping it here would leave `sumApiKeyCommittedTokens` at zero forever,
 * which is precisely the state this module exists to end.
 */
export function usageScopesFor(
  attribution: MeteringAttribution | undefined,
  event: MeteredCharge["event"],
): { scopeType: QuotaScopeKind; scopeId: string }[] {
  const tenantId = attribution?.tenantId ?? event.tenant.organization_id;
  const projectId = attribution?.projectId ?? event.tenant.project_id;
  const workspaceId = attribution?.workspaceId ?? event.tenant.workspace_id;
  const keyId = attribution?.apiKeyId ?? event.tenant.api_key_id;

  const scopes: { scopeType: QuotaScopeKind; scopeId: string }[] = [];
  const add = (scopeType: QuotaScopeKind, scopeId: string | undefined): void => {
    if (scopeId !== undefined && scopeId !== "") scopes.push({ scopeType, scopeId });
  };
  add("tenant", tenantId);
  add("project", projectId);
  add("workspace", workspaceId);
  add("key", keyId);
  return scopes;
}

/**
 * The deterministic `tenant_contexts.id` a request's usage is filed under.
 *
 * Deliberately derived from the attribution chain and NOT from the request id:
 * the row is a shared dimension that many requests roll up into, so a
 * per-request id would make `usage_aggregate_rollups` unbounded and the join in
 * `sumApiKeyCommittedTokens` a full scan.
 */
export function usageContextId(parts: readonly (string | undefined)[]): string {
  return parts.map((part) => (part === undefined || part === "" ? "-" : part)).join(":");
}

/**
 * Turn a settled charge into the aggregate write, or `null` when it cannot be
 * attributed to any scope at all.
 *
 * `null` is a REFUSAL to write, not a silent drop: `persistUsageAggregate`
 * itself throws on an empty scope list ("a call folded into no scope is spend
 * that no budget check can ever see"), and answering `null` here keeps that
 * refusal from becoming a rejected promise inside a drain.
 */
export function usageWriteFor(
  charge: MeteredCharge,
  attribution: MeteringAttribution | undefined,
): UsageAggregateWrite | null {
  // See the module doc: attribution belongs to ONE request, and is applied only
  // to that request's charge.
  const owned = attribution !== undefined && attribution.requestId === charge.requestId;
  const applied = owned ? attribution : undefined;
  const scopes = usageScopesFor(applied, charge.event);
  if (scopes.length === 0) return null;

  const tenantId = applied?.tenantId ?? charge.event.tenant.organization_id;
  const projectId = applied?.projectId ?? charge.event.tenant.project_id;
  const workspaceId = applied?.workspaceId ?? charge.event.tenant.workspace_id;
  const apiKeyId = applied?.apiKeyId ?? charge.event.tenant.api_key_id;

  return {
    context: {
      id: usageContextId([tenantId, projectId, workspaceId, apiKeyId]),
      ...(tenantId === undefined ? {} : { organizationId: tenantId }),
      ...(projectId === undefined ? {} : { projectId }),
      ...(workspaceId === undefined ? {} : { workspaceId }),
      ...(apiKeyId === undefined ? {} : { apiKeyId }),
    },
    logicalModel: charge.event.logical_model,
    provider: charge.event.provider,
    promptTokens: charge.event.usage.prompt_tokens,
    completionTokens: charge.event.usage.completion_tokens,
    totalTokens: charge.event.usage.total_tokens,
    costUsd: charge.entry.cost.total_cost,
    // A non-2xx still metered: it consumed prompt tokens upstream. `isError`
    // only splits the counter, it never suppresses the charge.
    isError: charge.event.status_code >= 400,
    occurredAtUnix: charge.occurredAtUnix,
    scopes,
  };
}
