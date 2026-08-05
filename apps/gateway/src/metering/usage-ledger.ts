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
 * The gateway's metering path now settles billing events, ledger, wallet, and
 * report outbox rows in the tenant object. This module writes the separate
 * usage rollup batch that follows that settlement.
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
 * and states why the billing and usage batches cannot be one commit:
 *
 * > **D1 has no transaction spanning independent batches.** … tenant billing
 * > settlement and this accumulate are separate writes … So: the CALLER still
 * > owns ordering and retry safety.
 *
 * The claim is `LedgerStore.record` returning `recorded` — the idempotent
 * `ON CONFLICT (billing_event_id) DO NOTHING` write keyed on
 * `ledgerEntryId(event)`. `MeteringUsageSink.#deliverOnce` accumulates on the
 * recorded branch, and may also retry the tenant object on a duplicate branch;
 * `usage_event_claims` keeps that repair from incrementing counters twice.
 *
 * The tenant-local usage claim makes replay of this additive batch safe, but it
 * still cannot make billing settlement and usage accumulation one commit.
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
import {
  D1UsageLedger,
  DurableObjectD1Database,
  periodMonthFromUnix,
  type UsageAggregateWrite,
} from "@ferrogate/storage";
import type { QuotaScopeKind } from "@ferrogate/storage";
import type { UsageRecordContext } from "../inference/ports.js";
import { gatewayTenantHandle } from "../ratelimit/wallet.js";
import { tenantDataObjectFor, type TenantDataBindings } from "../tenancy/tenant-data.js";
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
  /**
   * `x-ferrogate-agent-run-id` (#305/#522) — the agent run whose work produced
   * this spend, as declared on the request.
   *
   * Here for the SAME reason `apiKeyId` is: `Usage` (`src/inference/ports.ts`)
   * does not carry one and that file belongs to another slice, so the drain —
   * which holds the `Context` — is the only place it can be read. Applied by
   * `./agent-run.ts::chargeWithAgentRun` under the same request-id guard, and
   * for the same reason: a drain pass can settle an earlier request's outbox
   * row, and stamping this request's run onto it would be mis-attribution.
   */
  readonly agentRunId?: string | undefined;
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
  readonly usageDatabase?: D1Database | null | undefined;
}

/** Bindings this module reads. */
export interface UsageLedgerBindings {
  /**
   * The TENANT database (`sql/d1-ts/tenant/`), holding `tenant_contexts`,
   * `usage_aggregate_rollups` and `usage_monthly_rollups`.
   *
   * Billing settlement has already committed its tenant-local event, ledger,
   * wallet, and outbox rows before this usage batch runs. `BILLING_DB` remains
   * only the compatibility/projection surface for unscoped traffic; tenant
   * calls resolve through `TENANT_DATA`.
   */
  readonly DB?: D1Database | undefined;
  readonly TENANT_DATA?: TenantDataBindings["TENANT_DATA"] | undefined;
}

/** The seam the sink writes the accumulate through. */
export interface UsageAggregateSink {
  accumulate(write: UsageAggregateWrite): Promise<void>;
}

/** `env.DB`, when it is really a D1 binding (a `[vars]` `DB` is a string). */
export function usageDatabaseFrom(env: unknown, tenantId?: string): D1Database | undefined {
  if (tenantId !== undefined) {
    if (tenantId.trim() === "") return undefined;
    if (typeof env !== "object" || env === null) return undefined;
    const namespace = (env as UsageLedgerBindings).TENANT_DATA;
    if (namespace === undefined) return undefined;
    const stub = tenantDataObjectFor({ TENANT_DATA: namespace }, tenantId);
    return new DurableObjectD1Database(tenantId, stub).asD1Database();
  }
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
 * Add the durable identity needed to repair a control projection after an
 * isolate dies. The payload contains only projection lookup dimensions; the
 * projection reader reloads all counters from the tenant object, so retrying
 * never re-applies an additive delta.
 */
export function withUsageProjectionRetry(
  write: UsageAggregateWrite,
  sourceId: string,
): UsageAggregateWrite {
  return {
    ...write,
    projectionRetry: {
      sourceId,
      payloadJson: JSON.stringify({
        context: write.context,
        logicalModel: write.logicalModel,
        provider: write.provider,
        occurredAtUnix: write.occurredAtUnix,
        metadata: [...(write.metadata?.entries() ?? [])],
        ...(write.presenceTouch === undefined
          ? {}
          : { presenceApiKeyId: write.presenceTouch.apiKeyId }),
      }),
    },
  };
}

/** Persist request attribution on the charge for context-free outbox repair. */
export function chargeWithTenantAttribution(
  charge: MeteredCharge,
  attribution: MeteringAttribution | undefined,
): MeteredCharge {
  if (attribution === undefined || attribution.requestId !== charge.requestId) return charge;
  const tenant = {
    ...charge.event.tenant,
    ...(attribution.tenantId === undefined || attribution.tenantId === ""
      ? {}
      : { organization_id: attribution.tenantId }),
    ...(attribution.projectId === undefined || attribution.projectId === ""
      ? {}
      : { project_id: attribution.projectId }),
    ...(attribution.workspaceId === undefined || attribution.workspaceId === ""
      ? {}
      : { workspace_id: attribution.workspaceId }),
    ...(attribution.apiKeyId === undefined || attribution.apiKeyId === ""
      ? {}
      : { api_key_id: attribution.apiKeyId }),
  };
  return {
    ...charge,
    event: { ...charge.event, tenant },
    entry: { ...charge.entry, tenant },
  };
}

/** Fold the object-owned monotonic rollups into the same tenant batch. */
export function withUsageDerivedRollups(
  write: UsageAggregateWrite,
  charge: MeteredCharge,
  attribution: MeteringAttribution | undefined,
): UsageAggregateWrite {
  const owned = attribution !== undefined && attribution.requestId === charge.requestId;
  const tenantId = write.context.organizationId ?? charge.event.tenant.organization_id ?? "";
  if (tenantId === "") return write;
  const apiKeyId = charge.event.tenant.api_key_id;
  const agentRunId = charge.event.agent_run_id;
  if (apiKeyId === undefined && agentRunId === undefined && !owned) return write;
  return {
    ...write,
    ...(apiKeyId === undefined || apiKeyId === ""
      ? {}
      : {
          presenceTouch: {
            tenantId,
            apiKeyId,
            seenAtUnix: charge.occurredAtUnix,
          },
        }),
    ...(agentRunId === undefined || agentRunId === ""
      ? {}
      : {
          agentCostBurn: {
            tenantId,
            agentKey: agentRunId,
            period: periodMonthFromUnix(charge.occurredAtUnix),
            deltaUsd: charge.entry.cost.total_cost,
            nowUnix: charge.occurredAtUnix,
          },
        }),
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
    sourceId: charge.id,
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
    // #667. Subsets of the two counts above, so `totalTokens` is unchanged and
    // no existing budget read shifts — these accumulate purely so the report
    // API can EXPLAIN a bill (which portion was a cache read, which was
    // reasoning) instead of only stating it. Read off the priced entry's usage,
    // not the raw event, so the rollup agrees with the ledger row that produced
    // `costUsd` even after `reconcileSplit` repaired a one-sided report.
    cachedInputTokens: charge.entry.usage.cached_input_tokens ?? 0,
    cacheWriteTokens: charge.entry.usage.cache_write_tokens ?? 0,
    reasoningTokens: charge.entry.usage.reasoning_tokens ?? 0,
    costUsd: charge.entry.cost.total_cost,
    // A non-2xx still metered: it consumed prompt tokens upstream. `isError`
    // only splits the counter, it never suppresses the charge.
    isError: charge.event.status_code >= 400,
    occurredAtUnix: charge.occurredAtUnix,
    scopes,
    ...(Object.keys(charge.event.metadata ?? {}).length === 0
      ? {}
      : { metadata: new Map(Object.entries(charge.event.metadata)) }),
  };
}
