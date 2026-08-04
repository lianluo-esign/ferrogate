# Request Logs and Agent Runs in Tenant Objects

Status: approved implementation scope for #859 (2026-08-04)

Related work: #831 classification, #825 cross-tenant reads

## Source of truth

`TenantDataObject` is authoritative for `request_logs`, `agent_runs`, and
`agent_run_events`. Each authoritative row has a non-empty tenant id and is
written through the exact tenant object's D1-compatible facade. The control D1
tables with these names remain only as derived compatibility projections while
the existing fleet joins and one-database admin surfaces are migrated. They are
never authoritative and are not a fallback for an unavailable tenant object.

The projection is full-width for the current request-log and agent-run schema so
existing consumers can migrate without losing investigation fields. Projection
writes are idempotent and may be eventually consistent with the object; a
projection mutation must never change an object read.

Rows without tenant attribution are platform/unattributed compatibility rows
and remain control-D1-only. They cannot enter an authoritative tenant table.

## Write path

Gateway request-log writes group records by tenant and issue one append/upsert
batch per tenant object. The control projection is written after the object
batch for the existing fleet surface. Queue retries repeat both idempotent
operations. A failure to record evidence preserves the current request-serving
contract: it is reported in sink statistics and does not fail the request.

`AgentRunState` remains the live run-state object. Create, state transition, and
event append operations additionally write the complete run/event evidence to
the exact tenant object and update the derived control projection for the
platform list/timeline surface. The object write is the authority boundary;
there is no control-D1 fallback when the tenant object is not available.

## Reader dispositions

The exact cross-tenant path is: a control-D1 projection query discovers tenant
ids and applies pagination/limits; each returned tenant id is then routed with
`TenantDatabaseRouter.forTenant(tenantId)` and read from that tenant's
`TenantDataObject`. A reader that cannot perform that second step is explicitly
projection-backed and must label its data as derived/as-of; it must not call the
projection authoritative.

| Reader | #859 disposition |
| --- | --- |
| `admin_request_log.ts` tenant list/export | Exact tenant-object read. Control projection is only the existing fleet discovery/index path. |
| `admin_request_log.ts` guardrail investigation | Control projection discovers candidate tenants; request logs, runs, and run events are fetched from each exact tenant object. The investigation adds the tenant predicate before the object query; no request-id-only agent leg remains. Audit/billing/guardrail tables stay control-owned and are joined explicitly. |
| `agent_run.ts` list and timeline | Tenant-scoped reads use the exact tenant object. Existing platform pages keep the derived control projection until their bounded fan-out/pagination work in #825 is complete. |
| `admin_cost_record.ts` | Derived control projection for the existing billing/request join. Billing remains authoritative in its existing control/tenant billing store. |
| `admin_experiment.ts` | Derived control projection for the existing arm aggregate join. |
| `finops/source.ts` | Derived control projection for the existing fleet aggregate. The projection is labeled with its as-of time; Analytics Engine is a future option, not part of #859. |
| `siem/source.ts` | Derived control projection for the existing export pump, which currently owns one control-D1 read connection. Tenant-scoped investigation is not served from this path. |
| Gateway retention/scheduled cleanup | Candidate discovery may use the derived projection, but deletes are routed to each exact tenant object and then remove the projection row. |
| Gateway request-log queue/direct sink | Tenant-grouped object write followed by derived control projection; unattributed rows are control-D1-only. |
| `AgentRunState` lifecycle writer | Exact tenant object write plus derived control projection. |

## Explicit #825 boundary

#859 does not implement a general cross-tenant query service, Analytics Engine,
or removal of every control-D1 join. The remaining #825 dependency is the
bounded, paginated fleet-read contract and freshness/deletion guarantees for
all projection-backed consumers. Until that work lands, those consumers use
the labeled compatibility projection with visible staleness rather than
pretending that a control table is the source of truth.

## Verification contract

Mutation-backed tests must prove:

1. two tenant objects contain only their own request logs, runs, and events;
2. changing the control projection does not change an authoritative object
   read;
3. request-log writes preserve tenant attribution and retry/idempotency;
4. event reads are ordered by append sequence/time within a run; and
5. investigation reads route to the exact tenant object and cannot satisfy an
   agent leg from another tenant's matching request id.

