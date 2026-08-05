/**
 * The D1-backed half of `@ferrogate/storage`.
 *
 * Everything here needs a REAL `D1Database` binding and is therefore tested
 * against real SQLite in `workerd` (`test/d1/*.test.ts` under
 * `vitest.d1.config.ts`), never against a fake. The pure algorithms and their
 * in-memory reference backends stay in the parent directory and keep their
 * plain-vitest suite.
 *
 * Pairing:
 *
 * | pure / in-memory (`../`)      | durable (here)                |
 * |-------------------------------|-------------------------------|
 * | `MemoryWalletStore`           | `D1WalletStore`               |
 * | `MemoryWorkflowBudgetStore`   | `D1WorkflowBudgetStore`       |
 * | `presence.ts`, `agent-cost-burn.ts` | `TenantMonotonicUpserts`|
 * | replay floors (tenant object) | `TenantMonotonicUpserts`      |
 * | `quota.ts` rollup DTOs        | `D1UsageLedger`               |
 * | `MemoryReferenceGuardedDeletes` | `D1ReferenceGuardedDeletes` |
 * | `MemoryBudgetAlertStore`      | `D1BudgetAlertStore`          |
 * | `MemoryAssetStore`            | `D1AssetMetadataStore`        |
 * | `site-domain.ts` (pure rule)  | `D1SiteDomainVerificationStore` |
 * | `retention.ts` planners       | `D1RetentionPolicyStore` + `sweepAssetRetention` |
 * | `agent-schedule.ts` engine    | `D1AgentScheduleStore`        |
 *
 * The in-memory stores are not deprecated by these: they remain the executable
 * specification of the invariant, and the D1 tests assert the SAME observable
 * outcomes so a divergence between the two backends is a test failure.
 */
export * from "./rows.js";
export * from "./wallet-d1.js";
export * from "./workflow-budget-d1.js";
export * from "./monotonic.js";
export * from "./usage-d1.js";
export * from "./billing-d1.js";
export * from "./references-d1.js";
export * from "./assets-r2.js";
export * from "./budget-alerts-d1.js";
export * from "./assets-d1.js";
export * from "./site-domain-d1.js";
export * from "./retention-d1.js";
export * from "./agent-schedule-d1.js";
// Per-tenant BYOK alias rows (issue #682). The caller supplies the tenant
// object's database; the credential value never passes through this module.
export * from "./provider-credential-d1.js";
