/**
 * The router that reads the ROSTER to decide which router serves a tenant.
 *
 * ## The defect this closes
 *
 * `apps/gateway` routes every tenant to its own Durable Object (#819) and
 * `apps/control-plane` provisions every new tenant onto that same object (#820)
 * — but the control plane still resolved its own tenant-DATA paths through
 * `EnvBindingTenantDatabaseRouter`, which serves `[[d1_databases]]` bindings and
 * nothing else. The two Workers therefore disagreed about where a tenant's rows
 * live, and the disagreement was silent in the worst possible place:
 *
 *  - `POST /admin/v1/wallets/{t}/credit` for a `durable_object` tenant resolved
 *    to `not_found`, took the document-only branch, answered 200, and wrote no
 *    `wallets` row anywhere. `projectWalletMovement` is the ONLY production
 *    writer of that table, so the gateway's no-oversell reserve found no wallet,
 *    answered `not_applicable`, and the tenant was never denied on a prepaid
 *    balance no matter how much it spent. An operator saw $500 credited.
 *  - `GET /admin/v1/fleet/assets` enumerated the roster, resolved every
 *    `durable_object` row to `not_found`, skipped each one WITHOUT recording it
 *    in `unreadable_tenants`, and answered `{rows: [], unreadable_tenants: []}`
 *    — indistinguishable from "the fleet has no assets". Green, and wrong.
 *
 * ## Why dispatch, rather than moving every call site
 *
 * The alternative was to point the control plane's ~10 tenant-data call sites at
 * the Durable Object router outright. That is wrong twice over: it strands every
 * tenant already living in a real per-tenant D1 database (`native_binding` is a
 * supported posture and is what a self-hosted single-tenant deployment runs),
 * and it makes the topology a property of the WORKER when it is really a
 * property of the TENANT. `tenant_databases.storage_backend` is the field that
 * records which one a tenant is on; it was written by #820 and read by nobody.
 * Reading it is the whole of this class.
 *
 * The consequence worth stating: a tenant's backend is now decided in ONE place
 * for the control plane, from durable state, rather than by which router a call
 * site happened to be handed. A tenant migrated between backends is a roster
 * update, not a redeploy.
 *
 * ## Cost, stated rather than discovered
 *
 * A `native_binding` tenant now costs TWO registry reads per resolution — one
 * here and one inside `EnvBindingTenantDatabaseRouter`. That is acceptable
 * because this class is for the control plane's ADMIN paths, which are not the
 * inference hot path; `apps/gateway` resolves from
 * `GATEWAY_TENANT_DB_ROUTING` directly and never builds one of these. If it ever
 * does, the second read is the thing to remove, by handing the registration down
 * rather than re-reading it.
 *
 * ## Fail closed, in both directions
 *
 * There is no arm that reaches for a shared database. A roster row that names
 * `durable_object` on a Worker that binds no namespace is a `runtime` refusal
 * naming the missing binding — NOT `not_found`, because "this tenant's data is
 * somewhere I cannot reach" and "this tenant has no data" get opposite fixes,
 * and it is exactly the collapse that made the fleet view answer an empty page.
 */
import { StorageError } from "./errors.js";
import {
  ControlDatabaseTenantRegistry,
  PRE_CUTOVER_TENANT_MIGRATION_STATES,
  type TenantDatabaseHandle,
  type TenantDatabaseRouter,
} from "./tenant-router.js";
import type { TenantDataStatement } from "./tenant-data-object.js";

/** The arms {@link BackendDispatchingTenantDatabaseRouter} dispatches between. */
export interface TenantBackendArms {
  /**
   * Every tenant whose roster row does NOT say `durable_object`, including
   * every tenant with no row at all. Ordinarily
   * `EnvBindingTenantDatabaseRouter`, whose own refusals (no row or a missing
   * binding name) are passed through unchanged.
   */
  readonly fallback: TenantDatabaseRouter;
  /**
   * The router for `storage_backend = 'durable_object'` rows. ABSENT means this
   * Worker binds no `TENANT_DATA` namespace, which is a supported posture — and
   * is why the absence is a named refusal here rather than a silent fall
   * through to {@link TenantBackendArms.fallback}, which would resolve the
   * tenant to a D1 database that holds none of its rows.
   */
  readonly durableObject?: TenantDatabaseRouter | undefined;
  /**
   * The legacy shared tenant database used while #824 is in `shared`,
   * `copying`, or `verifying`. It is optional so deployments that have no
   * migration source fail closed rather than silently using another arm.
   */
  readonly legacyShared?: TenantDatabaseRouter | undefined;
}

/**
 * Route each tenant to the backend its `tenant_databases` row names.
 *
 * `provisionedTenants()` and `control()` come from the roster/control database
 * directly, because both are account-global and neither depends on which arm a
 * given tenant is on.
 */
export class BackendDispatchingTenantDatabaseRouter implements TenantDatabaseRouter {
  /**
   * Deliberately ABSENT. This router has no single backend — that is its whole
   * purpose — and `provisionTenantStorage` reads this property to label a
   * `pending` roster row. Answering anything here would stamp one backend onto
   * every tenant being provisioned, which is the mislabel the property exists to
   * prevent. Provisioning is wired to a router that DOES know
   * (`resolveTenantStorage` in `apps/control-plane`), and this one declines to
   * guess.
   */
  readonly backend = undefined;

  readonly #controlDb: D1Database;
  readonly #registry: ControlDatabaseTenantRegistry;
  readonly #arms: TenantBackendArms;

  constructor(controlDb: D1Database, arms: TenantBackendArms) {
    this.#controlDb = controlDb;
    this.#registry = new ControlDatabaseTenantRegistry(controlDb);
    this.#arms = arms;
  }

  control(): D1Database {
    return this.#controlDb;
  }

  async forTenant(tenantId: string): Promise<TenantDatabaseHandle> {
    if (tenantId === "") {
      // Refused HERE and not delegated, because the two arms refuse it with
      // different messages and a blank id must never depend on which arm a
      // roster lookup would have chosen.
      throw StorageError.runtime("tenant database routing requires a non-empty tenant id");
    }
    const registration = await this.#registry.get(tenantId);
    if (
      registration?.migrationState !== undefined &&
      PRE_CUTOVER_TENANT_MIGRATION_STATES.includes(registration.migrationState)
    ) {
      const legacyShared = this.#arms.legacyShared;
      if (legacyShared === undefined) {
        throw StorageError.runtime(
          `tenant ${tenantId} is in migration state ${registration.migrationState}, but this Worker binds no legacy shared tenant database`,
        );
      }
      return legacyShared.forTenant(tenantId);
    }
    if (registration?.storageBackend !== "durable_object") {
      // Includes "no row at all": a tenant nothing has provisioned is the
      // fallback's `not_found`, which callers already read as "no tenant
      // database, act on the document only".
      return this.#arms.fallback.forTenant(tenantId);
    }
    const durableObject = this.#arms.durableObject;
    if (durableObject === undefined) {
      throw StorageError.runtime(
        [
          `tenant ${tenantId} is provisioned on the durable_object backend, but this Worker`,
          "binds no TENANT_DATA namespace and therefore cannot reach its storage. Refusing",
          "rather than resolving it to a D1 database that holds none of its rows — bind the",
          "namespace, or move the tenant's roster row to a backend this deployment serves.",
        ].join(" "),
      );
    }
    return durableObject.forTenant(tenantId);
  }

  /** Route operator-only object writes by the same roster decision as reads. */
  async privilegedBatch(
    tenantId: string,
    statements: readonly TenantDataStatement[],
  ): Promise<void> {
    if (tenantId === "") {
      throw StorageError.runtime("tenant database routing requires a non-empty tenant id");
    }
    const registration = await this.#registry.get(tenantId);
    const router =
      registration?.migrationState !== undefined &&
      PRE_CUTOVER_TENANT_MIGRATION_STATES.includes(registration.migrationState)
        ? this.#arms.legacyShared
        : registration?.storageBackend === "durable_object"
          ? this.#arms.durableObject
          : this.#arms.fallback;
    if (router === undefined) {
      throw StorageError.runtime(
        `tenant ${tenantId} is provisioned on the durable_object backend, but this Worker binds no TENANT_DATA namespace`,
      );
    }
    if (router.privilegedBatch === undefined) {
      throw StorageError.runtime(
        `tenant ${tenantId} backend does not expose the privileged tenant-write RPC`,
      );
    }
    await router.privilegedBatch(tenantId, statements);
  }

  async setScheduleAlarm(tenantId: string, scheduledAtUnix: number): Promise<void> {
    const registration = await this.#registry.get(tenantId);
    const router =
      registration?.migrationState !== undefined &&
      PRE_CUTOVER_TENANT_MIGRATION_STATES.includes(registration.migrationState)
        ? this.#arms.legacyShared
        : registration?.storageBackend === "durable_object"
          ? this.#arms.durableObject
          : this.#arms.fallback;
    if (router === undefined) {
      throw StorageError.runtime(
        `tenant ${tenantId} backend does not expose the schedule alarm RPC`,
      );
    }
    // Native/shared D1 routers intentionally have no Durable Object alarm.
    // Preserve the optional capability so legacy schedule paths keep using
    // their existing control-plane tick.
    if (router.setScheduleAlarm === undefined) return;
    await router.setScheduleAlarm(tenantId, scheduledAtUnix);
  }

  async clearScheduleAlarm(tenantId: string): Promise<void> {
    const registration = await this.#registry.get(tenantId);
    const router =
      registration?.migrationState !== undefined &&
      PRE_CUTOVER_TENANT_MIGRATION_STATES.includes(registration.migrationState)
        ? this.#arms.legacyShared
        : registration?.storageBackend === "durable_object"
          ? this.#arms.durableObject
          : this.#arms.fallback;
    if (router === undefined) {
      throw StorageError.runtime(
        `tenant ${tenantId} backend does not expose the schedule alarm RPC`,
      );
    }
    if (router.clearScheduleAlarm === undefined) return;
    await router.clearScheduleAlarm(tenantId);
  }

  async rearmScheduleAlarm(tenantId: string): Promise<void> {
    const registration = await this.#registry.get(tenantId);
    const router =
      registration?.migrationState !== undefined &&
      PRE_CUTOVER_TENANT_MIGRATION_STATES.includes(registration.migrationState)
        ? this.#arms.legacyShared
        : registration?.storageBackend === "durable_object"
          ? this.#arms.durableObject
          : this.#arms.fallback;
    if (router === undefined) {
      throw StorageError.runtime(
        `tenant ${tenantId} backend does not expose the schedule alarm rearm RPC`,
      );
    }
    if (router.rearmScheduleAlarm === undefined) return;
    await router.rearmScheduleAlarm(tenantId);
  }

  async provisionedTenants(): Promise<readonly string[]> {
    return (await this.#registry.list()).map((row) => row.tenantId);
  }
}
