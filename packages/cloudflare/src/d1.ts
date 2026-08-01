/**
 * D1 database **LIFECYCLE** — slice **S5**.
 *
 * Ported from `crates/ferrogate-cloudflare/src/d1.rs:159-219`.
 *
 * ## Why this exists when "D1 is a binding"
 *
 * `cutover-parity-libraries.md` §6.1 classified ALL of `d1.rs` as "superseded by
 * the native D1 binding" and therefore never gave it a port-plan row. That is
 * true of the `/query` endpoint and **false of the lifecycle endpoints**: no
 * binding can CREATE a D1 database, for the same reason no binding can create
 * an R2 bucket. `env.DB` addresses a database that already exists.
 *
 * FerroGate's design is **one D1 database per tenant**, and nothing in the TS
 * tree creates one: `EnvBindingTenantDatabaseRouter` resolves
 * `tenantId → binding` through the control DB's `tenant_databases` table and
 * fails closed on a miss, but every reference to that table is a READER. The
 * documented onboarding procedure is a comment block instructing an operator to
 * run `wrangler d1 create`, hand-write an `INSERT INTO tenant_databases`, add a
 * `[[d1_databases]]` stanza and redeploy. This module removes the manual half.
 *
 * ## The `/query` endpoint is deliberately NOT here
 *
 * `@ferrogate/storage`'s `D1RestDatabase` already implements it, is exercised
 * against a real `workerd`, and models the atomicity limits the REST path has
 * (no transaction envelope → `batch()` refuses). A second copy here would be
 * exactly the duplication this package exists to end. Provisioning-time
 * migrations should run through that class.
 *
 * ## The deploy-time constraint this does NOT remove
 *
 * Creating a database is programmable; **binding** it is not. A newly created
 * database still needs a `[[d1_databases]]` stanza and a deploy before
 * `EnvBindingTenantDatabaseRouter` can route to it. That is the standing open
 * constraint on the whole one-DB-per-tenant design. The deploy-free alternative
 * is `NonAtomicD1RestTenantDatabaseRouter`, which addresses a database by
 * runtime uuid — and refuses the money paths for it.
 *
 * ## Wiring line
 *
 * From a control-plane tenant-onboarding handler (never the request path):
 *
 * ```ts
 * const database = await new D1LifecycleClient(cf).createDatabase({ name });
 * // then: run sql/d1-ts/tenant/* through @ferrogate/storage's D1RestDatabase,
 * // then INSERT the tenant_databases row, then add the binding + deploy.
 * ```
 */
import type { CloudflareClient } from "./client.js";
import { CloudflareError } from "./errors.js";

const D1_DATABASES_PATH = "accounts/{account_id}/d1/database";

/**
 * The list endpoint caps `per_page` at 1,000. D1's list is PAGE-NUMBERED
 * (`page`/`per_page`), unlike R2's cursor dialect; confusing the two silently
 * returns page 1.
 */
const D1_PER_PAGE = 1000;

/** Request body for `POST /accounts/{account_id}/d1/database`. */
export interface D1CreateDatabaseRequest {
  /** D1 database name, unique per account. */
  readonly name: string;
  /** `wnam`/`enam`/`weur`/`eeur`/`apac`/`oc`. Ignored when `jurisdiction` is set. */
  readonly primaryLocationHint?: string;
  /** Jurisdictional restriction (`eu`/`fedramp`). */
  readonly jurisdiction?: string;
}

/** A D1 database descriptor. All fields are optional in Cloudflare's schema. */
export interface D1DatabaseDescriptor {
  /** The identifier the query endpoint routes on — `tenant_databases.database_uuid`. */
  readonly uuid?: string;
  readonly name?: string;
  readonly version?: string;
  readonly created_at?: string;
  readonly file_size?: number;
  readonly num_tables?: number;
}

/** The D1 database-lifecycle surface over the shared client. */
export class D1LifecycleClient {
  constructor(private readonly client: CloudflareClient) {}

  /**
   * Provision a new D1 database. Returns the descriptor whose `uuid` the query
   * endpoint routes on and the `tenant_databases` registry row records.
   *
   * Retry is opted IN: D1 database names are unique per account, so a re-issued
   * create after a 5xx cannot silently produce a SECOND database — it either
   * succeeds or reports the duplicate. That is the property the token mint in
   * `r2-token.ts` lacks, which is why that one opts out.
   */
  async createDatabase(request: D1CreateDatabaseRequest): Promise<D1DatabaseDescriptor> {
    if (request.name.trim() === "") {
      throw CloudflareError.config("D1 create-database requires a non-empty name");
    }
    const body: Record<string, string> = { name: request.name };
    if (request.primaryLocationHint !== undefined) {
      body.primary_location_hint = request.primaryLocationHint;
    }
    if (request.jurisdiction !== undefined) body.jurisdiction = request.jurisdiction;
    return this.client.requestJson<D1DatabaseDescriptor>("POST", D1_DATABASES_PATH, {
      body,
      idempotent: true,
    });
  }

  /**
   * List **all** of the account's D1 databases, walking pages beyond the first.
   *
   * Terminates once a page returns fewer rows than `per_page` — no cursor state.
   * Costs one extra empty page only in the exact-multiple case.
   */
  async listDatabases(): Promise<D1DatabaseDescriptor[]> {
    const databases: D1DatabaseDescriptor[] = [];
    let page = 1;
    for (;;) {
      const batch = await this.client.getJson<D1DatabaseDescriptor[]>(
        `${D1_DATABASES_PATH}?per_page=${D1_PER_PAGE}&page=${page}`,
      );
      databases.push(...batch);
      if (batch.length < D1_PER_PAGE) return databases;
      page += 1;
    }
  }

  /** Fetch one database descriptor by uuid. */
  async getDatabase(databaseId: string): Promise<D1DatabaseDescriptor> {
    return this.client.getJson<D1DatabaseDescriptor>(databasePath(databaseId));
  }

  /** Delete a database **and all of its data**. */
  async deleteDatabase(databaseId: string): Promise<void> {
    await this.client.requestAck("DELETE", databasePath(databaseId), { idempotent: true });
  }
}

/**
 * Build the `d1/database/{uuid}` path, rejecting ids that could escape the path
 * segment. Cloudflare ids are hex uuids; anything else is a caller bug surfaced
 * before any request is sent.
 */
function databasePath(databaseId: string): string {
  if (databaseId === "" || !/^[a-zA-Z0-9-]+$/.test(databaseId)) {
    throw CloudflareError.config(
      `invalid D1 database id ${JSON.stringify(databaseId)}: expected a Cloudflare uuid`,
    );
  }
  return `${D1_DATABASES_PATH}/${databaseId}`;
}
