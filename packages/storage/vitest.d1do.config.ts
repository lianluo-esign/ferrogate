import { d1SuiteConfig } from "./vitest.d1.shared.js";

/**
 * THE ACCEPTANCE TEST FOR #823: `test/d1/**` — the same files, unmodified in
 * substance — run against per-tenant SQLite-backed **Durable Objects** through
 * the `D1Database` facade in `src/tenant-do.ts`, instead of against per-tenant
 * D1 bindings.
 *
 * ## Why this is a whole extra config and not a `describe.each`
 *
 * The bar the facade has to clear is not "a facade test passes". It is "every
 * test written against real D1, by someone who was not thinking about the
 * facade, still passes — and no module under `src/d1/` was edited to make it
 * so". A facade-shaped suite would agree with the facade. These files assert
 * the things that cost money: that `batch()` is one transaction, that an empty
 * `RETURNING` set is the guard's refusal, that five concurrent reserves against
 * a balance affording four admit exactly four.
 *
 * The pool builds one miniflare environment per config, so the backend has to
 * be chosen before workerd boots. Switching inside a file would also mean two
 * topologies sharing one set of D1 databases.
 *
 * ## What differs from `vitest.d1.config.ts`
 *
 * One binding: `TENANT_BACKEND = "durable_object"`. `test/d1/harness.ts` reads
 * it and hands back a `DurableObjectTenantDatabaseRouter` and DO-backed tenant
 * databases; everything else — the control database, the R2 bucket, the
 * migration sets, the file list — is identical, because everything else is
 * genuinely the same question.
 *
 * The control plane stays on D1 in BOTH legs for account-global `billing_*` and
 * `site_domain_verifications`. The #863 provider-credential and replay-floor
 * rows are tenant object tables, so their tests route through the object
 * database just like the other tenant-private families.
 */
export default d1SuiteConfig("durable_object");
