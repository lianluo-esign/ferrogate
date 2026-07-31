/**
 * Vite's `?raw` suffix, typed.
 *
 * `test/metering/d1-harness.ts` reads the
 * DEPLOYED migration `sql/d1-ts/control/0001_init_control.sql` as text rather
 * than restating its DDL, so a column rename in the migration breaks the
 * metering suite instead of the suite passing against a private schema. The
 * gateway's own `test/setup-d1.ts` gets the same guarantee for the TENANT
 * database from `readD1Migrations` in `vitest.config.ts`; that file is not this
 * slice's to edit, and Vite's `?raw` import is the equivalent that works from
 * inside a test directory.
 *
 * `@cloudflare/vitest-pool-workers` runs the tests through Vite, so the
 * transform is the real one — this declaration only tells `tsc` what it
 * produces.
 */
declare module "*.sql?raw" {
  const contents: string;
  export default contents;
}
