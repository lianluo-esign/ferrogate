/**
 * Vite's `?raw` suffix, typed.
 *
 * `test/setup.ts` reads the DEPLOYED control migration
 * (`sql/d1-ts/control/0001_init_control.sql`) as text rather than restating its
 * DDL, so a column rename in the migration breaks this suite instead of the
 * suite passing against a private schema.
 * `@cloudflare/vitest-pool-workers` runs the tests through Vite, so the
 * transform is the real one — this declaration only tells `tsc` what it
 * produces. Same file, same reason, as
 * `apps/gateway/test/metering/sql-raw.d.ts`.
 */
declare module "*.sql?raw" {
  const contents: string;
  export default contents;
}
