/**
 * Vite's `?raw` suffix over a TypeScript module, typed.
 *
 * `test/routes/agent-upstream-fleet-withdrawal.test.ts` reads
 * `apps/agent-runtime/src/agents/registry.ts` as TEXT in order to assert that
 * the cross-app value import it also performs stays a LEAF — that module has
 * exactly one import and it is `import type`, so pulling it into this Worker's
 * test bundle cannot drag another Worker's module graph along. Asserting that
 * off the file's own bytes is the only version of the claim that can go red; a
 * docblock saying "TYPE-ONLY, and it has to stay that way" cannot.
 *
 * Same mechanism and same reasoning as `test/metering/sql-raw.d.ts`: the
 * transform is real (`@cloudflare/vitest-pool-workers` runs tests through
 * Vite); this declaration only tells `tsc` what it produces.
 */
declare module "*.ts?raw" {
  const contents: string;
  export default contents;
}
