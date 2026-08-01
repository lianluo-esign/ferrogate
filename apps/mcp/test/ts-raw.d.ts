/**
 * Vite's `?raw` suffix over a TypeScript module, typed.
 *
 * `test/drain-fleet.test.ts` reads three Workers' drain modules as TEXT — its
 * own, `apps/agent-runtime/src/drain.ts`, and `apps/gateway/src/routes/drain.ts`
 * — in order to (a) compare the refusal constants the fleet answers as DATA and
 * (b) assert that the two modules it ALSO value-imports stay LEAVES, so pulling
 * them into this Worker's test bundle cannot drag another Worker's module graph
 * along. Asserting that off the files' own bytes is the only version of the
 * claim that can go red; a docblock saying "keep this a leaf" cannot.
 *
 * Same mechanism and same reasoning as
 * `apps/gateway/test/routes/ts-raw.d.ts`: the transform is real
 * (`@cloudflare/vitest-pool-workers` runs tests through Vite); this declaration
 * only tells `tsc` what it produces.
 */
declare module "*.ts?raw" {
  const contents: string;
  export default contents;
}
