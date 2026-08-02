/**
 * Vite's `?raw` suffix over a JSON module, typed.
 *
 * `test/spec-schema.ts` reads the vendored MCP specification schema as TEXT
 * rather than as a parsed module so it can digest the EXACT BYTES that are
 * committed. A parsed-then-re-serialized object would not reproduce the
 * upstream file's whitespace, so its digest could never be compared against the
 * one `spec/2026-07-28/PROVENANCE.json` records — and that comparison is the
 * whole mechanism by which a hand-edited vendored artifact is detected.
 *
 * Same mechanism and reasoning as `test/ts-raw.d.ts`: the transform is real
 * (`@cloudflare/vitest-pool-workers` runs tests through Vite); this declaration
 * only tells `tsc` what it produces.
 */
declare module "*.json?raw" {
  const contents: string;
  export default contents;
}
