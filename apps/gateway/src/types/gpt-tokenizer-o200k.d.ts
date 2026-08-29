/**
 * Type shim for `gpt-tokenizer/encoding/o200k_base` (#976 Phase B).
 *
 * gpt-tokenizer@4.0.0 ships declaration files that use string-literal import
 * specifiers (`import { "babbage-002" as babbage_002_spec } from ...`, in
 * `esm/models.d.ts`) which TypeScript 5.5's parser rejects with TS1003 — and
 * `skipLibCheck` suppresses only SEMANTIC lib errors, never PARSE errors, so the
 * whole gateway typecheck fails the moment `tokenizer.ts` imports the encoding
 * and tsc follows the package's type graph into that file.
 *
 * `apps/gateway/tsconfig.json` maps the encoding specifier to THIS file via
 * `paths`, so tsc reads the one binding this codebase uses from here instead of
 * resolving into the package's own broken declarations. It does NOT change what
 * runs: neither the Cloudflare vitest pool nor `wrangler deploy` honor tsconfig
 * `paths`, so both resolve the real `gpt-tokenizer` JS at build/runtime. This is
 * a type-checking shim only.
 *
 * `countTokens` is synchronous and returns the BPE token count of `input` under
 * the o200k_base encoding — the sole export `tokenizer.ts` consumes.
 */
export declare function countTokens(input: string, encodeOptions?: unknown): number;
