# Official MCP client fixture (2026-07-28 final)

This fixture drives two real FerroGate processes through the official Tier-1
TypeScript client. It is not a FerroGate-authored protocol client or server
double.

- npm package: `@modelcontextprotocol/client@2.0.0`
- npm integrity: recorded in `package-lock.json` and `provenance.json`
- official SDK tag: `@modelcontextprotocol/client@2.0.0`
- official SDK commit: `cc4b41617ce3601b1290d67216ea0b194a3cd9ac`
- protocol artifact: final `2026-07-28` at
  `modelcontextprotocol/modelcontextprotocol` tag `2026-07-28`, commit
  `5f5440bb26a62e2cf3440b92da5a667efa03b267`, schema `schema/2026-07-28/schema.ts`

The revision is published: the release tag promotes the schema out of
`schema/draft/` into `schema/2026-07-28/`. Against the pre-release artifact
FerroGate previously pinned (`71e306956a4959c9655e5036be215d41986596e6`, then
still `schema/draft/`), the only schema change is the `subscriptions/listen`
result envelope, which FerroGate does not implement — so re-pinning to the
release does not move the ingress contract.

Two commits under one revision name, recorded as two separate facts:

- **ingress pin** (`provenance.json` → `protocol_artifact`): released
  `5f5440bb26a62e2cf3440b92da5a667efa03b267`, `schema/2026-07-28/schema.ts`.
- **opponent SDK's generated-from** (`provenance.json` →
  `opponent_generated_from`): pre-release
  `71e306956a4959c9655e5036be215d41986596e6`, `schema/draft/schema.ts`. The SDK
  commit's `packages/core-internal/src/types/spec.types.2026-07-28.ts` names
  this commit in its own file header.

The pinned SDK was **not** generated from the released commit. Do not collapse
these two fields; `final_spec_pin_and_sdk_generated_from_pin_stay_distinct`
turns red if they are.

The `mcp-candidate-client-official` command name is historical and predates the
release; the artifact it pins and every claim it prints are final.

`client.mjs` uses official SDK `auto` negotiation to exercise
`server/discover -> tools/list -> tools/call`, alternating those consecutive
requests across the two processes, then official SDK `legacy` mode against one
process to exercise `initialize -> tools/list -> tools/call`. Its fetch wrapper
only records and forwards SDK-created requests. The Rust harness independently
validates the observed instance choice, headers, body metadata, ordering,
result, and absence of `Mcp-Session-Id`.

Run from a built checkout:

```bash
./target/debug/ferrogate-test mcp-candidate-client-official
```

The command copies this directory to a temporary checkout, runs locked
`npm ci --ignore-scripts`, and locates Node through `scripts/node-env.sh`.
Network access to the npm registry is required unless the configured npm cache
already contains every locked package.
