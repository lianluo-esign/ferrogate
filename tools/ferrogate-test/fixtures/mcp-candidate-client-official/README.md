# Official MCP candidate client fixture

This fixture drives two real FerroGate processes through the official Tier-1
TypeScript client. It is not a FerroGate-authored protocol client or server
double.

- npm package: `@modelcontextprotocol/client@2.0.0`
- npm integrity: recorded in `package-lock.json` and `provenance.json`
- official SDK tag: `@modelcontextprotocol/client@2.0.0`
- official SDK commit: `cc4b41617ce3601b1290d67216ea0b194a3cd9ac`
- protocol artifact: candidate `2026-07-28` at
  `modelcontextprotocol/modelcontextprotocol@71e306956a4959c9655e5036be215d41986596e6`

The SDK commit's generated
`packages/core-internal/src/types/spec.types.2026-07-28.ts` names that exact
protocol commit as its source. The npm package release does not turn the pinned
protocol artifact into a final specification; FerroGate continues to describe
it as a candidate.

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
