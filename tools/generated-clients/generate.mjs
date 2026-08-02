#!/usr/bin/env node
// `bun run generate` (repo root) — regenerate every client listed in
// artifacts.mjs from the committed OpenAPI contract.
//
// This is the ONLY place in the tree that writes a generated client. The drift
// gate deliberately does not (see artifacts.mjs): the regenerated diff has to
// stay visible in the PR, because that diff is how a reviewer sees that an
// operation appeared on the contract.
//
// Usage:
//   bun tools/generated-clients/generate.mjs                       # all
//   bun tools/generated-clients/generate.mjs --only admin-console  # one
//
// Runs unchanged under Bun (root workspace) and Node (admin-console's npm
// scripts), so `npm run generate:api` and `bun run generate` produce the same
// bytes.
import { selectArtifacts, writeArtifact } from "./artifacts.mjs";

const artifacts = selectArtifacts(process.argv.slice(2));
let changed = 0;

for (const artifact of artifacts) {
  const result = writeArtifact(artifact);
  if (result.changed) changed += 1;
  console.log(`${result.changed ? "regenerated" : "unchanged  "}  ${result.output}`);
}

console.log(
  changed === 0
    ? `generate: ${artifacts.length} generated client(s) already matched the contract`
    : `generate: ${changed} of ${artifacts.length} generated client(s) rewritten — COMMIT the diff so the contract change is reviewable`,
);
