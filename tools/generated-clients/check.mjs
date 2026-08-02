#!/usr/bin/env node
// Standalone drift gate over the generated clients, for entry points that are
// not the root Vitest suite: admin-console's `npm run check:api-types` (which
// the api-contract-drift workflow and scripts/check-admin-console.sh invoke)
// and any hand run.
//
// The root-reachable gate is test/drift.test.mjs; both call the same
// checkArtifact(), so a caller that is easy to forget can never be checking
// something weaker than the one that is not.
//
// Exit 0 = in sync, exit 1 = stale (with the fix instruction on stderr).
// It never writes to a committed file — regeneration is `bun run generate`.
import { selectArtifacts, checkArtifact } from "./artifacts.mjs";

const artifacts = selectArtifacts(process.argv.slice(2));
let stale = 0;

for (const artifact of artifacts) {
  const result = checkArtifact(artifact);
  if (result.ok) {
    console.log(`ok    ${result.reason}`);
  } else {
    stale += 1;
    console.error(`STALE ${result.reason}`);
  }
}

if (stale > 0) process.exit(1);
