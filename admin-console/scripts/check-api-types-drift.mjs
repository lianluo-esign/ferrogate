// OpenAPI -> generated-client drift guard for admin-console (#392, surfaced by
// #379). Since #766 the LOGIC lives at tools/generated-clients/, shared with
// every other client generated from the same contract; this file stays as the
// admin-console entry point into it.
//
// It is kept rather than deleted for two reasons. `npm run check:api-types` is
// what scripts/check-admin-console.sh and the api-contract-drift workflow call,
// neither of which has Bun; and the workflow path-filters on THIS path, so
// removing it would quietly narrow when the gate fires.
//
// What changed in #766: this guard used to be the only thing checking
// admin-console's client, and nothing ran it — admin-console is not a Bun
// workspace, so root `bun run test` never reached it and the client was stale
// twice without a report (#736, #737). The same check now also runs from
// tools/generated-clients/test/drift.test.mjs, which the root suite does reach.
// Both call the same checkArtifact(), so the reachable one cannot be weaker.
//
// Like the shared code, it NEVER writes to the committed file: it renders into
// a temp file and compares. Regeneration is `bun run generate` at the repo root
// (or `npm run generate:api` here), and its diff is meant to be reviewed.
import { artifactBySlug, checkArtifact } from "../../tools/generated-clients/artifacts.mjs";

const result = checkArtifact(artifactBySlug("admin-console"));

if (!result.ok) {
  console.error(`api-types drift: ${result.reason}`);
  process.exit(1);
}

console.log(`api-types drift: ${result.reason}`);
