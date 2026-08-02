// Prepends the "how to regenerate" banner onto src/api-types.generated.ts
// after openapi-typescript writes it (the CLI has no banner option). Runs as
// the second half of `bun run generate`, and is replayed byte-for-byte by
// test/generated-drift.test.ts — keep the two in step.
import { readFileSync, writeFileSync } from "node:fs";

export const BANNER = `// GENERATED FILE — DO NOT EDIT.
// Source contract: docs/openapi/admin-api.openapi.json (repo root).
// Regenerate with: bun run generate   (from sdks/typescript/)
`;

const file = new URL("../src/api-types.generated.ts", import.meta.url);
const text = readFileSync(file, "utf8");
if (!text.startsWith("// GENERATED FILE")) {
  writeFileSync(file, BANNER + text);
}
