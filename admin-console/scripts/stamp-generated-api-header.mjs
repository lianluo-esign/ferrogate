// Prepends the "how to regenerate" banner onto src/lib/api-types.generated.ts
// after openapi-typescript writes it (the CLI has no banner option). Runs as
// the second half of `npm run generate:api`.
import { readFileSync, writeFileSync } from "node:fs";

const file = new URL("../src/lib/api-types.generated.ts", import.meta.url);
const banner = `// GENERATED FILE — DO NOT EDIT.
// Source contract: docs/openapi/admin-api.openapi.json (repo root).
// Regenerate with: npm run generate:api   (from admin-console/)
`;

const text = readFileSync(file, "utf8");
if (!text.startsWith("// GENERATED FILE")) {
  writeFileSync(file, banner + text);
}
