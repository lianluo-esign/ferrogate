#!/usr/bin/env node

/**
 * CI guard for the current tenant-storage topology (#830).
 *
 * The retired D1 REST/proxy apparatus must not return through a comment, a
 * deployment variable, or a current document. Historical audit files are kept
 * outside the current-document scan and are checked for an explicit dated
 * annotation instead.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

function walk(directory, predicate) {
  return readdirSync(directory, { withFileTypes: true }).flatMap((entry) => {
    const full = path.join(directory, entry.name);
    if (entry.isDirectory()) return walk(full, predicate);
    return predicate(full) ? [full] : [];
  });
}

function read(file) {
  return readFileSync(file, "utf8");
}

const sourceFiles = [
  ...walk(path.join(root, "packages"), (file) => file.includes(`${path.sep}src${path.sep}`) && file.endsWith(".ts")),
  ...walk(path.join(root, "apps"), (file) => file.includes(`${path.sep}src${path.sep}`) && file.endsWith(".ts")),
  path.join(root, "apps/gateway/wrangler.toml"),
];

const sourceRules = [
  ["removed REST tenant router", /\b(?:NonAtomicD1RestTenantDatabaseRouter|D1RestTenantDatabaseRouter)\b/],
  ["removed D1 lifecycle client", /\bD1LifecycleClient\b/],
  ["removed registry-document migration", /\bmigrateTenantDatabaseRegistryDocument\b/],
  ["removed REST API constant", /\bD1_REST_API_BASE\b/],
  ["removed proxy strategy", /\bproxy_service\s*:/],
  ["removed REST strategy", /\b(?:TenantDatabaseRoutingMode|TENANT_DATABASE_ROUTING_MODES)\b[\s\S]{0,500}\|\s*"rest"/],
  ["removed REST routing value", /GATEWAY_TENANT_DB_ROUTING\s*=\s*["']rest["']/],
  ["removed REST credentials", /\bGATEWAY_TENANT_DB_(?:ACCOUNT_ID|API_TOKEN)\b/],
];

const failures = [];
for (const file of sourceFiles) {
  const text = read(file);
  for (const [label, pattern] of sourceRules) {
    if (pattern.test(text)) failures.push(`${label}: ${path.relative(root, file)}`);
  }
}

const currentDocs = [
  path.join(root, "README.md"),
  path.join(root, "packages/storage/README.md"),
  ...walk(path.join(root, "docs"), (file) => {
    const relative = path.relative(root, file);
    return file.endsWith(".md") &&
      !relative.startsWith(`docs${path.sep}legacy${path.sep}`) &&
      !relative.startsWith(`docs${path.sep}rewrite${path.sep}`) &&
      !relative.startsWith(`docs${path.sep}superpowers${path.sep}`);
  }),
];

const staleTopology = /\b(?:one )?(?:D1 )?database per tenant\b|\bper-tenant D1\b/i;
const historicalAnnotation = /\b(?:supersedes|superseded|retired|historical|no longer|replaced)\b.*\b2026-08-05\b|\b2026-08-05\b.*\b(?:supersedes|superseded|retired|historical|no longer|replaced)\b/i;

for (const file of currentDocs) {
  const paragraphs = read(file).split(/\n\s*\n/);
  for (const paragraph of paragraphs) {
    if (staleTopology.test(paragraph) && !historicalAnnotation.test(paragraph)) {
      failures.push(`current documentation still claims the retired topology: ${path.relative(root, file)}`);
    }
  }
}

const historicalDocs = [
  ...walk(path.join(root, "docs/legacy"), (file) => file.endsWith(".md")),
  ...walk(path.join(root, "docs/rewrite"), (file) => file.endsWith(".md")),
];
for (const file of historicalDocs) {
  const paragraphs = read(file).split(/\n\s*\n/);
  for (const paragraph of paragraphs) {
    if (staleTopology.test(paragraph) && !historicalAnnotation.test(paragraph)) {
      failures.push(`historical topology claim lacks dated annotation: ${path.relative(root, file)}`);
    }
  }
}

if (failures.length > 0) {
  console.error(failures.map((failure) => `- ${failure}`).join("\n"));
  process.exitCode = 1;
} else {
  console.log(`current topology guard passed (${sourceFiles.length} source/config files, ${currentDocs.length} current docs)`);
}
