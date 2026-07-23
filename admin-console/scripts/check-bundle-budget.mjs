import { readFile, stat } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Entry-chunk ceiling. The console's i18n runtime is hand-rolled precisely to
// keep the localized catalogs OUT of a heavyweight i18next dependency (see
// src/i18n/catalog.ts). Historically BOTH the EN and zh-CN catalogs were eagerly
// imported into the entry chunk, so every catalog growth ratcheted this ceiling
// up: 300_000 -> 312_000 (#348 copy-complete) -> 316_000 (#344 Assets registry)
// -> 321_000 (#345 Static Sites). Each bump was the real cost of new copy across
// BOTH locales landing in the entry — the ratchet #393 set out to break.
//
// LOWERED 321_000 -> 225_000 (#393): the i18n catalog is now code-split. Only the
// DEFAULT locale (English) is eagerly bundled; the non-default zh-CN catalog is
// pulled in by a dynamic import() (src/i18n/catalog.ts `catalogLoaders`) so Vite
// emits it as its OWN chunk OUTSIDE the entry (an operator downloads Chinese copy
// only if they switch to Chinese). Measured effect of the split on the SAME tree:
//   * entry  index-*.js : 319_716 B (312.22 KiB min / 80.06 KiB gzip)
//                      -> 221_805 B (216.61 KiB min / 56.76 KiB gzip)
//     i.e. -97_911 B min (-30.6%) / -23.3 KiB gzip left the entry chunk.
//   * new    zh-CN-*.js : 98_220 B — the Simplified Chinese copy, now lazy.
// The ceiling drops to 225_000 B: ~3.2 KiB (~1.4%) headroom over the measured
// 221_805 B entry — tight, so it stays a guard against an unintended heavy
// dependency (or a locale catalog accidentally re-entering the entry) rather than
// a blank cheque. Future EN-only key growth still nudges this; a large jump would
// signal regression (e.g. zh-CN back in the entry, or i18next reaching it).
const MAX_ENTRY_BYTES = 225_000;
const MAX_CHUNK_BYTES = 500_000;
const projectRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
const distRoot = path.join(projectRoot, "dist");
const manifestPath = path.join(distRoot, ".vite", "manifest.json");

const manifest = JSON.parse(await readFile(manifestPath, "utf8"));
const entries = Object.entries(manifest);
const entryRecord = entries.find(([, value]) => value.isEntry === true);

if (!entryRecord) throw new Error("bundle budget: Vite manifest has no entry chunk");

async function assetSize(file) {
  const absolutePath = path.join(distRoot, file);
  const { size } = await stat(absolutePath);
  const contents = await readFile(absolutePath);
  return { size, gzip: gzipSync(contents).byteLength };
}

function formatKiB(bytes) {
  return `${(bytes / 1024).toFixed(2)} KiB`;
}

function staticClosure(startKey) {
  const visited = new Set();
  const pending = [startKey];
  while (pending.length > 0) {
    const key = pending.pop();
    if (!key || visited.has(key)) continue;
    visited.add(key);
    for (const importedKey of manifest[key]?.imports ?? []) pending.push(importedKey);
  }
  return visited;
}

const [entryKey, entry] = entryRecord;
const jsAssets = new Map();
for (const [, record] of entries) {
  if (typeof record.file === "string" && record.file.endsWith(".js")) {
    jsAssets.set(record.file, await assetSize(record.file));
  }
}

const entrySize = jsAssets.get(entry.file);
if (!entrySize) throw new Error(`bundle budget: entry asset ${entry.file} is missing`);

const oversized = [...jsAssets.entries()].filter(([, size]) => size.size > MAX_CHUNK_BYTES);
if (entrySize.size > MAX_ENTRY_BYTES || oversized.length > 0) {
  const failures = [];
  if (entrySize.size > MAX_ENTRY_BYTES) {
    failures.push(
      `entry ${entry.file} is ${formatKiB(entrySize.size)} (budget ${formatKiB(MAX_ENTRY_BYTES)})`,
    );
  }
  for (const [file, size] of oversized) {
    failures.push(
      `chunk ${file} is ${formatKiB(size.size)} (budget ${formatKiB(MAX_CHUNK_BYTES)})`,
    );
  }
  throw new Error(`bundle budget exceeded:\n${failures.join("\n")}`);
}

const authEntries = ["src/pages/login.tsx", "src/pages/register.tsx"];
const protectedPageKeys = entries
  .filter(
    ([key, record]) =>
      key.startsWith("src/pages/") &&
      record.isDynamicEntry === true &&
      !authEntries.includes(key),
  )
  .map(([key]) => key);

for (const authKey of authEntries) {
  if (!manifest[authKey]?.isDynamicEntry) {
    throw new Error(`bundle budget: ${authKey} is not a lazy route entry`);
  }
  const closure = staticClosure(authKey);
  const leakedProtectedPages = protectedPageKeys.filter((key) => closure.has(key));
  if (leakedProtectedPages.length > 0) {
    throw new Error(
      `bundle budget: ${authKey} statically imports protected routes: ${leakedProtectedPages.join(", ")}`,
    );
  }
}

const initialKeys = staticClosure(entryKey);
const initialFiles = new Set(
  [...initialKeys]
    .map((key) => manifest[key]?.file)
    .filter((file) => typeof file === "string" && file.endsWith(".js")),
);
let initialBytes = 0;
let initialGzipBytes = 0;
for (const file of initialFiles) {
  const size = jsAssets.get(file);
  if (!size) continue;
  initialBytes += size.size;
  initialGzipBytes += size.gzip;
}

const largest = [...jsAssets.entries()].sort((a, b) => b[1].size - a[1].size)[0];
console.log(
  `bundle budget: entry ${formatKiB(entrySize.size)} min / ${formatKiB(entrySize.gzip)} gzip`,
);
console.log(
  `bundle budget: initial static graph ${formatKiB(initialBytes)} min / ${formatKiB(initialGzipBytes)} gzip across ${initialFiles.size} chunks`,
);
console.log(
  `bundle budget: largest chunk ${largest[0]} ${formatKiB(largest[1].size)} min / ${formatKiB(largest[1].gzip)} gzip`,
);
console.log("bundle budget: auth route isolation OK");
