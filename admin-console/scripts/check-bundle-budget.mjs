import { readFile, stat } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import path from "node:path";
import { fileURLToPath } from "node:url";

// Entry-chunk ceiling. The console's i18n runtime is hand-rolled precisely to
// keep the localized catalogs OUT of a heavyweight i18next dependency (see
// src/i18n/catalog.ts). That trade-off is MEASURED, not asserted: porting to
// i18next 26.3.6 + react-i18next 17.0.11 takes this entry
// from 128_993 B to 180_463 B — +51_470 B (+39.9%), 48.30 KiB over the ceiling
// below. Historically BOTH the EN and zh-CN catalogs were eagerly
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
//
// LOWERED 225_000 -> 131_000 (#394): the DEFAULT (English) catalog is now
// code-split TOO. Only a small chrome "bootstrap" subset (src/i18n/locales/en/
// bootstrap.ts — 133 keys: the language selector, `common.*`, app-shell `nav.*`/
// `shell.*`, the `auth.*` login copy, worker reveal warnings, and the theme
// switcher + route-load-boundary "Loading page…" + sidebar a11y) stays eager in
// the entry; the bulk (src/i18n/locales/en/rest.ts — the other 1_551 keys:
// dashboard/resource/every `page.<route>.*`) is pulled in by a dynamic import()
// (src/i18n/catalog.ts `catalogLoaders.en`) and merged over the bootstrap subset,
// so it lands in its OWN chunk outside the entry. Measured effect on the SAME tree:
//   * entry  index-*.js : 221_805 B (216.61 KiB min / 56.76 KiB gzip)
//                      -> 128_571 B (125.56 KiB min / 36.72 KiB gzip)
//     i.e. -93_234 B min (-42.0%) / -20.0 KiB gzip left the entry chunk.
//   * new    rest-*.js  : 95_740 B — the non-chrome English copy, now lazy.
// The type union `TranslationKey` is STILL the keys of the whole catalog: en.ts
// re-aggregates bootstrap+rest and is imported TYPE-ONLY (erased), so a mistyped
// `t()` still fails tsc and zh-CN completeness is still compile-enforced.
//
// The ceiling drops to 131_000 B: ~2.4 KiB (~1.9%) headroom over the measured
// 128_571 B entry — tight, so it stays a guard against an unintended heavy
// dependency (or a catalog chunk accidentally re-entering the entry: re-merging
// `en/rest` would jump the entry ~+95 KiB and trip this) rather than a blank
// cheque. Only EN CHROME (bootstrap) growth now nudges the entry — route/page
// copy lands in the lazy rest chunk — so this ratchet should hold far longer.
const MAX_ENTRY_BYTES = 131_000;
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
