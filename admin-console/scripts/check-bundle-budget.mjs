import { readFile, stat } from "node:fs/promises";
import { gzipSync } from "node:zlib";
import path from "node:path";
import { fileURLToPath } from "node:url";

const MAX_ENTRY_BYTES = 300_000;
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
