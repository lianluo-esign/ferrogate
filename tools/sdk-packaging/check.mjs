#!/usr/bin/env node

import { execFileSync } from "node:child_process";
import { cpSync, mkdtempSync, mkdirSync, readdirSync, rmSync } from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..", "..");
const TYPESCRIPT_ROOT = path.join(REPO_ROOT, "sdks", "typescript");
const PYTHON_ROOT = path.join(REPO_ROOT, "sdks", "python");
const PYTHON_EXECUTABLE = process.env.PYTHON ?? "python3";

function run(command, args, options) {
  return execFileSync(command, args, {
    encoding: "utf8",
    stdio: ["ignore", "pipe", "inherit"],
    ...options,
  });
}

export function checkTypeScriptPackage() {
  run("npm", ["run", "build"], { cwd: TYPESCRIPT_ROOT, stdio: "inherit" });
  const raw = run("npm", ["pack", "--dry-run", "--json", "--ignore-scripts"], {
    cwd: TYPESCRIPT_ROOT,
  });
  const [pack] = JSON.parse(raw);
  const files = new Set((pack?.files ?? []).map((file) => file.path));
  const required = ["dist/index.js", "dist/index.d.ts", "README.md", "LICENSE"];
  const missing = required.filter((file) => !files.has(file));
  const sourceFiles = [...files].filter((file) => file.startsWith("src/"));
  if (missing.length > 0 || sourceFiles.length > 0) {
    throw new Error(
      "TypeScript package contents are invalid: " +
        JSON.stringify({ missing, sourceFiles }),
    );
  }
  return pack.name + "@" + pack.version + ": " + files.size + " packed files";
}

export function checkPythonPackage() {
  const scratch = mkdtempSync(path.join(os.tmpdir(), "ferrogate-python-package-"));
  const source = path.join(scratch, "source");
  const output = path.join(scratch, "dist");
  mkdirSync(output);
  try {
    cpSync(PYTHON_ROOT, source, {
      recursive: true,
      filter: (entry) => !entry.includes("__pycache__") && !entry.endsWith(".egg-info"),
    });
    try {
      run(PYTHON_EXECUTABLE, ["-m", "build", "--wheel", "--sdist", "--outdir", output, source], {
        cwd: REPO_ROOT,
        stdio: "inherit",
      });
    } catch (error) {
      throw new Error(
        "Python package check needs the build module; install it with " +
          "python3 -m pip install build before running this check",
        { cause: error },
      );
    }
    const files = readdirSync(output);
    const wheels = files.filter((file) => file.endsWith(".whl"));
    const sdists = files.filter((file) => file.endsWith(".tar.gz"));
    if (wheels.length !== 1 || sdists.length !== 1) {
      throw new Error(
        "Python package did not produce one wheel and one sdist: " + files.join(", "),
      );
    }
    return "ferrogate-admin: " + wheels[0] + ", " + sdists[0];
  } finally {
    rmSync(scratch, { recursive: true, force: true });
  }
}

const selected = process.argv[2] ?? "all";
if (!["all", "typescript", "python"].includes(selected)) {
  throw new Error("usage: check.mjs [all|typescript|python]");
}

if (selected === "all" || selected === "typescript") {
  console.log("ok " + checkTypeScriptPackage());
}
if (selected === "all" || selected === "python") {
  console.log("ok " + checkPythonPackage());
}
