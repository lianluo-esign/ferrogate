#!/usr/bin/env bun
/**
 * `ferrogate` — the management CLI (a Bun binary, NOT a Worker).
 *
 * Clean-room port of the Rust crate `ferrogate-cli`
 * (docs/legacy/inventory-edge-control.md §1). The dispatcher walks the
 * assembled tree from `tree.ts`, parses the matched leaf's flags with the
 * dependency-free parser, and terminates on the stable exit-code contract:
 *
 *   0 ok · 2 usage · 3 auth · 4 not-found/conflict · 5 validation ·
 *   6 transport · 7 server
 *
 * Everything the process touches — env, files, stdin/stdout, the clock, the
 * RNG, and the network — arrives through `CliRuntime`, so `main()` is fully
 * testable with no I/O.
 */
import { parseArgs } from "./args.js";
import { createFileContextStorage } from "./context.js";
import { reportError } from "./diagnostics.js";
import { asCliError, exitCode } from "./errors.js";
import { renderCommandHelp, renderRootHelp, versionLine } from "./help.js";
import {
  createFetchControlPlaneClient,
  createFetchGatewayClient,
  createNodeIo,
  createNodeKeyHasher,
  createStructuralConfigValidator,
} from "./ports.js";
import type { CliRuntime, CommandNode } from "./runtime.js";
import { findChild } from "./runtime.js";
import { COMMANDS } from "./tree.js";

export { COMMANDS } from "./tree.js";
export type { CliRuntime } from "./runtime.js";

/** Build the runtime the shipped binary uses. */
export function createDefaultRuntime(): CliRuntime {
  const io = createNodeIo();
  return {
    io,
    client: createFetchControlPlaneClient(),
    gatewayClient: createFetchGatewayClient(),
    contextStorage: createFileContextStorage(io),
    configValidator: createStructuralConfigValidator(),
    keyHasher: createNodeKeyHasher(),
  };
}

/** Resolve `argv` to the deepest matching node plus its remaining arguments. */
function walk(
  argv: readonly string[],
): { node: CommandNode; path: string; rest: readonly string[] } | undefined {
  const first = argv[0];
  if (first === undefined) return undefined;
  let node = findChild(COMMANDS, first);
  if (node === undefined) return undefined;
  let path = node.name;
  let rest = argv.slice(1);
  // Descend only while the next token names a real subcommand; anything else
  // (a flag, an id segment) belongs to the node we are on.
  while (node.sub !== undefined && rest.length > 0) {
    const next = rest[0] as string;
    const child = findChild(node.sub, next);
    if (child === undefined) break;
    node = child;
    path = `${path} ${child.name}`;
    rest = rest.slice(1);
  }
  return { node, path, rest };
}

/** Run one invocation. Returns the exit code; never calls `process.exit`. */
export async function main(argv: readonly string[], runtime: CliRuntime): Promise<number> {
  const first = argv[0];
  if (first === undefined) {
    runtime.io.stderr(renderRootHelp(COMMANDS));
    return exitCode("usage");
  }
  if (first === "help" || first === "--help" || first === "-h") {
    runtime.io.stdout(renderRootHelp(COMMANDS));
    return 0;
  }
  if (first === "--version" || first === "-V" || first === "version") {
    runtime.io.stdout(versionLine());
    return 0;
  }

  const matched = walk(argv);
  if (matched === undefined) {
    runtime.io.stderr(`ferrogate: unknown command '${first}'\n`);
    runtime.io.stderr(renderRootHelp(COMMANDS));
    return exitCode("usage");
  }
  const { node, path, rest } = matched;

  if (node.deprecated !== undefined) {
    runtime.io.stderr(`warning: ${node.deprecated}\n`);
  }

  const wantsHelp = rest.includes("--help") || rest.includes("-h");
  if (wantsHelp && node.runRaw === undefined) {
    runtime.io.stdout(renderCommandHelp(path, node));
    return 0;
  }

  // A node that only groups subcommands needs one named.
  if (node.run === undefined && node.runRaw === undefined) {
    const attempted = rest[0];
    runtime.io.stderr(
      attempted === undefined
        ? `ferrogate ${path}: a subcommand is required\n`
        : `ferrogate ${path}: unknown subcommand '${attempted}'\n`,
    );
    runtime.io.stderr(renderCommandHelp(path, node));
    return exitCode("usage");
  }

  try {
    if (node.runRaw !== undefined) return await node.runRaw(runtime, rest);
    const args = parseArgs(rest, node.flags ?? [], {
      env: runtime.io.env,
      commandPath: `ferrogate ${path}`,
    });
    return await (node.run as NonNullable<CommandNode["run"]>)(runtime, args);
  } catch (error) {
    const cliError = asCliError(error);
    reportError(runtime.io, cliError);
    return cliError.exitCode();
  }
}

/* The process entry point; `main` is what the tests drive. */
const entry = typeof process === "undefined" ? undefined : process.argv[1];
if (entry !== undefined && (entry.endsWith("/index.ts") || entry.endsWith("/ferrogate"))) {
  process.exit(await main(process.argv.slice(2), createDefaultRuntime()));
}
