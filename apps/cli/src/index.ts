#!/usr/bin/env bun
/**
 * `ferrogate` — the management CLI (Bun binary, NOT a Worker).
 *
 * Replaces the Rust crate `ferrogate-cli`. Only the client half survives the
 * port: `serve` verbs collapse to deploy/health wrappers on Cloudflare (see
 * docs/rewrite/PORT-PLAN.md). This is a wired skeleton — every handler prints
 * "not yet implemented" until the corresponding subsystem is ported.
 */
import { PUBLIC_API_MAJOR } from "@ferrogate/core";

type Handler = (args: string[]) => number | Promise<number>;

interface Command {
  readonly summary: string;
  readonly run: Handler;
  readonly sub?: Record<string, Command>;
}

/** Stub handler: reports the command path and a non-zero "unimplemented" code. */
function notImplemented(path: string): Handler {
  return () => {
    process.stderr.write(`ferrogate ${path}: not yet implemented\n`);
    return 2;
  };
}

/** Control Plane resource families reachable via `ferrogate ctl <group> <verb>`. */
const CTL_GROUPS = [
  "organization",
  "iam",
  "agent",
  "worker",
  "mcp",
  "tool-approvals",
  "guardrail",
  "asset",
  "catalog",
  "billing",
  "evidence",
  "ops",
] as const;

/** Generic registry-driven dispatcher: `ctl <group> <verb> [id...] [--data|--file]`. */
const ctlDispatch: Handler = (args) => {
  const group = args[0];
  const verb = args[1];
  if (group === undefined || verb === undefined) {
    process.stderr.write(
      "usage: ferrogate ctl <group> <verb> [id...] [--data JSON] [--file PATH]\n",
    );
    process.stderr.write(`groups: ${CTL_GROUPS.join(", ")}\n`);
    return 1;
  }
  process.stderr.write(`ferrogate ctl ${group} ${verb}: not yet implemented\n`);
  return 2;
};

/** The full native command tree (mirrors the Rust clap surface). */
const COMMANDS: Record<string, Command> = {
  run: { summary: "Start the gateway data plane (alias: gateway)", run: notImplemented("run") },
  gateway: { summary: "Alias of `run`", run: notImplemented("gateway") },
  auth: {
    summary: "Identity / RBAC service",
    run: notImplemented("auth"),
    sub: { serve: { summary: "Run the identity service", run: notImplemented("auth serve") } },
  },
  "control-api": {
    summary: "Control Plane API service",
    run: notImplemented("control-api"),
    sub: {
      serve: {
        summary: "Run the Control Plane API service",
        run: notImplemented("control-api serve"),
      },
    },
  },
  billing: {
    summary: "Token-usage billing service",
    run: notImplemented("billing"),
    sub: { serve: { summary: "Run the billing service", run: notImplemented("billing serve") } },
  },
  validate: { summary: "Validate config + auth posture (alias: check)", run: notImplemented("validate") },
  check: { summary: "Alias of `validate`", run: notImplemented("check") },
  reload: { summary: "Validate or hot-reload a running gateway", run: notImplemented("reload") },
  "hash-key": { summary: "Hash a virtual API key secret", run: notImplemented("hash-key") },
  assets: {
    summary: "Manage hosted assets",
    run: notImplemented("assets"),
    sub: {
      push: { summary: "Upload a new asset version", run: notImplemented("assets push") },
      pull: { summary: "Download an asset", run: notImplemented("assets pull") },
      list: { summary: "List a tenant's assets", run: notImplemented("assets list") },
      delete: { summary: "Delete one asset version", run: notImplemented("assets delete") },
    },
  },
  plans: {
    summary: "Manage subscription plans",
    run: notImplemented("plans"),
    sub: {
      create: { summary: "Create a sellable plan", run: notImplemented("plans create") },
      list: { summary: "List all plans", run: notImplemented("plans list") },
      assign: { summary: "Assign a plan to a tenant", run: notImplemented("plans assign") },
    },
  },
  context: {
    summary: "Manage Control Plane API client contexts",
    run: notImplemented("context"),
    sub: {
      create: { summary: "Create/replace a context", run: notImplemented("context create") },
      list: { summary: "List contexts", run: notImplemented("context list") },
      show: { summary: "Show a context", run: notImplemented("context show") },
      use: { summary: "Select the current context", run: notImplemented("context use") },
      delete: { summary: "Delete a context", run: notImplemented("context delete") },
    },
  },
  ops: {
    summary: "Operational status",
    run: notImplemented("ops"),
    sub: { status: { summary: "Show Control Plane API status", run: notImplemented("ops status") } },
  },
  completions: {
    summary: "Emit shell completions (bash/zsh/fish/powershell/elvish)",
    run: notImplemented("completions"),
  },
  ctl: {
    summary: "Generic Control Plane resource families: ctl <group> <verb>",
    run: ctlDispatch,
  },
};

function printHelp(): void {
  process.stdout.write(`ferrogate — FerroGate management CLI (${PUBLIC_API_MAJOR})\n\n`);
  process.stdout.write("usage: ferrogate <command> [subcommand] [args...]\n\ncommands:\n");
  for (const [name, cmd] of Object.entries(COMMANDS)) {
    process.stdout.write(`  ${name.padEnd(14)}${cmd.summary}\n`);
    if (cmd.sub) {
      for (const [subName, sub] of Object.entries(cmd.sub)) {
        process.stdout.write(`    ${subName.padEnd(12)}${sub.summary}\n`);
      }
    }
  }
}

async function main(argv: readonly string[]): Promise<number> {
  const name = argv[0];
  if (name === undefined || name === "help" || name === "--help" || name === "-h") {
    printHelp();
    return name === undefined ? 1 : 0;
  }
  const cmd = COMMANDS[name];
  if (cmd === undefined) {
    process.stderr.write(`ferrogate: unknown command '${name}'\n`);
    printHelp();
    return 1;
  }
  const rest = argv.slice(1);
  const subName = rest[0];
  if (cmd.sub !== undefined && subName !== undefined) {
    const sub = cmd.sub[subName];
    if (sub !== undefined) {
      return await sub.run(rest.slice(1));
    }
  }
  return await cmd.run(rest);
}

process.exit(await main(process.argv.slice(2)));
