import { CLI_VERSION } from "./action-identity.js";
/**
 * Help rendering for the assembled tree.
 *
 * The tree is walked, not transcribed: a command that exists but is missing
 * from help is the class of drift a help test can actually catch, and
 * `test/help.test.ts` asserts every node appears.
 */
import { renderFlagHelp } from "./args.js";
import { GLOBAL_FLAGS } from "./global-args.js";
import { GROUPS } from "./registry.js";
import type { CommandNode } from "./runtime.js";
import { nodeNames } from "./runtime.js";

export const BANNER = "ferrogate — FerroGate AI Gateway management CLI (Token4AI Cloud)";

/** `ferrogate --version` output. */
export function versionLine(): string {
  return `ferrogate ${CLI_VERSION}\n`;
}

/** Every command path in the tree, e.g. `auth serve`, `ctl plans list`. */
export function commandPaths(commands: readonly CommandNode[]): readonly string[] {
  const paths: string[] = [];
  const visit = (prefix: string, nodes: readonly CommandNode[]): void => {
    for (const node of nodes) {
      const path = prefix === "" ? node.name : `${prefix} ${node.name}`;
      paths.push(path);
      if (node.sub !== undefined) visit(path, node.sub);
    }
  };
  visit("", commands);
  for (const group of GROUPS) {
    paths.push(`ctl ${group.name}`);
    for (const verb of group.verbs) paths.push(`ctl ${group.name} ${verb.name}`);
  }
  return paths;
}

/** The top-level help tree: every native command, subcommand, and ctl group. */
export function renderRootHelp(commands: readonly CommandNode[]): string {
  const lines = [BANNER, "", "usage: ferrogate <command> [subcommand] [args...]", "", "commands:"];
  // One column width across parents AND children, so a long subcommand name
  // (`migrate-to-supabase`) cannot run into its own description.
  const labels = commands.flatMap((node) => [
    nodeNames(node).join(", "),
    ...(node.sub ?? []).map((child) => `  ${nodeNames(child).join(", ")}`),
  ]);
  const width = labels.reduce((max, label) => Math.max(max, label.length), 0);
  for (const node of commands) {
    const label = nodeNames(node).join(", ");
    const deprecated = node.deprecated === undefined ? "" : "  [DEPRECATED]";
    lines.push(`  ${label.padEnd(width)}  ${node.about}${deprecated}`);
    for (const child of node.sub ?? []) {
      const childLabel = `  ${nodeNames(child).join(", ")}`;
      lines.push(`  ${childLabel.padEnd(width)}  ${child.about}`);
    }
  }
  lines.push("", "ctl groups (registry-derived):");
  const groupWidth = GROUPS.reduce((max, group) => Math.max(max, group.name.length), 0);
  for (const group of GROUPS) {
    lines.push(`  ${group.name.padEnd(groupWidth)}  ${group.about}`);
  }
  lines.push("", "global client flags (ctl, ops):", renderFlagHelp(GLOBAL_FLAGS));
  lines.push("", "run `ferrogate <command> --help` for a command's flags.");
  return `${lines.join("\n")}\n`;
}

/** Help for one node: its subcommands or its flags. */
export function renderCommandHelp(path: string, node: CommandNode): string {
  const lines = [
    `usage: ferrogate ${path}${node.sub === undefined ? " [flags]" : " <subcommand>"}`,
  ];
  lines.push("", node.about);
  if (node.deprecated !== undefined) lines.push("", `DEPRECATED: ${node.deprecated}`);
  if (node.positionals !== undefined && node.positionals.length > 0) {
    lines.push("", `positionals: ${node.positionals.join(" ")}`);
  }
  if (node.sub !== undefined) {
    lines.push("", "subcommands:");
    const width = node.sub.reduce((max, child) => Math.max(max, child.name.length), 0);
    for (const child of node.sub) {
      lines.push(`  ${child.name.padEnd(width)}  ${child.about}`);
    }
  }
  if (node.flags !== undefined && node.flags.length > 0) {
    lines.push("", "flags:", renderFlagHelp(node.flags));
  }
  return `${lines.join("\n")}\n`;
}
