/**
 * The assembled command tree: the native subcommands plus the registry-derived
 * `ctl` subtree, exactly as `ferrogate-cli::command_tree::assembled_command`
 * composed them (inventory-edge-control.md §1).
 */
import { applyCommand } from "./commands/apply.js";
import { assetsCommand } from "./commands/assets.js";
import { completionsCommand } from "./commands/completions.js";
import { hashKeyCommand, reloadCommand, validateCommand } from "./commands/config-commands.js";
import { contextCommand } from "./commands/context.js";
import { ctlCommand } from "./commands/ctl.js";
import { opsCommand } from "./commands/ops.js";
import { plansCommand } from "./commands/plans.js";
import {
  adminApiCommand,
  authCommand,
  billingCommand,
  controlApiCommand,
  runCommand,
  storageCommand,
} from "./commands/serve.js";
import type { CommandNode } from "./runtime.js";

/** Every top-level command, in help order. */
export const COMMANDS: readonly CommandNode[] = [
  runCommand,
  authCommand,
  controlApiCommand,
  adminApiCommand,
  billingCommand,
  storageCommand,
  validateCommand,
  reloadCommand,
  applyCommand,
  hashKeyCommand,
  assetsCommand,
  plansCommand,
  contextCommand,
  opsCommand,
  completionsCommand,
  ctlCommand,
];
