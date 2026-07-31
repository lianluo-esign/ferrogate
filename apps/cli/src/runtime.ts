/**
 * The command-tree shape and the injected runtime every handler receives.
 *
 * Kept in its own module so `tree.ts` (which imports every command module) and
 * the command modules (which need these types) do not form a cycle.
 */
import type { Args, FlagSpec } from "./args.js";
import type { ContextStorage } from "./context.js";
import type { ConfigValidator, ControlPlaneClient, GatewayClient, Io, KeyHasher } from "./ports.js";

/** Everything a command handler is allowed to touch. */
export interface CliRuntime {
  readonly io: Io;
  readonly client: ControlPlaneClient;
  /** Byte-faithful gateway transport for the legacy `assets`/`plans` verbs. */
  readonly gatewayClient: GatewayClient;
  readonly contextStorage: ContextStorage;
  readonly configValidator: ConfigValidator;
  readonly keyHasher: KeyHasher;
}

/** One node of the command tree. Leaves carry a handler. */
export interface CommandNode {
  readonly name: string;
  readonly about: string;
  readonly aliases?: readonly string[];
  /** Positional placeholders, for help and completions (e.g. `<shell>`). */
  readonly positionals?: readonly string[];
  readonly flags?: readonly FlagSpec[];
  readonly sub?: readonly CommandNode[];
  /** Deprecation warning emitted before the handler runs. */
  readonly deprecated?: string;
  /**
   * Handlers that own their own argument grammar (`ctl`) take the raw argv
   * instead of a parsed `Args`, so the registry drives the parse.
   */
  readonly runRaw?: (runtime: CliRuntime, argv: readonly string[]) => Promise<number>;
  readonly run?: (runtime: CliRuntime, args: Args) => Promise<number>;
}

/** Every alias a node answers to, including its own name. */
export function nodeNames(node: CommandNode): readonly string[] {
  return [node.name, ...(node.aliases ?? [])];
}

/** Find a child by name or alias. */
export function findChild(nodes: readonly CommandNode[], name: string): CommandNode | undefined {
  return nodes.find((node) => nodeNames(node).includes(name));
}
