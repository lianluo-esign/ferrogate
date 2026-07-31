/**
 * A dependency-free argument parser.
 *
 * Clean-room replacement for the Rust `clap` tree (inventory-edge-control.md
 * §1.4 explicitly leaves the parser choice open; a hand-rolled, registry-driven
 * parser is chosen so the generic `ctl <group> <verb>` tree stays data-driven).
 *
 * Supported syntax — deliberately the clap subset the Rust CLI actually used:
 *   `--flag value`   `--flag=value`   `-c value`   `-c=value`   `-cvalue`
 *   `-abc`           (bundled boolean shorts)
 *   `--`             (everything after is passthrough, never parsed)
 *   `--help` / `-h`  `--version` / `-V`
 *
 * Value resolution for a single flag is **flag > env > default**; the
 * context-file layer sits between env and default and lives in `context.ts`
 * (the full documented precedence is flag > env > context > default).
 */
import { CliError } from "./errors.js";

/** How a flag's value is read off the command line. */
export type FlagKind = "string" | "boolean" | "number";

/** One declared flag. */
export interface FlagSpec {
  /** Long name, without the leading `--` (e.g. `config`). */
  readonly name: string;
  /** Optional single-character short alias, without the leading `-`. */
  readonly short?: string;
  readonly kind: FlagKind;
  /** Repeatable flags collect every occurrence (e.g. `--filter`, `--sort`). */
  readonly repeatable?: boolean;
  /** Environment variable consulted when the flag is absent. */
  readonly env?: string;
  /** Value used when neither the flag nor its env var is present. */
  readonly default?: string | number | boolean;
  /** Placeholder shown in help (e.g. `JSON`, `KEY=VALUE`). */
  readonly valueName?: string;
  readonly help: string;
  /** Allow a value that starts with `-` (clap's `allow_hyphen_values`). */
  readonly allowHyphenValues?: boolean;
  /** Names that may not appear together with this one. */
  readonly conflictsWith?: readonly string[];
}

export interface ParseOptions {
  /** Environment used for `FlagSpec.env` fallbacks. Defaults to `{}`. */
  readonly env?: Readonly<Record<string, string | undefined>>;
  /** Context under which usage errors are reported (e.g. `ferrogate ctl plans list`). */
  readonly commandPath?: string;
}

/** The parse result. Values are resolved (flag > env > default) on read. */
export class Args {
  /** Free positional arguments, in order. */
  readonly positionals: readonly string[];
  /** Everything after a bare `--`, untouched. */
  readonly passthrough: readonly string[];
  /** `--help` / `-h` was present before `--`. */
  readonly help: boolean;
  /** `--version` / `-V` was present before `--`. */
  readonly version: boolean;

  readonly #values: ReadonlyMap<string, readonly string[]>;
  readonly #specs: ReadonlyMap<string, FlagSpec>;
  readonly #env: Readonly<Record<string, string | undefined>>;

  constructor(init: {
    positionals: readonly string[];
    passthrough: readonly string[];
    help: boolean;
    version: boolean;
    values: ReadonlyMap<string, readonly string[]>;
    specs: ReadonlyMap<string, FlagSpec>;
    env: Readonly<Record<string, string | undefined>>;
  }) {
    this.positionals = init.positionals;
    this.passthrough = init.passthrough;
    this.help = init.help;
    this.version = init.version;
    this.#values = init.values;
    this.#specs = init.specs;
    this.#env = init.env;
  }

  /** Whether the flag was typed on the command line (env/default excluded). */
  present(name: string): boolean {
    return this.#values.has(name);
  }

  /** Every occurrence of a repeatable flag, in command-line order. */
  getAll(name: string): readonly string[] {
    return this.#values.get(name) ?? [];
  }

  /** Resolved string value: flag > env > default > undefined. */
  getString(name: string): string | undefined {
    const typed = this.#values.get(name);
    if (typed !== undefined && typed.length > 0) return typed[typed.length - 1];
    const spec = this.#specs.get(name);
    if (spec === undefined) return undefined;
    if (spec.env !== undefined) {
      const fromEnv = this.#env[spec.env];
      if (fromEnv !== undefined && fromEnv.trim() !== "") return fromEnv;
    }
    if (typeof spec.default === "string") return spec.default;
    return undefined;
  }

  /** Resolved string value, or a usage error naming the flag. */
  requireString(name: string): string {
    const value = this.getString(name);
    if (value === undefined || value.trim() === "") {
      const spec = this.#specs.get(name);
      const envHint = spec?.env === undefined ? "" : ` (or set ${spec.env})`;
      throw CliError.usage(`--${name} is required${envHint}`);
    }
    return value;
  }

  /** Resolved boolean: present-on-the-line > truthy env > default > false. */
  getBoolean(name: string): boolean {
    if (this.#values.has(name)) {
      const raw = this.#values.get(name);
      const last = raw === undefined ? undefined : raw[raw.length - 1];
      return last === undefined || last === "true";
    }
    const spec = this.#specs.get(name);
    if (spec === undefined) return false;
    if (spec.env !== undefined) {
      const fromEnv = this.#env[spec.env];
      if (fromEnv !== undefined) {
        const normalized = fromEnv.trim().toLowerCase();
        if (normalized !== "" && normalized !== "0" && normalized !== "false") return true;
      }
    }
    return spec.default === true;
  }

  /** Resolved number, or a usage error when the text is not numeric. */
  getNumber(name: string): number | undefined {
    const raw = this.getString(name);
    if (raw === undefined) {
      const spec = this.#specs.get(name);
      return typeof spec?.default === "number" ? spec.default : undefined;
    }
    const parsed = Number(raw.trim());
    if (!Number.isFinite(parsed)) {
      throw CliError.usage(`--${name} expected a number, got '${raw}'`);
    }
    return parsed;
  }

  /** Resolved non-negative integer (pagination windows). */
  getUnsigned(name: string): number | undefined {
    const value = this.getNumber(name);
    if (value === undefined) return undefined;
    if (!Number.isInteger(value) || value < 0) {
      throw CliError.usage(`--${name} expected a non-negative integer, got '${value}'`);
    }
    return value;
  }
}

function isLongFlag(token: string): boolean {
  return token.startsWith("--") && token.length > 2;
}

function isShortFlag(token: string): boolean {
  return token.startsWith("-") && token.length > 1 && !token.startsWith("--");
}

/** Scan for `--help`/`-h` and `--version`/`-V` ahead of any strict validation. */
function scanEarlyExits(argv: readonly string[]): { help: boolean; version: boolean } {
  let help = false;
  let version = false;
  for (const token of argv) {
    if (token === "--") break;
    if (token === "--help" || token === "-h") help = true;
    if (token === "--version" || token === "-V") version = true;
  }
  return { help, version };
}

/**
 * Parse `argv` against `specs`.
 *
 * An unknown flag is a **usage error** (exit 2), never a silently-ignored
 * token: silently dropping a flag is how a mutation reaches the server with a
 * scope the operator did not ask for.
 */
export function parseArgs(
  argv: readonly string[],
  specs: readonly FlagSpec[],
  options: ParseOptions = {},
): Args {
  const env = options.env ?? {};
  const byName = new Map<string, FlagSpec>();
  const byShort = new Map<string, FlagSpec>();
  for (const spec of specs) {
    byName.set(spec.name, spec);
    if (spec.short !== undefined) byShort.set(spec.short, spec);
  }

  const early = scanEarlyExits(argv);
  const values = new Map<string, string[]>();
  const positionals: string[] = [];
  let passthrough: string[] = [];

  const record = (spec: FlagSpec, value: string): void => {
    const existing = values.get(spec.name);
    if (existing === undefined) {
      values.set(spec.name, [value]);
      return;
    }
    if (spec.repeatable !== true) {
      existing[existing.length - 1] = value;
      return;
    }
    existing.push(value);
  };

  const takeValue = (spec: FlagSpec, inline: string | undefined, rest: string[]): void => {
    if (spec.kind === "boolean") {
      if (inline !== undefined) {
        const normalized = inline.trim().toLowerCase();
        record(spec, normalized === "false" || normalized === "0" ? "false" : "true");
        return;
      }
      record(spec, "true");
      return;
    }
    if (inline !== undefined) {
      record(spec, inline);
      return;
    }
    const next = rest.shift();
    if (
      next === undefined ||
      (spec.allowHyphenValues !== true && next !== "-" && next.startsWith("-"))
    ) {
      if (next !== undefined) rest.unshift(next);
      throw CliError.usage(
        `--${spec.name} expects a ${spec.valueName ?? spec.kind.toUpperCase()} value`,
      );
    }
    record(spec, next);
  };

  const queue = [...argv];
  while (queue.length > 0) {
    const token = queue.shift();
    if (token === undefined) break;
    if (token === "--") {
      passthrough = [...queue];
      break;
    }
    if (token === "--help" || token === "-h" || token === "--version" || token === "-V") continue;

    if (isLongFlag(token)) {
      const body = token.slice(2);
      const eq = body.indexOf("=");
      const name = eq === -1 ? body : body.slice(0, eq);
      const inline = eq === -1 ? undefined : body.slice(eq + 1);
      const spec = byName.get(name);
      if (spec === undefined) {
        throw CliError.usage(
          `unknown flag '--${name}'${options.commandPath === undefined ? "" : ` for '${options.commandPath}'`}`,
        );
      }
      takeValue(spec, inline, queue);
      continue;
    }

    if (isShortFlag(token)) {
      let body = token.slice(1);
      while (body.length > 0) {
        const letter = body[0] as string;
        const spec = byShort.get(letter);
        if (spec === undefined) {
          throw CliError.usage(
            `unknown flag '-${letter}'${options.commandPath === undefined ? "" : ` for '${options.commandPath}'`}`,
          );
        }
        let remainder = body.slice(1);
        if (remainder.startsWith("=")) remainder = remainder.slice(1);
        if (spec.kind === "boolean") {
          record(spec, "true");
          body = body.slice(1);
          if (body.startsWith("=")) {
            throw CliError.usage(`-${letter} is a boolean flag and takes no value`);
          }
          continue;
        }
        if (remainder.length > 0) {
          record(spec, remainder);
        } else {
          takeValue(spec, undefined, queue);
        }
        body = "";
      }
      continue;
    }

    positionals.push(token);
  }

  for (const spec of specs) {
    if (!values.has(spec.name) || spec.conflictsWith === undefined) continue;
    for (const other of spec.conflictsWith) {
      if (values.has(other)) {
        throw CliError.usage(`--${spec.name} cannot be used with --${other}`);
      }
    }
  }

  return new Args({
    positionals,
    passthrough,
    help: early.help,
    version: early.version,
    values,
    specs: byName,
    env,
  });
}

/** Render a flag list as an aligned help block. */
export function renderFlagHelp(specs: readonly FlagSpec[], indent = "  "): string {
  if (specs.length === 0) return "";
  const left = specs.map((spec) => {
    const short = spec.short === undefined ? "    " : `-${spec.short}, `;
    const value = spec.kind === "boolean" ? "" : ` <${spec.valueName ?? "VALUE"}>`;
    return `${short}--${spec.name}${value}`;
  });
  const width = left.reduce((max, text) => Math.max(max, text.length), 0);
  return specs
    .map((spec, index) => {
      const suffix: string[] = [];
      if (spec.env !== undefined) suffix.push(`env: ${spec.env}`);
      if (spec.default !== undefined) suffix.push(`default: ${String(spec.default)}`);
      const tail = suffix.length === 0 ? "" : ` [${suffix.join("; ")}]`;
      return `${indent}${(left[index] as string).padEnd(width)}  ${spec.help}${tail}`;
    })
    .join("\n");
}
