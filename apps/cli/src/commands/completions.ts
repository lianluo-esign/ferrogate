/**
 * `ferrogate completions <shell>`.
 *
 * Port of `ferrogate-cli::completions` (inventory-edge-control.md §1.1): emits
 * a completion script for the **full assembled tree** — the native commands
 * *and* the registry-derived `ctl <group> <verb>` subtree — so a new resource
 * family completes without touching this file.
 *
 * Additive and side-effect-free: writes to stdout only.
 */
import { CliError } from "../errors.js";
import { GROUPS } from "../registry.js";
import type { CliRuntime, CommandNode } from "../runtime.js";
import { nodeNames } from "../runtime.js";

/** Shells the Rust CLI supported, and therefore this one must too. */
export const SUPPORTED_SHELLS = ["bash", "zsh", "fish", "powershell", "elvish"] as const;
export type SupportedShell = (typeof SUPPORTED_SHELLS)[number];

/** `command path -> completion candidates`, derived from the whole tree. */
export function completionTable(
  commands: readonly CommandNode[],
): ReadonlyMap<string, readonly string[]> {
  const table = new Map<string, string[]>();
  const visit = (path: string, nodes: readonly CommandNode[]): void => {
    const names: string[] = [];
    for (const node of nodes) {
      names.push(...nodeNames(node));
      if (node.sub !== undefined) visit(`${path} ${node.name}`.trim(), node.sub);
    }
    table.set(path, names);
  };
  visit("", commands);

  // The generic subtree is data, not code: derive it from the registry.
  table.set(
    "ctl",
    GROUPS.map((group) => group.name),
  );
  for (const group of GROUPS) {
    table.set(
      `ctl ${group.name}`,
      group.verbs.map((verb) => verb.name),
    );
  }
  return table;
}

function bashScript(table: ReadonlyMap<string, readonly string[]>): string {
  const cases = [...table.entries()]
    .map(
      ([path, names]) =>
        `    "${path}") COMPREPLY=($(compgen -W "${names.join(" ")}" -- "$cur"));;`,
    )
    .join("\n");
  return `# ferrogate bash completion
_ferrogate() {
  local cur prev words cword key
  cur="\${COMP_WORDS[COMP_CWORD]}"
  key=""
  local i
  for ((i=1; i<COMP_CWORD; i++)); do
    case "\${COMP_WORDS[i]}" in
      -*) continue;;
    esac
    if [ -z "$key" ]; then key="\${COMP_WORDS[i]}"; else key="$key \${COMP_WORDS[i]}"; fi
  done
  case "$key" in
${cases}
    *) COMPREPLY=();;
  esac
}
complete -F _ferrogate ferrogate
`;
}

function zshScript(table: ReadonlyMap<string, readonly string[]>): string {
  const cases = [...table.entries()]
    .map(
      ([path, names]) =>
        `    "${path}") _values 'command' ${names.map((name) => `'${name}'`).join(" ")};;`,
    )
    .join("\n");
  return `#compdef ferrogate
# ferrogate zsh completion
_ferrogate() {
  local key="\${(j: :)words[2,CURRENT-1]}"
  case "$key" in
${cases}
    *) _files;;
  esac
}
compdef _ferrogate ferrogate
`;
}

function fishScript(table: ReadonlyMap<string, readonly string[]>): string {
  const lines: string[] = ["# ferrogate fish completion"];
  for (const [path, names] of table) {
    const condition =
      path === ""
        ? "__fish_use_subcommand"
        : `__fish_seen_subcommand_from ${path.split(" ").join(" ")}`;
    for (const name of names) {
      lines.push(`complete -c ferrogate -n '${condition}' -a '${name}'`);
    }
  }
  return `${lines.join("\n")}\n`;
}

function powershellScript(table: ReadonlyMap<string, readonly string[]>): string {
  const entries = [...table.entries()]
    .map(([path, names]) => `    '${path}' = @(${names.map((name) => `'${name}'`).join(",")})`)
    .join("\n");
  return `# ferrogate powershell completion
Register-ArgumentCompleter -Native -CommandName ferrogate -ScriptBlock {
  param($wordToComplete, $commandAst, $cursorPosition)
  $table = @{
${entries}
  }
  $words = $commandAst.CommandElements | Select-Object -Skip 1 | ForEach-Object { $_.ToString() } | Where-Object { $_ -notlike '-*' }
  $key = ($words[0..($words.Length - 2)] -join ' ')
  if ($null -eq $key) { $key = '' }
  $table[$key] | Where-Object { $_ -like "$wordToComplete*" } | ForEach-Object {
    [System.Management.Automation.CompletionResult]::new($_, $_, 'ParameterValue', $_)
  }
}
`;
}

function elvishScript(table: ReadonlyMap<string, readonly string[]>): string {
  const entries = [...table.entries()]
    .map(([path, names]) => `  &'${path}'=[${names.map((name) => `'${name}'`).join(" ")}]`)
    .join("\n");
  return `# ferrogate elvish completion
set edit:completion:arg-completer[ferrogate] = {|@words|
  var table = [
${entries}
  ]
  var key = (str:join ' ' $words[1..(- (count $words) 1)])
  if (has-key $table $key) {
    put (all $table[$key])
  }
}
`;
}

export function renderCompletions(
  shell: SupportedShell,
  table: ReadonlyMap<string, readonly string[]>,
): string {
  switch (shell) {
    case "bash":
      return bashScript(table);
    case "zsh":
      return zshScript(table);
    case "fish":
      return fishScript(table);
    case "powershell":
      return powershellScript(table);
    case "elvish":
      return elvishScript(table);
  }
}

export const completionsCommand: CommandNode = {
  name: "completions",
  about: `Emit shell completions (${SUPPORTED_SHELLS.join("/")})`,
  positionals: ["<shell>"],
  run: async (runtime: CliRuntime, args) => {
    const requested = args.positionals[0];
    if (requested === undefined) {
      throw CliError.usage(`completions requires a shell: one of ${SUPPORTED_SHELLS.join(", ")}`);
    }
    const shell = SUPPORTED_SHELLS.find((candidate) => candidate === requested);
    if (shell === undefined) {
      throw CliError.usage(
        `unknown shell '${requested}'; expected one of: ${SUPPORTED_SHELLS.join(", ")}`,
      );
    }
    // Imported lazily: `tree.ts` imports this module, so a static import here
    // would be a cycle.
    const { COMMANDS } = await import("../tree.js");
    runtime.io.stdout(renderCompletions(shell, completionTable(COMMANDS)));
    return 0;
  },
};
