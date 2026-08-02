/**
 * The global client flags every Control Plane command accepts, and the one
 * place the **flag > env > context > default** precedence is resolved.
 *
 * Clean-room port of `ferrogate-control-plane-client::args::GlobalArgs` plus
 * `ferrogate-cli::ctl::dispatch::resolve_effective`.
 */
import type { Args, FlagSpec } from "./args.js";
import type { AuthSource, EffectiveContext, GlobalOverrides } from "./context.js";
import {
  DEFAULT_TOKEN_VAR,
  envOverrides,
  parseOutputFormat,
  resolve,
  unhonoredScopeNotice,
} from "./context.js";
import type { CliRuntime } from "./runtime.js";

/** Flags shared by `ctl`, `ops`, and every other client-side command. */
export const GLOBAL_FLAGS: readonly FlagSpec[] = [
  {
    name: "context",
    kind: "string",
    valueName: "NAME",
    env: "FERROGATE_CONTEXT",
    help: "Named context to use",
  },
  {
    name: "endpoint",
    kind: "string",
    valueName: "URL",
    env: "FERROGATE_ENDPOINT",
    help: "Control Plane API endpoint",
  },
  {
    name: "tenant",
    kind: "string",
    valueName: "ID",
    env: "FERROGATE_TENANT",
    help: "Tenant to attribute the call to",
  },
  {
    name: "token-env",
    kind: "string",
    valueName: "VAR",
    help: `Environment variable holding the bearer token (default source: ${DEFAULT_TOKEN_VAR})`,
    conflictsWith: ["token-stdin"],
  },
  {
    name: "token-stdin",
    kind: "boolean",
    help: "Read the bearer token from stdin",
    conflictsWith: ["token-env"],
  },
  {
    name: "timeout-millis",
    kind: "number",
    valueName: "MILLIS",
    env: "FERROGATE_TIMEOUT_MILLIS",
    help: "Per-request timeout",
  },
  {
    name: "output",
    kind: "string",
    valueName: "FORMAT",
    help: "Output format: table (default) or json",
  },
  {
    name: "non-interactive",
    kind: "boolean",
    help: "Never prompt; guarded verbs then require --yes",
  },
];

/** Read the command-line layer of the precedence chain. */
export function globalOverrides(args: Args): GlobalOverrides {
  let auth: AuthSource | undefined;
  if (args.getBoolean("token-stdin")) {
    auth = { kind: "stdin" };
  } else if (args.present("token-env")) {
    const variable = args.requireString("token-env");
    auth = { kind: "env", var: variable };
  }
  const rawOutput = args.getString("output");
  // Env-supplied context/endpoint/tenant belong to the ENV layer, not this one:
  // reading them here would make the two layers indistinguishable and let an
  // env value outrank a context that a flag selected.
  return {
    ...(args.present("context") ? { context: args.requireString("context") } : {}),
    ...(args.present("endpoint") ? { endpoint: args.requireString("endpoint") } : {}),
    ...(args.present("tenant") ? { tenant: args.requireString("tenant") } : {}),
    ...(auth === undefined ? {} : { auth }),
    ...(args.present("timeout-millis")
      ? { timeoutMillis: args.getUnsigned("timeout-millis") as number }
      : {}),
    ...(rawOutput === undefined ? {} : { output: parseOutputFormat(rawOutput) }),
    nonInteractive: args.getBoolean("non-interactive"),
  };
}

/**
 * Resolve the effective context once, and emit the unhonored-scope note.
 *
 * The note is the documented honesty contract: a context's tenant/project/
 * workspace are recorded locally but not honored server-side, and the operator
 * is told so rather than left believing the call was narrowed.
 */
export async function resolveEffective(runtime: CliRuntime, args: Args): Promise<EffectiveContext> {
  const store = await runtime.contextStorage.load();
  const effective = resolve(store, envOverrides(runtime.io.env), globalOverrides(args));
  const notice = unhonoredScopeNotice(effective);
  if (notice !== undefined) runtime.io.stderr(`${notice}\n`);
  return effective;
}
