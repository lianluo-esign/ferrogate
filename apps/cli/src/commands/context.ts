import type { Args } from "../args.js";
/**
 * `context create|list|show|use|delete`.
 *
 * Port of `ferrogate-cli::ctl::context_cmd` (inventory-edge-control.md §1.1).
 * These are `local` verbs: no request leaves the process, so they render
 * directly and owe no mutation receipt (the context store is the operator's own
 * file, not a governed Control-Plane object).
 *
 * A token VALUE is never stored — only its source (`--token-env` / `--token-stdin`).
 */
import type { AuthSource, Context } from "../context.js";
import {
  ANONYMOUS,
  describeAuth,
  getContext,
  removeContext,
  setCurrentContext,
  upsertContext,
} from "../context.js";
import { CliError } from "../errors.js";
import { Table } from "../output.js";
import type { CliRuntime, CommandNode } from "../runtime.js";

function requestedAuth(args: Args): AuthSource {
  if (args.getBoolean("token-stdin")) return { kind: "stdin" };
  const variable = args.getString("token-env");
  if (variable !== undefined) return { kind: "env", var: variable };
  return ANONYMOUS;
}

function requireName(args: Args, verb: string): string {
  const name = args.positionals[0];
  if (name === undefined || name.trim() === "") {
    throw CliError.usage(`context ${verb} requires a <name>`);
  }
  return name;
}

export const contextCommand: CommandNode = {
  name: "context",
  about: "Manage Control Plane API client contexts",
  sub: [
    {
      name: "create",
      about: "Create or replace a named context",
      positionals: ["<name>"],
      flags: [
        { name: "endpoint", kind: "string", valueName: "URL", help: "Control Plane API endpoint" },
        {
          name: "tenant",
          kind: "string",
          valueName: "ID",
          help: "Default tenant (recorded, not honored server-side)",
        },
        {
          name: "project",
          kind: "string",
          valueName: "ID",
          help: "Default project (recorded, not sent)",
        },
        {
          name: "workspace",
          kind: "string",
          valueName: "ID",
          help: "Default workspace (recorded, not sent)",
        },
        {
          name: "token-env",
          kind: "string",
          valueName: "VAR",
          help: "Env var the bearer token is read from",
          conflictsWith: ["token-stdin"],
        },
        {
          name: "token-stdin",
          kind: "boolean",
          help: "Read the bearer token from stdin at call time",
          conflictsWith: ["token-env"],
        },
        {
          name: "ca-bundle",
          kind: "string",
          valueName: "PATH",
          help: "Custom CA bundle",
          conflictsWith: ["insecure-skip-tls-verify"],
        },
        {
          name: "insecure-skip-tls-verify",
          kind: "boolean",
          help: "Do not verify the server certificate (dangerous)",
          conflictsWith: ["ca-bundle"],
        },
        { name: "use", kind: "boolean", help: "Select this context immediately" },
        {
          name: "overwrite",
          kind: "boolean",
          help: "Replace an existing context of the same name",
        },
      ],
      run: async (runtime, args) => {
        const name = requireName(args, "create");
        const auth = requestedAuth(args);
        const endpoint = args.requireString("endpoint");
        const tenant = args.getString("tenant");
        const project = args.getString("project");
        const workspace = args.getString("workspace");
        const caBundlePath = args.getString("ca-bundle");
        const context: Context = {
          name,
          endpoint,
          ...(tenant === undefined ? {} : { tenant }),
          ...(project === undefined ? {} : { project }),
          ...(workspace === undefined ? {} : { workspace }),
          ...(caBundlePath === undefined ? {} : { caBundlePath }),
          tlsInsecureSkipVerify: args.getBoolean("insecure-skip-tls-verify"),
          auth,
        };
        let store = await runtime.contextStorage.load();
        if (getContext(store, name) !== undefined && !args.getBoolean("overwrite")) {
          throw CliError.usage(`context '${name}' already exists; pass --overwrite to replace it`);
        }
        store = upsertContext(store, context);
        if (args.getBoolean("use")) store = setCurrentContext(store, name);
        await runtime.contextStorage.save(store);
        runtime.io.stderr(
          `created context '${name}' (endpoint ${endpoint}, auth ${describeAuth(auth)})${
            args.getBoolean("use") ? ", now current" : ""
          }\n`,
        );
        return 0;
      },
    },
    {
      name: "list",
      about: "List contexts (the current one is marked *)",
      run: async (runtime) => {
        const store = await runtime.contextStorage.load();
        const rows = store.contexts.map((context) => [
          context.name,
          store.current === context.name ? "*" : "",
          context.endpoint,
          describeAuth(context.auth),
          context.tenant ?? "-",
        ]);
        runtime.io.stdout(
          `${Table.create(["NAME", "CURRENT", "ENDPOINT", "AUTH", "TENANT"], rows).render()}\n`,
        );
        if (store.contexts.length === 0) {
          runtime.io.stderr("no contexts defined; create one with `ferrogate context create`\n");
        }
        return 0;
      },
    },
    {
      name: "show",
      about: "Show one context",
      positionals: ["<name>"],
      run: async (runtime, args) => {
        const name = requireName(args, "show");
        const store = await runtime.contextStorage.load();
        const context = getContext(store, name);
        if (context === undefined) {
          throw CliError.usage(`no such context '${name}'; run \`context list\``);
        }
        const rows: string[][] = [
          ["name", context.name],
          ["endpoint", context.endpoint],
          ["tenant", context.tenant ?? "-"],
          ["project", context.project ?? "-"],
          ["workspace", context.workspace ?? "-"],
          ["auth", describeAuth(context.auth)],
          ["ca_bundle", context.caBundlePath ?? "-"],
          ["tls_insecure_skip_verify", String(context.tlsInsecureSkipVerify)],
          ["current", String(store.current === name)],
        ];
        runtime.io.stdout(`${Table.create(["FIELD", "VALUE"], rows).render()}\n`);
        return 0;
      },
    },
    {
      name: "use",
      about: "Select the current context",
      positionals: ["<name>"],
      run: async (runtime, args) => {
        const name = requireName(args, "use");
        const store = setCurrentContext(await runtime.contextStorage.load(), name);
        await runtime.contextStorage.save(store);
        runtime.io.stderr(`selected context '${name}'\n`);
        return 0;
      },
    },
    {
      name: "delete",
      about: "Delete a context",
      positionals: ["<name>"],
      run: async (runtime, args) => {
        const name = requireName(args, "delete");
        const { store, removed } = removeContext(await runtime.contextStorage.load(), name);
        if (!removed) throw CliError.usage(`no such context '${name}'; nothing to delete`);
        await runtime.contextStorage.save(store);
        runtime.io.stderr(`deleted context '${name}'\n`);
        return 0;
      },
    },
  ],
};
