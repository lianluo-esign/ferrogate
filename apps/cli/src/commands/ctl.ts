/**
 * `ferrogate ctl <group> <verb>` — the generic, registry-driven dispatcher.
 *
 * Port of `ferrogate-cli::ctl::resource_cmd` (inventory-edge-control.md §1.2).
 * It builds its whole command surface from `registry.ts` metadata and routes
 * every matched command through one `buildRequest` seam, so adding a resource
 * family stays code-free here.
 *
 * The contracts it enforces, in order:
 *   1. precedence resolved once (flag > env > context > default);
 *   2. one action identity minted per invocation, shared by every page;
 *   3. confirmation before a guarded mutation leaves the process;
 *   4. the render gate — reads render bodies, mutations render receipts only;
 *   5. the contract-version gate — refuse to render a document from a server
 *      whose API contract predates the minimum this build understands;
 *   6. cursor/offset honesty — never print a continuation that does not exist.
 */
import type { JsonValue } from "@ferrogate/core";
import { ClientActionIdentity, fingerprintEnvFrom } from "../action-identity.js";
import type { Args, FlagSpec } from "../args.js";
import { parseArgs, renderFlagHelp } from "../args.js";
import type { EffectiveContext } from "../context.js";
import { resolveCredential } from "../context.js";
import { reportError } from "../diagnostics.js";
import { CliError, asCliError } from "../errors.js";
import { GLOBAL_FLAGS, resolveEffective } from "../global-args.js";
import {
  SORT_NOT_HONORED_NOTICE,
  cursorOffsetRefusal,
  renderOutput,
  truncationNotice,
} from "../output.js";
import { DEFAULT_PAGE_SIZE, mergePages, nextPage, pageEnvelope } from "../paging.js";
import type { ApiResponse, RequestContext, RequestSpec } from "../ports.js";
import { MutationPlan, type VerbOutput, renderGate } from "../receipt.js";
import type { GroupDescriptor, ResourceInput, VerbDescriptor } from "../registry.js";
import {
  GROUPS,
  ListParams,
  buildRequest,
  rawResponseMediaType,
  redactResponse,
  requiresConfirmation,
  resolveVerb,
  secretFieldsFor,
} from "../registry.js";
import type { CliRuntime, CommandNode } from "../runtime.js";
import { enforceContractVersion } from "../version.js";

/** Per-verb flags every `ctl` command accepts. */
export const RESOURCE_FLAGS: readonly FlagSpec[] = [
  {
    name: "data",
    kind: "string",
    valueName: "JSON",
    help: "Inline JSON request document",
    conflictsWith: ["file"],
  },
  {
    name: "file",
    kind: "string",
    valueName: "PATH",
    help: "Read the JSON request document from PATH ('-' = stdin)",
    conflictsWith: ["data"],
  },
  { name: "limit", kind: "number", valueName: "N", help: "Page size" },
  {
    name: "offset",
    kind: "number",
    valueName: "N",
    help: "Page offset (offset-paginated endpoints only)",
    conflictsWith: ["all-pages"],
  },
  {
    name: "filter",
    kind: "string",
    valueName: "KEY=VALUE",
    repeatable: true,
    help: "Server-side filter; repeatable",
  },
  {
    name: "sort",
    kind: "string",
    valueName: "FIELD",
    repeatable: true,
    allowHyphenValues: true,
    help: "Server-side sort key; repeatable, '-' prefix = descending",
  },
  {
    name: "all-pages",
    kind: "boolean",
    help: "Walk every offset page and merge the result",
    conflictsWith: ["offset"],
  },
  { name: "dry-run", kind: "boolean", help: "Build the mutation receipt without sending" },
];

/** `--yes` exists only on verbs whose registry entry demands confirmation. */
const CONFIRM_FLAG: FlagSpec = {
  name: "yes",
  kind: "boolean",
  help: "Acknowledge this guarded state-changing operation without prompting",
  conflictsWith: ["dry-run"],
};

// ---------------------------------------------------------------------------
// Argument → ResourceInput
// ---------------------------------------------------------------------------

async function readBody(runtime: CliRuntime, args: Args): Promise<JsonValue | undefined> {
  const inline = args.getString("data");
  const file = args.getString("file");
  let raw: string | undefined;
  if (inline !== undefined) {
    raw = inline;
  } else if (file !== undefined) {
    raw = file === "-" ? await runtime.io.readStdin() : await runtime.io.readFile(file);
  }
  if (raw === undefined) return undefined;
  try {
    return JSON.parse(raw) as JsonValue;
  } catch (error) {
    throw CliError.usage(
      `request document is not valid JSON: ${error instanceof Error ? error.message : String(error)}`,
    );
  }
}

/** Build the typed input, rejecting malformed `--filter`/`--sort` rather than dropping them. */
export async function toResourceInput(runtime: CliRuntime, args: Args): Promise<ResourceInput> {
  const allPages = args.getBoolean("all-pages");
  const limit = args.getUnsigned("limit");
  const offset = args.getUnsigned("offset");

  const sorts: string[] = [];
  for (const raw of args.getAll("sort")) {
    const key = raw.trim();
    if (key === "") throw CliError.usage("--sort key must not be empty");
    if (key.startsWith("--")) {
      throw CliError.usage(
        `--sort expected a field name but got the flag '${key}'; a sort key never begins with ` +
          `'--' (did you mean \`--sort <FIELD> ${key}\`?)`,
      );
    }
    sorts.push(key);
  }

  const filters: (readonly [string, string])[] = [];
  for (const raw of args.getAll("filter")) {
    const index = raw.indexOf("=");
    if (index === -1) throw CliError.usage(`--filter must be KEY=VALUE, got '${raw}'`);
    const key = raw.slice(0, index).trim();
    if (key === "") throw CliError.usage(`--filter key must not be empty in '${raw}'`);
    filters.push([key, raw.slice(index + 1)]);
  }

  const page =
    !allPages && (limit !== undefined || offset !== undefined)
      ? { offset: offset ?? 0, ...(limit === undefined ? {} : { limit }) }
      : undefined;

  const body = await readBody(runtime, args);
  return {
    segments: args.positionals,
    ...(body === undefined ? {} : { body }),
    list: new ListParams({ ...(page === undefined ? {} : { page }), filters, sorts }),
  };
}

// ---------------------------------------------------------------------------
// Confirmation
// ---------------------------------------------------------------------------

function displayCommand(group: string, verb: string, segments: readonly string[]): string {
  return ["ferrogate", "ctl", group, verb, ...segments].join(" ");
}

/**
 * Guarded mutations must be acknowledged before the request is built.
 *
 * `--non-interactive` and a non-TTY stdin both REFUSE rather than assume
 * consent: an unattended pipeline must say `--yes` out loud.
 */
export async function requireConfirmation(
  runtime: CliRuntime,
  verb: VerbDescriptor,
  group: string,
  segments: readonly string[],
  dryRun: boolean,
  confirmed: boolean,
  nonInteractive: boolean,
): Promise<void> {
  if (!requiresConfirmation(verb) || dryRun || confirmed) return;
  const command = displayCommand(group, verb.name, segments);
  if (nonInteractive) {
    throw CliError.usage(
      `'${command}' requires confirmation; rerun with --yes because --non-interactive disables prompts`,
    );
  }
  if (!runtime.io.isStdinTty()) {
    throw CliError.usage(
      `'${command}' requires confirmation, but stdin is not a terminal; rerun with --yes to acknowledge the operation explicitly`,
    );
  }
  runtime.io.stderr(`Confirm state-changing operation '${command}'? [y/N] `);
  const answer = (await runtime.io.readStdin()).trim().toLowerCase();
  if (answer === "y" || answer === "yes") return;
  throw CliError.usage(`'${command}' cancelled before any request was sent`);
}

// ---------------------------------------------------------------------------
// Transport helpers
// ---------------------------------------------------------------------------

/** Build the transport context, resolving the credential exactly once. */
export async function requestContextFor(
  runtime: CliRuntime,
  effective: EffectiveContext,
  identity: ClientActionIdentity,
): Promise<RequestContext> {
  const token = await resolveCredential(effective.auth, runtime.io);
  return {
    endpoint: effective.endpoint,
    ...(token === undefined ? {} : { token }),
    timeoutMillis: effective.timeoutMillis,
    ...(effective.tenant === undefined ? {} : { tenant: effective.tenant }),
    headers: identity.headers(),
    tlsInsecureSkipVerify: effective.tlsInsecureSkipVerify,
    ...(effective.caBundlePath === undefined ? {} : { caBundlePath: effective.caBundlePath }),
  };
}

function withPage(spec: RequestSpec, offset: number, limit: number): RequestSpec {
  const query = spec.query.filter(([key]) => key !== "offset" && key !== "limit");
  return { ...spec, query: [...query, ["offset", String(offset)], ["limit", String(limit)]] };
}

/** Harvest a server time token so later requests of this action carry it. */
function harvest(
  identity: ClientActionIdentity,
  response: ApiResponse,
  io: CliRuntime["io"],
): void {
  if (response.timeToken === undefined) return;
  identity.acceptTimeToken(response.timeToken, io.nowUnixSeconds());
}

/**
 * Walk every offset page and merge.
 *
 * A cursor endpoint is NOT walkable this way; the caller refuses `--all-pages`
 * for those, and the merged document drops the stale window/cursor keys so it
 * cannot be misread as page one.
 */
export async function sendAllPages(
  runtime: CliRuntime,
  spec: RequestSpec,
  context: RequestContext,
  identity: ClientActionIdentity,
  pageSize: number,
): Promise<ApiResponse> {
  const merged: JsonValue[] = [];
  let current: { offset: number; limit?: number } | undefined = { offset: 0, limit: pageSize };
  let last: ApiResponse | undefined;
  let itemsKey: string | undefined;
  let guard = 0;

  while (current !== undefined) {
    if (++guard > 10_000) {
      throw CliError.transport(
        "refusing to walk more than 10000 pages; the endpoint never reported an end",
      );
    }
    const response: ApiResponse = await runtime.client.send(
      withPage(spec, current.offset, current.limit ?? pageSize),
      { ...context, headers: identity.headers() },
    );
    harvest(identity, response, runtime.io);
    last = response;
    const envelope = pageEnvelope(response.body);
    if (envelope === undefined) return response;
    if (envelope.cursor) {
      throw CliError.usage(
        "--all-pages cannot walk a cursor-paginated endpoint; page it with --filter and the " +
          "cursor parameter this endpoint documents",
      );
    }
    itemsKey = envelope.itemsKey;
    merged.push(...envelope.items);
    current = nextPage(current, envelope.items.length, envelope.total);
  }

  if (last === undefined) throw CliError.transport("pagination produced no response");
  return { ...last, body: mergePages(last.body, itemsKey, merged) };
}

// ---------------------------------------------------------------------------
// The dispatcher
// ---------------------------------------------------------------------------

function ctlUsage(): string {
  const lines = [
    "usage: ferrogate ctl <group> <verb> [id...] [flags]",
    "",
    "Control Plane API resource families, dispatched generically from the registry.",
    "",
    "groups:",
  ];
  const width = GROUPS.reduce((max, group) => Math.max(max, group.name.length), 0);
  for (const group of GROUPS) {
    lines.push(`  ${group.name.padEnd(width)}  ${group.about}`);
  }
  return `${lines.join("\n")}\n`;
}

function groupUsage(group: GroupDescriptor): string {
  const lines = [
    `usage: ferrogate ctl ${group.name} <verb> [id...] [flags]`,
    "",
    group.about,
    "",
    "verbs:",
  ];
  const width = group.verbs.reduce((max, verb) => Math.max(max, verb.name.length), 0);
  for (const verb of group.verbs) {
    const marks: string[] = [];
    if (verb.effect === "mutating") marks.push("mutating");
    if (requiresConfirmation(verb)) marks.push("needs --yes");
    if (verb.responseMode.kind === "raw") marks.push(`raw ${verb.responseMode.mediaType}`);
    const suffix = marks.length === 0 ? "" : ` [${marks.join("; ")}]`;
    lines.push(`  ${verb.name.padEnd(width)}  ${verb.about}${suffix}`);
  }
  return `${lines.join("\n")}\n`;
}

function verbUsage(group: GroupDescriptor, verb: VerbDescriptor): string {
  const flags = [
    ...RESOURCE_FLAGS,
    ...(requiresConfirmation(verb) ? [CONFIRM_FLAG] : []),
    ...GLOBAL_FLAGS,
  ];
  return (
    `usage: ferrogate ctl ${group.name} ${verb.name} [id...] [flags]\n\n${verb.about}\n` +
    `operation: ${verb.operationId ?? "(local)"}   effect: ${verb.effect}\n\nflags:\n` +
    `${renderFlagHelp(flags)}\n`
  );
}

/** Run one `ctl` invocation. Returns the process exit code. */
export async function runResource(runtime: CliRuntime, argv: readonly string[]): Promise<number> {
  const groupName = argv[0];
  let secretFields: readonly string[] = [];
  try {
    if (groupName === undefined || groupName === "--help" || groupName === "-h") {
      runtime.io[groupName === undefined ? "stderr" : "stdout"](ctlUsage());
      return groupName === undefined ? CliError.usage("").exitCode() : 0;
    }
    secretFields = secretFieldsFor(groupName);
    const verbName = argv[1];
    if (verbName === undefined || verbName === "--help" || verbName === "-h") {
      // resolveVerb also validates the group name, so an unknown group is
      // reported before an unhelpful "specify a verb".
      const group = GROUPS.find((candidate) => candidate.name === groupName);
      if (group === undefined) {
        throw CliError.usage(
          `unknown resource group '${groupName}'; run \`ferrogate ctl --help\` for the command list`,
        );
      }
      runtime.io[verbName === undefined ? "stderr" : "stdout"](groupUsage(group));
      return verbName === undefined ? CliError.usage("").exitCode() : 0;
    }

    const { group, verb } = resolveVerb(groupName, verbName);
    const flags = [
      ...RESOURCE_FLAGS,
      ...(requiresConfirmation(verb) ? [CONFIRM_FLAG] : []),
      ...GLOBAL_FLAGS,
    ];
    const args = parseArgs(argv.slice(2), flags, {
      env: runtime.io.env,
      commandPath: `ferrogate ctl ${groupName} ${verbName}`,
    });
    if (args.help) {
      runtime.io.stdout(verbUsage(group, verb));
      return 0;
    }
    return await execute(runtime, group, verb, args);
  } catch (error) {
    const cliError = asCliError(error);
    reportError(runtime.io, cliError, secretFields);
    return cliError.exitCode();
  }
}

async function execute(
  runtime: CliRuntime,
  group: GroupDescriptor,
  verb: VerbDescriptor,
  args: Args,
): Promise<number> {
  const effective = await resolveEffective(runtime, args);
  const dryRun = args.getBoolean("dry-run");
  const allPages = args.getBoolean("all-pages");
  const offset = args.getUnsigned("offset");
  const limit = args.getUnsigned("limit");

  await requireConfirmation(
    runtime,
    verb,
    group.name,
    args.positionals,
    dryRun,
    args.getBoolean("yes"),
    effective.nonInteractive,
  );

  const input = await toResourceInput(runtime, args);
  if (input.list.sorts.length > 0) runtime.io.stderr(`${SORT_NOT_HONORED_NOTICE}\n`);

  const spec = buildRequest(group.name, verb.name, input);
  const rawMediaType = rawResponseMediaType(verb);
  if (rawMediaType !== undefined) {
    if (args.present("output")) {
      throw CliError.usage(
        `--output does not apply to '${group.name} ${verb.name}'; the command writes its ` +
          `${rawMediaType} export bytes to stdout unchanged`,
      );
    }
    if (allPages) {
      throw CliError.usage(
        `--all-pages does not apply to the raw '${group.name} ${verb.name}' export`,
      );
    }
  }

  const identity = ClientActionIdentity.mint(effective, runtime.io, fingerprintEnvFrom(runtime.io));
  const context = await requestContextFor(runtime, effective, identity);

  if (rawMediaType !== undefined) {
    const response = await runtime.client.sendRaw(spec, rawMediaType, context);
    if (response.requestId !== undefined) runtime.io.stderr(`request-id: ${response.requestId}\n`);
    if (response.traceId !== undefined) runtime.io.stderr(`trace-id: ${response.traceId}\n`);
    runtime.io.stdoutBytes(response.bytes);
    return 0;
  }

  const gate = renderGate(verb);
  let output: VerbOutput;
  let failure: CliError | undefined;

  if (gate.kind === "bare") {
    if (dryRun) {
      throw CliError.usage(
        `--dry-run applies to mutating verbs; '${group.name} ${verb.name}' is a ${verb.effect} verb and changes nothing`,
      );
    }
    const response = allPages
      ? await sendAllPages(runtime, spec, context, identity, limit ?? DEFAULT_PAGE_SIZE)
      : await runtime.client.send(spec, context);
    harvest(identity, response, runtime.io);
    if (response.requestId !== undefined) runtime.io.stderr(`request-id: ${response.requestId}\n`);
    if (response.traceId !== undefined) runtime.io.stderr(`trace-id: ${response.traceId}\n`);
    const body = redactResponse(group.name, spec, response.body);
    // Fail closed on an unsupported server contract BEFORE rendering, rather
    // than mis-mapping a document shaped by an older API version (#360).
    enforceContractVersion(verb.operationId, body);
    const refusal = cursorOffsetRefusal(body, offset, spec.path);
    if (refusal !== undefined) throw CliError.usage(refusal);
    output = gate.renderer.render(body);
  } else {
    if (allPages) {
      throw CliError.usage(
        `--all-pages is a list-walking flag; '${group.name} ${verb.name}' is a mutating verb and returns one document`,
      );
    }
    const plan = await MutationPlan.create({
      renderer: gate.renderer,
      group: group.name,
      spec,
      segments: input.segments,
      effective,
      identity,
      dryRun,
    });
    const report = plan.isDryRun
      ? { output: plan.dryRun() }
      : await plan.send(runtime.client, context);
    output = report.output;
    failure = "failure" in report ? report.failure : undefined;
    const receipt = output.receipt;
    if (receipt !== undefined) {
      const requestId = receipt.correlation.request_id.value;
      const traceId = receipt.correlation.trace_id.value;
      if (requestId !== null) runtime.io.stderr(`request-id: ${requestId}\n`);
      if (traceId !== null) runtime.io.stderr(`trace-id: ${traceId}\n`);
    }
  }

  runtime.io.stdout(`${renderOutput(effective.output, output)}\n`);

  if (output.body !== undefined && !allPages) {
    const notice = truncationNotice(output.body, offset ?? 0, limit);
    if (notice !== undefined) runtime.io.stderr(`${notice}\n`);
  }

  if (failure !== undefined) throw failure;
  return 0;
}

export const ctlCommand: CommandNode = {
  name: "ctl",
  about: "Generic Control Plane resource families: ctl <group> <verb>",
  runRaw: runResource,
};
