import { ClientActionIdentity, fingerprintEnvFrom } from "../action-identity.js";
/**
 * The legacy gateway-direct `assets` verbs: `push`, `pull`, `list`, `delete`.
 *
 * Port of `ferrogate-cli::assets_cli` (inventory-edge-control.md §1.1). These
 * predate `ctl` and target the DATA plane (`/v1/assets/...`) with
 * `--gateway-url` + `--api-key`, uploading and downloading raw bytes. Both
 * paths ship: `ctl assets` is the registry-driven `/admin/v1` route, these are
 * the byte-moving ones, and the nouns cannot collide because `ctl` namespaces
 * its tree.
 */
import type { Args, FlagSpec } from "../args.js";
import type { EffectiveContext } from "../context.js";
import { DEFAULT_TIMEOUT_MILLIS } from "../context.js";
import { CliError, exitClassFromHttpStatus, exitCode } from "../errors.js";
import { renderJson } from "../output.js";
import type { BinaryRequest, BinaryResponse, RequestContext } from "../ports.js";
import type { CliRuntime, CommandNode } from "../runtime.js";

/** `--gateway-url` + `--api-key`, shared by every asset and plan verb. */
export const CONNECTION_FLAGS: readonly FlagSpec[] = [
  {
    name: "gateway-url",
    kind: "string",
    valueName: "URL",
    env: "FERROGATE_GATEWAY_URL",
    help: "Gateway base URL",
  },
  {
    name: "api-key",
    kind: "string",
    valueName: "KEY",
    env: "FERROGATE_API_KEY",
    help: "Virtual API key",
  },
];

/**
 * Build the per-invocation request context.
 *
 * The action identity is minted here too: #548 says no verb is unattributable,
 * and these gateway-direct verbs are verbs.
 */
export function connectionContext(runtime: CliRuntime, args: Args): RequestContext {
  const endpoint = args.requireString("gateway-url");
  const apiKey = args.requireString("api-key");
  const effective: EffectiveContext = {
    endpoint,
    tlsInsecureSkipVerify: false,
    timeoutMillis: DEFAULT_TIMEOUT_MILLIS,
    auth: { kind: "inline", token: apiKey },
    output: "json",
    nonInteractive: true,
  };
  const identity = ClientActionIdentity.mint(effective, runtime.io, fingerprintEnvFrom(runtime.io));
  return {
    endpoint,
    token: apiKey,
    timeoutMillis: DEFAULT_TIMEOUT_MILLIS,
    headers: identity.headers(),
    tlsInsecureSkipVerify: false,
  };
}

/** Collect the optional query parameters that were actually supplied. */
function optionalQuery(args: Args, names: readonly string[]): (readonly [string, string])[] {
  const query: (readonly [string, string])[] = [];
  for (const name of names) {
    const value = args.getString(name);
    if (value !== undefined) query.push([name, value]);
  }
  return query;
}

function decode(bytes: Uint8Array): string {
  return new TextDecoder().decode(bytes);
}

/** Print a JSON response, or fail with the server's own exit class. */
export function printJsonOrRaise(
  runtime: CliRuntime,
  response: BinaryResponse,
  what: string,
): number {
  const text = decode(response.bytes);
  if (response.status < 200 || response.status > 299) {
    runtime.io.stderr(`error: ${what} failed: status=${response.status} body=${text}\n`);
    return exitCode(exitClassFromHttpStatus(response.status));
  }
  try {
    runtime.io.stdout(`${renderJson(JSON.parse(text) as unknown)}\n`);
  } catch {
    runtime.io.stdout(`${text}\n`);
  }
  return 0;
}

/** Content type inferred from the file suffix when `--content-type` is absent. */
export function guessContentType(path: string): string {
  const lower = path.toLowerCase();
  const table: readonly (readonly [string, string])[] = [
    [".json", "application/json"],
    [".wasm", "application/wasm"],
    [".js", "text/javascript"],
    [".css", "text/css"],
    [".html", "text/html"],
    [".htm", "text/html"],
    [".txt", "text/plain"],
    [".md", "text/markdown"],
    [".svg", "image/svg+xml"],
    [".png", "image/png"],
    [".jpg", "image/jpeg"],
    [".jpeg", "image/jpeg"],
    [".gz", "application/gzip"],
    [".zip", "application/zip"],
    [".tar", "application/x-tar"],
  ];
  for (const [suffix, mediaType] of table) {
    if (lower.endsWith(suffix)) return mediaType;
  }
  return "application/octet-stream";
}

const IDENTITY_FLAGS: readonly FlagSpec[] = [
  ...CONNECTION_FLAGS,
  { name: "type", kind: "string", valueName: "TYPE", help: "Asset type" },
  { name: "name", kind: "string", valueName: "NAME", help: "Asset name" },
  {
    name: "version",
    kind: "string",
    valueName: "VERSION",
    help: "Exact version, channel, or semver range",
  },
  { name: "platform", kind: "string", valueName: "PLATFORM", help: "Platform variant" },
];

async function sendAsset(
  runtime: CliRuntime,
  args: Args,
  request: Omit<BinaryRequest, "query"> & { query?: readonly (readonly [string, string])[] },
): Promise<BinaryResponse> {
  return runtime.gatewayClient.send(
    { ...request, query: request.query ?? [] },
    connectionContext(runtime, args),
  );
}

function assetPath(args: Args): string {
  const type = args.requireString("type");
  const name = args.requireString("name");
  const version = args.requireString("version");
  return `/v1/assets/${encodeURIComponent(type)}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`;
}

export const assetsCommand: CommandNode = {
  name: "assets",
  about: "Manage hosted assets on a gateway (byte-moving; see also `ctl assets`)",
  sub: [
    {
      name: "push",
      about: "Upload a local file as a new asset version",
      positionals: ["<path>"],
      flags: [
        ...IDENTITY_FLAGS,
        {
          name: "content-type",
          kind: "string",
          valueName: "MIME",
          help: "Override the content type",
        },
        {
          name: "channel",
          kind: "string",
          valueName: "CHANNEL",
          help: "Release channel to point at this version",
        },
      ],
      run: async (runtime, args) => {
        const path = args.positionals[0];
        if (path === undefined) throw CliError.usage("assets push requires a <path> to upload");
        const content = await runtime.io.readFileBytes(path);
        const response = await sendAsset(runtime, args, {
          method: "PUT",
          path: assetPath(args),
          query: optionalQuery(args, ["platform", "channel"]),
          contentType: args.getString("content-type") ?? guessContentType(path),
          body: content,
        });
        return printJsonOrRaise(runtime, response, "push");
      },
    },
    {
      name: "pull",
      about: "Download an asset to a file or stdout",
      flags: [
        ...IDENTITY_FLAGS,
        {
          name: "output",
          kind: "string",
          valueName: "PATH",
          help: "Write here instead of stdout ('-' = stdout)",
        },
      ],
      run: async (runtime, args) => {
        const response = await sendAsset(runtime, args, {
          method: "GET",
          path: assetPath(args),
          query: optionalQuery(args, ["platform"]),
        });
        if (response.status < 200 || response.status > 299) {
          runtime.io.stderr(
            `error: pull failed: status=${response.status} body=${decode(response.bytes)}\n`,
          );
          return exitCode(exitClassFromHttpStatus(response.status));
        }
        const output = args.getString("output");
        if (output === undefined || output === "-") {
          runtime.io.stdoutBytes(response.bytes);
          return 0;
        }
        await runtime.io.writeFileBytes(output, response.bytes);
        runtime.io.stderr(`wrote ${response.bytes.length} bytes to ${output}\n`);
        return 0;
      },
    },
    {
      name: "list",
      about: "List a tenant's assets",
      flags: [
        ...CONNECTION_FLAGS,
        { name: "type", kind: "string", valueName: "TYPE", help: "Restrict to one asset type" },
      ],
      run: async (runtime, args) => {
        const type = args.getString("type");
        const response = await sendAsset(runtime, args, {
          method: "GET",
          path: type === undefined ? "/v1/assets" : `/v1/assets/${encodeURIComponent(type)}`,
        });
        return printJsonOrRaise(runtime, response, "list");
      },
    },
    {
      name: "delete",
      about: "Delete one asset version",
      flags: IDENTITY_FLAGS,
      run: async (runtime, args) => {
        const response = await sendAsset(runtime, args, {
          method: "DELETE",
          path: assetPath(args),
          query: optionalQuery(args, ["platform"]),
        });
        return printJsonOrRaise(runtime, response, "delete");
      },
    },
  ],
};
