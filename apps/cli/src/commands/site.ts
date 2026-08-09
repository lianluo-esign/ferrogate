/**
 * `ferrogate site push ./dist --name docs --version 1.2.3` — issue #736.
 *
 * `assets push` uploads ONE file. A static website is a directory tree, so
 * publishing one through it means either publishing a single `index.html` or
 * hand-rolling a tarball and remembering to declare its content type. This verb
 * is the missing one: walk a directory, pack it deterministically, and PUT it
 * at the existing `PUT /v1/assets/static_site/{name}/{version}` — the same
 * operation, the same auth, the same channel query parameter. No new endpoint
 * exists for it, and none should: the gateway decides a `static_site` push is a
 * BUNDLE from the archive content type, and everything downstream (channels,
 * semver ranges, yank, the manifest) then works on it unchanged.
 *
 * ## What this file refuses, and why the CLIENT refuses it at all
 *
 * The gateway is the authority — it re-checks every path, every file type, and
 * every ceiling on the bytes it actually receives, and nothing here can weaken
 * that. These client-side refusals exist for a different reason: they are the
 * only place that can see the LOCAL filesystem.
 *
 *  - A **symlink** in `dist/` is refused rather than followed. By the time the
 *    archive reaches the gateway a followed symlink is indistinguishable from a
 *    real file, so `dist/secrets -> ~/.ssh/id_rsa` would upload the key and the
 *    server would have no way to know. This is the one check that CANNOT be
 *    delegated.
 *  - An empty directory is refused, because "I published nothing" should not be
 *    a 201.
 *
 * Everything else — the per-file content-type allowlist, traversal, the
 * zip-bomb ceilings — is deliberately NOT duplicated here. A client-side copy
 * of a security rule is a rule that drifts, and any attacker can simply not run
 * this client.
 */
import type { Args, FlagSpec } from "../args.js";
import { CliError } from "../errors.js";
import type { DirectoryEntry } from "../ports.js";
import type { CliRuntime, CommandNode } from "../runtime.js";
import { TAR_MAX_PATH_BYTES, type TarFile, buildTar } from "../tar.js";
import { CONNECTION_FLAGS, connectionContext, printJsonOrRaise } from "./assets.js";

/** The `asset_type` a site is published under; the gateway's bundle trigger. */
export const SITE_ASSET_TYPE = "static_site";

/** The archive content type. `x-tar` is on the gateway's `static_site` allowlist. */
export const SITE_ARCHIVE_CONTENT_TYPE = "application/x-tar";

const SITE_FLAGS: readonly FlagSpec[] = [
  ...CONNECTION_FLAGS,
  { name: "name", kind: "string", valueName: "NAME", help: "Site name" },
  { name: "version", kind: "string", valueName: "VERSION", help: "Exact version to publish" },
  {
    name: "channel",
    kind: "string",
    valueName: "CHANNEL",
    help: "Release channel to point at this version",
  },
];

/**
 * Turn a directory walk into the archive members, or raise.
 *
 * Exported so the refusals are testable without a filesystem: the walk is an
 * `Io` seam, so a test hands it a tree containing a symlink and asserts the
 * error, which is what proves the refusal is reachable rather than merely
 * present.
 */
export async function collectSiteFiles(
  runtime: CliRuntime,
  root: string,
  entries: readonly DirectoryEntry[],
): Promise<TarFile[]> {
  const files: TarFile[] = [];
  for (const entry of [...entries].sort((left, right) => (left.path < right.path ? -1 : 1))) {
    if (entry.kind === "symlink") {
      throw CliError.usage(
        `site push refuses ${entry.path}: it is a symlink, and following it would upload whatever it points at under a name that hides where the bytes came from`,
      );
    }
    if (entry.kind !== "file") {
      throw CliError.usage(
        `site push refuses ${entry.path}: only regular files can be published in a site bundle`,
      );
    }
    if (new TextEncoder().encode(entry.path).length > TAR_MAX_PATH_BYTES) {
      throw CliError.usage(
        `site push refuses ${entry.path}: the path is longer than the ${TAR_MAX_PATH_BYTES}-byte ustar name field`,
      );
    }
    files.push({
      path: entry.path,
      content: await runtime.io.readFileBytes(`${root.replace(/\/+$/, "")}/${entry.path}`),
    });
  }
  if (files.length === 0) {
    throw CliError.usage(`site push found no files under ${root}`);
  }
  return files;
}

export const siteCommand: CommandNode = {
  name: "site",
  about: "Publish a static website directory as one versioned asset bundle",
  sub: [
    {
      name: "push",
      about: "Pack a directory and publish it as a static_site bundle version",
      positionals: ["<dir>"],
      flags: SITE_FLAGS,
      run: async (runtime, args: Args) => {
        const directory = args.positionals[0];
        if (directory === undefined) {
          throw CliError.usage("site push requires a <dir> to publish");
        }
        const name = args.requireString("name");
        const version = args.requireString("version");

        const entries = await runtime.io.listDirectory(directory);
        const files = await collectSiteFiles(runtime, directory, entries);
        const archive = buildTar(files);

        const channel = args.getString("channel");
        const response = await runtime.gatewayClient.send(
          {
            method: "PUT",
            path: `/v1/assets/${encodeURIComponent(SITE_ASSET_TYPE)}/${encodeURIComponent(name)}/${encodeURIComponent(version)}`,
            query: channel === undefined ? [] : [["channel", channel] as const],
            contentType: SITE_ARCHIVE_CONTENT_TYPE,
            body: archive,
          },
          connectionContext(runtime, args),
        );
        runtime.io.stderr(
          `packed ${files.length} files (${archive.length} bytes) from ${directory}\n`,
        );
        return printJsonOrRaise(runtime, response, "site push");
      },
    },
  ],
};
