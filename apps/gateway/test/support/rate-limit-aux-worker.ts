/**
 * The `ferrogate-gateway` AUXILIARY WORKER that makes the fleet's cross-script
 * `RATE_LIMIT` binding resolvable OFFLINE.
 *
 * ## What this exists to unblock (issue #666)
 *
 * `apps/mcp` and `apps/agent-runtime` bind the gateway's already-deployed
 * `RateLimiterDurableObject` with
 *
 *     [[durable_objects.bindings]]
 *     name = "RATE_LIMIT"
 *     class_name = "RateLimiterDurableObject"
 *     script_name = "ferrogate-gateway"
 *
 * so `idFromName("key:<id>")` addresses the SAME instance from all three
 * Workers and a credential capped at 60 rpm is charged ONE window across
 * `/v1/chat/completions`, MCP `tools/call` and `POST /v1/agent-jobs`. Until
 * this file existed both stanzas were COMMENTED OUT and a human had to
 * uncomment them at deploy time, because a bare
 * `@cloudflare/vitest-pool-workers` session refuses to start:
 *
 *     Worker "core:user:vitest-pool-workers-runner-"'s binding "RATE_LIMIT"
 *     refers to a service "core:user:ferrogate-gateway", but no such service
 *     is defined.
 *
 * The error is exactly what it says: workerd cannot resolve a `script_name`
 * against a script that is not in the session. It is NOT a statement that
 * workerd cannot do cross-script bindings offline — it can, as soon as the
 * session CONTAINS a script by that name. Miniflare's auxiliary-worker list
 * (`miniflare: { workers: [...] }`) is how a test session adds one, and that
 * is the whole trick here.
 *
 * ## Why it bundles the REAL class instead of a stub
 *
 * A stub would prove the binding RESOLVES and nothing about what it counts. The
 * property the fleet is sold on is that one window is shared, so the auxiliary
 * script is `apps/gateway/src/ratelimit/durable-object.ts` itself, bundled by
 * esbuild — the same source `wrangler deploy` ships for `ferrogate-gateway`.
 * A test can therefore charge a counter key THROUGH the binding (playing the
 * gateway) and then watch the MCP / agent-runtime admission ladder find that
 * window already spent.
 *
 * The bundle is built here rather than pointed at with `scriptPath` because
 * Miniflare auxiliary workers take JavaScript: they are not passed through the
 * Vite pipeline that transpiles the Worker under test.
 *
 * ## What this does NOT prove, stated so nobody reads more into it
 *
 * The auxiliary script carries the gateway's LIMITER and nothing else. It is
 * proof that the committed binding resolves, that the class it resolves to is
 * the gateway's, and that all three Workers charge one namespace. It is not
 * proof that the `ferrogate-gateway` script deployed to Cloudflare is this
 * source, nor that it was deployed FIRST — a `script_name` binding to a script
 * that does not exist yet fails the deploy, which is the (real, loud)
 * deploy-time assertion that replaces the old hand-uncommenting step.
 */
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { buildSync } from "esbuild";

/**
 * The script name every borrower's `script_name` must spell, and the name the
 * auxiliary worker must be registered under. Read out of the gateway's
 * committed config rather than typed here, so renaming the Worker breaks the
 * harness instead of silently detaching it.
 */
function gatewayIdentity(gatewayAppRoot: URL): { name: string; compatibilityDate: string } {
  const toml = readFileSync(new URL("wrangler.toml", gatewayAppRoot), "utf8");
  const name = /^name\s*=\s*"([^"]+)"/m.exec(toml)?.[1];
  const compatibilityDate = /^compatibility_date\s*=\s*"([^"]+)"/m.exec(toml)?.[1];
  if (name === undefined || compatibilityDate === undefined) {
    throw new Error(
      "rate-limit aux worker: could not read name/compatibility_date out of apps/gateway/wrangler.toml",
    );
  }
  return { name, compatibilityDate };
}

/**
 * Miniflare auxiliary-worker options that publish `RateLimiterDurableObject`
 * under the gateway's script name.
 *
 * @param gatewayAppRoot `apps/gateway/` as a directory URL (trailing slash).
 *   Passed in rather than derived from `import.meta.url`: Vite bundles a
 *   `vitest.config.ts` into a sibling temp file, so `import.meta.url` is only
 *   trustworthy in the config file itself.
 */
export function gatewayRateLimiterAuxWorker(
  gatewayAppRoot: URL,
  options: { readonly tenantData?: boolean } = {},
) {
  const { name, compatibilityDate } = gatewayIdentity(gatewayAppRoot);
  const includeTenantData = options.tenantData === true;

  // `stdin` rather than a checked-in entry file: the entry is two lines and
  // keeping it here means there is no second place for the export list to rot.
  // `default` is present because workerd wants an entrypoint for a module
  // worker; nothing routes to it, and a request that somehow arrives says so.
  const built = buildSync({
    stdin: {
      contents: [
        'export { RateLimiterDurableObject } from "./src/ratelimit/durable-object.js";',
        ...(includeTenantData
          ? ['export { TenantDataObject } from "@ferrogate/storage/durable-objects";']
          : []),
        "export default {",
        "  fetch() {",
        '    return new Response("ferrogate-gateway test aux worker: RPC only", { status: 404 });',
        "  },",
        "};",
      ].join("\n"),
      resolveDir: fileURLToPath(gatewayAppRoot),
      sourcefile: "rate-limit-aux-worker-entry.ts",
      loader: "ts",
    },
    bundle: true,
    format: "esm",
    target: "es2022",
    platform: "neutral",
    // Resolved by the runtime, not by the bundler.
    external: ["cloudflare:workers"],
    write: false,
  });

  const script = built.outputFiles[0]?.text;
  if (script === undefined || script.length === 0) {
    throw new Error("rate-limit aux worker: esbuild produced no output for the limiter bundle");
  }
  if (!script.includes("RateLimiterDurableObject")) {
    // A guard on the harness itself. If the bundle ever came back without the
    // class, every cross-script assertion downstream would fail with an opaque
    // workerd startup error instead of naming its cause.
    throw new Error("rate-limit aux worker: bundle does not contain RateLimiterDurableObject");
  }

  const durableObjects: Record<string, { className: string; useSQLite: boolean }> = {
    RATE_LIMIT: { className: "RateLimiterDurableObject", useSQLite: true },
  };
  if (includeTenantData) {
    durableObjects.TENANT_DATA = { className: "TenantDataObject", useSQLite: true };
  }

  return {
    name,
    compatibilityDate,
    compatibilityFlags: ["nodejs_compat"],
    // `as const` on the type tag: Miniflare's `ModuleDefinition` discriminates
    // on the literal, and a widened `string` makes the whole object
    // unassignable to `WorkerOptions` at the call site.
    modules: [{ type: "ESModule" as const, path: "index.mjs", contents: script }],
    // Mirrors `apps/gateway/wrangler.toml`: the gateway binds the class it
    // defines, and its SQLite export means `useSQLite` here. Getting
    // this wrong locally would exercise the key-value backend the real
    // namespace does not use.
    durableObjects,
  };
}

/**
 * The same trick for `TenantDataObject` (#820) — the namespace
 * `apps/control-plane` borrows with `script_name = "ferrogate-gateway"` so that
 * `idFromName(tenantId)` names the SAME object from both Workers.
 *
 * A SECOND function rather than a second class on the one above, because the two
 * are never needed in the same session: `apps/mcp` and `apps/agent-runtime`
 * borrow only RATE_LIMIT, `apps/control-plane` borrows only TENANT_DATA, and a
 * session may contain exactly ONE auxiliary worker named `ferrogate-gateway`.
 * Merging them would publish a class into sessions whose Worker never binds it —
 * harmless today and exactly the kind of harmless that makes a later
 * "why is this here" edit break a suite it has no visible connection to.
 *
 * `useSQLite: true` mirrors the gateway's SQLite
 * `[exports.TenantDataObject]` declaration.
 * Getting it wrong locally would exercise the key-value backend against a class
 * whose entire implementation is `ctx.storage.sql`, so the suite would fail
 * loudly rather than silently — but it would fail for a reason that has nothing
 * to do with the code under test.
 */
export function gatewayTenantDataAuxWorker(gatewayAppRoot: URL) {
  const { name, compatibilityDate } = gatewayIdentity(gatewayAppRoot);

  const built = buildSync({
    stdin: {
      contents: [
        // The SAME specifier `apps/gateway/src/worker.ts:140` re-exports, so a
        // move of the class breaks this harness instead of detaching it.
        'export { TenantDataObject } from "@ferrogate/storage/durable-objects";',
        // #879 (Zero-D1 S3): the control-plane binds CONTROL_DATA cross-script to
        // this same gateway-hosted class, so publish it here too.
        'export { ControlDataObject } from "@ferrogate/storage/durable-objects";',
        "export default {",
        "  fetch() {",
        '    return new Response("ferrogate-gateway test aux worker: RPC only", { status: 404 });',
        "  },",
        "};",
      ].join("\n"),
      resolveDir: fileURLToPath(gatewayAppRoot),
      sourcefile: "tenant-data-aux-worker-entry.ts",
      loader: "ts",
    },
    bundle: true,
    format: "esm",
    target: "es2022",
    platform: "neutral",
    external: ["cloudflare:workers"],
    write: false,
  });

  const script = built.outputFiles[0]?.text;
  if (script === undefined || script.length === 0) {
    throw new Error("tenant-data aux worker: esbuild produced no output for the object bundle");
  }
  if (!script.includes("TenantDataObject")) {
    throw new Error("tenant-data aux worker: bundle does not contain TenantDataObject");
  }
  if (!script.includes("ControlDataObject")) {
    throw new Error("tenant-data aux worker: bundle does not contain ControlDataObject");
  }

  return {
    name,
    compatibilityDate,
    compatibilityFlags: ["nodejs_compat"],
    modules: [{ type: "ESModule" as const, path: "index.mjs", contents: script }],
    durableObjects: {
      TENANT_DATA: { className: "TenantDataObject", useSQLite: true },
      // #879: the singleton CONTROL object, bound cross-script by the control-plane.
      CONTROL_DATA: { className: "ControlDataObject", useSQLite: true },
    },
  };
}
