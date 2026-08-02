/**
 * `GET|HEAD /sites/{site}/{path}` — the contract mount of the static-site serve
 * mode (issue #737).
 *
 * The serving itself lives in `./serve.ts` and is shared, statement for
 * statement, with the custom-domain entry point in `./host.ts` (issue #738).
 * This file is only the mount: it names the contract operation, hands the
 * router a handler, and commits the audit buffer on the way out.
 */
import type { Context } from "hono";
import type { GatewayRouter, RouteModule } from "../routes/index.js";
import { SITE_OPERATION_ID, type SiteEnv, SiteServer, type SiteServerOptions } from "./serve.js";

export { SITE_OPERATION_ID, SITE_READ_SCOPE, SiteServer } from "./serve.js";
export type { SiteEntry, SiteServerOptions } from "./serve.js";

/** Retained name for the mount's options — one shape, two mounts. */
export type SiteRouteModuleOptions = SiteServerOptions;

export function siteRouteModule(options: SiteRouteModuleOptions = {}): RouteModule {
  const server = new SiteServer(options);
  return {
    operationIds: [SITE_OPERATION_ID],
    register(router: GatewayRouter): void {
      router.register(SITE_OPERATION_ID, async (c) => {
        const context = c as unknown as Context<SiteEnv>;
        try {
          return await server.serve(context, { kind: "slug" });
        } finally {
          // The pull-side audit row (`asset.pull`) is buffered by the durable
          // sink and committed once per request — including on the refusals,
          // which are the rows an operator most wants.
          await server.flushAudit(context);
        }
      });
    },
  };
}
