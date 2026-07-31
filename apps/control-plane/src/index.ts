/**
 * `ferrogate-control-plane` Worker — the `/admin/v1/*` control plane.
 *
 * Replaces `ferrogate-admin` + `ferrogate-auth-service` +
 * `ferrogate-control-plane-client` (server side) + the `d1-proxy` Worker. Hono
 * over a D1 control-plane store, with Secrets Store for credentials.
 */
import { Hono } from "hono";
import { PUBLIC_API_MAJOR } from "@ferrogate/core";

const app = new Hono();

app.get("/health", (c) => c.json({ ok: true }));
app.get("/version", (c) => c.json({ api: PUBLIC_API_MAJOR }));

// Route groups this Worker will own:
//   /admin/v1/*     canonical control plane (tenancy, IAM, config, agents,
//                   workers, MCP, guardrails, assets, billing, evidence, ops)
//   /control/v1/*   alias folded to /admin/v1/* (canonicalize_alias_path)
//   /v1/admin/*     console identity (register/login/refresh/logout/me/team)
//   /v1/auth/*      resolve-api-key, authorize (RBAC)
//   /scim/v2/*      SCIM 2.0 provisioning

export default app;
