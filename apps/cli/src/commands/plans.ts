/**
 * The legacy gateway-direct `plans` verbs: `create`, `list`, `assign`.
 *
 * Port of `ferrogate-cli::plans_cli` (inventory-edge-control.md §1.1). Like
 * `assets`, these use `--gateway-url` + `--api-key` rather than a context, and
 * coexist with the registry-driven `ctl plans` / `ctl tenant-accounts` paths.
 */
import type { JsonValue } from "@ferrogate/core";
import type { Args } from "../args.js";
import { exitClassFromHttpStatus, exitCode } from "../errors.js";
import { renderJson } from "../output.js";
import type { BinaryResponse } from "../ports.js";
import type { CliRuntime, CommandNode } from "../runtime.js";
import { CONNECTION_FLAGS, connectionContext } from "./assets.js";

function emit(runtime: CliRuntime, response: BinaryResponse, what: string): number {
  const text = new TextDecoder().decode(response.bytes);
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

function jsonBody(value: JsonValue): Uint8Array {
  return new TextEncoder().encode(JSON.stringify(value));
}

function optionalNumber(args: Args, name: string): number | null {
  const value = args.getNumber(name);
  return value === undefined ? null : value;
}

export const plansCommand: CommandNode = {
  name: "plans",
  about: "Manage subscription plans on a gateway (see also `ctl plans`)",
  sub: [
    {
      name: "create",
      about: "Create a sellable subscription plan",
      flags: [
        ...CONNECTION_FLAGS,
        {
          name: "id",
          kind: "string",
          valueName: "ID",
          help: "Explicit plan id (server-generated when omitted)",
        },
        { name: "name", kind: "string", valueName: "NAME", help: "Display name" },
        { name: "slug", kind: "string", valueName: "SLUG", help: "URL-safe slug" },
        { name: "mcp-enabled", kind: "boolean", help: "Feature: MCP" },
        {
          name: "self-hosted-workers-enabled",
          kind: "boolean",
          help: "Feature: self-hosted workers",
        },
        { name: "asset-hosting-enabled", kind: "boolean", help: "Feature: asset hosting" },
        { name: "extension-tools-enabled", kind: "boolean", help: "Feature: extension tools" },
        {
          name: "default-rpm-limit",
          kind: "number",
          valueName: "N",
          help: "Default requests/minute",
        },
        {
          name: "default-tpm-limit",
          kind: "number",
          valueName: "N",
          help: "Default tokens/minute",
        },
        {
          name: "default-monthly-budget-usd",
          kind: "number",
          valueName: "USD",
          help: "Default monthly budget",
        },
      ],
      run: async (runtime, args) => {
        const payload: Record<string, JsonValue> = {
          name: args.requireString("name"),
          slug: args.requireString("slug"),
          mcp_enabled: args.getBoolean("mcp-enabled"),
          self_hosted_workers_enabled: args.getBoolean("self-hosted-workers-enabled"),
          asset_hosting_enabled: args.getBoolean("asset-hosting-enabled"),
          extension_tools_enabled: args.getBoolean("extension-tools-enabled"),
          default_rpm_limit: optionalNumber(args, "default-rpm-limit"),
          default_tpm_limit: optionalNumber(args, "default-tpm-limit"),
          default_monthly_budget_usd: optionalNumber(args, "default-monthly-budget-usd"),
        };
        const id = args.getString("id");
        if (id !== undefined) payload.id = id;
        const response = await runtime.gatewayClient.send(
          {
            method: "POST",
            path: "/admin/v1/plans",
            query: [],
            contentType: "application/json",
            body: jsonBody(payload),
          },
          connectionContext(runtime, args),
        );
        return emit(runtime, response, "create plan");
      },
    },
    {
      name: "list",
      about: "List all plans",
      flags: CONNECTION_FLAGS,
      run: async (runtime, args) => {
        const response = await runtime.gatewayClient.send(
          { method: "GET", path: "/admin/v1/plans", query: [] },
          connectionContext(runtime, args),
        );
        return emit(runtime, response, "list plans");
      },
    },
    {
      name: "assign",
      about: "Assign a plan to a tenant",
      flags: [
        ...CONNECTION_FLAGS,
        { name: "tenant-id", kind: "string", valueName: "ID", help: "Target tenant" },
        { name: "plan-id", kind: "string", valueName: "ID", help: "Plan to assign" },
      ],
      run: async (runtime, args) => {
        const tenantId = args.requireString("tenant-id");
        const response = await runtime.gatewayClient.send(
          {
            method: "PATCH",
            path: `/admin/v1/tenant-accounts/${encodeURIComponent(tenantId)}`,
            query: [],
            contentType: "application/json",
            body: jsonBody({ plan_id: args.requireString("plan-id") }),
          },
          connectionContext(runtime, args),
        );
        return emit(runtime, response, "assign plan");
      },
    },
  ],
};
