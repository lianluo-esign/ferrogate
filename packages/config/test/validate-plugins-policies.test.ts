/**
 * Table-driven port checks for the plugin/extension and policy-surface
 * validators of `Config::validate()` (`validate_plugins` + its manifest,
 * permission, secret-config and builtin-shape helpers; `validate_agent_workflows`;
 * `validate_prompt_templates`; `validate_skill_packages`; `validate_guardrails`),
 * plus `materialize_skill_package_resources[_with_previous]`.
 *
 * Every rejection case asserts the EXACT `field <path>: <reason>`.
 */
import { describe, expect, test } from "vitest";
import { configSchema } from "../src/schema/config.js";
import {
  materializeSkillPackageResources,
  materializeSkillPackageResourcesWithPrevious,
  validateConfig,
} from "../src/validate.js";

function firstError(raw: Record<string, unknown>): string {
  const config = configSchema.parse(raw);
  try {
    validateConfig(config);
  } catch (error) {
    return error instanceof Error ? error.message : String(error);
  }
  throw new Error("expected validateConfig to reject this config, but it passed");
}

function expectAccepted(raw: Record<string, unknown>): void {
  validateConfig(configSchema.parse(raw));
}

const echoPlugin = (extra: Record<string, unknown> = {}) => ({
  id: "tool.echo",
  kind: "tool_provider",
  ...extra,
});

describe("validate_plugins", () => {
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "a blank plugin id",
      { plugins: [echoPlugin({ id: " " })] },
      "field plugins[0].id: cannot be empty",
    ],
    [
      "a duplicate plugin id across [[plugins]] and [[extensions]]",
      { plugins: [echoPlugin()], extensions: [echoPlugin()] },
      "field extensions[0].id: duplicate plugin id tool.echo",
    ],
    [
      "a non-builtin source",
      { plugins: [echoPlugin({ source: "oci://registry/plugin" })] },
      "field plugins[0].source: only builtin plugins are supported in this phase",
    ],
    [
      "two enabled plugins of one kind at the same order",
      { plugins: [echoPlugin(), echoPlugin({ id: "tool.health_check" })] },
      "field plugins[1].order: duplicate enabled plugin order 100 for kind ToolProvider",
    ],
    [
      "a blank permission entry",
      { plugins: [echoPlugin({ permissions: { tools: ["search", " "] } })] },
      "field plugins[0].permissions.tools[1]: cannot be empty",
    ],
    [
      "a duplicated permission entry",
      { plugins: [echoPlugin({ permissions: { network: ["a.example", "a.example"] } })] },
      "field plugins[0].permissions.network[1]: duplicate permission value a.example",
    ],
    [
      "tenant-scoped config without permissions.tenant_scope",
      { plugins: [echoPlugin({ config: { tenant_allowlist: ["acme"] } })] },
      "field plugins[0].config: tenant/api-key/route scoped plugin config requires " +
        "permissions.tenant_scope = true",
    ],
    [
      "a scope allowlist that is not an array",
      { plugins: [echoPlugin({ config: { route_allowlist: "acme" } })] },
      "field plugins[0].config.route_allowlist: must be an array of strings",
    ],
    [
      "a non-string scope allowlist entry",
      { plugins: [echoPlugin({ config: { api_key_allowlist: [1] } })] },
      "field plugins[0].config.api_key_allowlist[0]: must be a string",
    ],
    [
      "secret-shaped config without permissions.secrets",
      { plugins: [echoPlugin({ config: { api_token: "t0ps3cret" } })] },
      "field plugins[0].config.api_token: secret-shaped plugin config requires permissions.secrets = true",
    ],
    [
      "secret-shaped config NESTED inside an array (path is reported in full)",
      { plugins: [echoPlugin({ config: { upstreams: [{ url: "x" }, { password: "hunter2" }] } })] },
      "field plugins[0].config.upstreams.1.password: secret-shaped plugin config requires " +
        "permissions.secrets = true",
    ],
    [
      "a non-semver plugin version",
      { plugins: [echoPlugin({ version: "1.0" })] },
      "field plugins[0].version: must be a semantic version",
    ],
    [
      "a non-semver compatibility bound",
      { plugins: [echoPlugin({ compatibility: { min_gateway_version: "next" } })] },
      "field plugins[0].compatibility.min_gateway_version: must be a semantic version",
    ],
    [
      "an inverted compatibility range",
      {
        plugins: [
          echoPlugin({ compatibility: { min_gateway_version: "2.0.0", max_gateway_version: "v1.9.0" } }),
        ],
      },
      "field plugins[0].compatibility: min_gateway_version must be <= max_gateway_version",
    ],
    [
      "a manifest capability with an illegal character",
      { plugins: [echoPlugin({ manifest: { capabilities: ["tool search"] } })] },
      "field plugins[0].manifest.capabilities[0]: must contain only letters, numbers, dot, " +
        "underscore, colon, or dash",
    ],
    [
      "a duplicated manifest hook",
      { plugins: [echoPlugin({ manifest: { hooks: ["on_request", "on_request"] } })] },
      "field plugins[0].manifest.hooks[1]: duplicate value on_request",
    ],
    [
      "a required tool permission the grant does not cover",
      {
        plugins: [
          echoPlugin({ manifest: { required_permissions: { tools: ["search"] } }, permissions: { tools: ["echo"] } }),
        ],
      },
      "field plugins[0].permissions.tools: must grant manifest.required_permissions.tools value search",
    ],
    [
      "a required boolean permission the grant does not cover",
      { plugins: [echoPlugin({ manifest: { required_permissions: { shell: true } } })] },
      "field plugins[0].permissions.shell: must be true because " +
        "manifest.required_permissions.shell is true",
    ],
    [
      "a manifest config_schema that is not an object",
      { plugins: [echoPlugin({ manifest: { config_schema: "string" } })] },
      "field plugins[0].manifest.config_schema: must be an object",
    ],
    [
      "a builtin registered under the wrong kind",
      { plugins: [echoPlugin({ kind: "request_hook" })] },
      "field plugins[0].kind: tool.echo must be tool_provider",
    ],
    [
      "an audit-log sink registered as a tool provider",
      { plugins: [echoPlugin({ id: "event.audit_log" })] },
      "field plugins[0].kind: event.audit_log must be event_sink",
    ],
    [
      "mcp.http with no endpoint",
      { plugins: [echoPlugin({ id: "mcp.http" })] },
      "field plugins[0].config.endpoint: required for mcp.http",
    ],
    [
      "mcp.http over https (this phase is http-only)",
      { plugins: [echoPlugin({ id: "mcp.http", config: { endpoint: "https://mcp.internal/rpc" } })] },
      "field plugins[0].config.endpoint: mcp.http supports http endpoints only in this phase",
    ],
    [
      "mcp.http whose host the network grant does not allow",
      { plugins: [echoPlugin({ id: "mcp.http", config: { endpoint: "http://mcp.internal/rpc" } })] },
      "field plugins[0].permissions.network: must allow MCP host mcp.internal",
    ],
    [
      "an unknown builtin that is enabled",
      { plugins: [echoPlugin({ id: "custom.thing" })] },
      "field plugins[0].id: unsupported builtin plugin custom.thing",
    ],
    [
      "a hook.noop variant under the wrong kind",
      { plugins: [echoPlugin({ id: "hook.noop.audit" })] },
      "field plugins[0].kind: hook.noop.audit must be request_hook",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("accepts the builtin plugin set, wildcards, and a disabled unknown plugin", () => {
    expectAccepted({
      plugins: [
        echoPlugin({
          permissions: { tools: ["*"], secrets: true, tenant_scope: true },
          config: { api_token: "env://T", tenant_allowlist: ["acme"] },
          manifest: {
            capabilities: ["tool:echo"],
            hooks: ["on_request"],
            required_permissions: { tools: ["echo"], secrets: true },
            config_schema: { type: "object" },
          },
          compatibility: { min_gateway_version: "0.1.0", max_gateway_version: "v1.0.0" },
        }),
        {
          id: "mcp.http",
          kind: "tool_provider",
          order: 200,
          config: { endpoint: "http://mcp.internal/rpc" },
          permissions: { network: ["mcp.internal"] },
        },
        { id: "hook.noop", kind: "request_hook" },
        { id: "event.audit_log", kind: "event_sink" },
        { id: "custom.thing", kind: "request_hook", enabled: false, order: 900 },
      ],
    });
  });
});

describe("validate_agent_workflows", () => {
  const base = {
    providers: [{ name: "openai", base_url: "https://api.openai.com/v1" }],
    models: [{ name: "gpt", provider: "openai", provider_model: "gpt-4o" }],
    plugins: [{ id: "tool.echo", kind: "tool_provider", permissions: { tools: ["echo"] } }],
  };
  const workflow = (extra: Record<string, unknown> = {}) => ({
    id: "w",
    name: "w",
    nodes: [{ id: "n1", kind: "model", model: "gpt" }],
    ...extra,
  });
  const withWorkflows = (workflows: Record<string, unknown>[]) => ({
    ...base,
    agent_workflows: workflows,
  });
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "a blank workflow id",
      withWorkflows([workflow({ id: " " })]),
      "field agent_workflows[0].id: cannot be empty",
    ],
    [
      "a duplicate id/version pair",
      withWorkflows([workflow(), workflow()]),
      "field agent_workflows[1]: duplicate workflow id/version w@1",
    ],
    [
      "a zero version",
      withWorkflows([workflow({ version: 0 })]),
      "field agent_workflows[0].version: must be greater than zero",
    ],
    [
      "a workflow with no nodes",
      withWorkflows([workflow({ nodes: [] })]),
      "field agent_workflows[0].nodes: at least one node is required",
    ],
    [
      "a workflow naming an unknown api key",
      withWorkflows([workflow({ api_key_ids: ["ghost"] })]),
      "field agent_workflows[0].api_key_ids: workflow w references unknown api key ghost",
    ],
    [
      "a zero max_model_calls budget",
      withWorkflows([workflow({ max_model_calls: 0 })]),
      "field agent_workflows[0].max_model_calls: must be greater than zero",
    ],
    [
      "a zero node token budget",
      withWorkflows([workflow({ nodes: [{ id: "n1", kind: "model", token_budget: 0 }] })]),
      "field agent_workflows[0].nodes[0].token_budget: must be greater than zero",
    ],
    [
      "a duplicate node id",
      withWorkflows([
        workflow({ nodes: [{ id: "n1", kind: "model" }, { id: "n1", kind: "checkpoint" }] }),
      ]),
      "field agent_workflows[0].nodes[1].id: duplicate node id n1",
    ],
    [
      "a node naming an unknown model",
      withWorkflows([workflow({ nodes: [{ id: "n1", kind: "model", model: "ghost" }] })]),
      "field agent_workflows[0].nodes[0].model: workflow w references unknown model ghost",
    ],
    [
      "a node naming an unknown provider",
      withWorkflows([workflow({ nodes: [{ id: "n1", kind: "model", providers: ["ghost"] }] })]),
      "field agent_workflows[0].nodes[0].providers: workflow w references unknown provider ghost",
    ],
    [
      "a model node that declares a tool",
      withWorkflows([workflow({ nodes: [{ id: "n1", kind: "model", tool: "echo" }] })]),
      "field agent_workflows[0].nodes[0].tool: only tool nodes may declare a tool",
    ],
    [
      "a tool node that declares providers",
      withWorkflows([
        workflow({ nodes: [{ id: "n1", kind: "tool", tool: "echo", providers: ["openai"] }] }),
      ]),
      "field agent_workflows[0].nodes[0].providers: only model nodes may declare providers",
    ],
    [
      "a tool node with no tool",
      withWorkflows([workflow({ nodes: [{ id: "n1", kind: "tool" }] })]),
      "field agent_workflows[0].nodes[0].tool: tool node n1 must declare a tool",
    ],
    [
      "a tool node naming a tool nothing provides",
      withWorkflows([workflow({ nodes: [{ id: "n1", kind: "tool", tool: "ghost" }] })]),
      "field agent_workflows[0].nodes[0].tool: workflow w references unknown tool ghost",
    ],
    [
      "a router node that declares providers",
      withWorkflows([workflow({ nodes: [{ id: "n1", kind: "router", providers: ["openai"] }] })]),
      "field agent_workflows[0].nodes[0].providers: only model nodes may declare providers",
    ],
    [
      "an edge from an unknown node",
      withWorkflows([workflow({ edges: [{ from: "ghost", to: "n1" }] })]),
      "field agent_workflows[0].edges[0].from: unknown node ghost",
    ],
    [
      "an edge to an unknown node",
      withWorkflows([workflow({ edges: [{ from: "n1", to: "ghost" }] })]),
      "field agent_workflows[0].edges[0].to: unknown node ghost",
    ],
    [
      "a blank edge condition",
      withWorkflows([workflow({ edges: [{ from: "n1", to: "n1", condition: " " }] })]),
      "field agent_workflows[0].edges[0].condition: cannot be empty",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("accepts model + tool nodes wired to real models, providers and tools", () => {
    expectAccepted(
      withWorkflows([
        workflow({
          nodes: [
            { id: "n1", kind: "model", model: "gpt", providers: ["openai"] },
            { id: "n2", kind: "tool", tool: "echo" },
          ],
          edges: [{ from: "n1", to: "n2", condition: "ok" }],
        }),
        workflow({ version: 2 }),
      ]),
    );
  });

  test("an MCP server's tools are addressable as <server>-<tool>", () => {
    expectAccepted({
      ...base,
      mcp_servers: [{ name: "srv", transport: "stdio", command: "/usr/bin/srv", tools_to_execute: ["fetch"] }],
      agent_workflows: [workflow({ nodes: [{ id: "n1", kind: "tool", tool: "srv-fetch" }] })],
    });
  });
});

describe("validate_prompt_templates", () => {
  const base = {
    providers: [{ name: "openai", base_url: "https://api.openai.com/v1" }],
    models: [{ name: "gpt", provider: "openai", provider_model: "gpt-4o" }],
  };
  const template = (extra: Record<string, unknown> = {}) => ({
    id: "t",
    name: "t",
    model: "gpt",
    versions: [{ messages: [{ role: "user", content: "hello" }] }],
    ...extra,
  });
  const withTemplates = (templates: Record<string, unknown>[]) => ({
    ...base,
    prompt_templates: templates,
  });
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "a duplicate template id",
      withTemplates([template(), template()]),
      "field prompt_templates[1].id: duplicate prompt template id t",
    ],
    [
      "a template on an unknown model",
      withTemplates([template({ model: "ghost" })]),
      "field prompt_templates[0].model: prompt template t references unknown model ghost",
    ],
    [
      "a template with no versions",
      withTemplates([template({ versions: [] })]),
      "field prompt_templates[0].versions: at least one version is required",
    ],
    [
      "a variable name with an illegal character",
      withTemplates([template({ variables: [{ name: "user name" }] })]),
      "field prompt_templates[0].variables[0].name: must use letters, numbers, _, or -",
    ],
    [
      "a duplicate variable",
      withTemplates([template({ variables: [{ name: "who" }, { name: "who" }] })]),
      "field prompt_templates[0].variables[1].name: duplicate variable who",
    ],
    [
      "an empty variable default",
      withTemplates([template({ variables: [{ name: "who", default: "" }] })]),
      "field prompt_templates[0].variables[0].default: cannot be empty",
    ],
    [
      "a zero revision",
      withTemplates([
        template({ versions: [{ revision: 0, messages: [{ role: "user", content: "hi" }] }] }),
      ]),
      "field prompt_templates[0].versions[0].revision: must be greater than zero",
    ],
    [
      "a duplicate revision",
      withTemplates([
        template({
          versions: [
            { revision: 1, messages: [{ role: "user", content: "hi" }] },
            { revision: 1, messages: [{ role: "user", content: "hi" }] },
          ],
        }),
      ]),
      "field prompt_templates[0].versions[1].revision: duplicate revision 1",
    ],
    [
      "a version with no messages",
      withTemplates([template({ versions: [{ messages: [] }] })]),
      "field prompt_templates[0].versions[0].messages: at least one message is required",
    ],
    [
      "an unsupported message role",
      withTemplates([template({ versions: [{ messages: [{ role: "function", content: "hi" }] }] })]),
      "field prompt_templates[0].versions[0].messages[0].role: must be system, developer, user, " +
        "assistant, or tool",
    ],
    [
      "a blank message body",
      withTemplates([template({ versions: [{ messages: [{ role: "user", content: "  " }] }] })]),
      "field prompt_templates[0].versions[0].messages[0].content: cannot be empty",
    ],
    [
      "an unclosed prompt variable",
      withTemplates([
        template({ versions: [{ messages: [{ role: "user", content: "hi {{who" }] }] }),
      ]),
      "field prompt_templates[0].versions[0].messages[0].content: unclosed prompt variable",
    ],
    [
      "an invalid prompt variable name",
      withTemplates([
        template({ versions: [{ messages: [{ role: "user", content: "hi {{who!}}" }] }] }),
      ]),
      "field prompt_templates[0].versions[0].messages[0].content: invalid prompt variable name who!",
    ],
    [
      "a prompt variable that is not declared",
      withTemplates([
        template({ versions: [{ messages: [{ role: "user", content: "hi {{who}}" }] }] }),
      ]),
      "field prompt_templates[0].versions[0].messages[0].content: unknown prompt variable who",
    ],
    [
      "a temperature outside [0, 2]",
      withTemplates([
        template({ versions: [{ temperature: 2.5, messages: [{ role: "user", content: "hi" }] }] }),
      ]),
      "field prompt_templates[0].versions[0].temperature: must be between 0 and 2",
    ],
    [
      "a top_p outside [0, 1]",
      withTemplates([
        template({ versions: [{ top_p: 1.5, messages: [{ role: "user", content: "hi" }] }] }),
      ]),
      "field prompt_templates[0].versions[0].top_p: must be between 0 and 1",
    ],
    [
      "a zero max_tokens",
      withTemplates([
        template({ versions: [{ max_tokens: 0, messages: [{ role: "user", content: "hi" }] }] }),
      ]),
      "field prompt_templates[0].versions[0].max_tokens: must be greater than zero",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("accepts a template whose placeholders are all declared", () => {
    expectAccepted(
      withTemplates([
        template({
          variables: [{ name: "who" }, { name: "tone-1", default: "warm" }],
          versions: [
            {
              revision: 2,
              temperature: 0,
              top_p: 1,
              max_tokens: 512,
              messages: [
                { role: "system", content: "be {{ tone-1 }}" },
                { role: "user", content: "hello {{who}}, {{who}}" },
              ],
            },
          ],
        }),
      ]),
    );
  });
});

describe("validate_skill_packages", () => {
  const base = {
    plugins: [{ id: "tool.echo", kind: "tool_provider", permissions: { tools: ["echo"] } }],
  };
  const pkg = (extra: Record<string, unknown> = {}) => ({
    id: "pkg",
    name: "pkg",
    capabilities: [{ kind: "plugin", id: "tool.echo" }],
    ...extra,
  });
  const withPackages = (packages: Record<string, unknown>[]) => ({
    ...base,
    skill_packages: packages,
  });
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "a duplicate package id",
      withPackages([pkg(), pkg()]),
      "field skill_packages[1].id: duplicate skill package id pkg",
    ],
    [
      "a blank version",
      withPackages([pkg({ version: " " })]),
      "field skill_packages[0].version: cannot be empty",
    ],
    [
      "a package with no capabilities",
      withPackages([pkg({ capabilities: [] })]),
      "field skill_packages[0].capabilities: at least one capability is required",
    ],
    [
      "a package naming an unknown api key",
      withPackages([pkg({ api_key_ids: ["ghost"] })]),
      "field skill_packages[0].api_key_ids: skill package pkg references unknown api key ghost",
    ],
    [
      "a duplicated package permission",
      withPackages([pkg({ permissions: { tools: ["echo", "echo"] } })]),
      "field skill_packages[0].permissions.tools[1]: duplicate permission value echo",
    ],
    [
      "a blank compatible agent runtime",
      withPackages([pkg({ compatibility: { agent_runtimes: [" "] } })]),
      "field skill_packages[0].compatibility.agent_runtimes[0]: cannot be empty",
    ],
    [
      "an embedded plugin that is not declared as a capability",
      withPackages([
        pkg({ resources: { plugins: [{ id: "tool.embedded", kind: "tool_provider" }] } }),
      ]),
      "field skill_packages[0].resources.plugins[0].id: embedded plugin tool.embedded must be " +
        "declared as a plugin capability",
    ],
    [
      "an embedded MCP server that is not declared as a capability",
      withPackages([
        pkg({
          resources: {
            mcp_servers: [{ name: "srv", transport: "stdio", command: "/usr/bin/srv", tools_to_execute: ["fetch"] }],
          },
        }),
      ]),
      "field skill_packages[0].resources.mcp_servers[0].name: embedded MCP server srv must be " +
        "declared as an MCP server capability",
    ],
    [
      "a capability naming an unknown plugin",
      withPackages([pkg({ capabilities: [{ kind: "plugin", id: "ghost" }] })]),
      "field skill_packages[0].capabilities[0].id: skill package pkg references unknown plugin ghost",
    ],
    [
      "a capability naming an unknown tool",
      withPackages([pkg({ capabilities: [{ kind: "tool", id: "ghost" }] })]),
      "field skill_packages[0].capabilities[0].id: skill package pkg references unknown tool ghost",
    ],
    [
      "a capability naming an unknown prompt template",
      withPackages([pkg({ capabilities: [{ kind: "prompt_template", id: "ghost" }] })]),
      "field skill_packages[0].capabilities[0].id: skill package pkg references unknown prompt " +
        "template ghost",
    ],
    [
      "a capability naming an unknown agent workflow",
      withPackages([pkg({ capabilities: [{ kind: "agent_workflow", id: "ghost" }] })]),
      "field skill_packages[0].capabilities[0].id: skill package pkg references unknown agent " +
        "workflow ghost",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("accepts a package whose embedded resources are all declared", () => {
    expectAccepted(
      withPackages([
        pkg({
          capabilities: [
            { kind: "plugin", id: "tool.echo" },
            { kind: "tool", id: "echo" },
            { kind: "mcp_server", id: "srv" },
            { kind: "mcp_tool", id: "srv-fetch" },
          ],
          resources: {
            mcp_servers: [{ name: "srv", transport: "stdio", command: "/usr/bin/srv", tools_to_execute: ["fetch"] }],
          },
        }),
      ]),
    );
  });
});

describe("materialize_skill_package_resources", () => {
  test("an enabled package's resources replace the top-level entries it owns", () => {
    const config = configSchema.parse({
      plugins: [{ id: "tool.echo", kind: "tool_provider", order: 1 }],
      mcp_servers: [{ name: "srv", transport: "stdio", tools_to_execute: ["stale"] }],
      skill_packages: [
        {
          id: "pkg",
          name: "pkg",
          capabilities: [{ kind: "plugin", id: "tool.echo" }],
          resources: {
            plugins: [{ id: "tool.echo", kind: "tool_provider", order: 42 }],
            mcp_servers: [{ name: "srv", transport: "stdio", tools_to_execute: ["fresh"] }],
          },
        },
      ],
    });
    materializeSkillPackageResources(config);
    expect(config.plugins).toHaveLength(1);
    expect(config.plugins[0]!.order).toBe(42);
    expect(config.mcp_servers).toHaveLength(1);
    expect(config.mcp_servers[0]!.tools_to_execute).toEqual(["fresh"]);
  });

  test("a DISABLED package's resources are evicted, not re-projected", () => {
    const config = configSchema.parse({
      plugins: [{ id: "tool.echo", kind: "tool_provider" }],
      skill_packages: [
        {
          id: "pkg",
          name: "pkg",
          enabled: false,
          capabilities: [{ kind: "plugin", id: "tool.echo" }],
          resources: { plugins: [{ id: "tool.echo", kind: "tool_provider", order: 42 }] },
        },
      ],
    });
    materializeSkillPackageResources(config);
    expect(config.plugins).toEqual([]);
  });

  test("resources a PREVIOUS package owned are evicted too (uninstall path)", () => {
    const previous = configSchema.parse({
      skill_packages: [
        {
          id: "old",
          name: "old",
          capabilities: [{ kind: "agent_workflow", id: "w" }],
          resources: {
            agent_workflows: [{ id: "w", name: "w", version: 3, nodes: [{ id: "n", kind: "model" }] }],
          },
        },
      ],
    }).skill_packages;
    const config = configSchema.parse({
      agent_workflows: [{ id: "w", name: "w", version: 3, nodes: [{ id: "n", kind: "model" }] }],
    });
    materializeSkillPackageResourcesWithPrevious(config, previous);
    expect(config.agent_workflows).toEqual([]);
  });
});

describe("validate_guardrails", () => {
  const base = {
    providers: [{ name: "openai", base_url: "https://api.openai.com/v1" }],
    models: [{ name: "gpt", provider: "openai", provider_model: "gpt-4o" }],
  };
  const guardrail = (extra: Record<string, unknown> = {}) => ({
    id: "g",
    name: "g",
    keywords: ["secret"],
    ...extra,
  });
  const withGuardrails = (guardrails: Record<string, unknown>[]) => ({ ...base, guardrails });
  const cases: [string, Record<string, unknown>, string][] = [
    [
      "a duplicate guardrail id",
      withGuardrails([guardrail(), guardrail()]),
      "field guardrails[1].id: duplicate guardrail id g",
    ],
    [
      "an empty source list",
      withGuardrails([guardrail({ sources: [] })]),
      "field guardrails[0].sources: must contain unique content sources",
    ],
    [
      "a duplicated content source",
      withGuardrails([guardrail({ sources: ["user", "user"] })]),
      "field guardrails[0].sources: must contain unique content sources",
    ],
    [
      "a rule with no detector at all",
      withGuardrails([guardrail({ keywords: [] })]),
      "field guardrails[0]: at least one keyword, regex, max_input_bytes, or provider is required",
    ],
    [
      "a blank keyword",
      withGuardrails([guardrail({ keywords: ["ok", " "] })]),
      "field guardrails[0].keywords[1]: cannot be empty",
    ],
    [
      "an uncompilable regex",
      withGuardrails([guardrail({ keywords: [], regex: ["("] })]),
      "field guardrails[0].regex[0]: invalid regex",
    ],
    [
      "a zero max_input_bytes",
      withGuardrails([guardrail({ max_input_bytes: 0 })]),
      "field guardrails[0].max_input_bytes: must be greater than zero",
    ],
    [
      "a guardrail naming an unknown model",
      withGuardrails([guardrail({ models: ["ghost"] })]),
      "field guardrails[0].models: guardrail g references unknown model ghost",
    ],
    [
      "redaction at the request stage",
      withGuardrails([guardrail({ stage: "request", effect: "redact" })]),
      "field guardrails[0].effect: request guardrails support deny only",
    ],
    [
      "a max-input-length rule at the response stage",
      withGuardrails([guardrail({ stage: "response", max_input_bytes: 100 })]),
      "field guardrails[0].max_input_bytes: max input length guardrails apply to request stage only",
    ],
    [
      "presidio-only knobs on another provider",
      withGuardrails([guardrail({ provider_language: "en" })]),
      "field guardrails[0].provider_language/provider_entities: only valid when provider is presidio",
    ],
    [
      "semantic-only knobs on a non-semantic provider",
      withGuardrails([guardrail({ provider_score_threshold_percent: 50 })]),
      "field guardrails[0].provider_score_threshold_percent/provider_fingerprint_secret_ref: only " +
        "valid when provider is presidio or llm_guard_prompt_injection",
    ],
    [
      "a detector endpoint with no detector provider",
      withGuardrails([guardrail({ provider_endpoint: "https://detect.example" })]),
      "field guardrails[0].provider_endpoint: only valid when provider is custom_http",
    ],
    [
      "detector runtime knobs with no detector provider",
      withGuardrails([guardrail({ provider_max_retries: 1 })]),
      "field guardrails[0].provider_*: detector runtime settings are only valid when provider is custom_http",
    ],
    [
      "custom_http with no endpoint",
      withGuardrails([guardrail({ provider: "custom_http" })]),
      "field guardrails[0].provider_endpoint: required when provider is custom_http",
    ],
    [
      "an unparsable detector endpoint",
      withGuardrails([guardrail({ provider: "custom_http", provider_endpoint: "detect.example" })]),
      "field guardrails[0].provider_endpoint: invalid URL",
    ],
    [
      "a detector endpoint carrying credentials",
      withGuardrails([
        guardrail({ provider: "custom_http", provider_endpoint: "https://user:pw@detect.example" }),
      ]),
      "field guardrails[0].provider_endpoint: guardrail detector endpoint must be an http(s) URL " +
        "without credentials, query, or fragment",
    ],
    [
      "a private-network detector endpoint without the explicit opt-in (SSRF)",
      withGuardrails([
        guardrail({ provider: "custom_http", provider_endpoint: "http://169.254.169.254/latest" }),
      ]),
      "field guardrails[0].provider_endpoint: guardrail detector private-network endpoint " +
        "requires explicit allow_private_network",
    ],
    [
      "a detector secret reference that is not a secret ref",
      withGuardrails([
        guardrail({
          provider: "custom_http",
          provider_endpoint: "https://detect.example",
          provider_secret_ref: "raw",
        }),
      ]),
      "field guardrails[0].provider_secret_ref: unsupported secret reference scheme " +
        "(expected env://, vault://, cf://, or byok://): raw",
    ],
    [
      "more than one detector retry",
      withGuardrails([
        guardrail({
          provider: "custom_http",
          provider_endpoint: "https://detect.example",
          provider_max_retries: 2,
        }),
      ]),
      "field guardrails[0].provider_max_retries: must be zero or one",
    ],
    [
      "fallback_detector with nothing to fall back to",
      withGuardrails([
        guardrail({
          keywords: [],
          provider: "custom_http",
          provider_endpoint: "https://detect.example",
          provider_on_error: "fallback_detector",
        }),
      ]),
      "field guardrails[0].provider_on_error: fallback_detector requires a keyword, regex, or " +
        "max_input_bytes fallback",
    ],
    [
      "presidio with no fingerprint secret",
      withGuardrails([
        guardrail({ provider: "presidio", provider_endpoint: "https://presidio.example" }),
      ]),
      "field guardrails[0].provider_fingerprint_secret_ref: required when provider is presidio or " +
        "llm_guard_prompt_injection",
    ],
    [
      "a score threshold above 100",
      withGuardrails([
        guardrail({
          provider: "llm_guard_prompt_injection",
          provider_endpoint: "https://llmguard.example",
          provider_fingerprint_secret_ref: "env://FP",
          provider_score_threshold_percent: 101,
        }),
      ]),
      "field guardrails[0].provider_score_threshold_percent: must be between 0 and 100",
    ],
    [
      "an empty presidio entity list",
      withGuardrails([
        guardrail({
          provider: "presidio",
          provider_endpoint: "https://presidio.example",
          provider_fingerprint_secret_ref: "env://FP",
          provider_entities: [],
        }),
      ]),
      "field guardrails[0].provider_entities: entries must be non-empty",
    ],
    [
      "a zero detector timeout",
      withGuardrails([guardrail({ provider_timeout_ms: 0 })]),
      "field guardrails[0].provider_timeout_ms: must be greater than zero",
    ],
    [
      "a detector timeout above the 30s ceiling",
      withGuardrails([guardrail({ provider_timeout_ms: 30001 })]),
      "field guardrails[0].provider_timeout_ms: must not exceed 30000 milliseconds",
    ],
  ];
  test.each(cases)("rejects %s", (_name, raw, expected) => {
    expect(firstError(raw)).toBe(expected);
  });

  test("accepts keyword, custom_http and presidio guardrails", () => {
    expectAccepted(
      withGuardrails([
        guardrail({ regex: ["^sk-[a-z0-9]+$"], max_input_bytes: 4096, models: ["gpt"], providers: ["openai"] }),
        guardrail({
          id: "g2",
          provider: "custom_http",
          provider_endpoint: "https://detect.example/scan",
          provider_secret_ref: "env://DETECTOR_TOKEN",
          provider_on_error: "fallback_detector",
        }),
        guardrail({
          id: "g3",
          stage: "response",
          effect: "redact",
          keywords: [],
          provider: "presidio",
          provider_endpoint: "https://presidio.example",
          provider_fingerprint_secret_ref: "vault://secret/data/fp#key",
          provider_language: "en",
          provider_entities: ["EMAIL_ADDRESS"],
          provider_score_threshold_percent: 80,
        }),
        guardrail({
          id: "g4",
          provider: "custom_http",
          provider_endpoint: "http://127.0.0.1:9100/scan",
          provider_allow_private_network: true,
        }),
      ]),
    );
  });
});

/**
 * `guardrails[].regex` engine parity — the leg a previous wave left as a
 * PORT-TODO ("Rust compiles with the `regex` crate, which rejects backreferences
 * and lookaround that JS RegExp accepts"), now CLOSED by
 * `usesRegexCrateUnsupportedSyntax`.
 *
 * The Rust `regex` crate is a finite-automaton engine, so it refuses the two
 * backtracking-only constructs. Accepting them here would let a config that
 * Rust REFUSES at load run with different match semantics — a detector that
 * silently stops detecting. Rust's observable message for every rejection is the
 * outermost anyhow context, `invalid regex`, at `guardrails[i].regex[j]`.
 */
describe("validate_guardrails: regex-crate accept-set parity", () => {
  const withRegex = (...patterns: string[]) => ({
    guardrails: [{ id: "g", name: "g", keywords: [], regex: patterns }],
  });

  const rejected: [string, string][] = [
    ["a \\1 backreference", "(a)\\1"],
    ["a \\9 backreference", "(a)(b)(c)(d)(e)(f)(g)(h)(i)\\9"],
    ["a \\k<name> named backreference", "(?<x>a)\\k<x>"],
    ["positive lookahead", "foo(?=bar)"],
    ["negative lookahead", "foo(?!bar)"],
    ["positive lookbehind", "(?<=foo)bar"],
    ["negative lookbehind", "(?<!foo)bar"],
  ];
  test.each(rejected)("rejects %s at the exact field path", (_name, pattern) => {
    expect(firstError(withRegex(pattern))).toBe("field guardrails[0].regex[0]: invalid regex");
  });

  test("attributes the failure to the offending regex INDEX, not the first one", () => {
    expect(firstError(withRegex("^ok$", "a(?=b)"))).toBe(
      "field guardrails[0].regex[1]: invalid regex",
    );
  });

  const accepted: [string, string][] = [
    // `\\1` is an escaped backslash then a literal `1` — not a backreference.
    ["an escaped backslash before a digit", "\\\\1"],
    // Inside a character class `(`, `?`, `=` and `!` are literals.
    ["lookaround-shaped characters inside a class", "[(?=!<]+"],
    // `(?<name>...)` is a NAMED GROUP, which the regex crate supports (>=1.9).
    ["a named capture group", "(?<word>[a-z]+)"],
    ["a non-capturing group", "(?:abc|def)"],
    ["an ordinary anchored pattern", "^sk-[a-zA-Z0-9]{10,}$"],
  ];
  test.each(accepted)("accepts %s", (_name, pattern) => {
    expectAccepted(withRegex(pattern));
  });

  /**
   * The RESIDUAL, OPPOSITE-DIRECTION gap, pinned rather than papered over: a few
   * patterns the `regex` crate accepts are rejected by JS `RegExp`, so this port
   * is strictly stricter there. That direction fails CLOSED (a config is refused
   * at load, never silently mis-matched at runtime), which is why it is left as a
   * divergence instead of being emulated.
   */
  const strictlyStricterThanRust: [string, string][] = [
    ["an inline-flag group `(?i)`", "(?i)abc"],
    ["the `(?P<name>...)` named-group spelling", "(?P<word>[a-z]+)"],
  ];
  test.each(strictlyStricterThanRust)(
    "is stricter than the regex crate for %s (fails closed)",
    (_name, pattern) => {
      expect(firstError(withRegex(pattern))).toBe("field guardrails[0].regex[0]: invalid regex");
    },
  );
});
