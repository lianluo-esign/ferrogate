/**
 * Plugin/extension validators of `Config::validate()` (inventory §5.4):
 * `validate_plugins` and every free function it leans on (manifest + version
 * compatibility, required-vs-granted permissions, the secret-shaped-config and
 * tenant-scope permission gates, and the builtin-plugin shape table), plus the
 * skill-package resource materialization that runs before validation.
 *
 * Ported 1:1 from `config/validate.rs`. Rust reads plugin `config` as
 * `BTreeMap<String, toml::Value>`; the TS model is a JSON object, so key
 * iteration is SORTED here to keep `BTreeMap`'s deterministic "first offending
 * path" reporting.
 */
import type {
  AgentWorkflowPolicy,
  Config,
  ExtensionConfig,
  McpServerConfig,
  PromptTemplate,
  SkillPackage,
} from "../schema/index.js";
import {
  compareVersionParts,
  fail,
  isBlank,
  validateExtensionPermissionNames,
  validateOptionalPluginVersion,
  validatePluginManifestNames,
  validatePluginVersion,
} from "./helpers.js";

/** One `(section, index, plugin)` triple of `plugin_registrations_for_validation`. */
export interface PluginRegistration {
  section: "plugins" | "extensions";
  index: number;
  plugin: ExtensionConfig;
}

/** `Config::plugin_registrations()`: `[[plugins]]` then `[[extensions]]`. */
export function pluginRegistrations(config: Config): ExtensionConfig[] {
  return [...config.plugins, ...config.extensions];
}

/** `Config::plugin_registrations_for_validation()`. */
export function pluginRegistrationsForValidation(config: Config): PluginRegistration[] {
  return [
    ...config.plugins.map((plugin, index) => ({ section: "plugins" as const, index, plugin })),
    ...config.extensions.map((plugin, index) => ({
      section: "extensions" as const,
      index,
      plugin,
    })),
  ];
}

/** `validate_plugins`. */
export function validatePlugins(config: Config): void {
  const ids = new Set<string>();
  const enabledOrders = new Set<string>();

  for (const { section, index, plugin } of pluginRegistrationsForValidation(config)) {
    const at = (field: string) => `${section}[${index}].${field}`;
    if (isBlank(plugin.id)) fail(at("id"), "cannot be empty");
    if (ids.has(plugin.id)) fail(at("id"), `duplicate plugin id ${plugin.id}`);
    ids.add(plugin.id);
    if (isBlank(plugin.source)) fail(at("source"), "cannot be empty");
    if (plugin.source !== "builtin") {
      fail(at("source"), "only builtin plugins are supported in this phase");
    }
    if (plugin.enabled) {
      const orderKey = `${plugin.kind}\u0000${plugin.order}`;
      if (enabledOrders.has(orderKey)) {
        fail(
          at("order"),
          `duplicate enabled plugin order ${plugin.order} for kind ${debugExtensionKind(plugin.kind)}`,
        );
      }
      enabledOrders.add(orderKey);
    }

    validateExtensionPermissionNames(section, index, "permissions.tools", plugin.permissions.tools);
    validateExtensionPermissionNames(
      section,
      index,
      "permissions.network",
      plugin.permissions.network,
    );
    validatePluginTenantScopePermission(section, index, plugin);
    validatePluginSecretPermission(section, index, plugin);
    validatePluginManifest(section, index, plugin);
    validateBuiltinPluginShape(section, index, plugin);
  }
}

/** Rust prints the `ExtensionKind` variant with `{:?}` (`RequestHook`, ...). */
function debugExtensionKind(kind: ExtensionConfig["kind"]): string {
  switch (kind) {
    case "request_hook":
      return "RequestHook";
    case "tool_provider":
      return "ToolProvider";
    case "event_sink":
      return "EventSink";
  }
}

// --- secret-shaped plugin config -------------------------------------------

/** `is_plugin_secret_config_key`. */
function isPluginSecretConfigKey(key: string): boolean {
  const lower = key.toLowerCase();
  return ["secret", "token", "password", "credential", "api_key", "auth"].some((needle) =>
    lower.includes(needle),
  );
}

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

/** `first_secret_value_path`. */
function firstSecretValuePath(value: unknown): string | null {
  if (Array.isArray(value)) {
    for (let index = 0; index < value.length; index += 1) {
      const path = firstSecretValuePath(value[index]);
      if (path !== null) return `${index}.${path}`;
    }
    return null;
  }
  if (isPlainObject(value)) {
    for (const key of Object.keys(value).sort()) {
      if (isPluginSecretConfigKey(key)) return key;
      const path = firstSecretValuePath(value[key]);
      if (path !== null) return `${key}.${path}`;
    }
    return null;
  }
  return null;
}

/** `first_secret_config_path` (`BTreeMap` order → sorted keys). */
function firstSecretConfigPath(config: Record<string, unknown>): string | null {
  for (const key of Object.keys(config).sort()) {
    if (isPluginSecretConfigKey(key)) return key;
    const path = firstSecretValuePath(config[key]);
    if (path !== null) return `${key}.${path}`;
  }
  return null;
}

/** `validate_plugin_secret_permission`. */
export function validatePluginSecretPermission(
  section: string,
  index: number,
  plugin: ExtensionConfig,
): void {
  if (plugin.permissions.secrets) return;
  const path = firstSecretConfigPath(plugin.config);
  if (path !== null) {
    fail(
      `${section}[${index}].config.${path}`,
      "secret-shaped plugin config requires permissions.secrets = true",
    );
  }
}

/** `validate_plugin_tenant_scope_permission`. */
export function validatePluginTenantScopePermission(
  section: string,
  index: number,
  plugin: ExtensionConfig,
): void {
  let usesTenantScope = false;
  for (const field of ["tenant_allowlist", "api_key_allowlist", "route_allowlist"]) {
    const value = plugin.config[field];
    if (value === undefined) continue;
    if (!Array.isArray(value)) {
      fail(`${section}[${index}].config.${field}`, "must be an array of strings");
    }
    for (let valueIndex = 0; valueIndex < value.length; valueIndex += 1) {
      const entry = value[valueIndex];
      if (typeof entry !== "string") {
        fail(`${section}[${index}].config.${field}[${valueIndex}]`, "must be a string");
      }
      if (isBlank(entry)) {
        fail(`${section}[${index}].config.${field}[${valueIndex}]`, "cannot be empty");
      }
    }
    usesTenantScope ||= value.length > 0;
  }
  if (usesTenantScope && !plugin.permissions.tenant_scope) {
    fail(
      `${section}[${index}].config`,
      "tenant/api-key/route scoped plugin config requires permissions.tenant_scope = true",
    );
  }
}

// --- manifest ---------------------------------------------------------------

/** `permission_list_covers`. */
function permissionListCovers(granted: string[], required: string): boolean {
  return granted.some((value) => value === "*" || value === required);
}

/** `validate_required_bool_permission`. */
function validateRequiredBoolPermission(
  section: string,
  index: number,
  permission: string,
  required: boolean,
  granted: boolean,
): void {
  if (required && !granted) {
    fail(
      `${section}[${index}].permissions.${permission}`,
      `must be true because manifest.required_permissions.${permission} is true`,
    );
  }
}

/** `validate_plugin_required_permissions`. */
export function validatePluginRequiredPermissions(
  section: string,
  index: number,
  plugin: ExtensionConfig,
): void {
  const required = plugin.manifest.required_permissions;
  const granted = plugin.permissions;
  for (const tool of required.tools) {
    if (!permissionListCovers(granted.tools, tool)) {
      fail(
        `${section}[${index}].permissions.tools`,
        `must grant manifest.required_permissions.tools value ${tool}`,
      );
    }
  }
  for (const host of required.network) {
    if (!permissionListCovers(granted.network, host)) {
      fail(
        `${section}[${index}].permissions.network`,
        `must grant manifest.required_permissions.network value ${host}`,
      );
    }
  }
  validateRequiredBoolPermission(
    section,
    index,
    "filesystem",
    required.filesystem,
    granted.filesystem,
  );
  validateRequiredBoolPermission(section, index, "shell", required.shell, granted.shell);
  validateRequiredBoolPermission(
    section,
    index,
    "tenant_scope",
    required.tenant_scope,
    granted.tenant_scope,
  );
  validateRequiredBoolPermission(section, index, "secrets", required.secrets, granted.secrets);
  validateRequiredBoolPermission(
    section,
    index,
    "admin_mutation",
    required.admin_mutation,
    granted.admin_mutation,
  );
}

/** `validate_plugin_manifest`. */
export function validatePluginManifest(
  section: string,
  index: number,
  plugin: ExtensionConfig,
): void {
  validatePluginVersion(section, index, "version", plugin.version);
  validateOptionalPluginVersion(
    section,
    index,
    "compatibility.min_gateway_version",
    plugin.compatibility.min_gateway_version,
  );
  validateOptionalPluginVersion(
    section,
    index,
    "compatibility.max_gateway_version",
    plugin.compatibility.max_gateway_version,
  );
  const min = plugin.compatibility.min_gateway_version;
  const max = plugin.compatibility.max_gateway_version;
  if (min !== null && max !== null && compareVersionParts(min, max) > 0) {
    fail(
      `${section}[${index}].compatibility`,
      "min_gateway_version must be <= max_gateway_version",
    );
  }
  validatePluginManifestNames(
    section,
    index,
    "manifest.capabilities",
    plugin.manifest.capabilities,
  );
  validateExtensionPermissionNames(
    section,
    index,
    "manifest.required_permissions.tools",
    plugin.manifest.required_permissions.tools,
  );
  validateExtensionPermissionNames(
    section,
    index,
    "manifest.required_permissions.network",
    plugin.manifest.required_permissions.network,
  );
  validatePluginRequiredPermissions(section, index, plugin);
  validatePluginManifestNames(section, index, "manifest.hooks", plugin.manifest.hooks);
  const schema = plugin.manifest.config_schema;
  if (schema !== null && schema !== undefined && !isPlainObject(schema)) {
    fail(`${section}[${index}].manifest.config_schema`, "must be an object");
  }
}

// --- builtin plugin shapes --------------------------------------------------

/** `validate_builtin_plugin_shape`. */
/**
 * `http::Uri::authority()` on the RAW endpoint string: the substring between
 * `//` and the next `/`, `?` or `#`. `null` when the URI has no `//authority`
 * at all, or when that authority is empty — the two shapes whose `authority()`
 * Rust treats as absent/invalid and refuses.
 */
function authorityOf(uri: string): string | null {
  const schemeEnd = uri.indexOf("://");
  if (schemeEnd < 0) return null;
  const rest = uri.slice(schemeEnd + 3);
  const end = rest.search(/[/?#]/);
  const authority = end < 0 ? rest : rest.slice(0, end);
  return authority.length === 0 ? null : authority;
}

export function validateBuiltinPluginShape(
  section: string,
  index: number,
  plugin: ExtensionConfig,
): void {
  const at = (field: string) => `${section}[${index}].${field}`;
  switch (plugin.id) {
    case "tool.echo":
    case "tool.health_check": {
      if (plugin.kind !== "tool_provider") fail(at("kind"), `${plugin.id} must be tool_provider`);
      return;
    }
    case "mcp.http": {
      if (plugin.kind !== "tool_provider") fail(at("kind"), "mcp.http must be tool_provider");
      const endpoint = plugin.config.endpoint;
      if (typeof endpoint !== "string") fail(at("config.endpoint"), "required for mcp.http");
      let url: URL;
      try {
        url = new URL(endpoint);
      } catch {
        fail(at("config.endpoint"), "invalid URI");
      }
      if (url.protocol !== "http:") {
        fail(at("config.endpoint"), "mcp.http supports http endpoints only in this phase");
      }
      // Rust reads the host off `http::Uri::authority()`, which is absent when
      // the endpoint carries no authority component ("http:///rpc",
      // "http:/rpc") — so Rust REFUSES those. The WHATWG `URL` parser used here
      // does not agree: it re-parses "http:///rpc" as "http://rpc/" and hands
      // back the FIRST PATH SEGMENT as the hostname, which would (a) make this
      // branch structurally dead and (b) let a hostless endpoint through as a
      // host named after a path segment. The authority is therefore taken from
      // the RAW string, exactly where Rust takes it, before trusting `url`.
      const host = authorityOf(endpoint) === null ? "" : url.hostname;
      if (host.length === 0) fail(at("config.endpoint"), "must include host");
      if (!plugin.permissions.network.some((allowed) => allowed === "*" || allowed === host)) {
        fail(at("permissions.network"), `must allow MCP host ${host}`);
      }
      return;
    }
    case "event.audit_log": {
      if (plugin.kind !== "event_sink") fail(at("kind"), "event.audit_log must be event_sink");
      return;
    }
    default: {
      if (plugin.id === "hook.noop" || plugin.id.startsWith("hook.noop.")) {
        if (plugin.kind !== "request_hook") fail(at("kind"), `${plugin.id} must be request_hook`);
        return;
      }
      if (plugin.enabled) fail(at("id"), `unsupported builtin plugin ${plugin.id}`);
    }
  }
}

// --- skill-package resource materialization ---------------------------------

/** `skill_package_workflow_resource_id`. */
export function skillPackageWorkflowResourceId(workflow: AgentWorkflowPolicy): string {
  return `${workflow.id}@${workflow.version}`;
}

/** `collect_skill_package_resource_ids`. */
function collectSkillPackageResourceIds(
  pkg: SkillPackage,
  pluginIds: Set<string>,
  mcpServerNames: Set<string>,
  promptTemplateIds: Set<string>,
  agentWorkflowKeys: Set<string>,
): void {
  for (const plugin of pkg.resources.plugins) pluginIds.add(plugin.id);
  for (const server of pkg.resources.mcp_servers) mcpServerNames.add(server.name);
  for (const template of pkg.resources.prompt_templates) promptTemplateIds.add(template.id);
  for (const workflow of pkg.resources.agent_workflows) {
    agentWorkflowKeys.add(workflow.id);
    agentWorkflowKeys.add(skillPackageWorkflowResourceId(workflow));
  }
}

function upsertOrReplace<T>(list: T[], item: T, sameAs: (existing: T) => boolean): void {
  const index = list.findIndex(sameAs);
  if (index === -1) list.push(item);
  else list[index] = item;
}

/**
 * `Config::materialize_skill_package_resources_with_previous`: the resources a
 * skill package OWNS are re-projected onto the top-level lists — every id a
 * previous or current package owns is first evicted, then each ENABLED package's
 * resources are upserted back. Mutates `config` in place, like the Rust `&mut self`.
 */
export function materializeSkillPackageResourcesWithPrevious(
  config: Config,
  previousPackages: SkillPackage[] = [],
): void {
  const ownedPluginIds = new Set<string>();
  const ownedMcpServerNames = new Set<string>();
  const ownedPromptTemplateIds = new Set<string>();
  const ownedAgentWorkflowKeys = new Set<string>();

  for (const pkg of [...previousPackages, ...config.skill_packages]) {
    collectSkillPackageResourceIds(
      pkg,
      ownedPluginIds,
      ownedMcpServerNames,
      ownedPromptTemplateIds,
      ownedAgentWorkflowKeys,
    );
  }

  config.plugins = config.plugins.filter((plugin) => !ownedPluginIds.has(plugin.id));
  config.extensions = config.extensions.filter((plugin) => !ownedPluginIds.has(plugin.id));
  config.mcp_servers = config.mcp_servers.filter((server) => !ownedMcpServerNames.has(server.name));
  config.prompt_templates = config.prompt_templates.filter(
    (template) => !ownedPromptTemplateIds.has(template.id),
  );
  config.agent_workflows = config.agent_workflows.filter(
    (workflow) =>
      !ownedAgentWorkflowKeys.has(workflow.id) &&
      !ownedAgentWorkflowKeys.has(skillPackageWorkflowResourceId(workflow)),
  );

  for (const pkg of config.skill_packages) {
    if (!pkg.enabled) continue;
    for (const plugin of pkg.resources.plugins) {
      upsertOrReplace<ExtensionConfig>(
        config.plugins,
        plugin,
        (existing) => existing.id === plugin.id,
      );
    }
    for (const server of pkg.resources.mcp_servers) {
      upsertOrReplace<McpServerConfig>(
        config.mcp_servers,
        server,
        (existing) => existing.name === server.name,
      );
    }
    for (const template of pkg.resources.prompt_templates) {
      upsertOrReplace<PromptTemplate>(
        config.prompt_templates,
        template,
        (existing) => existing.id === template.id,
      );
    }
    for (const workflow of pkg.resources.agent_workflows) {
      upsertOrReplace<AgentWorkflowPolicy>(
        config.agent_workflows,
        workflow,
        (existing) => existing.id === workflow.id && existing.version === workflow.version,
      );
    }
  }
}

/** `Config::materialize_skill_package_resources`. */
export function materializeSkillPackageResources(config: Config): void {
  materializeSkillPackageResourcesWithPrevious(config, []);
}
