/**
 * Policy-surface validators of `Config::validate()` (inventory §5.4): agent
 * workflows, prompt templates, skill packages and guardrails — ported 1:1 from
 * `config/validate.rs`.
 *
 * The detector-endpoint and detector-timeout rules delegate to
 * `@ferrogate/guardrails` (`validate_custom_http_endpoint`,
 * `MAX_DETECTOR_TIMEOUT`), exactly as the Rust crate calls
 * `ferrogate_guardrails`, so config-load validity and runtime evaluability stay
 * one definition.
 */
import {
  DetectorError,
  MAX_DETECTOR_TIMEOUT_MS,
  validateCustomHttpEndpoint,
} from "@ferrogate/guardrails";
import { guardrailProviderRuntimeConfigSchema } from "../schema/entities.js";
import type { Config, GuardrailRule, SkillPackage } from "../schema/index.js";
import {
  fail,
  isBlank,
  isPromptVariableName,
  isSetAndBlank,
  isSetAndEmpty,
  usesRegexCrateUnsupportedSyntax,
  validatePositiveOptional,
  validatePromptMessageRole,
  validatePromptPlaceholders,
  validateSecretRef,
} from "./helpers.js";
import { pluginRegistrationsForValidation } from "./plugins.js";

/** `struct WorkflowToolNames` — the executable tool vocabulary a workflow may name. */
export interface WorkflowToolNames {
  names: Set<string>;
  wildcard: boolean;
}

/** `WorkflowToolNames::contains`. */
export function workflowToolNamesContain(tools: WorkflowToolNames, name: string): boolean {
  return tools.wildcard || tools.names.has(name);
}

/** `Config::workflow_tool_names`: tool-provider plugin grants + MCP `<server>-<tool>`. */
export function workflowToolNames(config: Config): WorkflowToolNames {
  const names = new Set<string>();
  let wildcard = false;
  for (const { plugin } of pluginRegistrationsForValidation(config)) {
    if (plugin.kind !== "tool_provider") continue;
    for (const tool of plugin.permissions.tools) {
      if (tool === "*") wildcard = true;
      else names.add(tool);
    }
  }
  for (const server of config.mcp_servers) {
    for (const tool of server.tools_to_execute) {
      if (tool === "*") wildcard = true;
      else names.add(`${server.name}-${tool}`);
    }
  }
  return { names, wildcard };
}

/** `validate_agent_workflows`. */
export function validateAgentWorkflows(
  config: Config,
  apiKeyIds: Set<string>,
  modelNames: Set<string>,
  providerNames: Set<string>,
  toolNames: WorkflowToolNames,
): void {
  const workflowVersions = new Set<string>();
  for (let index = 0; index < config.agent_workflows.length; index += 1) {
    const workflow = config.agent_workflows[index]!;
    const at = (field: string) => `agent_workflows[${index}].${field}`;
    if (isBlank(workflow.id)) fail(at("id"), "cannot be empty");
    const versionKey = `${workflow.id}@${workflow.version}`;
    if (workflowVersions.has(versionKey)) {
      throw new Error(
        `field agent_workflows[${index}]: duplicate workflow id/version ${workflow.id}@${workflow.version}`,
      );
    }
    workflowVersions.add(versionKey);
    if (isBlank(workflow.name)) fail(at("name"), "cannot be empty");
    if (workflow.version === 0) fail(at("version"), "must be greater than zero");
    if (workflow.nodes.length === 0) fail(at("nodes"), "at least one node is required");
    for (const apiKeyId of workflow.api_key_ids) {
      if (!apiKeyIds.has(apiKeyId)) {
        fail(at("api_key_ids"), `workflow ${workflow.id} references unknown api key ${apiKeyId}`);
      }
    }
    validatePositiveOptional(workflow.max_model_calls, `field ${at("max_model_calls")}`);
    validatePositiveOptional(workflow.max_tool_calls, `field ${at("max_tool_calls")}`);
    validatePositiveOptional(workflow.max_parallelism, `field ${at("max_parallelism")}`);
    validatePositiveOptional(workflow.max_iterations, `field ${at("max_iterations")}`);
    validatePositiveOptional(workflow.timeout_millis, `field ${at("timeout_millis")}`);
    validatePositiveOptional(workflow.token_budget, `field ${at("token_budget")}`);

    const nodeIds = new Set<string>();
    for (let nodeIndex = 0; nodeIndex < workflow.nodes.length; nodeIndex += 1) {
      const node = workflow.nodes[nodeIndex]!;
      const atNode = (field: string) => `${at("nodes")}[${nodeIndex}].${field}`;
      if (isBlank(node.id)) fail(atNode("id"), "cannot be empty");
      if (nodeIds.has(node.id)) fail(atNode("id"), `duplicate node id ${node.id}`);
      nodeIds.add(node.id);
      if (node.model !== null) {
        if (isBlank(node.model)) fail(atNode("model"), "cannot be empty");
        if (!modelNames.has(node.model)) {
          fail(atNode("model"), `workflow ${workflow.id} references unknown model ${node.model}`);
        }
      }
      if (isSetAndBlank(node.tool)) fail(atNode("tool"), "cannot be empty");
      for (const provider of node.providers) {
        if (isBlank(provider)) fail(atNode("providers"), "provider names cannot be empty");
        if (!providerNames.has(provider)) {
          fail(
            atNode("providers"),
            `workflow ${workflow.id} references unknown provider ${provider}`,
          );
        }
      }
      switch (node.kind) {
        case "model": {
          if (node.tool !== null) fail(atNode("tool"), "only tool nodes may declare a tool");
          break;
        }
        case "tool": {
          if (node.providers.length > 0) {
            fail(atNode("providers"), "only model nodes may declare providers");
          }
          if (node.tool === null) {
            fail(atNode("tool"), `tool node ${node.id} must declare a tool`);
          }
          if (!workflowToolNamesContain(toolNames, node.tool)) {
            fail(atNode("tool"), `workflow ${workflow.id} references unknown tool ${node.tool}`);
          }
          break;
        }
        default: {
          if (node.providers.length > 0) {
            fail(atNode("providers"), "only model nodes may declare providers");
          }
          if (node.tool !== null) fail(atNode("tool"), "only tool nodes may declare a tool");
        }
      }
      validatePositiveOptional(node.max_iterations, `field ${atNode("max_iterations")}`);
      validatePositiveOptional(node.token_budget, `field ${atNode("token_budget")}`);
    }
    for (let edgeIndex = 0; edgeIndex < workflow.edges.length; edgeIndex += 1) {
      const edge = workflow.edges[edgeIndex]!;
      const atEdge = (field: string) => `${at("edges")}[${edgeIndex}].${field}`;
      if (!nodeIds.has(edge.from)) fail(atEdge("from"), `unknown node ${edge.from}`);
      if (!nodeIds.has(edge.to)) fail(atEdge("to"), `unknown node ${edge.to}`);
      if (isSetAndBlank(edge.condition)) fail(atEdge("condition"), "cannot be empty");
    }
  }
}

/** `validate_prompt_templates`. */
export function validatePromptTemplates(config: Config, modelNames: Set<string>): void {
  const ids = new Set<string>();
  for (let index = 0; index < config.prompt_templates.length; index += 1) {
    const template = config.prompt_templates[index]!;
    const at = (field: string) => `prompt_templates[${index}].${field}`;
    if (isBlank(template.id)) fail(at("id"), "cannot be empty");
    if (ids.has(template.id)) fail(at("id"), `duplicate prompt template id ${template.id}`);
    ids.add(template.id);
    if (isBlank(template.name)) fail(at("name"), "cannot be empty");
    if (isBlank(template.model)) fail(at("model"), "cannot be empty");
    if (!modelNames.has(template.model)) {
      fail(
        at("model"),
        `prompt template ${template.id} references unknown model ${template.model}`,
      );
    }
    if (template.versions.length === 0) fail(at("versions"), "at least one version is required");

    const variableNames = new Set<string>();
    for (let variableIndex = 0; variableIndex < template.variables.length; variableIndex += 1) {
      const variable = template.variables[variableIndex]!;
      const atVariable = (field: string) => `${at("variables")}[${variableIndex}].${field}`;
      if (isBlank(variable.name)) fail(atVariable("name"), "cannot be empty");
      if (!isPromptVariableName(variable.name)) {
        fail(atVariable("name"), "must use letters, numbers, _, or -");
      }
      if (variableNames.has(variable.name)) {
        fail(atVariable("name"), `duplicate variable ${variable.name}`);
      }
      variableNames.add(variable.name);
      if (isSetAndEmpty(variable.default)) fail(atVariable("default"), "cannot be empty");
    }

    const revisions = new Set<number>();
    for (let versionIndex = 0; versionIndex < template.versions.length; versionIndex += 1) {
      const version = template.versions[versionIndex]!;
      const atVersion = (field: string) => `${at("versions")}[${versionIndex}].${field}`;
      if (version.revision === 0) fail(atVersion("revision"), "must be greater than zero");
      if (revisions.has(version.revision)) {
        fail(atVersion("revision"), `duplicate revision ${version.revision}`);
      }
      revisions.add(version.revision);
      if (version.messages.length === 0) {
        fail(atVersion("messages"), "at least one message is required");
      }
      for (let messageIndex = 0; messageIndex < version.messages.length; messageIndex += 1) {
        const message = version.messages[messageIndex]!;
        validatePromptMessageRole(index, versionIndex, messageIndex, message.role);
        if (isBlank(message.content)) {
          fail(`${atVersion("messages")}[${messageIndex}].content`, "cannot be empty");
        }
        validatePromptPlaceholders(
          index,
          versionIndex,
          messageIndex,
          message.content,
          variableNames,
        );
      }
      if (version.temperature !== null && !(version.temperature >= 0 && version.temperature <= 2)) {
        fail(atVersion("temperature"), "must be between 0 and 2");
      }
      if (version.top_p !== null && !(version.top_p >= 0 && version.top_p <= 1)) {
        fail(atVersion("top_p"), "must be between 0 and 1");
      }
      if (version.max_tokens === 0) fail(atVersion("max_tokens"), "must be greater than zero");
    }
  }
}

/** `skill_package_has_capability`. */
function skillPackageHasCapability(
  pkg: SkillPackage,
  kind: SkillPackage["capabilities"][number]["kind"],
  id: string,
): boolean {
  return pkg.capabilities.some((capability) => capability.kind === kind && capability.id === id);
}

/** `validate_skill_package_resource_capabilities`: an embedded resource must be declared. */
function validateSkillPackageResourceCapabilities(packageIndex: number, pkg: SkillPackage): void {
  const at = (field: string) => `skill_packages[${packageIndex}].resources.${field}`;
  for (let resourceIndex = 0; resourceIndex < pkg.resources.plugins.length; resourceIndex += 1) {
    const plugin = pkg.resources.plugins[resourceIndex]!;
    if (!skillPackageHasCapability(pkg, "plugin", plugin.id)) {
      fail(
        at(`plugins[${resourceIndex}].id`),
        `embedded plugin ${plugin.id} must be declared as a plugin capability`,
      );
    }
  }
  for (
    let resourceIndex = 0;
    resourceIndex < pkg.resources.mcp_servers.length;
    resourceIndex += 1
  ) {
    const server = pkg.resources.mcp_servers[resourceIndex]!;
    if (!skillPackageHasCapability(pkg, "mcp_server", server.name)) {
      fail(
        at(`mcp_servers[${resourceIndex}].name`),
        `embedded MCP server ${server.name} must be declared as an MCP server capability`,
      );
    }
  }
  for (
    let resourceIndex = 0;
    resourceIndex < pkg.resources.prompt_templates.length;
    resourceIndex += 1
  ) {
    const template = pkg.resources.prompt_templates[resourceIndex]!;
    if (!skillPackageHasCapability(pkg, "prompt_template", template.id)) {
      fail(
        at(`prompt_templates[${resourceIndex}].id`),
        `embedded prompt template ${template.id} must be declared as a prompt template capability`,
      );
    }
  }
  for (
    let resourceIndex = 0;
    resourceIndex < pkg.resources.agent_workflows.length;
    resourceIndex += 1
  ) {
    const workflow = pkg.resources.agent_workflows[resourceIndex]!;
    if (!skillPackageHasCapability(pkg, "agent_workflow", workflow.id)) {
      fail(
        at(`agent_workflows[${resourceIndex}].id`),
        `embedded agent workflow ${workflow.id} must be declared as an agent workflow capability`,
      );
    }
  }
}

/** `validate_skill_packages`. */
export function validateSkillPackages(
  config: Config,
  apiKeyIds: Set<string>,
  toolNames: WorkflowToolNames,
): void {
  const pluginIds = new Set(
    pluginRegistrationsForValidation(config).map(({ plugin }) => plugin.id),
  );
  const mcpServerNames = new Set(config.mcp_servers.map((server) => server.name));
  const promptTemplateIds = new Set(config.prompt_templates.map((template) => template.id));
  const agentWorkflowIds = new Set(config.agent_workflows.map((workflow) => workflow.id));
  const embeddedToolNames = new Set<string>();
  for (const pkg of config.skill_packages) {
    for (const plugin of pkg.resources.plugins) {
      pluginIds.add(plugin.id);
      for (const tool of plugin.permissions.tools) embeddedToolNames.add(tool);
    }
    for (const server of pkg.resources.mcp_servers) {
      mcpServerNames.add(server.name);
      for (const tool of server.tools_to_execute) {
        embeddedToolNames.add(tool);
        embeddedToolNames.add(`${server.name}-${tool}`);
      }
    }
    for (const template of pkg.resources.prompt_templates) promptTemplateIds.add(template.id);
    for (const workflow of pkg.resources.agent_workflows) agentWorkflowIds.add(workflow.id);
  }

  const ids = new Set<string>();
  for (let index = 0; index < config.skill_packages.length; index += 1) {
    const pkg = config.skill_packages[index]!;
    const at = (field: string) => `skill_packages[${index}].${field}`;
    if (isBlank(pkg.id)) fail(at("id"), "cannot be empty");
    if (ids.has(pkg.id)) fail(at("id"), `duplicate skill package id ${pkg.id}`);
    ids.add(pkg.id);
    if (isBlank(pkg.name)) fail(at("name"), "cannot be empty");
    if (isBlank(pkg.version)) fail(at("version"), "cannot be empty");
    if (pkg.capabilities.length === 0) {
      fail(at("capabilities"), "at least one capability is required");
    }
    for (const apiKeyId of pkg.api_key_ids) {
      if (!apiKeyIds.has(apiKeyId)) {
        fail(at("api_key_ids"), `skill package ${pkg.id} references unknown api key ${apiKeyId}`);
      }
    }
    validateExtensionPermissionNamesForPackage(index, "permissions.tools", pkg.permissions.tools);
    validateExtensionPermissionNamesForPackage(
      index,
      "permissions.network",
      pkg.permissions.network,
    );
    for (
      let runtimeIndex = 0;
      runtimeIndex < pkg.compatibility.agent_runtimes.length;
      runtimeIndex += 1
    ) {
      if (isBlank(pkg.compatibility.agent_runtimes[runtimeIndex]!)) {
        fail(at(`compatibility.agent_runtimes[${runtimeIndex}]`), "cannot be empty");
      }
    }
    validateSkillPackageResourceCapabilities(index, pkg);
    for (let capabilityIndex = 0; capabilityIndex < pkg.capabilities.length; capabilityIndex += 1) {
      const capability = pkg.capabilities[capabilityIndex]!;
      const atCapability = at(`capabilities[${capabilityIndex}].id`);
      if (isBlank(capability.id)) fail(atCapability, "cannot be empty");
      const known = (label: string, present: boolean) => {
        if (!present) {
          fail(
            atCapability,
            `skill package ${pkg.id} references unknown ${label} ${capability.id}`,
          );
        }
      };
      switch (capability.kind) {
        case "plugin":
          known("plugin", pluginIds.has(capability.id));
          break;
        case "tool":
          known(
            "tool",
            workflowToolNamesContain(toolNames, capability.id) ||
              embeddedToolNames.has(capability.id),
          );
          break;
        case "mcp_server":
          known("MCP server", mcpServerNames.has(capability.id));
          break;
        case "mcp_tool":
          known(
            "MCP tool",
            workflowToolNamesContain(toolNames, capability.id) ||
              embeddedToolNames.has(capability.id),
          );
          break;
        case "prompt_template":
          known("prompt template", promptTemplateIds.has(capability.id));
          break;
        case "agent_workflow":
          known("agent workflow", agentWorkflowIds.has(capability.id));
          break;
      }
    }
  }
}

/** `validate_extension_permission_names` applied to a `skill_packages[i]` entry. */
function validateExtensionPermissionNamesForPackage(
  index: number,
  field: string,
  names: string[],
): void {
  const seen = new Set<string>();
  for (let nameIndex = 0; nameIndex < names.length; nameIndex += 1) {
    const name = names[nameIndex]!;
    if (isBlank(name)) fail(`skill_packages[${index}].${field}[${nameIndex}]`, "cannot be empty");
    if (seen.has(name)) {
      fail(`skill_packages[${index}].${field}[${nameIndex}]`, `duplicate permission value ${name}`);
    }
    seen.add(name);
  }
}

// --- guardrails -------------------------------------------------------------

const DEFAULT_PROVIDER_RUNTIME = guardrailProviderRuntimeConfigSchema.parse({});

/**
 * `guardrail.provider_runtime != GuardrailProviderRuntimeConfig::default()`.
 * `provider_runtime` is `#[serde(flatten)]` in Rust, so the fields sit at the top
 * level of the rule here and the comparison is field-by-field.
 */
function providerRuntimeIsDefault(rule: GuardrailRule): boolean {
  return (
    rule.provider_on_error === DEFAULT_PROVIDER_RUNTIME.provider_on_error &&
    rule.provider_max_concurrency === DEFAULT_PROVIDER_RUNTIME.provider_max_concurrency &&
    rule.provider_circuit_failure_threshold ===
      DEFAULT_PROVIDER_RUNTIME.provider_circuit_failure_threshold &&
    rule.provider_circuit_cooldown_ms === DEFAULT_PROVIDER_RUNTIME.provider_circuit_cooldown_ms &&
    rule.provider_max_retries === DEFAULT_PROVIDER_RUNTIME.provider_max_retries &&
    rule.provider_max_payload_bytes === DEFAULT_PROVIDER_RUNTIME.provider_max_payload_bytes &&
    rule.provider_max_response_bytes === DEFAULT_PROVIDER_RUNTIME.provider_max_response_bytes &&
    rule.provider_allow_private_network ===
      DEFAULT_PROVIDER_RUNTIME.provider_allow_private_network &&
    rule.provider_secret_ref === DEFAULT_PROVIDER_RUNTIME.provider_secret_ref
  );
}

/**
 * `tokio::sync::Semaphore::MAX_PERMITS` (`usize::MAX >> 3` on 64-bit) — the
 * ceiling the Rust runtime's detector concurrency gate cannot exceed. Kept as the
 * same numeric bound for parity; a Worker has no semaphore to overflow.
 */
// biome-ignore lint/correctness/noPrecisionLoss: this is a documented parity ceiling used only as an unreachable upper bound in a comparison, so f64 rounding of the exact value is immaterial
const SEMAPHORE_MAX_PERMITS = 2_305_843_009_213_693_951;

/** `validate_custom_http_endpoint` + `SecretRef` legs shared by every non-`none` provider. */
function validateDetectorEndpoint(
  index: number,
  endpoint: string,
  allowPrivateNetwork: boolean,
): void {
  const field = `guardrails[${index}].provider_endpoint`;
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    fail(field, "invalid URL");
  }
  try {
    validateCustomHttpEndpoint(url, allowPrivateNetwork);
  } catch (error) {
    fail(field, error instanceof DetectorError ? error.safeMessage() : String(error));
  }
}

/** `validate_guardrails`. */
export function validateGuardrails(
  config: Config,
  apiKeyIds: Set<string>,
  modelNames: Set<string>,
  providerNames: Set<string>,
): void {
  const ids = new Set<string>();
  for (let index = 0; index < config.guardrails.length; index += 1) {
    const guardrail = config.guardrails[index]!;
    const at = (field: string) => `guardrails[${index}].${field}`;
    if (isBlank(guardrail.id)) fail(at("id"), "cannot be empty");
    if (ids.has(guardrail.id)) fail(at("id"), `duplicate guardrail id ${guardrail.id}`);
    ids.add(guardrail.id);
    if (isBlank(guardrail.name)) fail(at("name"), "cannot be empty");
    const uniqueSources = new Set(guardrail.sources);
    if (guardrail.sources.length === 0 || uniqueSources.size !== guardrail.sources.length) {
      fail(at("sources"), "must contain unique content sources");
    }
    if (
      guardrail.provider === "none" &&
      guardrail.keywords.length === 0 &&
      guardrail.regex.length === 0 &&
      guardrail.max_input_bytes === null
    ) {
      throw new Error(
        `field guardrails[${index}]: at least one keyword, regex, max_input_bytes, or provider is required`,
      );
    }
    for (let keywordIndex = 0; keywordIndex < guardrail.keywords.length; keywordIndex += 1) {
      if (isBlank(guardrail.keywords[keywordIndex]!)) {
        fail(at(`keywords[${keywordIndex}]`), "cannot be empty");
      }
    }
    for (let regexIndex = 0; regexIndex < guardrail.regex.length; regexIndex += 1) {
      const pattern = guardrail.regex[regexIndex]!;
      if (isBlank(pattern)) fail(at(`regex[${regexIndex}]`), "cannot be empty");
      // Rust: `regex::Regex::new(pattern).with_context(|| "... invalid regex")`.
      // anyhow's `Display` renders only the outermost context, so the observable
      // Rust message is exactly `invalid regex` for EVERY rejection reason —
      // including the two constructs the `regex` crate refuses but JS accepts.
      if (usesRegexCrateUnsupportedSyntax(pattern)) {
        fail(at(`regex[${regexIndex}]`), "invalid regex");
      }
      try {
        new RegExp(pattern);
      } catch {
        fail(at(`regex[${regexIndex}]`), "invalid regex");
      }
    }
    if (guardrail.max_input_bytes === 0) {
      fail(at("max_input_bytes"), "must be greater than zero");
    }
    for (const apiKeyId of guardrail.api_key_ids) {
      if (!apiKeyIds.has(apiKeyId)) {
        fail(at("api_key_ids"), `guardrail ${guardrail.id} references unknown api key ${apiKeyId}`);
      }
    }
    for (const model of guardrail.models) {
      if (!modelNames.has(model)) {
        fail(at("models"), `guardrail ${guardrail.id} references unknown model ${model}`);
      }
    }
    for (const provider of guardrail.providers) {
      if (!providerNames.has(provider)) {
        fail(at("providers"), `guardrail ${guardrail.id} references unknown provider ${provider}`);
      }
    }
    if (guardrail.stage === "request" && guardrail.effect === "redact") {
      fail(at("effect"), "request guardrails support deny only");
    }
    if (guardrail.max_input_bytes !== null && guardrail.stage !== "request") {
      fail(at("max_input_bytes"), "max input length guardrails apply to request stage only");
    }
    const isSemanticProvider =
      guardrail.provider === "presidio" || guardrail.provider === "llm_guard_prompt_injection";
    if (
      guardrail.provider !== "presidio" &&
      (guardrail.provider_language !== null || guardrail.provider_entities !== null)
    ) {
      fail(at("provider_language/provider_entities"), "only valid when provider is presidio");
    }
    if (
      !isSemanticProvider &&
      (guardrail.provider_score_threshold_percent !== null ||
        guardrail.provider_fingerprint_secret_ref !== null)
    ) {
      fail(
        at("provider_score_threshold_percent/provider_fingerprint_secret_ref"),
        "only valid when provider is presidio or llm_guard_prompt_injection",
      );
    }
    switch (guardrail.provider) {
      case "none": {
        if (guardrail.provider_endpoint !== null) {
          fail(at("provider_endpoint"), "only valid when provider is custom_http");
        }
        if (!providerRuntimeIsDefault(guardrail)) {
          fail(
            at("provider_*"),
            "detector runtime settings are only valid when provider is custom_http",
          );
        }
        break;
      }
      case "custom_http": {
        const endpoint = guardrail.provider_endpoint ?? "";
        if (isBlank(endpoint)) {
          fail(at("provider_endpoint"), "required when provider is custom_http");
        }
        validateDetectorEndpoint(index, endpoint, guardrail.provider_allow_private_network);
        if (guardrail.provider_secret_ref !== null) {
          validateSecretRef(at("provider_secret_ref"), guardrail.provider_secret_ref);
        }
        if (guardrail.provider_max_concurrency === 0) {
          fail(at("provider_max_concurrency"), "must be greater than zero");
        }
        if (guardrail.provider_max_concurrency > SEMAPHORE_MAX_PERMITS) {
          fail(at("provider_max_concurrency"), "exceeds the runtime semaphore limit");
        }
        if (guardrail.provider_circuit_failure_threshold === 0) {
          fail(at("provider_circuit_failure_threshold"), "must be greater than zero");
        }
        if (guardrail.provider_circuit_cooldown_ms === 0) {
          fail(at("provider_circuit_cooldown_ms"), "must be greater than zero");
        }
        if (guardrail.provider_max_retries > 1) {
          fail(at("provider_max_retries"), "must be zero or one");
        }
        if (guardrail.provider_max_payload_bytes === 0) {
          fail(at("provider_max_payload_bytes"), "must be greater than zero");
        }
        if (guardrail.provider_max_response_bytes === 0) {
          fail(at("provider_max_response_bytes"), "must be greater than zero");
        }
        if (
          guardrail.provider_on_error === "fallback_detector" &&
          guardrail.keywords.length === 0 &&
          guardrail.regex.length === 0 &&
          guardrail.max_input_bytes === null
        ) {
          fail(
            at("provider_on_error"),
            "fallback_detector requires a keyword, regex, or max_input_bytes fallback",
          );
        }
        break;
      }
      case "presidio":
      case "llm_guard_prompt_injection": {
        const endpoint = guardrail.provider_endpoint ?? "";
        if (isBlank(endpoint)) {
          fail(
            at("provider_endpoint"),
            "required when provider is presidio or llm_guard_prompt_injection",
          );
        }
        validateDetectorEndpoint(index, endpoint, guardrail.provider_allow_private_network);
        if (guardrail.provider_secret_ref !== null) {
          validateSecretRef(at("provider_secret_ref"), guardrail.provider_secret_ref);
        }
        const fingerprintRef = guardrail.provider_fingerprint_secret_ref ?? "";
        if (isBlank(fingerprintRef)) {
          fail(
            at("provider_fingerprint_secret_ref"),
            "required when provider is presidio or llm_guard_prompt_injection",
          );
        }
        validateSecretRef(at("provider_fingerprint_secret_ref"), fingerprintRef);
        if (
          guardrail.provider_score_threshold_percent !== null &&
          guardrail.provider_score_threshold_percent > 100
        ) {
          fail(at("provider_score_threshold_percent"), "must be between 0 and 100");
        }
        if (isSetAndBlank(guardrail.provider_language)) {
          fail(at("provider_language"), "cannot be empty");
        }
        if (
          guardrail.provider_entities !== null &&
          (guardrail.provider_entities.length === 0 ||
            guardrail.provider_entities.some((entity) => isBlank(entity)))
        ) {
          fail(at("provider_entities"), "entries must be non-empty");
        }
        if (guardrail.provider_max_payload_bytes === 0) {
          fail(at("provider_max_payload_bytes"), "must be greater than zero");
        }
        if (guardrail.provider_max_response_bytes === 0) {
          fail(at("provider_max_response_bytes"), "must be greater than zero");
        }
        if (
          guardrail.provider_on_error === "fallback_detector" &&
          guardrail.keywords.length === 0 &&
          guardrail.regex.length === 0 &&
          guardrail.max_input_bytes === null
        ) {
          fail(
            at("provider_on_error"),
            "fallback_detector requires a keyword, regex, or max_input_bytes fallback",
          );
        }
        break;
      }
    }
    if (guardrail.provider_timeout_ms === 0) {
      fail(at("provider_timeout_ms"), "must be greater than zero");
    }
    if (guardrail.provider_timeout_ms > MAX_DETECTOR_TIMEOUT_MS) {
      fail(at("provider_timeout_ms"), "must not exceed 30000 milliseconds");
    }
  }
}
